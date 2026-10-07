"""ONE targeted MOCK/fake-controller group. NOT real Engine or isolation proof."""
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import brokerproof_runner as proof


def mocked_enrollment(root):
    resources = [format(n, "064x") for n in range(1, 9)]
    return {"schema": "owned-broker-fixture-v1", "fixture": "mock-owned",
            "ownerUid": os.getuid(), "controllerSocket": str(root / "control.sock"),
            "controllerDigest": "d" * 64, "resources": resources,
            "containerA": resources[0], "containerB": resources[1], "context": "fixture"}


def mocked_topology(enrolled):
    # Simulated evidence fields for verifier coverage, not measured Linux namespaces.
    resources = enrolled["resources"]
    kinds = ("ingress", "caller-credential", "engine-tap", "engine", "daemon-control", "daemon-data")
    roles = {"client": ("ingress", "caller-credential"), "broker": ("ingress", "engine-tap"),
             "observer": ("engine-tap", "engine", "daemon-control"), "daemon": ("engine", "daemon-data")}
    mounts = {role: [{"kind": kind, "resource": resources[kinds.index(kind) + 2],
                      "device": 1, "inode": kinds.index(kind) + 10,
                      "mode": "0700" if kind == "daemon-data" else "0600", "uid": 1000}
                     for kind in selected] for role, selected in roles.items()}
    return {"backend": "real-engine", "controllerDigest": enrolled["controllerDigest"],
            "resources": resources, "hostSocketMounts": [], "hostNamespaceJoins": [],
            "budget": {"cpuMillis": 2000, "memoryBytes": 1_073_741_824},
            "processes": {role: {"uid": 1000, "capEff": "0000000000000000",
                                 "namespaces": {k: index + 10 for k in ("mnt", "net", "pid", "user")},
                                 "routes": [], "tcpListeners": []}
                          for index, role in enumerate(proof.ROLES)},
            "mounts": mounts,
            "access": [{"kind": kind, "asRole": "client", "errno": 0 if kind == "ingress" else 13,
                        "result": "connected" if kind == "ingress" else "inaccessible"}
                       for kind in ("ingress", "engine", "engine-tap", "daemon-data", "daemon-control", "controller")],
            "engine": {"apiMin": "1.24", "apiMax": "1.47", "containerA": enrolled["containerA"],
                       "containerB": enrolled["containerB"], "targetLabels": [enrolled["fixture"]] * 2}}


def mocked_evidence(enrolled, topology):
    snapshot = {"schemaVersion": "inspect-snapshot-v1", "containerId": enrolled["containerA"],
                "context": {"id": enrolled["context"], "version": 1},
                "observedAt": "2026-10-07T00:00:00.000Z", "coverage": "runtime-config-inspect",
                "facts": {"configuredUser": "non-root", "privileged": False, "readonlyRootfs": True,
                          "capAdd": [], "capDrop": ["ALL"],
                          "security": {"seccomp": "default", "apparmor": "unknown"},
                          "namespaces": {"network": "private", "pid": "private", "ipc": "private", "user": "unknown"},
                          "mounts": {"groups": [], "socketPresent": False}, "ports": [],
                          "resources": {k: "unknown" for k in ("memory", "nanoCpus", "pids", "cpuQuota", "cpuPeriod")}}}
    snapshot["hash"] = hashlib.sha256(json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    cases = []
    counts = {"adapter": 0, "received": 0, "forwarded": 0}
    for index, name in enumerate(proof.CASES):
        positive = name == "positive"
        before = dict(counts)
        if positive:
            counts = {k: v + 1 for k, v in counts.items()}
        reason = "allowed" if positive else "disabled" if name == "ro-only" else "authorization" if name.startswith("wrong-") else "invalid_request"
        audit = [{"correlationId": f"00000000-0000-4000-8000-{index:012x}", "time": snapshot["observedAt"],
                  "subject": "subject-a" if positive else "anonymous",
                  "containerId": enrolled["containerA"] if positive else "invalid",
                  "context": enrolled["context"] if positive else "invalid", "operation": "inspect",
                  "scope": "container:inspect", "stage": "admission", "decision": "allowed" if positive else "not_authorized",
                  "reason": reason, "dispatched": False}]
        if positive:
            audit.append({**audit[0], "stage": "publication", "decision": "checked", "dispatched": True})
        cases.append({"name": name, "clientRequest": proof.client_request(name, enrolled), "before": before, "after": dict(counts),
                      "requests": [{"method": "GET", "path": "/v1.47/containers/" + enrolled["containerA"] + "/json"}] if positive else [],
                      "response": {"status": "checked", "snapshot": snapshot} if positive else {"status": "not_authorized"}, "audit": audit})
    return {"cases": cases, "caller": {"digest": "c" * 64, "bytes": 32, "grant": "grant-a", "consent": "consent-a", "subject": "subject-a"},
            "defaultOff": {"stdout": "inspect_broker_disabled\n", "listeners": 0}, "topology": topology}


class MockController:
    def __init__(self, enrolled, deadline):
        self.enrolled, self.deadline = enrolled, deadline
        self.calls = []
        self.topology = mocked_topology(enrolled)
        self.evidence = mocked_evidence(enrolled, self.topology)
        self.cleanup_fails = False
        self.run_fails = False

    def call(self, action, challenge, **payload):
        self.calls.append((action, payload))
        if action == "qualify":
            return self.topology
        if action == "run":
            if self.run_fails:
                raise proof.Failure("PROOF_DEADLINE")
            return self.evidence
        if self.cleanup_fails:
            raise proof.Failure("DOCKER_ENGINE_UNAVAILABLE")
        return {"released": payload["resources"], "remaining": []}


class BrokerProofMockControllerTests(unittest.TestCase):
    def setUp(self):
        # macOS TMPDIR can exceed sockaddr_un; use an owned short temporary path.
        self.temporary = tempfile.TemporaryDirectory(prefix="bpm-", dir="/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.enrolled = mocked_enrollment(self.root)
        self.path = self.root / "enrollment.json"
        self.path.write_text(json.dumps(self.enrolled))
        self.path.chmod(0o600)
        self.controller = MockController(self.enrolled, time.monotonic() + 10)

    def run_mock(self):
        return proof.run(self.path, "mock-owned", lambda enrolled, deadline: self.controller)

    def test_no_fixture_is_nonpassing_and_does_not_discover_docker(self):
        with patch.object(proof.socket, "socket", side_effect=AssertionError("must not connect")):
            self.assertEqual(proof.run()["status"], "TOPOLOGY_UNQUALIFIED")

    def test_candidate_from_simulated_fields_is_never_real_acceptance(self):
        result = self.run_mock()
        self.assertEqual(result["status"], "EVIDENCE_CANDIDATE")
        self.assertFalse(result["passed"])
        self.assertFalse(result["realProofAccepted"])
        self.assertFalse(result["productionEnabled"])
        self.assertEqual([a for a, _ in self.controller.calls], ["qualify", "run", "cleanup"])
        self.assertEqual(result["cleanup"], "owned-resources-released")
        self.assertEqual(self.controller.calls[-1][1], {"resources": self.enrolled["resources"]})

    def test_explicit_consent_private_file_owner_no_symlink(self):
        self.assertEqual(proof.run(self.path, "other")["status"], "TOPOLOGY_UNQUALIFIED")
        self.path.chmod(0o644)
        self.assertEqual(self.run_mock()["status"], "TOPOLOGY_UNQUALIFIED")
        self.path.chmod(0o600)
        alias = self.root / "alias.json"
        alias.symlink_to(self.path)
        self.assertEqual(proof.run(alias, "mock-owned")["status"], "TOPOLOGY_UNQUALIFIED")
        self.assertEqual(self.controller.calls, [])

    def test_bad_topologies_block_before_run_or_cleanup(self):
        original = copy.deepcopy(self.controller.topology)
        mutations = [lambda e: e.update(backend="mock"), lambda e: e.update(hostSocketMounts=["host"]),
                     lambda e: e.update(hostNamespaceJoins=["net"]),
                     lambda e: e["processes"]["client"].update(capEff="0000000000200000"),
                     lambda e: e["processes"]["client"].update(uid=0),
                     lambda e: e["processes"]["client"].update(routes=["default"]),
                     lambda e: e["processes"]["client"].update(tcpListeners=[2375]),
                     lambda e: e["processes"]["client"].update(namespaces=e["processes"]["broker"]["namespaces"]),
                     lambda e: e["mounts"]["client"].append(e["mounts"]["daemon"][0]),
                     lambda e: e["access"][1].update(result="connected", errno=0),
                     lambda e: e["engine"].update(apiMax="1.46"),
                     lambda e: e.update(resources=["foreign"])]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.controller.topology = copy.deepcopy(original)
                self.controller.calls.clear()
                mutation(self.controller.topology)
                self.assertEqual(self.run_mock()["status"], "TOPOLOGY_UNQUALIFIED")
                self.assertEqual([a for a, _ in self.controller.calls], ["qualify"])

    def test_each_negative_requires_three_zero_deltas(self):
        original = copy.deepcopy(self.controller.evidence)
        for index in range(1, len(proof.CASES)):
            for counter in ("adapter", "received", "forwarded"):
                with self.subTest(case=proof.CASES[index], counter=counter):
                    self.controller.evidence = copy.deepcopy(original)
                    self.controller.evidence["cases"][index]["after"][counter] += 1
                    self.assertEqual(self.run_mock()["status"], "PROOF_FAILED")
                    self.assertEqual(self.controller.calls[-1][0], "cleanup")

    def test_wrong_path_hash_schema_audit_replay_or_missing_case_fail(self):
        original = copy.deepcopy(self.controller.evidence)
        mutations = [lambda e: e["cases"][0]["requests"][0].update(method="POST"),
                     lambda e: e["cases"][1]["clientRequest"].update(method="GET"),
                     lambda e: e["cases"][0]["response"]["snapshot"].update(hash="0" * 64),
                     lambda e: e["cases"][0]["response"]["snapshot"].update(Env=["secret"]),
                     lambda e: e["cases"][1]["audit"][0].update(containerId=self.enrolled["containerB"]),
                     lambda e: e["cases"][1]["audit"][0].update(correlationId=e["cases"][0]["audit"][0]["correlationId"]),
                     lambda e: e["cases"].pop(), lambda e: e["cases"][0]["before"].update(adapter=True)]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.controller.evidence = copy.deepcopy(original)
                mutation(self.controller.evidence)
                self.assertEqual(self.run_mock()["status"], "PROOF_FAILED")

    def test_actual_raw_ingress_rejections_preserve_all_denial_callbacks(self):
        # Actual existing parser/Broker.deny + stub transport, NOT real Engine proof.
        root = Path(__file__).resolve().parents[3]
        script = r"""
const { createIngress } = require('./server/broker/src/ingress.ts');
const { Broker } = require('./server/broker/src/broker.ts');
const { AuditBuffer } = require('./server/broker/src/audit.ts');
const { PolicyStore } = require('./server/broker/src/policy.ts');
const net = require('node:net');
const fs = require('node:fs');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
(async () => {
  const observations = [];
  for (const request of input.requests) {
    const audit = new AuditBuffer();
    let adapterCalls = 0, handleCalls = 0, denialCallbacks = 0;
    const broker = new Broker({ policy: new PolicyStore(), audit,
      engine: { inspect: async () => { adapterCalls++; throw new Error('unexpected dispatch'); } } });
    const originalDeny = broker.deny.bind(broker);
    broker.deny = (...args) => { denialCallbacks++; return originalDeny(...args); };
    const originalHandle = broker.handle.bind(broker);
    broker.handle = (...args) => { handleCalls++; return originalHandle(...args); };
    const server = createIngress(broker);
    try {
      await new Promise((resolve, reject) => {
        server.once('error', reject); server.listen(input.socket, resolve);
      });
      fs.chmodSync(input.socket, 0o600);
      const wireBytes = await new Promise((resolve, reject) => {
        const client = net.createConnection(input.socket);
        let bytes = 0;
        client.setTimeout(1000, () => { client.destroy(); reject(new Error('probe deadline')); });
        client.on('error', reject);
        client.on('data', chunk => { bytes += chunk.length; });
        client.on('close', () => resolve(bytes));
        client.on('connect', () => client.write(request.method + ' ' + request.path +
          ' HTTP/1.1\r\nHost: broker\r\nConnection: close\r\nContent-Length: 0\r\n\r\n'));
      });
      await new Promise(resolve => setImmediate(resolve));
      const records = audit.drain();
      observations.push({ adapterCalls, audit: records,
        response: { status: 'ingress_rejected', wireBytes, closed: true, handleCalls,
          denialCallbacks, auditCorrelations: records.map(record => record.correlationId) } });
    } finally {
      await new Promise(resolve => server.close(resolve));
    }
  }
  process.stdout.write(JSON.stringify(observations));
})().catch(error => { console.error(error); process.exitCode = 1; });
"""
        loader = "const r=require('node:module').createRequire(process.cwd()+'/server/api/package.json'); const s=require('node:child_process').spawnSync(process.execPath,[r.resolve('tsx/cli'),'--eval',process.argv[1]],{stdio:'inherit',timeout:8000}); process.exit(s.status??1);"
        result = subprocess.run(["node", "-e", loader, script], cwd=root, text=True,
                                input=json.dumps({"socket": str(self.root / "raw.sock"),
                                                  "requests": [proof.client_request(n, self.enrolled) for n in ("exec", "create", "export")]}),
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        observations = json.loads(result.stdout)
        self.assertEqual(len(observations), 3)
        for index, observation in enumerate(observations, 1):
            self.assertEqual(observation["adapterCalls"], 0)
            self.assertEqual(observation["response"]["wireBytes"], 0)
            self.assertEqual(observation["response"]["handleCalls"], 0)
            self.assertEqual(observation["response"]["denialCallbacks"], 2)
            self.assertEqual(len(observation["audit"]), 2)
            self.controller.evidence["cases"][index].update(response=observation["response"], audit=observation["audit"])
        result = self.run_mock()
        self.assertEqual(result["status"], "EVIDENCE_CANDIDATE")
        self.assertFalse(result["realProofAccepted"])
        self.assertEqual(result["counters"][1]["response"], observations[0]["response"])
        original = copy.deepcopy(self.controller.evidence)
        mutations = [lambda c: c["audit"].pop(), lambda c: c["audit"].append(copy.deepcopy(c["audit"][0])),
                     lambda c: c["audit"][1].update(correlationId=c["audit"][0]["correlationId"]),
                     lambda c: c["audit"][1].update(stage="publication"),
                     lambda c: c["audit"][1].update(reason="overload"),
                     lambda c: c["audit"][1].update(subject="subject-a"),
                     lambda c: c["response"]["auditCorrelations"].reverse(),
                     lambda c: c["response"].update(wireBytes=1), lambda c: c["response"].update(closed=False),
                     lambda c: c["response"].update(handleCalls=1), lambda c: c["response"].update(denialCallbacks=1),
                     lambda c: c["response"].update(wireBytes=False), lambda c: c["response"].update(wireBytes=0.0),
                     lambda c: c["response"].update(handleCalls=False), lambda c: c["response"].update(handleCalls=0.0),
                     lambda c: c["response"].update(denialCallbacks=2.0),
                     lambda c: c["response"].update(status="not_authorized")]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.controller.evidence = copy.deepcopy(original)
                mutation(self.controller.evidence["cases"][1])
                self.assertEqual(self.run_mock()["status"], "PROOF_FAILED")
        self.controller.evidence = copy.deepcopy(original)
        case = self.controller.evidence["cases"][1]
        replay = self.controller.evidence["cases"][0]["audit"][0]["correlationId"]
        case["audit"][0]["correlationId"] = replay
        case["response"]["auditCorrelations"][0] = replay
        self.assertEqual(self.run_mock()["status"], "PROOF_FAILED")
        self.controller.evidence = copy.deepcopy(original)
        self.controller.evidence["cases"][4]["audit"].append(copy.deepcopy(self.controller.evidence["cases"][4]["audit"][0]))
        self.assertEqual(self.run_mock()["status"], "PROOF_FAILED")
        for name in proof.CASES[1:]:
            for counter in ("adapter", "received", "forwarded"):
                self.controller.evidence = copy.deepcopy(original)
                self.controller.evidence["cases"][proof.CASES.index(name)]["after"][counter] += 1
                self.assertEqual(self.run_mock()["status"], "PROOF_FAILED")
        for index in (4, 5, 6):
            self.controller.evidence = copy.deepcopy(original)
            self.controller.evidence["cases"][index].update(response=observations[0]["response"], audit=observations[0]["audit"])
            self.assertEqual(self.run_mock()["status"], "PROOF_FAILED")

    def test_snapshot_context_is_exact_string_id_and_strict_integer_version(self):
        original = copy.deepcopy(self.controller.evidence)
        contexts = [{"id": self.enrolled["context"], "version": value} for value in (True, False, 1.0, "1", 0, -1, 2)]
        contexts += [{"id": 1, "version": 1}, {"id": self.enrolled["context"]},
                     {"id": self.enrolled["context"], "version": 1, "extra": 0}]
        for context in contexts:
            with self.subTest(context=context):
                self.controller.evidence = copy.deepcopy(original)
                snapshot = self.controller.evidence["cases"][0]["response"]["snapshot"]
                snapshot["context"] = context
                snapshot["hash"] = hashlib.sha256(json.dumps({k: v for k, v in snapshot.items() if k != "hash"}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                self.assertEqual(self.run_mock()["status"], "PROOF_FAILED")

    def test_candidate_numeric_fields_reject_bool_float_and_integer_lookalikes(self):
        original = copy.deepcopy(self.controller.evidence)
        paths = [("caller", "bytes"), ("defaultOff", "listeners"),
                 ("topology", "budget", "cpuMillis"), ("topology", "budget", "memoryBytes"),
                 ("topology", "processes", "client", "uid"), ("topology", "processes", "client", "namespaces", "mnt"),
                 ("topology", "mounts", "client", 0, "device"), ("topology", "mounts", "client", 0, "inode"),
                 ("topology", "mounts", "client", 0, "uid"), ("topology", "access", 0, "errno")]
        paths += [("cases", i, phase, counter) for i in range(len(proof.CASES))
                  for phase in ("before", "after") for counter in ("adapter", "received", "forwarded")]
        for path in paths:
            for kind in (bool, float, str):
                with self.subTest(path=path, kind=kind):
                    evidence = copy.deepcopy(original)
                    parent = evidence
                    for key in path[:-1]:
                        parent = parent[key]
                    parent[path[-1]] = kind(parent[path[-1]])
                    with self.assertRaises(proof.Failure):
                        proof.verify_run(evidence, self.enrolled)
        for value in (True, False, float(os.getuid()), str(os.getuid())):
            enrollment = {**self.enrolled, "ownerUid": value}
            self.path.write_text(json.dumps(enrollment))
            with self.assertRaises(proof.Failure):
                proof.enrollment(self.path, "mock-owned")
        self.path.write_text(json.dumps(self.enrolled))
        for facts in ({"resources": {k: True for k in ("memory", "nanoCpus", "pids", "cpuQuota", "cpuPeriod")}},
                      {"mounts": {"groups": [{"type": "bind", "readOnly": True, "count": True}], "socketPresent": False}},
                      {"ports": [{"port": True, "protocol": "tcp", "published": False}]}):
            snapshot = copy.deepcopy(original["cases"][0]["response"]["snapshot"])
            snapshot["facts"].update(facts)
            snapshot["hash"] = hashlib.sha256(json.dumps({k: v for k, v in snapshot.items() if k != "hash"}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            with self.assertRaises(proof.Failure):
                proof.snapshot_hash(snapshot, self.enrolled)

    def test_ambiguous_run_and_cleanup_failure_are_not_pass(self):
        self.controller.run_fails = True
        self.assertEqual(self.run_mock()["status"], "PROOF_DEADLINE")
        self.assertEqual(self.controller.calls[-1][0], "cleanup")
        self.controller.run_fails = False
        self.controller.cleanup_fails = True
        self.assertEqual(self.run_mock()["status"], "CLEANUP_FAILED")

    def test_missing_explicit_control_endpoint_is_unavailable(self):
        result = proof.run(self.path, "mock-owned")
        self.assertEqual(result["status"], "DOCKER_ENGINE_UNAVAILABLE")
        self.assertEqual(result["cleanup"], "not-requested")

    def test_duplicate_oversize_and_nonfinite_json_fail(self):
        for value in (b'{"x":1,"x":2}', b'{"x":NaN}', b' ' * (proof.MAX_BYTES + 1), b'\xff'):
            with self.subTest(value=value[:32]):
                with self.assertRaises(proof.Failure):
                    proof.decode(value)

    def test_fake_socket_envelope_and_absolute_deadline(self):
        endpoint = self.root / "control.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(str(endpoint))
        endpoint.chmod(0o600)
        listener.listen(1)
        errors = []

        def serve():
            try:
                with listener.accept()[0] as connection:
                    connection.settimeout(1)
                    request = json.loads(connection.recv(4096))
                    response = {k: request[k] for k in ("schema", "fixture", "challenge", "action")}
                    response["evidence"] = {"mock": True}
                    connection.sendall(json.dumps(response).encode())
            except Exception as error:
                errors.append(error)
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        controller = proof.Controller(self.enrolled, time.monotonic() + 1)
        self.assertEqual(controller.call("qualify", "challenge"), {"mock": True})
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        controller.deadline = time.monotonic() - 1
        with self.assertRaises(proof.Failure) as caught:
            controller.call("qualify", "challenge")
        self.assertEqual(caught.exception.status, "PROOF_DEADLINE")

    def test_fake_control_slow_drip_cannot_extend_call_deadline(self):
        endpoint = self.root / "control.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(endpoint))
            endpoint.chmod(0o600)
            listener.listen(1)
            stop = threading.Event()

            def drip():
                try:
                    with listener.accept()[0] as connection:
                        connection.settimeout(0.2)
                        connection.recv(4096)
                        while not stop.wait(0.01):
                            connection.sendall(b" ")
                except OSError:
                    pass
            thread = threading.Thread(target=drip, daemon=True)
            thread.start()
            start = time.monotonic()
            try:
                with patch.object(proof, "CALL_SECONDS", 0.05):
                    controller = proof.Controller(self.enrolled, start + 1)
                    with self.assertRaises(proof.Failure) as caught:
                        controller.call("qualify", "challenge")
                    self.assertEqual(caught.exception.status, "PROOF_DEADLINE")
                self.assertLess(time.monotonic() - start, 0.5)
            finally:
                stop.set()
                thread.join(0.5)
            self.assertFalse(thread.is_alive())


if __name__ == "__main__":
    unittest.main()
