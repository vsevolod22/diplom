"""ONE targeted MOCK/fake-controller group. NOT real Engine or isolation proof."""
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
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
