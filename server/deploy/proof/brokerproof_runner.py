"""Bounded external OWNED fixture protocol; never discovers/connects a Docker socket.

An operator-reviewed controller supplies Linux measurements and executes the existing
broker inside that fixture. Valid evidence is a review candidate, NEVER acceptance.
See server/broker/proof/EXTERNAL_FIXTURE.md. Stdlib only; no provision/pull/privilege path.
"""
from __future__ import annotations

import argparse
import hashlib
import json

import os
from pathlib import Path
import re
import secrets
import socket
import stat
import time

MAX_BYTES = 131_072
TOTAL_SECONDS = 120
CALL_SECONDS = 10
ROLES = ("client", "broker", "observer", "daemon")
CASES = ("positive", "exec", "create", "export", "wrong-id", "wrong-context", "ro-only")
HEX = re.compile(r"[a-f0-9]{64}\Z")
IDENT = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
AUDIT_KEYS = {"correlationId", "time", "subject", "containerId", "context", "operation",
              "scope", "stage", "decision", "reason", "dispatched"}


class Failure(Exception):
    def __init__(self, status: str):
        self.status = status


def require(condition: bool, status: str = "TOPOLOGY_UNQUALIFIED"):
    if not condition:
        raise Failure(status)


def exact(value, keys):
    return isinstance(value, dict) and set(value) == set(keys)


def integer(value, minimum=0):
    return type(value) is int and minimum <= value <= 9_007_199_254_740_991


def hex_id(value):
    return isinstance(value, str) and HEX.fullmatch(value) is not None


def identifier(value):
    return isinstance(value, str) and IDENT.fullmatch(value) is not None


def decode(data: bytes):
    require(len(data) <= MAX_BYTES)

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result

    def invalid_constant(_):
        raise Failure("TOPOLOGY_UNQUALIFIED")

    try:
        return json.loads(data.decode("utf-8", "strict"), object_pairs_hook=pairs,
                          parse_constant=invalid_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise Failure("TOPOLOGY_UNQUALIFIED") from None


def private_path(path: Path, kind: str):
    """Reject symlinks/alias paths and other-owner or publicly accessible endpoints."""
    require(path.is_absolute() and path == path.resolve())
    info, parent = path.lstat(), path.parent.lstat()
    require(info.st_uid == os.getuid() == parent.st_uid)
    require(stat.S_IMODE(info.st_mode) == 0o600)
    require(stat.S_ISDIR(parent.st_mode) and stat.S_IMODE(parent.st_mode) == 0o700)
    require(stat.S_ISREG(info.st_mode) if kind == "file" else stat.S_ISSOCK(info.st_mode))
    require(path.name not in ("docker.sock", "podman.sock"))
    return (info.st_dev, info.st_ino)


def enrollment(path: Path, authorization: str):
    private_path(path, "file")
    with path.open("rb") as source:
        value = decode(source.read(MAX_BYTES + 1))
    require(exact(value, ("schema", "fixture", "ownerUid", "controllerSocket", "controllerDigest",
                          "resources", "containerA", "containerB", "context")))
    require(value["schema"] == "owned-broker-fixture-v1")
    require(identifier(value["fixture"]) and authorization == value["fixture"])
    require(type(value["ownerUid"]) is int and value["ownerUid"] == os.getuid())
    require(hex_id(value["controllerDigest"]))
    require(isinstance(value["controllerSocket"], str) and len(value["controllerSocket"]) <= 100)
    require(hex_id(value["containerA"]) and hex_id(value["containerB"]))
    require(value["containerA"] != value["containerB"] and identifier(value["context"]) and value["context"] != "unregistered")
    resources = value["resources"]
    require(isinstance(resources, list) and 6 <= len(resources) <= 16)
    require(all(hex_id(item) for item in resources) and len(set(resources)) == len(resources))
    require(value["containerA"] in resources and value["containerB"] in resources)
    return value


class Controller:
    """Private non-Engine control endpoint, explicitly consented in enrollment.

    No HTTP/Docker API, commands, URLs, shell, ambient Docker env or fallback. The
    controller is a trusted operator dependency, not an untrusted client's assertions.
    """
    def __init__(self, enrolled, deadline):
        self.enrolled = enrolled
        self.path = Path(enrolled["controllerSocket"])
        self.deadline = deadline
        self.identity = None

    def call(self, action, challenge, **payload):
        end = min(self.deadline, time.monotonic() + CALL_SECONDS)
        remaining = end - time.monotonic()
        require(remaining > 0, "PROOF_DEADLINE")
        try:
            identity = private_path(self.path, "socket")
            require(self.identity is None or identity == self.identity)
            self.identity = identity
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(min(CALL_SECONDS, remaining))
                connection.connect(str(self.path))
                # Bound connect + send + receive, not a sliding idle timeout.
                remaining = end - time.monotonic()
                require(remaining > 0, "PROOF_DEADLINE")
                connection.settimeout(remaining)
                message = {"schema": "brokerproof-control-v1", "fixture": self.enrolled["fixture"],
                           "challenge": challenge, "action": action, **payload}
                connection.sendall(json.dumps(message, separators=(",", ":")).encode() + b"\n")
                response = bytearray()
                while True:
                    remaining = end - time.monotonic()
                    require(remaining > 0, "PROOF_DEADLINE")
                    connection.settimeout(remaining)
                    block = connection.recv(min(4096, MAX_BYTES + 1 - len(response)))
                    if not block:
                        break
                    response.extend(block)
                    require(len(response) <= MAX_BYTES)
                result = decode(bytes(response))
            require(exact(result, ("schema", "fixture", "challenge", "action", "evidence")))
            require(result["schema"] == "brokerproof-control-v1" and result["action"] == action)
            require(result["fixture"] == self.enrolled["fixture"] and result["challenge"] == challenge)
            evidence = result["evidence"]
            if exact(evidence, ("error",)):
                require(evidence["error"] in ("DOCKER_ENGINE_UNAVAILABLE", "TOPOLOGY_UNQUALIFIED", "PROOF_FAILED"))
                raise Failure(evidence["error"])
            return evidence
        except (socket.timeout, TimeoutError):
            raise Failure("PROOF_DEADLINE") from None
        except OSError:
            raise Failure("DOCKER_ENGINE_UNAVAILABLE") from None


def qualify(e, enrolled):
    require(exact(e, ("backend", "controllerDigest", "resources", "processes", "mounts", "access",
                      "engine", "budget", "hostSocketMounts", "hostNamespaceJoins")))
    require(e["backend"] == "real-engine" and e["controllerDigest"] == enrolled["controllerDigest"])
    require(e["resources"] == enrolled["resources"])
    require(e["hostSocketMounts"] == [] and e["hostNamespaceJoins"] == [])
    require(e["budget"] == {"cpuMillis": 2000, "memoryBytes": 1_073_741_824})
    processes = e["processes"]
    require(exact(processes, ROLES))
    for role in ROLES:
        process = processes[role]
        require(exact(process, ("uid", "capEff", "namespaces", "routes", "tcpListeners")))
        require(integer(process["uid"], 1) and process["capEff"] == "0000000000000000")
        require(process["routes"] == [] and process["tcpListeners"] == [])
        require(exact(process["namespaces"], ("mnt", "net", "pid", "user")))
        require(all(integer(n, 1) for n in process["namespaces"].values()))
    for namespace in ("mnt", "net", "pid", "user"):
        require(len({processes[role]["namespaces"][namespace] for role in ROLES}) == 4)
    # Resource handles represent measured mount device/inode identities, not path names.
    mounts = e["mounts"]
    require(exact(mounts, ROLES))
    expected = {"client": {"ingress", "caller-credential"},
                "broker": {"ingress", "engine-tap"},
                "observer": {"engine-tap", "engine", "daemon-control"},
                "daemon": {"engine", "daemon-data"}}
    identities = {}
    for role in ROLES:
        require(isinstance(mounts[role], list) and len(mounts[role]) == len(expected[role]))
        require({m.get("kind") for m in mounts[role] if isinstance(m, dict)} == expected[role])
        for mount in mounts[role]:
            require(exact(mount, ("kind", "resource", "device", "inode", "mode", "uid")))
            require(mount["resource"] in enrolled["resources"])
            require(integer(mount["device"]) and integer(mount["inode"], 1))
            require(mount["mode"] == ("0700" if mount["kind"] == "daemon-data" else "0600") and integer(mount["uid"], 1))
            identity = (mount["resource"], mount["device"], mount["inode"], mount["uid"])
            require(mount["kind"] not in identities or identities[mount["kind"]] == identity)
            identities[mount["kind"]] = identity
    require(len({v[0] for v in identities.values()}) == len(identities))
    require(len({v[1:3] for v in identities.values()}) == len(identities))
    access = e["access"]
    require(isinstance(access, list) and len(access) == 6)
    expected_access = {"ingress": "connected", "engine": "inaccessible",
                       "engine-tap": "inaccessible", "daemon-data": "inaccessible",
                       "daemon-control": "inaccessible", "controller": "inaccessible"}
    require({a.get("kind") for a in access if isinstance(a, dict)} == set(expected_access))
    for item in access:
        require(exact(item, ("kind", "asRole", "errno", "result")))
        require(item["asRole"] == "client" and item["result"] == expected_access[item["kind"]])
        if item["kind"] == "ingress":
            require(type(item["errno"]) is int and item["errno"] == 0)
        if item["kind"] != "ingress":
            require(type(item["errno"]) is int and item["errno"] in (2, 13))
    engine = e["engine"]
    require(exact(engine, ("apiMin", "apiMax", "containerA", "containerB", "targetLabels")))
    for key in ("apiMin", "apiMax"):
        require(isinstance(engine[key], str) and re.fullmatch(r"1\.[0-9]{2}", engine[key]) is not None)
    require(int(engine["apiMin"].split(".")[1]) <= 47 <= int(engine["apiMax"].split(".")[1]))
    require(engine["containerA"] == enrolled["containerA"] and engine["containerB"] == enrolled["containerB"])
    require(engine["targetLabels"] == [enrolled["fixture"], enrolled["fixture"]])


def snapshot_hash(snapshot, enrolled):
    require(exact(snapshot, ("schemaVersion", "containerId", "context", "observedAt", "coverage", "facts", "hash")), "PROOF_FAILED")
    require(snapshot["schemaVersion"] == "inspect-snapshot-v1" and snapshot["containerId"] == enrolled["containerA"], "PROOF_FAILED")
    require(snapshot["context"] == {"id": enrolled["context"], "version": 1}, "PROOF_FAILED")
    require(snapshot["coverage"] == "runtime-config-inspect" and hex_id(snapshot["hash"]), "PROOF_FAILED")
    require(isinstance(snapshot["observedAt"], str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", snapshot["observedAt"]) is not None, "PROOF_FAILED")
    require(exact(snapshot["facts"], ("configuredUser", "privileged", "readonlyRootfs", "capAdd", "capDrop", "security", "namespaces", "mounts", "ports", "resources")), "PROOF_FAILED")
    # Hash language is constrained to ASCII strings + safe integers, matching JS canonical
    # serialization without Python/JS floating-point or UTF-16 sorting ambiguities.
    def canonical(value):
        if value is None or type(value) is bool or integer(value):
            return json.dumps(value, separators=(",", ":"))
        if isinstance(value, str):
            require(value.isascii() and all(ord(c) >= 32 for c in value), "PROOF_FAILED")
            return json.dumps(value, ensure_ascii=False)
        if isinstance(value, list):
            return "[" + ",".join(canonical(v) for v in value) + "]"
        require(isinstance(value, dict), "PROOF_FAILED")
        require(all(isinstance(k, str) and k.isascii() for k in value), "PROOF_FAILED")
        return "{" + ",".join(canonical(k) + ":" + canonical(value[k]) for k in sorted(value)) + "}"
    envelope = {k: v for k, v in snapshot.items() if k != "hash"}
    encoded = canonical(envelope).encode()
    require(len(encoded) <= 32_768 and hashlib.sha256(encoded).hexdigest() == snapshot["hash"], "PROOF_FAILED")
    facts = snapshot["facts"]
    require(facts["configuredUser"] in ("root", "non-root", "unknown"), "PROOF_FAILED")
    require(type(facts["privileged"]) is bool and type(facts["readonlyRootfs"]) is bool, "PROOF_FAILED")
    caps = set("CHOWN DAC_OVERRIDE DAC_READ_SEARCH FOWNER FSETID KILL SETGID SETUID SETPCAP LINUX_IMMUTABLE NET_BIND_SERVICE NET_BROADCAST NET_ADMIN NET_RAW IPC_LOCK IPC_OWNER SYS_MODULE SYS_RAWIO SYS_CHROOT SYS_PTRACE SYS_PACCT SYS_ADMIN SYS_BOOT SYS_NICE SYS_RESOURCE SYS_TIME SYS_TTY_CONFIG MKNOD LEASE AUDIT_WRITE AUDIT_CONTROL SETFCAP MAC_OVERRIDE MAC_ADMIN SYSLOG WAKE_ALARM BLOCK_SUSPEND AUDIT_READ PERFMON BPF CHECKPOINT_RESTORE ALL unknown".split())
    for key in ("capAdd", "capDrop"):
        value = facts[key]
        require(value == "unknown" or (isinstance(value, list) and len(value) <= 64 and all(isinstance(v, str) and v in caps for v in value)), "PROOF_FAILED")
    require(exact(facts["security"], ("seccomp", "apparmor")), "PROOF_FAILED")
    require(all(v in ("default", "custom", "unconfined", "unknown") for v in facts["security"].values()), "PROOF_FAILED")
    require(exact(facts["namespaces"], ("network", "pid", "ipc", "user")), "PROOF_FAILED")
    require(all(v in ("private", "host", "shared-container", "unknown") for v in facts["namespaces"].values()), "PROOF_FAILED")
    require(facts["namespaces"]["user"] in ("host", "unknown"), "PROOF_FAILED")
    require(exact(facts["resources"], ("memory", "nanoCpus", "pids", "cpuQuota", "cpuPeriod")), "PROOF_FAILED")
    require(all(v == "unknown" or integer(v) for v in facts["resources"].values()), "PROOF_FAILED")
    mounts = facts["mounts"]
    require(exact(mounts, ("groups", "socketPresent")), "PROOF_FAILED")
    require(type(mounts["socketPresent"]) is bool or mounts["socketPresent"] == "unknown", "PROOF_FAILED")
    groups = mounts["groups"]
    require(groups == "unknown" or (isinstance(groups, list) and len(groups) <= 256), "PROOF_FAILED")
    if isinstance(groups, list):
        for group in groups:
            require(exact(group, ("type", "readOnly", "count")), "PROOF_FAILED")
            require(group["type"] in ("bind", "volume", "tmpfs", "npipe", "cluster", "unknown"), "PROOF_FAILED")
            require(type(group["readOnly"]) is bool or group["readOnly"] == "unknown", "PROOF_FAILED")
            require(integer(group["count"], 1) and group["count"] <= 256, "PROOF_FAILED")
        require(sum(g["count"] for g in groups) <= 256, "PROOF_FAILED")
    ports = facts["ports"]
    require(ports == "unknown" or (isinstance(ports, list) and len(ports) <= 256), "PROOF_FAILED")
    if isinstance(ports, list):
        for port in ports:
            require(exact(port, ("port", "protocol", "published")), "PROOF_FAILED")
            require(integer(port["port"], 1) and port["port"] <= 65535 and port["protocol"] in ("tcp", "udp", "sctp") and type(port["published"]) is bool, "PROOF_FAILED")


def client_request(name, enrolled):
    target = "/v1/contexts/" + enrolled["context"] + "/containers/" + enrolled["containerA"] + "/inspect"
    engine = "/v1.47/containers/" + enrolled["containerA"]
    methods_paths = {"positive": ("GET", target), "exec": ("POST", engine + "/exec"),
                     "create": ("POST", "/v1.47/containers/create"), "export": ("GET", engine + "/export"),
                     "wrong-id": ("GET", target.replace(enrolled["containerA"], enrolled["containerB"])),
                     "wrong-context": ("GET", target.replace("/contexts/" + enrolled["context"] + "/", "/contexts/unregistered/")),
                     "ro-only": ("GET", target)}
    method, path = methods_paths[name]
    return {"method": method, "path": path, "brokerMode": "ro-only-no-permit" if name == "ro-only" else "disposable"}


def verify_run(e, enrolled):
    require(exact(e, ("cases", "caller", "defaultOff", "topology")), "PROOF_FAILED")
    require(e["defaultOff"] == {"stdout": "inspect_broker_disabled\n", "listeners": 0} and type(e["defaultOff"]["listeners"]) is int, "PROOF_FAILED")
    require(exact(e["caller"], ("digest", "bytes", "grant", "consent", "subject")), "PROOF_FAILED")
    require(hex_id(e["caller"]["digest"]) and e["caller"]["bytes"] == 32, "PROOF_FAILED")
    require(e["caller"]["grant"] == "grant-a" and e["caller"]["consent"] == "consent-a" and e["caller"]["subject"] == "subject-a", "PROOF_FAILED")
    cases = e["cases"]
    require(isinstance(cases, list) and len(cases) == len(CASES), "PROOF_FAILED")
    correlations = set()
    previous = None
    for name, case in zip(CASES, cases):
        require(exact(case, ("name", "clientRequest", "response", "before", "after", "requests", "audit")), "PROOF_FAILED")
        require(case["name"] == name and case["clientRequest"] == client_request(name, enrolled), "PROOF_FAILED")
        for counts in (case["before"], case["after"]):
            require(exact(counts, ("adapter", "received", "forwarded")) and all(integer(v) for v in counts.values()), "PROOF_FAILED")
        require(previous is None or case["before"] == previous, "PROOF_FAILED")
        previous = case["after"]
        delta = 1 if name == "positive" else 0
        require(all(case["after"][k] - case["before"][k] == delta for k in case["before"]), "PROOF_FAILED")
        path = "/v1.47/containers/" + enrolled["containerA"] + "/json"
        require(case["requests"] == ([{"method": "GET", "path": path}] if delta else []), "PROOF_FAILED")
        response = case["response"]
        require(exact(response, ("status", "snapshot") if delta else ("status",)), "PROOF_FAILED")
        require(response["status"] == ("checked" if delta else "not_authorized"), "PROOF_FAILED")
        if delta:
            snapshot_hash(response["snapshot"], enrolled)
        audit = case["audit"]
        require(isinstance(audit, list) and len(audit) == (2 if delta else 1), "PROOF_FAILED")
        correlation = None
        for index, record in enumerate(audit):
            require(exact(record, AUDIT_KEYS), "PROOF_FAILED")
            require(isinstance(record["correlationId"], str) and re.fullmatch(r"[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}", record["correlationId"]) is not None, "PROOF_FAILED")
            require(isinstance(record["time"], str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", record["time"]) is not None, "PROOF_FAILED")
            require(correlation is None or record["correlationId"] == correlation, "PROOF_FAILED")
            correlation = record["correlationId"]
            require(record["operation"] == "inspect" and record["scope"] == "container:inspect", "PROOF_FAILED")
            require(record["subject"] in ("anonymous", "subject-a") and record["containerId"] in ("invalid", enrolled["containerA"]) and record["context"] in ("invalid", enrolled["context"]), "PROOF_FAILED")
            require(record["stage"] == ("publication" if index == 1 else "admission"), "PROOF_FAILED")
            require(type(record["dispatched"]) is bool and record["dispatched"] == (delta == 1 and index == 1), "PROOF_FAILED")
            require(record["decision"] == (("allowed" if index == 0 else "checked") if delta else "not_authorized"), "PROOF_FAILED")
            reason = "allowed" if delta else "disabled" if name == "ro-only" else "authorization" if name.startswith("wrong-") else "invalid_request"
            require(record["reason"] == reason and len(json.dumps(record)) <= 1024, "PROOF_FAILED")
            if delta:
                require(record["subject"] == "subject-a" and record["containerId"] == enrolled["containerA"] and record["context"] == enrolled["context"], "PROOF_FAILED")
        require(correlation not in correlations, "PROOF_FAILED")
        correlations.add(correlation)
    qualify(e["topology"], enrolled)


def run(path=None, authorization=None, controller_factory=Controller):
    start = time.monotonic()
    result = {"status": "TOPOLOGY_UNQUALIFIED", "passed": False, "realProofAccepted": False,
              "productionEnabled": False, "evidenceKind": "none", "cleanup": "not-requested"}
    controller = None
    owned = None
    started = False
    challenge = secrets.token_hex(32)
    try:
        require(path is not None and authorization is not None)
        owned = enrollment(Path(path), authorization)
        # Reserve ten seconds for bounded cleanup after any ambiguous run response.
        controller = controller_factory(owned, start + TOTAL_SECONDS - CALL_SECONDS)
        topology = controller.call("qualify", challenge)
        qualify(topology, owned)
        started = True
        evidence = controller.call("run", challenge, resources=owned["resources"], cases=list(CASES),
                                   containerA=owned["containerA"], containerB=owned["containerB"],
                                   context=owned["context"], apiVersion="1.47")
        verify_run(evidence, owned)
        require(evidence["topology"] == topology, "TOPOLOGY_UNQUALIFIED")
        result.update(status="EVIDENCE_CANDIDATE", evidenceKind="operator-fixture-candidate",
                      fixture=owned["fixture"], controllerDigest=owned["controllerDigest"],
                      challenge=challenge,
                      topologyDigest=hashlib.sha256(json.dumps(topology, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                      snapshotHash=evidence["cases"][0]["response"]["snapshot"]["hash"],
                      counters=[{"case": c["name"], "clientRequest": c["clientRequest"], "before": c["before"], "after": c["after"],
                                 "requests": c["requests"], "audit": c["audit"]} for c in evidence["cases"]])
    except Failure as error:
        result["status"] = error.status
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        result["status"] = "TOPOLOGY_UNQUALIFIED"
    finally:
        if started:
            try:
                controller.deadline = start + TOTAL_SECONDS
                cleanup = controller.call("cleanup", challenge, resources=owned["resources"])
                require(cleanup == {"released": owned["resources"], "remaining": []}, "CLEANUP_FAILED")
                result["cleanup"] = "owned-resources-released"
            except (Failure, OSError, ValueError, TypeError, KeyError):
                result.update(status="CLEANUP_FAILED", cleanup="operator-action-required")
    result["elapsedSeconds"] = round(time.monotonic() - start, 3)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--authorize-owned-fixture")
    args = parser.parse_args()
    result = run(args.fixture, args.authorize_owned_fixture)
    print(json.dumps(result, sort_keys=True))
    # Candidate is NOT a successful acceptance/skip. Independent fixture review remains.
    return 2 if result["status"] == "EVIDENCE_CANDIDATE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
