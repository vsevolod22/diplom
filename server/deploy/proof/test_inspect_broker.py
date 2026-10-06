"""Owned standalone broker proof. Fake Unix Engine != real Docker/topology acceptance.

Default: run actual TS unit + raw HTTP + Unix adapter tests, typecheck and default-off.
--real: bounded Docker prerequisite only, never reset/restart/pull/mutate the live stand.
Unavailable prerequisites are failures, not unittest skips/pass. A disposable real-daemon
fixture and its independent topology evidence are intentionally still pending.
"""
from pathlib import Path
import json
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[3]
LAUNCHER = ROOT / "server" / "broker" / "run.mjs"


def run_mode(mode, timeout=40):
    return subprocess.run(["node", str(LAUNCHER), mode], cwd=ROOT,
                          capture_output=True, text=True, timeout=timeout)


class InspectBrokerFakeUnixProof(unittest.TestCase):
    def test_typecheck(self):
        result = run_mode("typecheck")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_unit_and_actual_http_unix_matrix(self):
        result = run_mode("test")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ℹ skipped 0", result.stdout)
        self.assertIn("ℹ fail 0", result.stdout)

    def test_production_start_remains_off(self):
        result = run_mode("start")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "inspect_broker_disabled\n")
        self.assertEqual(result.stderr, "")


def real_prerequisite():
    start = time.monotonic()
    status = "unavailable"
    try:
        result = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"],
                                capture_output=True, text=True, timeout=20)
        if result.returncode == 0 and result.stdout.strip():
            status = "responsive_disposable_topology_not_configured"
    except subprocess.TimeoutExpired:
        status = "timeout"
    except OSError:
        pass
    print(json.dumps({"proof": "real_engine", "passed": False, "status": status,
                      "timeoutSeconds": 20, "elapsedSeconds": round(time.monotonic() - start, 1),
                      "engineMutations": 0, "productionEnabled": False}))
    return 1


if __name__ == "__main__":
    if sys.argv[1:] == ["--real"]:
        raise SystemExit(real_prerequisite())
    unittest.main()
