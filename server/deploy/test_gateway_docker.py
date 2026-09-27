"""Real Docker/internal-network tests; no lab DNS or certificate exceptions."""
import pathlib
import subprocess
import unittest

COMPOSE = pathlib.Path(__file__).with_name("compose.yaml")
BASE = ("docker", "compose", "-f", str(COMPOSE))
NETWORK = "dip-secure-egress_scan_internal"


def run(*args, timeout=90):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


PROBE = '''import socket, ssl, sys
mode = sys.argv[1]
if mode == 'direct':
    for host, port in [('1.1.1.1', 443), ('169.254.169.254', 80), ('host.docker.internal', 2375)]:
        try:
            socket.create_connection((host, port), timeout=2).close()
            sys.exit(1)
        except OSError:
            pass
else:
    host = sys.argv[2]
    with socket.create_connection(('egress', 8080), timeout=8) as sock:
        sock.sendall(('CONNECT ' + host + ':443 HTTP/1.1\\r\\nHost: ' + host + ':443\\r\\n\\r\\n').encode())
        status = sock.recv(256)
        if mode == 'deny':
            sys.exit(0 if b'403' in status else 1)
        if b'200' not in status:
            sys.exit(2)
        with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as secure:
            secure.sendall(b'GET /v2/ HTTP/1.1\\r\\nHost: registry-1.docker.io\\r\\nConnection: close\\r\\n\\r\\n')
            sys.exit(0 if b'HTTP/1.1 401' in secure.recv(4096) else 3)
'''


class DockerGatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if run("docker", "info", timeout=15).returncode:
            raise AssertionError("Docker Engine required; not silently skipped")
        if run(*BASE, "up", "-d", "--build", "egress", timeout=120).returncode:
            raise AssertionError("gateway did not start")

    @classmethod
    def tearDownClass(cls):
        run(*BASE, "down", timeout=60)

    def probe(self, mode, host=""):
        result = run("docker", "run", "--rm", "--network", NETWORK,
                     "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                     "python:3.13.7-slim", "python", "-c", PROBE, mode, host, timeout=40)
        self.assertEqual(result.returncode, 0, f"probe {mode} failed (exit {result.returncode})")

    def test_no_direct_public_metadata_or_daemon(self):
        self.probe("direct")

    def test_disallowed_connect_denied(self):
        for host in ("169.254.169.254", "127.0.0.1", "evil.example.org"):
            with self.subTest(host=host):
                self.probe("deny", host)

    def test_public_registry_through_verified_tls(self):
        self.probe("tls", "registry-1.docker.io")


if __name__ == "__main__":
    unittest.main()
