"""Opt-in Docker/Trivy smoke tests; run with python3 -m unittest discover -s server/security-lab -p 'test_*.py'."""
import json
import pathlib
import subprocess
import unittest
from dataclasses import dataclass

from diagnostics import scanner_failure


COMPOSE = pathlib.Path(__file__).with_name("compose.yaml")
BASE = ["docker", "compose", "-f", str(COMPOSE)]


@dataclass(frozen=True)
class ScanResult:
    returncode: int
    forbidden: bool
    remote_error: bool
    cloudfront: bool


def docker(*args, timeout=45):
    return subprocess.run([*args], capture_output=True, text=True, timeout=timeout)


class ScannerBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if docker("docker", "info", timeout=10).returncode:
            raise unittest.SkipTest("Docker Linux Engine unavailable")
        ready = docker(*BASE, "up", "-d", "--build", "egress", "registry", timeout=120)
        if ready.returncode:
            raise AssertionError("Cannot start security lab containers")

    def scan(self, image, *env):
        raw = docker(*BASE, "run", "-T", "--rm", *env, "scanner", "image",
                     "--image-src", "remote", "--scanners", "secret", "--platform", "linux/amd64",
                                          "--insecure", "--timeout", "10s", image,
                     timeout=45)
        # The raw stderr can contain signed blob URLs; expose only safe booleans.
        return ScanResult(raw.returncode, "Forbidden" in raw.stderr,
                          "remote error" in raw.stderr,
                          "production.cloudfront.docker.com" in raw.stderr)

    def fixture(self, mode):
        result = docker(*BASE, "exec", "-T", "registry", "python", "-c",
                        "from pathlib import Path; Path('/tmp/mode').write_text(" + repr(mode) + "); Path('/tmp/hits').write_text('')")
        self.assertEqual(result.returncode, 0, scanner_failure(result.returncode))

    def hits(self):
        result = docker(*BASE, "exec", "-T", "registry", "cat", "/tmp/hits")
        return result.stdout.splitlines()

    def test_controlled_registry_positive_scan(self):
        self.fixture("normal")
        result = self.scan("registry.lab.test/demo:stable")
        self.assertEqual(result.returncode, 0, scanner_failure(result.returncode))
        self.assertTrue(any("/blobs/" in hit for hit in self.hits()))

    def test_digest_survives_tag_removal_with_explicit_platform(self):
        self.fixture("tag-removed")
        self.assertNotEqual(self.scan("registry.lab.test/demo:stable").returncode, 0)
        self.fixture("tag-removed")
        pinned = docker(*BASE, "exec", "-T", "registry", "python", "-c",
                        "from registry import digest, manifest; print(digest(manifest))").stdout.strip()
        self.assertRegex(pinned, r"^sha256:[0-9a-f]{64}$")
        result = self.scan("registry.lab.test/demo@" + pinned)
        self.assertEqual(result.returncode, 0, scanner_failure(result.returncode))
        self.assertTrue(any("/blobs/" in hit for hit in self.hits()))

    def test_malicious_manifest_blob_token_redirects(self):
        for mode, expected in (("manifest", "/manifests/"), ("blob", "/blobs/"),
                               ("token", "/v2/"), ("token-host", "/v2/")):
            with self.subTest(mode=mode):
                self.fixture(mode)
                result = self.scan("registry.lab.test/demo:stable")
                self.assertNotEqual(result.returncode, 0, mode)
                self.assertTrue(any(expected in hit for hit in self.hits()), mode)
                self.assertTrue(result.forbidden, mode)
                self.assertNotIn("DO_NOT_LOG", str(scanner_failure(result.returncode)))

    def test_dns_rebinding_at_second_connection(self):
        self.fixture("normal")
        self.assertEqual(self.scan("registry.lab.test/demo:stable").returncode, 0)
        self.fixture("normal")
        marker = docker(*BASE, "exec", "-T", "egress", "touch", "/tmp/rebind")
        self.assertEqual(marker.returncode, 0)
        try:
            result = self.scan("registry.lab.test/demo:stable")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(self.hits(), [])
        finally:
            docker(*BASE, "exec", "-T", "egress", "rm", "-f", "/tmp/rebind")

    def test_daemon_socket_not_mounted(self):
        result = docker(*BASE, "run", "-T", "--rm", "--entrypoint", "/bin/sh", "scanner",
                        "-c", "test ! -e /var/run/docker.sock && test -z \"$DOCKER_HOST\"")
        self.assertEqual(result.returncode, 0, scanner_failure(result.returncode))
        network = docker("docker", "network", "inspect", "dip-security-lab_scanner")
        self.assertTrue(json.loads(network.stdout)[0]["Internal"])

    def test_direct_scanner_connection_cannot_bypass_proxy(self):
        result = self.scan("registry.lab.test/demo:stable",
                           "-e", "HTTP_PROXY=", "-e", "HTTPS_PROXY=")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(result.remote_error)

    def test_disallowed_registry_is_denied_by_real_scanner(self):
        result = self.scan("example.com/library/alpine:latest")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(result.forbidden)

    def test_blob_redirect_outside_policy_fails_closed(self):
        result = self.scan("registry-1.docker.io/library/alpine:3.20")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(result.cloudfront)
        self.assertTrue(result.forbidden)
        self.assertNotIn("production.cloudfront.docker.com", str(scanner_failure(result.returncode)))


if __name__ == "__main__":
    unittest.main()
