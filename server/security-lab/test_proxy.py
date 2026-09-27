import socket
import unittest
from unittest.mock import patch

from proxy import connect, target


class EgressPolicyTests(unittest.TestCase):
    def setUp(self):
        self.allowed = patch("proxy.ALLOWED", frozenset({"registry-1.docker.io"}))
        self.allowed.start()
        self.addCleanup(self.allowed.stop)

    def test_exact_allowed_host(self):
        self.assertEqual(target("registry-1.docker.io:443"), "registry-1.docker.io")

    def test_unlisted_and_metadata_hosts(self):
        for authority in (
            "169.254.169.254:443",
            "127.0.0.1:443",
            "registry-1.docker.io.evil.test:443",
            "registry-1.docker.io:80",
            "user@registry-1.docker.io:443",
        ):
            with self.subTest(authority=authority), self.assertRaises(ValueError):
                target(authority)

    def test_dns_rebind_to_private_ip_never_connects(self):
        private = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443))]
        with patch("proxy.socket.getaddrinfo", return_value=private), patch("proxy.socket.socket") as sock:
            with self.assertRaises(OSError):
                connect("registry-1.docker.io")
            sock.assert_not_called()

    def test_lab_exception_is_exact_ip_only(self):
        private = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("172.30.91.10", 443))]
        with patch("proxy.LAB_MODE", True), patch("proxy.socket.getaddrinfo", return_value=private), patch("proxy.socket.socket") as sock:
            connect("registry.lab.test")
            sock.return_value.connect.assert_called_once_with(("172.30.91.10", 443))
            sock.reset_mock()
            with self.assertRaises(OSError):
                connect("registry-1.docker.io")
            sock.assert_not_called()

    def test_lab_rebinding_to_metadata_is_denied_even_with_exception(self):
        with patch("proxy.LAB_MODE", True), patch("proxy.os.path.exists", return_value=True), patch("proxy.socket.socket") as sock:
            with self.assertRaises(OSError):
                connect("registry.lab.test")
            sock.assert_not_called()

    def test_mixed_dns_answers_fail_closed(self):
        answers = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443)),
        ]
        with patch("proxy.socket.getaddrinfo", return_value=answers), patch("proxy.socket.socket") as sock:
            with self.assertRaises(OSError):
                connect("registry-1.docker.io")
            sock.assert_not_called()

    def test_each_connection_checks_dns_again(self):
        public = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443))]
        private = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
        with patch("proxy.socket.getaddrinfo", side_effect=[public, private]) as lookup, patch("proxy.socket.socket") as sock:
            connect("registry-1.docker.io")
            with self.assertRaises(OSError):
                connect("registry-1.docker.io")
            self.assertEqual(lookup.call_count, 2)
            self.assertEqual(sock.return_value.connect.call_count, 1)

    def test_host_confusion_rejected(self):
        for authority in ("REGISTRY-1.DOCKER.IO:443", "registry-1.docker.io.:443",
                          "registry-1.docker.io%00.evil:443", "registry-1..docker.io:443"):
            with self.subTest(authority=authority), self.assertRaises(ValueError):
                target(authority)


if __name__ == "__main__":
    unittest.main()
