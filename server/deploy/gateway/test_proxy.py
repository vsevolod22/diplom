import os
import socket
import sys
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(__file__))
import proxy


class GatewayPolicyTests(unittest.TestCase):
    def test_exact_hosts_and_no_private_or_literals(self):
        for value in ("169.254.169.254:443", "127.0.0.1:443", "registry-1.docker.io.evil.test:443",
                      "REGISTRY-1.DOCKER.IO:443", "auth.docker.io:80", "auth.docker.io:443@evil.test:443",
                      "production.cloudflare.docker.com:443", "production.cloudfront.docker.com:8443"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                proxy.authority(value)
        self.assertEqual(proxy.authority("registry-1.docker.io:443"), "registry-1.docker.io")
        self.assertEqual(proxy.authority("hub.docker.com:443"), "hub.docker.com")
        with self.assertRaises(ValueError):
            proxy.authority("hub.docker.com.evil.test:443")

    def test_mixed_dns_and_rebinding_deny_before_dial(self):
        public = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443))
        private = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443))
        attempts = []
        def connector(*args):
            attempts.append(args)
            raise AssertionError("must never dial")
        for answers in ([], [private], [public, private], [public, (*private[:4], ("127.0.0.1", 443))]):
            with self.subTest(answers=answers), self.assertRaises(OSError):
                proxy.dial("registry-1.docker.io", lambda *_args, **_kwargs: answers, connector)
        self.assertEqual(attempts, [])

    def test_public_dns_dials_numeric_answer_and_checks_each_connect(self):
        calls = []
        class Socket:
            def settimeout(self, seconds):
                pass
            def connect(self, sockaddr):
                calls.append(sockaddr)
            def close(self):
                pass
        answers = [[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443))],
                   [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 443))]]
        def lookup(*_args, **_kwargs):
            return answers.pop(0)
        proxy.dial("registry-1.docker.io", lookup, lambda *_args: Socket())
        with self.assertRaises(OSError):
            proxy.dial("registry-1.docker.io", lookup, lambda *_args: Socket())
        self.assertEqual(calls, [("1.1.1.1", 443)])

    def test_fixture_pairs_are_exact_and_production_remains_public_only(self):
        fixture = (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('172.30.92.10', 443))
        policy = proxy.Policy(fixture_pairs=frozenset({('registry-1.docker.io', '172.30.92.10')}),
                              lookup=lambda *_args, **_kwargs: [fixture])
        self.assertEqual(proxy.addresses_for('registry-1.docker.io', policy.lookup, policy), [fixture])
        for host, active_policy in (('auth.docker.io', policy), ('registry-1.docker.io', proxy.PRODUCTION_POLICY)):
            with self.subTest(host=host), self.assertRaises(OSError):
                proxy.addresses_for(host, lambda *_args, **_kwargs: [fixture], active_policy)
        mixed = [fixture, (socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('::1', 443, 0, 0))]
        with self.assertRaises(OSError):
            proxy.addresses_for('registry-1.docker.io', lambda *_args, **_kwargs: mixed, policy)
        with self.assertRaises(ValueError):
            proxy.authority('169.254.169.254:443', policy)

    def test_go_client_connect_headers_are_accepted_without_forward_auth(self):
        upstream, peer = socket.socketpair()
        with patch.object(proxy, "dial", return_value=upstream) as dial, proxy.Server(("127.0.0.1", 0), proxy.Handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with socket.create_connection(server.server_address) as client:
                    client.sendall(b"CONNECT registry-1.docker.io:443 HTTP/1.1\r\n"
                                   b"Host: registry-1.docker.io:443\r\n"
                                   b"User-Agent: Go-http-client/1.1\r\n\r\n")
                    client.settimeout(2)
                    self.assertIn(b"200 Connection Established", client.recv(512))
                dial.assert_called_once_with("registry-1.docker.io")
            finally:
                peer.close()
                server.shutdown()
                thread.join(timeout=2)

    def test_live_connect_denials_do_not_dial(self):
        with patch.object(proxy, "dial") as dial, proxy.Server(("127.0.0.1", 0), proxy.Handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                for request in (b"CONNECT 169.254.169.254:443 HTTP/1.1\r\n\r\n",
                                b"CONNECT registry-1.docker.io:443 HTTP/1.1\r\nProxy-Authorization: Basic canary\r\n\r\n",
                                b"GET / HTTP/1.1\r\n\r\n"):
                    with socket.create_connection(server.server_address) as client:
                        client.sendall(request)
                        self.assertIn(b"403", client.recv(512))
                dial.assert_not_called()
            finally:
                server.shutdown()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
