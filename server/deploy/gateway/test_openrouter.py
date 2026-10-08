import socket
import threading
import unittest
from unittest.mock import patch
from server.deploy.gateway import openrouter

proxy = __import__('proxy')


class OpenRouterTests(unittest.TestCase):
    def test_fixed_host_public_dns_and_worker_policy_unchanged(self):
        policy = openrouter.OPENROUTER_POLICY
        self.assertEqual(policy.hosts, frozenset({'openrouter.ai'}))
        self.assertEqual(policy.fixture_pairs, frozenset())
        self.assertNotIn('openrouter.ai', proxy.PRODUCTION_POLICY.hosts)
        self.assertEqual(proxy.authority('openrouter.ai:443', policy), 'openrouter.ai')
        for host in ('registry-1.docker.io:443', '169.254.169.254:443', 'openrouter.ai:80',
                     'openrouter.ai.evil:443', 'OPENROUTER.AI:443', 'openrouter.ai:443@evil:443'):
            with self.assertRaises(ValueError): proxy.authority(host, policy)
        public = (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('1.1.1.1', 443))
        private = (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.1', 443))
        for answers in ([], [private], [public, private]):
            with self.assertRaises(OSError): proxy.addresses_for('openrouter.ai', lambda *a, **k: answers, policy)

    def test_actual_handler_denies_hosts_methods_and_proxy_secrets_before_dial(self):
        with patch.object(proxy, 'dial') as dial, proxy.Server(('127.0.0.1', 0), proxy.Handler) as server:
            server.policy = openrouter.OPENROUTER_POLICY
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                for raw in (b'CONNECT registry-1.docker.io:443 HTTP/1.1\r\nHost: registry-1.docker.io:443\r\n\r\n',
                            b'GET https://openrouter.ai/ HTTP/1.1\r\n\r\n',
                            b'CONNECT openrouter.ai:443 HTTP/1.1\r\nHost: openrouter.ai:443\r\nAuthorization: CANARY\r\n\r\n'):
                    with socket.create_connection(server.server_address) as client:
                        client.sendall(raw); self.assertIn(b'403', client.recv(512))
                dial.assert_not_called()
            finally:
                server.shutdown(); thread.join(timeout=2)


if __name__ == '__main__':
    unittest.main()
