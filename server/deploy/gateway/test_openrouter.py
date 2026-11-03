import contextlib
import io
import os
import socket
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, call, patch
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

    def test_cli_selects_only_fixed_public_or_legacy_handler(self):
        for argv, handler in (([], proxy.Handler), (['--public-90s'], openrouter.Public90sHandler)):
            with self.subTest(argv=argv), patch.object(openrouter, 'Server') as server_type:
                openrouter.main(argv)
                server_type.assert_called_once_with(('0.0.0.0', 8080), handler)
                server = server_type.return_value.__enter__.return_value
                self.assertIs(server.policy, openrouter.OPENROUTER_POLICY)
                server.serve_forever.assert_called_once_with()
        with patch.object(openrouter, 'Server') as server_type:
            openrouter.serve()
            server_type.assert_called_once_with(('0.0.0.0', 8080), proxy.Handler)

    def test_cli_rejects_unknown_abbreviated_and_numeric_timeout_arguments(self):
        for argv in (['--public-90'], ['--public-90s=95'], ['--public-90s', '95'],
                     ['--selector-timeout', '95'], ['--socket-timeout', '95'],
                     ['--timeout', '95'], ['95'], ['--public-90s', '--unknown']):
            with self.subTest(argv=argv), patch.object(openrouter, 'Server') as server_type, \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                try:
                    openrouter.main(argv)
                finally:
                    server_type.assert_not_called()
            self.assertEqual(error.exception.code, 2)

    def test_environment_cannot_enable_or_change_timeouts(self):
        with patch.dict(os.environ, {'PUBLIC_90S': '1', 'OPENROUTER_TIMEOUT': '999',
                                     'TUNNEL_IDLE_TIMEOUT': '999', 'TUNNEL_SOCKET_TIMEOUT': '999'}), \
                patch.object(openrouter, 'Server') as server_type:
            openrouter.main([])
            server_type.assert_called_once_with(('0.0.0.0', 8080), proxy.Handler)
            openrouter.main(['--public-90s'])
            self.assertEqual(server_type.call_args, call(('0.0.0.0', 8080), openrouter.Public90sHandler))
        self.assertEqual((proxy.Handler.tunnel_idle_timeout, proxy.Handler.tunnel_socket_timeout), (30, 35))
        self.assertEqual((openrouter.Public90sHandler.tunnel_idle_timeout,
                          openrouter.Public90sHandler.tunnel_socket_timeout), (95, 95))

    def test_only_explicit_public_handler_extends_tunnel_not_header_timeout(self):
        for handler, idle, socket_timeout in ((proxy.Handler, 30, 35), (openrouter.Public90sHandler, 95, 95)):
            with self.subTest(handler=handler):
                request = Mock()
                request.recv.return_value = (b'CONNECT openrouter.ai:443 HTTP/1.1\r\n'
                                             b'Host: openrouter.ai:443\r\n\r\n')
                upstream = Mock()
                selector = MagicMock()
                selector.select.return_value = []
                with patch.object(proxy, 'dial', return_value=upstream) as dial, \
                        patch.object(proxy.selectors, 'DefaultSelector') as factory:
                    factory.return_value.__enter__.return_value = selector
                    handler(request, ('127.0.0.1', 1234), SimpleNamespace(policy=openrouter.OPENROUTER_POLICY))
                dial.assert_called_once_with('openrouter.ai', policy=openrouter.OPENROUTER_POLICY)
                self.assertEqual(request.settimeout.call_args_list, [call(10), call(socket_timeout)])
                upstream.settimeout.assert_called_once_with(socket_timeout)
                selector.select.assert_called_once_with(timeout=idle)
                request.sendall.assert_called_once_with(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                upstream.close.assert_called_once_with()

    def test_client_headers_cannot_select_or_override_timeouts(self):
        for handler in (proxy.Handler, openrouter.Public90sHandler):
            for header in (b'X-Public-90s: true', b'X-Tunnel-Idle-Timeout: 95',
                           b'X-Tunnel-Socket-Timeout: 999', b'--public-90s: true'):
                with self.subTest(handler=handler, header=header):
                    request = Mock()
                    request.recv.return_value = (b'CONNECT openrouter.ai:443 HTTP/1.1\r\n'
                                                 b'Host: openrouter.ai:443\r\n' + header + b'\r\n\r\n')
                    with patch.object(proxy, 'dial') as dial, \
                            patch.object(proxy.selectors, 'DefaultSelector') as factory:
                        handler(request, ('127.0.0.1', 1234), SimpleNamespace(policy=openrouter.OPENROUTER_POLICY))
                    dial.assert_not_called()
                    factory.assert_not_called()
                    request.settimeout.assert_called_once_with(10)
                    self.assertIn(b'403 Forbidden', request.sendall.call_args.args[0])

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
