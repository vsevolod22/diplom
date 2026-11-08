"""Offline gateway tests: no listeners, DNS or real sockets."""
import importlib.util
from pathlib import Path
import socket
import socketserver
import threading
import types
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('independent_moduleapi_gateway', Path(__file__).with_name('moduleapi.py'))
gateway = importlib.util.module_from_spec(spec)
# Capture a denied default resolver at import as well as denying runtime calls.
# Otherwise public_answers' default argument retains the original OS resolver.
with patch.object(socket, 'getaddrinfo', side_effect=AssertionError('real DNS forbidden')):
    spec.loader.exec_module(gateway)


def answer(ip):
    ipv6 = ':' in ip
    return (socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_STREAM,
            socket.IPPROTO_TCP, '', (ip, 443, 0, 0) if ipv6 else (ip, 443))


class GatewayTests(unittest.TestCase):
    def setUp(self):
        for name in ['getaddrinfo', 'create_connection', 'socket']:
            guard = patch.object(socket, name, side_effect=AssertionError('real network forbidden'))
            guard.start()
            self.addCleanup(guard.stop)

    def test_all_dns_answers_must_be_public(self):
        public = [answer('8.8.8.8'), answer('2606:4700:4700::1111')]
        self.assertEqual(gateway.public_answers('moduleapi.pro', lookup=lambda *a, **k: public), public)
        for ip in ['127.0.0.1', '10.0.0.1', '169.254.169.254', '::1', 'fc00::1',
                   'fe80::1', '::ffff:8.8.8.8', '2002:0808:0808::1', 'ff0e::1', '0.0.0.0']:
            with self.subTest(ip=ip), self.assertRaises((OSError, ValueError)):
                gateway.public_answers('moduleapi.pro', lookup=lambda *a, **k: [public[0], answer(ip)])
        for answers in [[], public * 33, [(*public[0][:4], ('8.8.8.8', 80))]]:
            with self.assertRaises(OSError):
                gateway.public_answers('moduleapi.pro', lookup=lambda *a, **k: answers)

    def test_malformed_connect_never_resolves_or_dials(self):
        valid = b'CONNECT moduleapi.pro:443 HTTP/1.1\r\nHost: moduleapi.pro:443\r\n\r\n'
        invalid = [valid + b'early TLS', valid.replace(b'CONNECT', b'GET'),
                   valid.replace(b'moduleapi.pro:443', b'moduleapi.pro:0443'),
                   valid.replace(b'moduleapi.pro:443', b'https://moduleapi.pro:443'),
                   valid.replace(b'\r\n\r\n', b'\r\nAuthorization: Bearer synthetic\r\n\r\n'),
                   valid.replace(b'\r\n\r\n', b'\r\nHost: moduleapi.pro:443\r\n\r\n'), b'x' * 8193]
        with patch.object(gateway, 'resolve') as resolve, patch.object(gateway.socket, 'socket') as dial:
            for data in invalid:
                client = Mock(); client.recv.side_effect = [data, b'']
                gateway.Handler(client, ('synthetic', 0), Mock())
                self.assertTrue(client.sendall.call_args.args[0].startswith(b'HTTP/1.1 403'))
            resolve.assert_not_called(); dial.assert_not_called()

    def test_numeric_connect_idle_and_body_bounds(self):
        header = b'CONNECT moduleapi.pro:443 HTTP/1.1\r\nHost: moduleapi.pro:443\r\n\r\n'
        for chunk in [b'', b'x' * (gateway.MAX_BYTES + 1), b'ok']:
            client = Mock(); client.recv.side_effect = [header, chunk]
            upstream = Mock(); selector = Mock()
            selector.select.side_effect = [[(types.SimpleNamespace(fileobj=client, data=upstream), 1)], []]
            with patch.object(gateway, 'resolve', return_value=[answer('8.8.8.8')]), \
                    patch.object(gateway.socket, 'socket', return_value=upstream), \
                    patch.object(gateway.selectors, 'DefaultSelector') as factory:
                factory.return_value.__enter__.return_value = selector
                gateway.Handler(client, ('synthetic', 0), Mock())
            upstream.connect.assert_called_once_with(('8.8.8.8', 443))
            upstream.close.assert_called_once()
            if chunk == b'ok':
                upstream.sendall.assert_called_once_with(b'ok')
            else:
                upstream.sendall.assert_not_called()

    def test_connect_failure_closes_upstream_without_fallback(self):
        client = Mock()
        client.recv.return_value = b'CONNECT moduleapi.pro:443 HTTP/1.1\r\nHost: moduleapi.pro:443\r\n\r\n'
        upstream = Mock(); upstream.connect.side_effect = TimeoutError('synthetic sensitive failure')
        with patch.object(gateway, 'resolve', return_value=[answer('8.8.8.8'), answer('1.1.1.1')]), \
                patch.object(gateway.socket, 'socket', return_value=upstream) as factory:
            gateway.Handler(client, ('synthetic', 0), Mock())
        factory.assert_called_once(); upstream.connect.assert_called_once()
        upstream.close.assert_called_once()
        self.assertNotIn(b'synthetic sensitive failure', client.sendall.call_args.args[0])
        self.assertTrue(client.sendall.call_args.args[0].startswith(b'HTTP/1.1 403'))

    def test_absolute_deadline_stops_before_dns(self):
        client = Mock()
        with patch.object(gateway.time, 'monotonic', side_effect=[0, 0, 101, 101]), \
                patch.object(gateway, 'resolve') as resolve:
            gateway.Handler(client, ('synthetic', 0), Mock())
        resolve.assert_not_called(); client.recv.assert_not_called()

    def test_deadline_and_dns_worker_admission(self):
        with patch.object(gateway.time, 'monotonic', return_value=10):
            self.assertEqual(gateway.remaining(12, 5), 2)
            with self.assertRaises(OSError):
                gateway.remaining(10, 5)
        slots = threading.BoundedSemaphore(1)
        with patch.object(gateway, 'DNS_SLOTS', slots), patch.object(gateway.threading, 'Thread') as worker, \
                        patch.object(gateway, 'public_answers', return_value=[answer('8.8.8.8')]) as answers:
            with self.assertRaises(OSError):
                gateway.resolve('moduleapi.pro', 0)
            with self.assertRaises(OSError):
                gateway.resolve('moduleapi.pro', 0)
            worker.assert_called_once()
            worker.call_args.kwargs['target']()  # Timed-out worker alone releases its slot.
            answers.assert_called_once_with('moduleapi.pro')
            self.assertTrue(slots.acquire(blocking=False))

    def test_wrong_hosts_refuse_before_lookup_and_default_start_is_inert(self):
        lookup = Mock(side_effect=AssertionError('lookup not allowed'))
        for host in ['api.openai.com', 'openrouter.ai', 'api.moduleapi.com', 'MODULEAPI.PRO', 'moduleapi.pro.', 'moduleapi.pro.evil']:
            with self.subTest(host=host), self.assertRaises(ValueError):
                gateway.public_answers(host, lookup=lookup)
        lookup.assert_not_called()
        with patch.object(gateway, 'Server') as listener:
            gateway.main([])
            listener.assert_not_called()

    def test_malformed_sockaddr_and_protocols_refuse_before_numeric_dial(self):
        public = answer('8.8.8.8')
        bad = [(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_TCP, '', ('8.8.8.8', 443)),
               (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_UDP, '', ('8.8.8.8', 443)),
               (*public[:4], ('8.8.8.8', 443, 0)),
               (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('2606:4700:4700::1111', 443, 0, 1)),
               (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('2606:4700:4700::1111%1', 443, 0, 0))]
        for record in bad:
            with self.subTest(record=record), self.assertRaises((ValueError, OSError)):
                gateway.public_answers('moduleapi.pro', lookup=lambda *a, **k: [public, record])

    def test_resolver_error_and_thread_creation_failure_release_slots(self):
        for thread_error in [True, False]:
            slots = threading.BoundedSemaphore(1)
            with patch.object(gateway, 'DNS_SLOTS', slots), \
                    patch.object(gateway, 'public_answers', side_effect=OSError('synthetic refused')), \
                    patch.object(gateway.threading, 'Thread') as thread:
                if thread_error:
                    thread.return_value.start.side_effect = RuntimeError('synthetic')
                else:
                    thread.return_value.start.side_effect = lambda: thread.call_args.kwargs['target']()
                with self.assertRaises(OSError):
                    gateway.resolve('moduleapi.pro', 0)
                self.assertTrue(slots.acquire(blocking=False))

    def test_connection_admission_precedes_thread_creation_and_releases_on_failure(self):
        server = object.__new__(gateway.Server)
        server.slots = threading.BoundedSemaphore(1)
        server.shutdown_request = Mock()
        with patch.object(socketserver.ThreadingTCPServer, 'process_request') as dispatch:
            server.process_request(Mock(), ('synthetic', 0))
            server.process_request(Mock(), ('synthetic', 0))
            dispatch.assert_called_once(); server.shutdown_request.assert_called_once()
        with patch.object(socketserver.ThreadingTCPServer, 'process_request_thread'):
            server.process_request_thread(Mock(), ('synthetic', 0))
        with patch.object(socketserver.ThreadingTCPServer, 'process_request', side_effect=RuntimeError('synthetic')):
            server.process_request(Mock(), ('synthetic', 0))
        self.assertTrue(server.slots.acquire(blocking=False))
        self.assertEqual(gateway.Server.request_queue_size, gateway.MAX_CONNECTIONS)


if __name__ == '__main__':
    unittest.main()
