"""Opt-in, separate API-only OpenAI CONNECT gateway; never the OpenRouter default.

Run with python3 -I openai.py --serve only inside a reviewed API-only egress
network. TLS identity and the exact /v1/chat/completions path are enforced by
openai-transport.ts, not inspected by this opaque tunnel. No secrets are read.
"""
import argparse
import ipaddress
import queue
import selectors
import socket
import threading
import time
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from proxy import Policy, authority, addresses_for
import socketserver

POLICY = Policy(hosts=frozenset({'api.openai.com'}))
MAX_CONNECTIONS = 8
MAX_BYTES = 1_048_576  # Includes encrypted TLS handshake/framing in both directions.
HEADER_BYTES = 8192
TOTAL_SECONDS = 100
IDLE_SECONDS = 95
DNS_SECONDS = 5
CONNECT_SECONDS = 5
DNS_SLOTS = threading.BoundedSemaphore(MAX_CONNECTIONS)


def public_answers(host, lookup=socket.getaddrinfo):
    # Reuse the existing all-answer validation, then reject transition, scoped,
    # multicast and reserved addresses that ipaddress.is_global alone can admit.
    if host != 'api.openai.com':
        raise ValueError('destination denied')
    answers = addresses_for(host, lookup=lookup, policy=POLICY)
    for family, kind, protocol, _, sockaddr in answers:
        address = ipaddress.ip_address(sockaddr[0])
        if (protocol not in (0, socket.IPPROTO_TCP) or sockaddr[1] != 443 or
                address.is_multicast or address.is_reserved or address.is_loopback or
                address.is_link_local or address.is_unspecified or '%' in sockaddr[0]):
            raise OSError('DNS refused')
        if family == socket.AF_INET6:
            if (address.version != 6 or len(sockaddr) != 4 or sockaddr[2:] != (0, 0) or
                    address not in ipaddress.ip_network('2000::/3') or address.ipv4_mapped or
                    address.sixtofour or address.teredo):
                raise OSError('DNS refused')
        elif address.version != 4 or len(sockaddr) != 2:
            raise OSError('DNS refused')
    return answers


def resolve(host, timeout):
    # getaddrinfo has no portable cancellation. Timed-out resolver threads keep
    # their slots until they exit, so malicious/stuck DNS cannot grow a thread pool.
    if not DNS_SLOTS.acquire(blocking=False):
        raise OSError('DNS unavailable')
    result = queue.Queue(maxsize=1)

    def lookup():
        try:
            result.put(public_answers(host))
        except Exception:
            result.put(None)
        finally:
            DNS_SLOTS.release()

    try:
        threading.Thread(target=lookup, daemon=True).start()
    except Exception:
        DNS_SLOTS.release()
        raise OSError('DNS unavailable') from None
    try:
        answers = result.get(timeout=timeout)
    except queue.Empty:
        raise OSError('DNS unavailable') from None
    if answers is None:
        raise OSError('DNS unavailable')
    return answers


def remaining(deadline, ceiling):
    budget = min(ceiling, deadline - time.monotonic())
    if budget <= 0:
        raise OSError('deadline')
    return budget


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        upstream = None
        established = False
        deadline = time.monotonic() + TOTAL_SECONDS
        try:
            header_deadline = min(deadline, time.monotonic() + 5)
            header = bytearray()
            while b'\r\n\r\n' not in header:
                self.request.settimeout(remaining(header_deadline, 5))
                part = self.request.recv(min(1024, HEADER_BYTES + 1 - len(header)))
                if not part:
                    return
                header.extend(part)
                if len(header) > HEADER_BYTES:
                    raise ValueError('header limit')
            raw, _, extra = header.partition(b'\r\n\r\n')
            lines = raw.split(b'\r\n')
            request = lines[0].decode('ascii').split(' ')
            if (extra or len(request) != 3 or request[0] != 'CONNECT' or request[2] != 'HTTP/1.1' or
                    len(lines) not in (2, 3)):
                raise ValueError('CONNECT only')
            host = authority(request[1], POLICY)
            fields = [line.lower() for line in lines[1:]]
            expected = b'host: api.openai.com:443'
            if fields.count(expected) != 1 or any(line not in (
                    expected, b'connection: close', b'connection: keep-alive') for line in fields):
                raise ValueError('CONNECT only')
            answers = resolve(host, remaining(deadline, DNS_SECONDS))
            family, kind, protocol, _, sockaddr = answers[0]
            upstream = socket.socket(family, kind, protocol)
            upstream.settimeout(remaining(deadline, CONNECT_SECONDS))
            # Already validated numeric sockaddr. No second DNS lookup or direct fallback.
            upstream.connect(sockaddr)
            self.request.settimeout(remaining(deadline, 5))
            self.request.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            established = True
            transferred = 0
            with selectors.DefaultSelector() as selector:
                selector.register(self.request, selectors.EVENT_READ, upstream)
                selector.register(upstream, selectors.EVENT_READ, self.request)
                while True:
                    events = selector.select(remaining(deadline, IDLE_SECONDS))
                    if not events:
                        return
                    for key, _ in events:
                        key.fileobj.settimeout(remaining(deadline, 5))
                        chunk = key.fileobj.recv(16384)
                        if not chunk:
                            return
                        transferred += len(chunk)
                        if transferred > MAX_BYTES:
                            return
                        key.data.settimeout(remaining(deadline, 5))
                        key.data.sendall(chunk)
        except (OSError, UnicodeError, ValueError, TypeError, IndexError):
            if not established:
                try:
                    self.request.settimeout(remaining(deadline, 1))
                    self.request.sendall(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                except OSError:
                    pass
        finally:
            if upstream is not None:
                upstream.close()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = MAX_CONNECTIONS

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        # Admission BEFORE ThreadingMixIn creates a thread, unlike the shared handler.
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            self.shutdown_request(request)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        # No request, destination, client metadata or exception trace in logs.
        pass


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--serve', action='store_true', help='explicitly start the isolated OpenAI listener')
    args = parser.parse_args(argv)
    if not args.serve:
        return
    with Server(('0.0.0.0', 8080), Handler) as server:
        server.serve_forever()


if __name__ == '__main__':
    main()
