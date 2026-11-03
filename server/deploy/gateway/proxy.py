"""CONNECT-only production egress: exact hosts, all DNS answers, numeric-IP dial.

This is a host-level boundary. TLS paths and credentials remain the client's responsibility;
only an internal-network caller may reach this listener (see compose.yaml).
"""

import argparse
import ipaddress
import os
import selectors
import signal
import time
import socket
import socketserver
import threading
from dataclasses import dataclass
from typing import Callable

# hub.docker.com is only for bounded public discovery in the API; image/DB pulls stay on existing hosts.
HOSTS = frozenset(("registry-1.docker.io", "auth.docker.io", "production.cloudfront.docker.com", "hub.docker.com"))
MAX_CONNECTIONS = 64
MAX_BYTES = 64 * 1024 * 1024
PUBLIC_BLOB_BYTES = 272 * 1024 * 1024
PUBLIC_BLOB_HOSTS = frozenset(('registry-1.docker.io', 'production.cloudfront.docker.com'))
SLOTS = threading.BoundedSemaphore(MAX_CONNECTIONS)


@dataclass(frozen=True)
class Policy:
    hosts: frozenset[str] = HOSTS
    # Only the separately built proof gateway supplies an exact host/IP fixture map.
    # Production creates Policy() below and has no runtime configuration for this field.
    fixture_pairs: frozenset[tuple[str, str]] = frozenset()
    lookup: Callable = socket.getaddrinfo
    on_dial: Callable[[str, str], None] | None = None


PRODUCTION_POLICY = Policy()


def authority(value, policy=PRODUCTION_POLICY):
    if not isinstance(value, str) or value.count(":") != 1:
        raise ValueError("invalid CONNECT authority")
    host, port = value.split(":")
    if (host not in policy.hosts or port != "443" or len(host) > 253 or
            any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") or
                any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in label)
                for label in host.split("."))):
        raise ValueError("destination denied")
    return host


def addresses_for(host, lookup=socket.getaddrinfo, policy=PRODUCTION_POLICY):
    answers = lookup(host, 443, type=socket.SOCK_STREAM)
    # A mixed public/private answer is unsafe even if the first record is public.
    if not answers or len(answers) > 64:
        raise OSError("DNS refused")
    for family, kind, protocol, _, sockaddr in answers:
        if (family not in (socket.AF_INET, socket.AF_INET6) or kind != socket.SOCK_STREAM or
                not (ipaddress.ip_address(sockaddr[0]).is_global or
                                     (host, sockaddr[0]) in policy.fixture_pairs)):
            raise OSError("DNS refused")
    return answers


def dial(host, lookup=socket.getaddrinfo, connector=socket.socket, policy=PRODUCTION_POLICY):
    answers = addresses_for(host, policy.lookup if policy is not PRODUCTION_POLICY else lookup, policy)
    for family, kind, protocol, _, sockaddr in answers:
        connection = connector(family, kind, protocol)
        try:
            connection.settimeout(5)
            # sockaddr is the numeric, already validated answer; no second DNS lookup.
            connection.connect(sockaddr)
            if policy.on_dial:
                policy.on_dial(host, sockaddr[0])
            return connection
        except OSError:
            connection.close()
    raise OSError("connect failed")


class Handler(socketserver.BaseRequestHandler):
    tunnel_idle_timeout = 30
    tunnel_socket_timeout = 35

    def byte_limit(self, host):
        return MAX_BYTES

    def handle(self):
        upstream = None
        # Transport handlers also run standalone; only Server owns thread lifecycle.
        lifecycle = self.server if isinstance(self.server, Server) else None
        if not SLOTS.acquire(blocking=False):
            return
        try:
            self.request.settimeout(10)
            header = bytearray()
            while b"\r\n\r\n" not in header and len(header) <= 8192:
                part = self.request.recv(1024)
                if not part:
                    return
                header.extend(part)
            raw, sep, extra = header.partition(b"\r\n\r\n")
            lines = raw.split(b"\r\n")
            request = lines[0].decode("ascii").split(" ")
            if (not sep or extra or len(header) > 8192 or len(request) != 3 or
                    request[0] != "CONNECT" or request[2] != "HTTP/1.1" or
                    any(line.lower() not in (b"host: " + request[1].encode("ascii"), b"connection: close", b"connection: keep-alive",
                                             b"user-agent: go-http-client/1.1")
                                            for line in lines[1:]) or len(lines) > 4 or
                                        sum(line.lower().startswith(b"host:") for line in lines[1:]) != 1):
                raise ValueError("CONNECT only")
            policy = getattr(self.server, 'policy', PRODUCTION_POLICY)
            host = authority(request[1], policy)
            upstream = dial(host) if policy is PRODUCTION_POLICY else dial(host, policy=policy)
            if lifecycle is not None and not lifecycle.track_connection(upstream):
                return
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self.request.settimeout(self.tunnel_socket_timeout)
            upstream.settimeout(self.tunnel_socket_timeout)
            transferred = 0
            byte_limit = self.byte_limit(host)
            with selectors.DefaultSelector() as selector:
                selector.register(self.request, selectors.EVENT_READ, upstream)
                selector.register(upstream, selectors.EVENT_READ, self.request)
                while True:
                    events = selector.select(timeout=self.tunnel_idle_timeout)
                    if not events:
                        return
                    for key, _ in events:
                        chunk = key.fileobj.recv(16384)
                        if not chunk:
                            return
                        transferred += len(chunk)
                        if transferred > byte_limit:
                            return
                        key.data.sendall(chunk)
        except (OSError, UnicodeError, ValueError):
            if upstream is None:
                try:
                    self.request.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                except OSError:
                    pass
        finally:
            if upstream is not None:
                if lifecycle is not None:
                    lifecycle.untrack_connection(upstream)
                upstream.close()
            SLOTS.release()


class PublicImageV2Handler(Handler):
    def byte_limit(self, host):
        # CONNECT cannot see encrypted paths. Clients still enforce exact blob,
        # metadata and per-attempt budgets; auth/discovery retain the old cap.
        return PUBLIC_BLOB_BYTES if host in PUBLIC_BLOB_HOSTS else MAX_BYTES


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    shutdown_timeout = 5.0

    def __init__(self, *args, **kwargs):
        self._condition = threading.Condition()
        self._connections = set()
        self._active_handlers = 0
        self._stopping = False
        super().__init__(*args, **kwargs)

    def track_connection(self, connection):
        with self._condition:
            if self._stopping:
                return False
            self._connections.add(connection)
            return True

    def untrack_connection(self, connection):
        with self._condition:
            self._connections.discard(connection)

    def process_request(self, request, client_address):
        with self._condition:
            if self._stopping:
                self.shutdown_request(request)
                return
            self._connections.add(request)
            self._active_handlers += 1
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._handler_finished(request)
            raise

    def _handler_finished(self, request):
        with self._condition:
            self._connections.discard(request)
            self._active_handlers -= 1
            self._condition.notify_all()

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._handler_finished(request)

    def finish_shutdown(self):
        # Called outside serve_forever's thread: shutdown() would deadlock there.
        with self._condition:
            self._stopping = True
        self.shutdown()
        self.server_close()
        deadline = time.monotonic() + self.shutdown_timeout
        with self._condition:
            connections = tuple(self._connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        with self._condition:
            while self._active_handlers:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    # A resolver/dial that did not return must not claim a clean exit.
                    return False
                self._condition.wait(remaining)
        return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--public-images-v2', action='store_true',
                        help='fixed 272MiB registry/blob TLS tunnel cap; other hosts unchanged')
    args = parser.parse_args(argv)
    handler = PublicImageV2Handler if args.public_images_v2 else Handler
    stop_requested = False

    def request_stop(_sig, _frame):
        # Signals execute on the main thread: never acquire an Event/Condition
        # lock here (a repeated signal could interrupt that same lock holder).
        nonlocal stop_requested
        stop_requested = True

    previous = {sig: signal.signal(sig, request_stop)
                for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        with Server(("0.0.0.0", 8080), handler) as server:
            thread = threading.Thread(target=server.serve_forever,
                                      kwargs={'poll_interval': 0.1}, daemon=True)
            thread.start()
            while not stop_requested:
                if not thread.is_alive():
                    raise SystemExit('gateway listener stopped unexpectedly')
                time.sleep(0.1)
            clean = server.finish_shutdown()
            thread.join(timeout=1)
            if not clean or thread.is_alive():
                raise SystemExit('gateway shutdown deadline exceeded')
    finally:
        for sig, old_handler in previous.items():
            signal.signal(sig, old_handler)


if __name__ == "__main__":
    main()
