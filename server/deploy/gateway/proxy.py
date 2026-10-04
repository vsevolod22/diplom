"""CONNECT-only production egress: exact hosts, all DNS answers, numeric-IP dial.

This is a host-level boundary. TLS paths and credentials remain the client's responsibility;
only an internal-network caller may reach this listener (see compose.yaml).
"""

import ipaddress
import os
import selectors
import socket
import socketserver
import threading
from dataclasses import dataclass
from typing import Callable

# hub.docker.com is only for bounded public discovery in the API; image/DB pulls stay on existing hosts.
HOSTS = frozenset(("registry-1.docker.io", "auth.docker.io", "production.cloudfront.docker.com", "hub.docker.com"))
MAX_CONNECTIONS = 64
MAX_BYTES = 64 * 1024 * 1024
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
    def handle(self):
        upstream = None
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
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self.request.settimeout(35)
            upstream.settimeout(35)
            transferred = 0
            with selectors.DefaultSelector() as selector:
                selector.register(self.request, selectors.EVENT_READ, upstream)
                selector.register(upstream, selectors.EVENT_READ, self.request)
                while True:
                    events = selector.select(timeout=30)
                    if not events:
                        return
                    for key, _ in events:
                        chunk = key.fileobj.recv(16384)
                        if not chunk:
                            return
                        transferred += len(chunk)
                        if transferred > MAX_BYTES:
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
                upstream.close()
            SLOTS.release()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server(("0.0.0.0", 8080), Handler) as server:
        server.serve_forever()
