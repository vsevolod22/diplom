"""Small fail-closed CONNECT-only lab proxy; not a production egress gateway."""

import ipaddress
import os
import selectors
import socket
import socketserver

ALLOWED = frozenset(host.strip() for host in os.environ.get("ALLOWED_HOSTS", "").split(",") if host.strip())
# Test-only DNS injection. Never enable this exception in a deployed gateway.
LAB_HOST = "registry.lab.test"
LAB_MODE = os.environ.get("LAB_FIXTURE") == "1"


def target(authority):
    # Registry connections must use DNS names, not literals or userinfo.
    if authority.count(":") != 1:
        raise ValueError("invalid authority")
    host, port = authority.split(":")
    if host not in ALLOWED or not host or port != "443":
        raise ValueError("host not allowed")
    if (host != host.lower() or len(host) > 253 or
            any(not label or len(label) > 63 or label[0] == "-" or label[-1] == "-" or
                any(char not in "abcdefghijklmnopqrstuvwxyz0123456789-" for char in label)
                for label in host.split("."))):
        raise ValueError("invalid DNS name")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("IP literal")
    return host


def connect(host):
    if LAB_MODE and host == LAB_HOST and os.path.exists("/tmp/rebind"):
        # Simulate a DNS answer changing between separate scanner CONNECTs.
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443))]
    else:
        addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    # Reject the entire answer set, not just the unsafe record: a mixed response
    # must not become a usable rebinding path on the next connection.
    if not addresses or any(not ipaddress.ip_address(addr[4][0]).is_global and
                            not (LAB_MODE and host == LAB_HOST and addr[4][0] == "172.30.91.10")
                            for addr in addresses):
        raise OSError("unsafe DNS response")
    for family, kind, protocol, _, sockaddr in addresses:
        try:
            sock = socket.socket(family, kind, protocol)
            sock.settimeout(5)
            # Connect to the validated numeric address, never resolve again.
            sock.connect(sockaddr)
            return sock
        except OSError:
            sock.close()
    raise OSError("no allowed destination")


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        upstream = None
        try:
            self.request.settimeout(10)
            request = bytearray()
            while b"\r\n\r\n" not in request and len(request) < 8192:
                data = self.request.recv(4096)
                if not data:
                    return
                request.extend(data)
            header, separator, extra = request.partition(b"\r\n\r\n")
            lines = header.split(b"\r\n")
            parts = lines[0].decode("ascii").split(" ")
            if (not separator or extra or len(parts) != 3 or parts[0] != "CONNECT" or
                    parts[2] != "HTTP/1.1" or any(b":" not in line or
                    line.startswith((b" ", b"\t")) for line in lines[1:])):
                raise ValueError("CONNECT only")
            host = target(parts[1])
            upstream = connect(host)
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self.request.settimeout(None)
            upstream.settimeout(None)
            with selectors.DefaultSelector() as selector:
                selector.register(self.request, selectors.EVENT_READ, upstream)
                selector.register(upstream, selectors.EVENT_READ, self.request)
                while True:
                    for key, _ in selector.select(timeout=30):
                        chunk = key.fileobj.recv(16384)
                        if not chunk:
                            return
                        key.data.sendall(chunk)
        except (OSError, UnicodeError, ValueError):
            try:
                if upstream is None:
                    self.request.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
        finally:
            if upstream is not None:
                upstream.close()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server(("0.0.0.0", 8080), Handler) as server:
        server.serve_forever()
