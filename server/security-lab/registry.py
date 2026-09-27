"""Disposable TLS OCI registry with deterministic adversarial responses. No credentials."""
import gzip
import hashlib
import io
import json
import os
import ssl
import tarfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def encoded(obj):
    return json.dumps(obj, separators=(",", ":")).encode()


def digest(blob):
    return "sha256:" + hashlib.sha256(blob).hexdigest()


config = encoded({"architecture": "amd64", "os": "linux", "rootfs": {"type": "layers", "diff_ids": []}, "config": {}})
with io.BytesIO() as stream:
    with tarfile.open(fileobj=stream, mode="w") as tar:
        data = b"lab fixture\n"
        info = tarfile.TarInfo("hello.txt")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    layer = gzip.compress(stream.getvalue(), mtime=0)
manifest = encoded({"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                    "config": {"mediaType": "application/vnd.docker.container.image.v1+json", "size": len(config), "digest": digest(config)},
                    "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "size": len(layer), "digest": digest(layer)}]})
blobs = {digest(config): config, digest(layer): layer}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # Request paths may contain signed tokens.

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/events":
            self.reply(200, encoded({"hits": Path("/tmp/hits").read_text().splitlines() if Path("/tmp/hits").exists() else [],
                                      "digest": digest(manifest)}), "application/json")
            return
        with open("/tmp/hits", "a") as hits:
            hits.write(path + "\n")
        mode = Path("/tmp/mode").read_text().strip() if Path("/tmp/mode").exists() else "normal"
        if mode == "token" and path == "/v2/":
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Bearer realm="https://169.254.169.254/token",service="lab"')
            self.end_headers()
        elif mode == "token-host" and path == "/v2/":
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Bearer realm="https://evil.example/token",service="lab"')
            self.end_headers()
        elif (mode == "manifest" and "/manifests/" in path) or (mode == "blob" and "/blobs/" in path):
            self.send_response(307)
            self.send_header("Location", "https://169.254.169.254/secret?signature=DO_NOT_LOG")
            self.end_headers()
        elif path == "/v2/":
            self.reply(200, b"{}", "application/json")
        elif mode == "tag-removed" and path == "/v2/demo/manifests/stable":
            self.reply(404, b"", "application/json")
        elif path.startswith("/v2/demo/manifests/"):
            self.reply(200, manifest, "application/vnd.docker.distribution.manifest.v2+json")
        elif path.startswith("/v2/demo/blobs/") and path.rsplit("/", 1)[-1] in blobs:
            self.reply(200, blobs[path.rsplit("/", 1)[-1]], "application/octet-stream")
        else:
            self.reply(404, b"", "application/json")

    def do_HEAD(self):
        self.do_GET()

    def reply(self, status, body, kind):
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Docker-Content-Digest", digest(body))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/cert.pem", "/key.pem")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
