"""Disposable trusted-TLS OCI registry; paths/counters never include signed queries."""
import gzip
import hashlib
import io
import json
import ssl
import tarfile
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

ROOT = Path('/tmp')

def encoded(obj):
    return json.dumps(obj, separators=(',', ':')).encode()

def digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def image(letter):
    with io.BytesIO() as stream:
        with tarfile.open(fileobj=stream, mode='w') as tar:
            data = ('safe-' + letter + '\n').encode()
            info = tarfile.TarInfo('hello.txt')
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        layer_bytes = stream.getvalue()
        layer = gzip.compress(layer_bytes, mtime=0)
    config = encoded({'architecture': 'amd64', 'os': 'linux',
                      'rootfs': {'type': 'layers', 'diff_ids': [digest(layer_bytes)]}, 'config': {}})
    manifest = encoded({'schemaVersion': 2, 'mediaType': 'application/vnd.docker.distribution.manifest.v2+json',
        'config': {'mediaType': 'application/vnd.docker.container.image.v1+json', 'size': len(config), 'digest': digest(config)},
        'layers': [{'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip', 'size': len(layer), 'digest': digest(layer)}]})
    return manifest, layer, config

images = {letter: image(letter) for letter in 'AB'}
blobs = {digest(config): config for _, _, config in images.values()}
blobs.update({digest(layer): layer for _, layer, _ in images.values()})
manifest_by_digest = {digest(manifest): manifest for manifest, _, _ in images.values()}
manifest_type = 'application/vnd.docker.distribution.manifest.v2+json'
index_type = 'application/vnd.docker.distribution.manifest.list.v2+json'

def index(letter):
    manifest, _, _ = images[letter]
    return encoded({'schemaVersion': 2, 'mediaType': index_type,
                    'manifests': [{'mediaType': manifest_type, 'size': len(manifest), 'digest': digest(manifest),
                                   'platform': {'os': 'linux', 'architecture': 'amd64'}}]})

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def reply(self, code, body=b'', kind='application/json', **headers):
        self.send_response(code)
        self.send_header('Content-Type', kind)
        self.send_header('Content-Length', str(len(body)))
        if code == 200:
            self.send_header('Docker-Content-Digest', digest(body))
        for key, value in headers.items():
            self.send_header(key.replace('_', '-'), value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        path = unquote(self.path.split('?', 1)[0])
        mode = (ROOT / 'mode').read_text().strip() if (ROOT / 'mode').exists() else 'normal'
        letter = (ROOT / 'tag').read_text().strip() if (ROOT / 'tag').exists() else 'A'
        if letter not in images:
            self.reply(404)
            return
        host = self.headers.get('Host', '').split(':')[0]
        # Only a literal non-sensitive path label is recorded. Never record Authorization or a signed query.
        with (ROOT / 'hits').open('a') as hits:
            hits.write(host + ' ' + path + '\n')
        if host == 'auth.docker.io':
            query = parse_qs(urlsplit(self.path).query)
            if path != '/token' or query.get('service') != ['registry.docker.io'] or query.get('scope') != ['repository:library/alpine:pull']:
                self.reply(403)
            else:
                # The token server must not turn an untrusted wrong-scope challenge into
                                # a credential for this repository, regardless of Trivy's recovery behavior.
                                token = 'fixture-other-scope' if mode in ('token-scope', 'token-service') else 'fixture-token'
                                self.reply(200, encoded({'token': token}))
            return
        if host == 'production.cloudfront.docker.com':
            if self.headers.get('Authorization') or self.headers.get('Cookie'):
                (ROOT / 'leak').write_text('credential forwarded')
            key = path.rsplit('/', 1)[-1]
            if key in blobs:
                self.reply(200, blobs[key], 'application/octet-stream')
            else:
                self.reply(404)
            return
        if host != 'registry-1.docker.io' or not path.startswith('/v2/'):
            self.reply(404)
            return
        if mode.startswith('token') or mode == 'normal':
            if self.headers.get('Authorization') != 'Bearer fixture-token':
                realm = ('https://169.254.169.254/token' if mode == 'token-metadata' else
                         'https://172.30.92.11/token' if mode == 'token-sink' else
                         'https://auth.docker.io/token')
                service = 'wrong-service' if mode == 'token-service' else 'registry.docker.io'
                scope = 'repository:other:pull' if mode == 'token-scope' else 'repository:library/alpine:pull'
                self.reply(401, WWW_Authenticate=f'Bearer realm="{realm}",service="{service}",scope="{scope}"')
                return
        if mode in ('manifest-redirect', 'manifest-sink', 'manifest-host') and '/manifests/' in path:
            destination = '169.254.169.254' if mode == 'manifest-redirect' else (
                '172.30.92.11' if mode == 'manifest-sink' else 'evil.example.org')
            self.reply(307, Location='https://' + destination + '/secret?sig=CANARY_SIGNED')
            return
        if mode in ('blob-redirect', 'blob-metadata') and '/blobs/' in path:
            destination = '172.30.92.11' if mode == 'blob-redirect' else '169.254.169.254'
            self.reply(307, Location='https://' + destination + '/secret?sig=CANARY_SIGNED')
            return
        if path == '/v2/':
            self.reply(200, b'{}')
        elif path == '/v2/library/alpine/manifests/stable':
            self.reply(200, index(letter), index_type)
        elif path.startswith('/v2/library/alpine/manifests/'):
            key = path.rsplit('/', 1)[-1]
            if key in manifest_by_digest:
                self.reply(200, manifest_by_digest[key], manifest_type)
            else:
                self.reply(404)
        elif path.startswith('/v2/library/alpine/blobs/'):
            key = path.rsplit('/', 1)[-1]
            if key == digest(images['A'][1]) and (ROOT / 'pause').exists():
                (ROOT / 'arrived').touch()
                deadline = time.monotonic() + 25
                while not (ROOT / 'release').exists() and time.monotonic() < deadline:
                    time.sleep(.05)
                if not (ROOT / 'release').exists():
                    self.reply(503)
                    return
            if key in blobs:
                # Real Trivy follows the CDN redirect; the resolver strips Authorization.
                self.reply(307, Location='https://production.cloudfront.docker.com/blob/' + key + '?sig=CANARY_SIGNED')
            else:
                self.reply(404)
        else:
            self.reply(404)

if __name__ == '__main__':
    server = ThreadingHTTPServer(('0.0.0.0', 443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('/certs/cert.pem', '/certs/key.pem')
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
