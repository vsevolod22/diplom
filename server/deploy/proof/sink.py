"""Forbidden endpoint counter; must never be reached by the proof gateway."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

class Sink(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass
    def do_GET(self):
        with Path('/tmp/hits').open('a') as log:
            log.write('hit\n')
        self.send_response(200)
        self.end_headers()

ThreadingHTTPServer(('0.0.0.0', 443), Sink).serve_forever()
