"""Dedicated API-only TLS tunnel. No credentials, environment policy or registry hosts."""
import sys
from pathlib import Path

# -I keeps ambient PYTHONPATH out; import only the adjacent audited CONNECT handler.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from proxy import Handler, Policy, Server

OPENROUTER_POLICY = Policy(hosts=frozenset({'openrouter.ai'}))


def serve():
    with Server(('0.0.0.0', 8080), Handler) as server:
        server.policy = OPENROUTER_POLICY
        server.serve_forever()


if __name__ == '__main__':
    serve()
