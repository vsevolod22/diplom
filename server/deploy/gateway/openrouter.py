"""Dedicated API-only TLS tunnel. No credentials, environment policy or registry hosts."""
import argparse
import sys
from pathlib import Path

# -I keeps ambient PYTHONPATH out; import only the adjacent audited CONNECT handler.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from proxy import Handler, Policy, Server

OPENROUTER_POLICY = Policy(hosts=frozenset({'openrouter.ai'}))


class Public90sHandler(Handler):
    # Selected only by the trusted public-v2 container command, never by a client.
    tunnel_idle_timeout = 95
    tunnel_socket_timeout = 95


def serve(*, public_90s=False):
    handler = Public90sHandler if public_90s else Handler
    with Server(('0.0.0.0', 8080), handler) as server:
        server.policy = OPENROUTER_POLICY
        server.serve_forever()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--public-90s', action='store_true',
                        help='use fixed 95s tunnel idle/socket timeouts for the public 90s API budget')
    args = parser.parse_args(argv)
    serve(public_90s=args.public_90s)


if __name__ == '__main__':
    main()
