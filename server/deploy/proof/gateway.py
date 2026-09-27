"""Proof-image-only exact fixture mapping; not copied into the shipped gateway image."""
import socket
from pathlib import Path

from proxy import Handler, Policy, Server, HOSTS

FIXTURE = '172.30.92.10'
PAIRS = frozenset((host, FIXTURE) for host in HOSTS)
CONTROL = Path('/tmp/proof-dns')
DIALS = Path('/tmp/proof-dials')


def lookup(host, port, **kwargs):
    # Read on EACH CONNECT; never trust a cached preflight answer.
    mode = CONTROL.read_text().strip() if CONTROL.exists() else 'fixture'
    good = (socket.AF_INET, socket.SOCK_STREAM, 6, '', (FIXTURE, 443))
    bad = (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('169.254.169.254', 443))
    if mode in ('rebind-after-one', 'mixed-after-one'):
        previous = DIALS.read_text().splitlines() if DIALS.exists() else []
        if not previous:
            return [good]
        mode = 'mixed' if mode == 'mixed-after-one' else 'rebind'
    if mode == 'mixed':
        return [good, (socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('::1', 443, 0, 0))]
    if mode == 'rebind':
        return [bad]
    if mode != 'fixture':
        raise OSError('DNS mode refused')
    return [good]


def on_dial(host, ip):
    # Safe host/IP counts only, no tunneled paths, credentials or HTTP payloads.
    with DIALS.open('a') as log:
        log.write(f'{host} {ip}\n')


if __name__ == '__main__':
    policy = Policy(fixture_pairs=PAIRS, lookup=lookup, on_dial=on_dial)
    with Server(('0.0.0.0', 8080), Handler) as server:
        server.policy = policy
        server.serve_forever()
