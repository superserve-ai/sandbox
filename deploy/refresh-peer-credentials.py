#!/usr/bin/env python3
"""Publish a validated managed credential generation for the peer proxy."""
import fcntl
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import time

PEER = Path('/etc/superserve/peer')
SOURCE = Path('/run/secrets/workload-spiffe-credentials')


def openssl(*args):
    return subprocess.check_output(['openssl', *map(str, args)], stderr=subprocess.PIPE)


def validate(directory, identity):
    cert, key, ca = (directory / f for f in ('tls.crt', 'tls.key', 'ca.crt'))
    decoded = ssl._ssl._test_decode_cert(str(cert))
    if [value for kind, value in decoded.get('subjectAltName', ()) if kind == 'URI'] != [identity]:
        raise ValueError('peer certificate URI SAN does not match infrastructure identity')
    openssl('x509', '-in', cert, '-checkend', '3600', '-noout')
    if openssl('x509', '-in', cert, '-pubkey', '-noout') != openssl('pkey', '-in', key, '-pubout'):
        raise ValueError('managed certificate and key changed during refresh; retry')
    for purpose in ('sslserver', 'sslclient'):
        openssl('verify', '-purpose', purpose, '-CAfile', ca, '-untrusted', cert, cert)


def refresh(peer=PEER, source=SOURCE):
    os.umask(0o077)
    peer.mkdir(parents=True, exist_ok=True, mode=0o700)
    with Path('/run/lock/vmd-peer-credentials.lock').open('w') as lock:
        os.fchmod(lock.fileno(), 0o644)
        fcntl.flock(lock, fcntl.LOCK_EX)
        config = json.loads((peer / 'identity.json').read_text())
        source.chmod(0o700)
        candidate = Path(tempfile.mkdtemp(prefix='generation-', dir=peer))
        published = False
        try:
            for src, dst in [('certificates.pem', 'tls.crt'), ('private_key.pem', 'tls.key'),
                             ('ca_certificates.pem', 'ca.crt')]:
                (candidate / dst).write_bytes((source / src).read_bytes())
                (candidate / dst).chmod(0o600)
            validate(candidate, config['spiffe_uri'])
            current = peer / 'current'
            unchanged = current.exists() and all(
                (current / name).read_bytes() == (candidate / name).read_bytes()
                for name in ('tls.crt', 'tls.key', 'ca.crt'))
            if unchanged:
                repair_aliases(peer)
                reload_proxy(peer, current.resolve(), config['spiffe_uri'])
                return
            # Retain two certificate lifetimes for recovery and inspection.
            pending = peer / 'current.next'
            pending.unlink(missing_ok=True)
            pending.symlink_to(candidate.name)
            pending.replace(current)
            published = True
            repair_aliases(peer)
            reload_proxy(peer, candidate, config['spiffe_uri'])
            for old in peer.glob('generation-*'):
                if old != candidate and old.stat().st_mtime < time.time() - 172800:
                    shutil.rmtree(old)
        finally:
            if not published:
                shutil.rmtree(candidate)


def repair_aliases(peer):
    for name in ('tls.crt', 'tls.key', 'ca.crt'):
        alias = peer / name
        if not alias.is_symlink() or os.readlink(alias) != f'current/{name}':
            pending = peer / (name + '.next')
            pending.unlink(missing_ok=True)
            pending.symlink_to(f'current/{name}')
            pending.replace(alias)


def reload_proxy(peer, generation, identity):
    env = Path('/etc/sandbox/proxy.env')
    loaded = peer / 'loaded-generation'
    if (env.exists() and f"PEER_PROXY_SPIFFE_URI={identity}" in env.read_text().splitlines()
            and (not loaded.exists() or loaded.read_text() != generation.name)):
        # Retry failed service refreshes even if the certificate is unchanged.
        subprocess.run(['systemctl', 'try-restart', 'proxy.service'], check=True)
        loaded.write_text(generation.name)


if __name__ == '__main__':
    import sys
    if sys.argv[1:] == ['--check']:
        validate((PEER / 'current').resolve(strict=True), json.loads((PEER / 'identity.json').read_text())['spiffe_uri'])
    elif not sys.argv[1:]:
        refresh()
    else:
        raise SystemExit('usage: refresh-peer-credentials [--check]')
