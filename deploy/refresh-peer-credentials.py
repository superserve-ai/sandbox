#!/usr/bin/env python3
"""Publish a validated explicit credential generation for the peer proxy."""
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


def validate(directory, identity, minimum_remaining=0):
    cert, key, ca = (directory / f for f in ('tls.crt', 'tls.key', 'ca.crt'))
    decoded = ssl._ssl._test_decode_cert(str(cert))
    if [value for kind, value in decoded.get('subjectAltName', ()) if kind == 'URI'] != [identity]:
        raise ValueError('peer certificate URI SAN does not match infrastructure identity')
    now = time.time()
    if not ssl.cert_time_to_seconds(decoded['notBefore']) <= now < ssl.cert_time_to_seconds(decoded['notAfter']):
        raise ValueError('peer certificate is expired or not yet valid')
    openssl('x509', '-in', cert, '-checkend', str(minimum_remaining), '-noout')
    if openssl('x509', '-in', cert, '-pubkey', '-noout') != openssl('pkey', '-in', key, '-pubout'):
        raise ValueError('managed certificate and key changed during refresh; retry')
    for purpose in ('sslserver', 'sslclient'):
        openssl('verify', '-purpose', purpose, '-CAfile', ca, '-untrusted', cert, cert)
    return {'expires_at': ssl.cert_time_to_seconds(decoded['notAfter']),
            'seconds_remaining': int(ssl.cert_time_to_seconds(decoded['notAfter']) - now)}


def refresh(peer=PEER, source=SOURCE, *, mode='mwi', cert=None, key=None, ca=None):
    if mode not in ('mwi', 'superserve'):
        raise ValueError('unknown credential mode')
    if mode == 'superserve' and not all((cert, key, ca)):
        raise ValueError('superserve provider requires explicit cert, key and CA files')
    if mode == 'mwi' and any((cert, key, ca)):
        raise ValueError('MWI mode does not accept Superserve files')
    os.umask(0o077)
    peer.mkdir(parents=True, exist_ok=True, mode=0o700)
    with Path('/run/lock/vmd-peer-credentials.lock').open('w') as lock:
        os.fchmod(lock.fileno(), 0o644)
        fcntl.flock(lock, fcntl.LOCK_EX)
        config = json.loads((peer / 'identity.json').read_text())
        policy = config.get('credential_policy', {})
        lifetime = int(policy.get('leaf_lifetime_seconds', 30 * 86400))
        if lifetime <= 0:
            raise ValueError('leaf lifetime must be positive')
        if mode == 'mwi':
            source.chmod(0o700)
            files = [(source / 'certificates.pem', 'tls.crt'),
                     (source / 'private_key.pem', 'tls.key'),
                     (source / 'ca_certificates.pem', 'ca.crt')]
        else:
            files = [(Path(cert), 'tls.crt'), (Path(key), 'tls.key'), (Path(ca), 'ca.crt')]
        candidate = Path(tempfile.mkdtemp(prefix='generation-', dir=peer))
        published = False
        try:
            for src, dst in files:
                (candidate / dst).write_bytes(src.read_bytes())
                (candidate / dst).chmod(0o600)
            validity = validate(candidate, config['spiffe_uri'], minimum_remaining=3600)
            if mode == 'superserve':
                decoded = ssl._ssl._test_decode_cert(str(candidate / 'tls.crt'))
                if ssl.cert_time_to_seconds(decoded['notAfter']) - ssl.cert_time_to_seconds(decoded['notBefore']) > lifetime:
                    raise ValueError('certificate exceeds configured leaf lifetime')
            (candidate / 'mode').write_text(mode + '\n')
            current = peer / 'current'
            unchanged = (current / 'mode').exists() and (current / 'mode').read_text().strip() == mode and all(
                (current / name).read_bytes() == (candidate / name).read_bytes()
                for name in ('tls.crt', 'tls.key', 'ca.crt'))
            if unchanged:
                repair_aliases(peer)
                if mode == 'mwi':
                    reload_proxy(peer, current.resolve(), config['spiffe_uri'])
                report(peer, mode, validity)
                return
            (candidate / 'installed_at').write_text(str(time.time()))
            # Keep recent generations for operator recovery.
            pending = peer / 'current.next'
            pending.unlink(missing_ok=True)
            pending.symlink_to(candidate.name)
            pending.replace(current)
            published = True
            repair_aliases(peer)
            if mode == 'mwi':
                reload_proxy(peer, candidate, config['spiffe_uri'])
            report(peer, mode, validity)
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


def report(peer, provider, validity, error=None):
    with (peer / 'status.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        status_path = peer / 'status.json'
        status = json.loads(status_path.read_text()) if status_path.exists() else {}
        installed_at = peer / 'current/installed_at'
        if installed_at.exists():
            status['last_successful_installation'] = float(installed_at.read_text())
        status.update(provider=provider, checked_at=time.time(), **validity)
        status['last_error'] = error
        if error:
            status['failures'] = status.get('failures', 0) + 1
            status['last_failure_at'] = time.time()
        current = peer / 'current'
        snapshot = Path('/run/credentials/proxy.service')
        try:
            status['proxy_reload_required'] = any(
                (current / name).read_bytes() != (snapshot / runtime).read_bytes()
                for name, runtime in [('tls.crt', 'peer-cert'), ('tls.key', 'peer-key'), ('ca.crt', 'peer-ca')])
        except OSError:
            status['proxy_reload_required'] = True
        policy = json.loads((peer / 'identity.json').read_text()).get('credential_policy', {})
        remaining = validity.get('seconds_remaining', -1)
        defaults = (15 * 86400, 10 * 86400, 3 * 86400) if provider == 'superserve' else (43200, 21600, 3600)
        status['renewal_due'] = remaining <= int(policy.get('renew_before_seconds', defaults[0]))
        status['severity'] = ('critical' if remaining <= int(policy.get('critical_before_seconds', defaults[2]))
                              else 'warning' if remaining <= int(policy.get('warn_before_seconds', defaults[1]))
                              else 'error' if error else 'info')
        pending = peer / 'status.next'
        pending.write_text(json.dumps(status) + '\n')
        pending.chmod(0o600)
        pending.replace(status_path)
        print(json.dumps(status), flush=True)


def configured_provider(peer=PEER):
    path = peer / 'current/mode'
    provider = path.read_text().strip() if path.exists() else 'mwi'
    if provider not in ('mwi', 'superserve'):
        raise ValueError('unknown configured credential provider')
    return provider


if __name__ == '__main__':
    import argparse
    import sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--provider', choices=('mwi', 'superserve'))
    parser.add_argument('--cert', type=Path)
    parser.add_argument('--key', type=Path)
    parser.add_argument('--ca', type=Path)
    args = parser.parse_args()
    provider = args.provider or configured_provider()
    try:
        if os.geteuid() != 0:
            raise ValueError('credential operations must run as root')
        if args.check or (not args.provider and provider == 'superserve'):
            if any((args.cert, args.key, args.ca)):
                raise ValueError('supplied files require explicit --provider superserve')
            current = (PEER / 'current').resolve(strict=True)
            validity = validate(current, json.loads((PEER / 'identity.json').read_text())['spiffe_uri'])
            report(PEER, configured_provider(), validity)
        else:
            refresh(mode=provider, cert=args.cert, key=args.key, ca=args.ca)
    except Exception as error:
        message = (error.stderr.decode(errors='replace') if isinstance(error, subprocess.CalledProcessError)
                   and error.stderr else str(error))
        print(message, file=sys.stderr)
        try:
            current = (PEER / 'current').resolve(strict=True)
            decoded = ssl._ssl._test_decode_cert(str(current / 'tls.crt'))
            expiry = ssl.cert_time_to_seconds(decoded['notAfter'])
            report(PEER, configured_provider(), {'expires_at': expiry,
                   'seconds_remaining': int(expiry - time.time())}, error=message)
        except Exception:
            pass
        raise SystemExit(1)
