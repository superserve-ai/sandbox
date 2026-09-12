#!/usr/bin/env python3
"""Operator-driven CAS issuance with host-local private keys; no runtime deployment."""
import argparse
import base64
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import urllib.request
import uuid

HOSTS = ('superserve-vmd-staging', 'superserve-vmd-staging-2')
PROJECT = 'rayai-dev'
ZONE = 'us-central1-a'
URI = 'spiffe://vmd-peer-staging-usc1.global.669325949364.workload.id.goog/ns/vmd/sa/vmd-peer-proxy'


def run(args):
    try:
        return subprocess.run(args, check=True, capture_output=True, text=True, timeout=120).stdout
    except subprocess.CalledProcessError as error:
        print(error.stderr, file=sys.stderr)
        raise


def ssh(host, command):
    return run(['gcloud', 'compute', 'ssh', host, f'--project={PROJECT}', f'--zone={ZONE}',
                '--tunnel-through-iap', '--command', command])


def check_host(host, policy):
    if host not in HOSTS:
        raise ValueError('operator helper supports the two staging hosts only')
    principal = policy['hosts'][host]['service_account']
    instance = json.loads(run(['gcloud', 'compute', 'instances', 'describe', host,
                              f'--project={PROJECT}', f'--zone={ZONE}', '--format=json']))
    if [a['email'] for a in instance.get('serviceAccounts', [])] != [principal]:
        raise ValueError('host service account differs from reviewed issuer policy')
    if instance.get('status') != 'RUNNING':
        raise ValueError('host must already be running; this helper never activates VMs')
    if host == HOSTS[1] and (instance.get('labels', {}).get('component') != 'vmd-staging-standby'
                            or instance.get('labels', {}).get('sandbox_status') == 'ready'):
        raise ValueError('Host 2 must remain standby and non-ready')
    if policy['spiffe_uri'] != URI:
        raise ValueError('policy must preserve the existing staging peer SPIFFE URI')
    return instance


def certificate_request(csr, policy):
    # The signed CSR proves possession of the key. Its subject/extensions confer no authority.
    run(['openssl', 'req', '-in', str(csr), '-verify', '-noout'])
    public_key = run(['openssl', 'req', '-in', str(csr), '-pubkey', '-noout']).encode()
    lifetime = int(policy.get('credential_policy', {}).get('leaf_lifetime_seconds', 30 * 86400))
    if lifetime <= 0:
        raise ValueError('leaf lifetime must be positive')
    return {'lifetime': f'{lifetime}s', 'config': {
        'publicKey': {'format': 'PEM', 'key': base64.b64encode(public_key).decode()},
        'subjectConfig': {'subject': {'commonName': 'vmd-peer-proxy'},
                          'subjectAltName': {'uris': [policy['spiffe_uri']]}},
        'x509Config': {'caOptions': {'isCa': False}, 'keyUsage': {
            'baseKeyUsage': {'digitalSignature': True},
            'extendedKeyUsage': {'serverAuth': True, 'clientAuth': True}}}}}


def issue(csr, policy, request_id):
    pool = policy['ca_pool']
    if not re.fullmatch(r'projects/[a-z0-9-]+/locations/[a-z0-9-]+/caPools/[a-zA-Z0-9_-]+', pool):
        raise ValueError('invalid CA pool resource')
    body = certificate_request(csr, policy)
    # Only the issuer principal has issuance IAM. Operators need narrowly scoped impersonation.
    token = run(['gcloud', 'auth', 'print-access-token',
                 '--impersonate-service-account=' + policy['issuer_service_account']]).strip()
    url = (f'https://privateca.googleapis.com/v1/{pool}/certificates'
           f'?certificateId=peer-{request_id}&requestId={request_id}')
    request = urllib.request.Request(url, data=json.dumps(body).encode(), headers={
        'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=60) as response:
        result = json.load(response)
    chain = result['pemCertificateChain']
    if not chain:
        raise ValueError('CAS response did not include its trust chain')
    return result['pemCertificate'] + ''.join(chain[:-1]), chain[-1]


def prepare(host, directory, request_id):
    remote = f'/etc/superserve/peer/requests/{request_id}'
    ssh(host, f'''set -eu
sudo install -d -m 0700 /etc/superserve/peer/requests
if ! sudo test -f {remote}/request.csr; then
  sudo mkdir -p -m 0700 {remote}
  if ! sudo test -s {remote}/tls.key; then
    sudo openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out {remote}/tls.key
  fi
  sudo openssl req -new -key {remote}/tls.key -subj /CN=vmd-peer-proxy -out {remote}/request.csr
  sudo chmod 0600 {remote}/tls.key
fi
sudo openssl req -in {remote}/request.csr -verify -noout
''')
    (directory / 'request.csr').write_text(ssh(host, f'sudo cat {remote}/request.csr'))


def install(host, directory, request_id, policy):
    remote = f'/etc/superserve/peer/requests/{request_id}'
    upload = ssh(host, 'mktemp -d /tmp/peer-cas.XXXXXXXX').strip()
    if not re.fullmatch(r'/tmp/peer-cas\.[A-Za-z0-9]+', upload):
        raise ValueError('unexpected upload path')
    config = {'spiffe_uri': policy['spiffe_uri'], 'credential_policy': policy.get('credential_policy', {})}
    (directory / 'identity.json').write_text(json.dumps(config))
    script = Path(__file__).with_name('refresh-peer-credentials.py')
    try:
        run(['gcloud', 'compute', 'scp', f'--project={PROJECT}', f'--zone={ZONE}',
             '--tunnel-through-iap', str(directory / 'tls.crt'), str(directory / 'ca.crt'),
             str(directory / 'identity.json'), str(script), f'{host}:{upload}/'])
        check_host(host, policy)
        print(ssh(host, f'''set -eu
sudo python3 - {upload}/identity.json <<'CHECK'
import json, pathlib, sys
old = pathlib.Path('/etc/superserve/peer/identity.json')
new = json.load(open(sys.argv[1]))
if old.exists():
    existing = json.loads(old.read_text())
    if existing['spiffe_uri'] != new['spiffe_uri']:
        raise SystemExit('existing identity mismatch')
    if existing.get('credential_policy', {{}}) != new.get('credential_policy', {{}}):
        raise SystemExit('update the root-owned credential_policy to the reviewed policy before installing')
CHECK
sudo install -d -m 0700 /etc/superserve/peer
if ! sudo test -f /etc/superserve/peer/identity.json; then
  sudo install -m 0600 {upload}/identity.json /etc/superserve/peer/identity.json
fi
for unit in vmd-peer-credentials.timer vmd-peer-credentials.service; do
  if [ "$(sudo systemctl show "$unit" -p LoadState --value)" = loaded ]; then
    sudo systemctl stop "$unit"
  fi
done
sudo install -m 0755 {upload}/refresh-peer-credentials.py /usr/local/sbin/refresh-peer-credentials
sudo /usr/local/sbin/refresh-peer-credentials --provider superserve \\
  --cert {upload}/tls.crt --key {remote}/tls.key --ca {upload}/ca.crt
sudo tee /etc/systemd/system/vmd-peer-credentials.service >/dev/null <<'UNIT'
[Unit]
Description=Validate and report peer credentials
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/refresh-peer-credentials
UNIT
sudo tee /etc/systemd/system/vmd-peer-credentials.timer >/dev/null <<'TIMER'
[Unit]
Description=Check peer credentials
[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
[Install]
WantedBy=timers.target
TIMER
sudo systemctl daemon-reload
sudo systemctl enable --now vmd-peer-credentials.timer
sudo /usr/local/sbin/refresh-peer-credentials --check
'''))
    finally:
        ssh(host, 'rm -rf -- ' + shlex.quote(upload))


def verify(host, target, fingerprint):
    # Read an HTTP/2 SETTINGS frame so TLS 1.3 server rejection of our client is observable.
    print(ssh(host, "sudo python3 - " + shlex.quote(target) + " " + shlex.quote(fingerprint) + " <<'VERIFY'\n" + '''import hashlib, json, socket, ssl, sys
from pathlib import Path
p = Path('/etc/superserve/peer/current').resolve(strict=True)
identity = json.loads(Path('/etc/superserve/peer/identity.json').read_text())['spiffe_uri']
c = ssl.create_default_context(cafile=str(p / 'ca.crt'))
c.check_hostname = False
c.minimum_version = ssl.TLSVersion.TLSv1_3
c.load_cert_chain(str(p / 'tls.crt'), str(p / 'tls.key'))
c.set_alpn_protocols(['h2'])
with socket.create_connection((sys.argv[1], 5009), timeout=10) as raw:
    with c.wrap_socket(raw) as tls:
        if identity not in [v for k,v in tls.getpeercert().get('subjectAltName', ()) if k == 'URI']:
            raise SystemExit('unauthorized peer SPIFFE URI')
        if hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest() != sys.argv[2]:
            raise SystemExit('listener is not serving the currently installed peer certificate; reload required')
        if tls.selected_alpn_protocol() != 'h2':
            raise SystemExit('peer did not negotiate HTTP/2')
        tls.sendall(b'PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n' + bytes.fromhex('000000040000000000'))
        header = b''
        while len(header) < 9:
            part = tls.recv(9 - len(header))
            if not part:
                raise SystemExit('peer rejected authenticated connection')
            header += part
        if header[3] != 4:
            raise SystemExit('expected peer HTTP/2 SETTINGS')
        print('Verified bidirectional certificate authentication:', tls.version(), identity)
VERIFY'''))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'issue', 'install', 'verify'))
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--host', choices=HOSTS, required=True)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    policy = json.loads(args.policy.read_text())
    check_host(args.host, policy)
    directory = args.directory
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    state = directory / 'request.json'
    if not state.exists():
        if args.action != 'prepare':
            raise ValueError('prepare a host-local request first')
        state.write_text(json.dumps({'host': args.host, 'request_id': str(uuid.uuid4())}))
    request = json.loads(state.read_text())
    if request['host'] != args.host:
        raise ValueError('request belongs to another host')
    request_id = str(uuid.UUID(request['request_id']))
    if args.action == 'prepare':
        prepare(args.host, directory, request_id)
    elif args.action == 'issue':
        cert, ca = issue(directory / 'request.csr', policy, request_id)
        (directory / 'tls.crt').write_text(cert)
        (directory / 'ca.crt').write_text(ca)
    elif args.action == 'install':
        install(args.host, directory, request_id, policy)
    else:
        other = HOSTS[1] if args.host == HOSTS[0] else HOSTS[0]
        target = check_host(other, policy)['networkInterfaces'][0]['networkIP']
        fingerprint = ssh(other, 'sudo openssl x509 -in /etc/superserve/peer/current/tls.crt -outform DER | sha256sum').split()[0]
        if not re.fullmatch(r'[a-f0-9]{64}', fingerprint):
            raise ValueError('invalid installed certificate fingerprint')
        verify(args.host, target, fingerprint)


if __name__ == '__main__':
    main()
