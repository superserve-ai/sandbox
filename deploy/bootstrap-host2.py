#!/usr/bin/env python3
"""Install peer bootstrap on a cold standby using a Terraform output artifact."""
import argparse
import json
import re
from pathlib import Path
import shlex
import subprocess
import tempfile


def bootstrap(config, verify_only=False):
    targets = {'superserve-vmd-staging-2': 'superserve-vmd-staging-2', 'superserve-vmd-usw2-2': 'usw2-2'}
    if targets.get(config['instance_name']) != config['host_id']:
        raise ValueError('bootstrap is restricted to the existing cold-standby Host 2 identities')
    project, zone, name = config['project_id'], config['zone'], config['instance_name']
    flags = [f'--project={project}', f'--zone={zone}', '--quiet']
    def run(*args):
        return subprocess.run(['gcloud', *args], check=True, capture_output=True, text=True).stdout
    instance = json.loads(run('compute', 'instances', 'describe', name, *flags, '--format=json'))
    if str(instance['id']) != config['instance_id'] or instance['networkInterfaces'][0]['networkIP'] != config['internal_ip']:
        raise ValueError('Host 2 immutable identity or private IP changed; regenerate Terraform output')
    if instance['serviceAccounts'][0]['email'] != config['runtime_email']:
        raise ValueError('apply the dedicated runtime identity first')
    labels = instance.get('labels', {})
    if not verify_only and (labels.get('sandbox_status') == 'ready' or labels.get('component') == 'vmd'):
        raise ValueError('Host 2 must be excluded from sandbox_status=ready and component=vmd deployment discovery before migration')
    if not verify_only and instance.get('status') == 'TERMINATED':
        run('compute', 'instances', 'start', name, *flags)
    def ssh(script):
        return run('compute', 'ssh', name, *flags, '--tunnel-through-iap', '--command', script)
    if verify_only:
        expected = config['spiffe_uri'].removeprefix('spiffe://')
        identity = instance.get('workloadIdentityConfig', {})
        if identity.get('identity') != expected or not identity.get('identityCertificateEnabled'):
            raise ValueError('Compute managed identity configuration is missing or mismatched')
        host_id = shlex.quote(config['host_id'])
        ssh(f'''set -eu
for credential in certificates.pem private_key.pem ca_certificates.pem; do
    sudo test -s "/run/secrets/workload-spiffe-credentials/$credential"
done
sudo /usr/local/sbin/refresh-peer-credentials --check
sudo test "$(sudo stat -c '%u:%a' /etc/superserve/peer/current/tls.key)" = 0:600
sudo grep -Fx 'HOST_ID={config['host_id']}' /etc/sandbox/vmd.env >/dev/null
findmnt -T /var/lib/sandbox -n -o TARGET | grep -v '^/$'
mountpoint -q /mnt/sandbox-data
sudo systemctl is-active --quiet google-guest-agent.service vmd-peer-credentials.timer superserve-secretsproxy.service superserve-otel-collector.service superserve-vmd.service
invocation=$(sudo systemctl show -p InvocationID --value superserve-vmd.service)
sudo journalctl "_SYSTEMD_INVOCATION_ID=$invocation" --quiet -g 'gRPC serving requests' --no-pager >/dev/null
sudo journalctl "_SYSTEMD_INVOCATION_ID=$invocation" --quiet -g 'host endpoint heartbeat accepted' --no-pager | grep -F {host_id} >/dev/null
test "$invocation" = "$(sudo systemctl show -p InvocationID --value superserve-vmd.service)"
''')
        print('Host 2 identity, TLS, mounts, services and current-invocation endpoint heartbeat verified.')
        print('Admission remains gated on the directory, capabilities, artifacts and agent evidence in deploy/host2-identity-runbook.md.')
        return
    # Require the existing cold standby baseline. Never synthesize a partial
    # secret configuration or reformat storage containing an unknown filesystem.
    ssh('''set -eu
sudo test -s /etc/sandbox/vmd.env
sudo test -s /etc/sandbox/secretsproxy.env
sudo test -s /var/lib/secretsproxy/ca.crt
sudo test -s /var/lib/secretsproxy/ca.key
sudo test -x /usr/local/bin/template-builder
sudo test -x /usr/local/bin/firecracker
sudo test -c /dev/kvm
findmnt -T /var/lib/sandbox -n -o TARGET | grep -v '^/$'
mountpoint -q /mnt/sandbox-data
sudo systemctl cat google-guest-agent.service >/dev/null
''')
    upload_dir = ssh('umask 077; mktemp -d /tmp/vmd-peer.XXXXXXXX').strip()
    if not re.fullmatch(r'/tmp/vmd-peer\.[A-Za-z0-9]+', upload_dir):
        raise ValueError('unexpected upload directory')
    assets = Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory() as tmp:
        identity = Path(tmp) / 'identity.json'
        identity.write_text(json.dumps(config))
        for src, dst in [(identity, f'{upload_dir}/identity.json'),
                         (assets / 'refresh-peer-credentials.py', f'{upload_dir}/refresh-peer-credentials.py')]:
            run('compute', 'scp', str(src), f'{name}:{dst}', *flags, '--tunnel-through-iap')
    host_id = shlex.quote(config['host_id'])
    ssh(f'''set -eu
sudo systemctl stop superserve-vmd.socket superserve-vmd.service
sudo install -d -m 0700 /etc/superserve/peer /run/secrets/workload-spiffe-credentials
sudo install -m 0600 {upload_dir}/identity.json /etc/superserve/peer/identity.json
sudo install -m 0755 {upload_dir}/refresh-peer-credentials.py /usr/local/sbin/refresh-peer-credentials
for env in /etc/sandbox/vmd.env /etc/superserve/vmd.env; do
    sudo test -f "$env" || continue
    current=$(sudo sed -n 's/^HOST_ID=//p' "$env")
    if [ -n "$current" ] && [ "$current" != {host_id} ]; then
        echo 'existing HOST_ID disagrees with the host directory contract' >&2
        exit 1
    fi
    sudo sed -i '/^HOST_ID=/d' "$env"
    printf 'HOST_ID=%s\\n' {host_id} | sudo tee -a "$env" >/dev/null
done
sudo tee /etc/tmpfiles.d/vmd-peer.conf >/dev/null <<'CONF'
d /run/secrets/workload-spiffe-credentials 0700 root root -
f /run/lock/vmd-peer-credentials.lock 0644 root root -
CONF
sudo tee /etc/systemd/system/vmd-peer-credentials.service >/dev/null <<'UNIT'
[Unit]
Description=Validate and publish managed peer credentials
After=google-guest-agent.service network-online.target
[Service]
Type=oneshot
UMask=0077
ExecStart=/usr/local/sbin/refresh-peer-credentials
UNIT
sudo tee /etc/systemd/system/vmd-peer-credentials.timer >/dev/null <<'UNIT'
[Unit]
Description=Refresh managed peer credentials
[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
[Install]
WantedBy=timers.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable vmd-peer-credentials.timer
sudo python3 - <<'PY'
import configparser
from pathlib import Path

path = Path('/etc/default/instance_configs.cfg')
config = configparser.ConfigParser(interpolation=None)
config.optionxform = str
if path.exists():
    with path.open() as source:
        config.read_file(source)
if not config.has_section('MWLID'):
    config.add_section('MWLID')
config.set('MWLID', 'enabled', 'true')
with path.open('w') as destination:
    config.write(destination)
PY
rm -rf {upload_dir}
''')
    ssh('''set -eu
sudo systemd-tmpfiles --create /etc/tmpfiles.d/vmd-peer.conf
if command -v ggactl_plugin >/dev/null 2>&1; then
    sudo ggactl_plugin coreplugin restart
else
    sudo systemctl restart google-guest-agent.service
fi
sudo systemctl start vmd-peer-credentials.timer
''')
    print('Host 2 peer bootstrap installed. Deploy and verify the normal runtime before admission.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify', action='store_true', help='read-only local checks; complete the runbook evidence before admission')
    parser.add_argument('configuration', type=Path, help='terraform output -json host2_peer_bootstrap')
    args = parser.parse_args()
    bootstrap(json.loads(args.configuration.read_text()), args.verify)
