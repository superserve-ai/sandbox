#!/usr/bin/env python3
"""Deploy proxy + boxd binaries to VMD instances and inject boxd into rootfs.

All configuration is read from environment variables (set by the GitHub
Actions workflow). The script discovers instances by GCE label, uploads
binaries via SCP, injects boxd into the rootfs atomically, and restarts
the proxy and VMD services.
"""
import os, sys, subprocess, textwrap, shlex, re

# ---------------------------------------------------------------------------
# Config from env
# ---------------------------------------------------------------------------
project     = os.environ['GCP_PROJECT']
label       = os.environ.get('VMD_LABEL', 'component=vmd')
service     = os.environ.get('VMD_SERVICE', 'vmd')
install_dir = os.environ.get('VMD_INSTALL_DIR', '/usr/local/bin')
sha         = os.environ['SHA'][:8]

# HMAC seed for per-sandbox access tokens.
access_seed = os.environ.get('SANDBOX_ACCESS_TOKEN_SEED', '')
if access_seed:
    print(f'::add-mask::{access_seed}')
if access_seed and not re.fullmatch(r'[0-9a-fA-F]{64,}', access_seed):
    print('ERROR: SANDBOX_ACCESS_TOKEN_SEED must be hex-encoded, >= 32 bytes (64 hex chars)', file=sys.stderr)
    sys.exit(1)

# Allowed browser origins for the WS terminal upgrade.
terminal_origins = os.environ.get('TERMINAL_ALLOWED_ORIGINS', '')
if terminal_origins and not re.fullmatch(r'[A-Za-z0-9.,:/*\-]+', terminal_origins):
    print('ERROR: TERMINAL_ALLOWED_ORIGINS contains disallowed characters', file=sys.stderr)
    sys.exit(1)

require_data_plane = os.environ.get('REQUIRE_DATA_PLANE', '')
if require_data_plane not in ('', '0', '1'):
    print('ERROR: REQUIRE_DATA_PLANE must be empty, "0", or "1"', file=sys.stderr)
    sys.exit(1)

proxy_domain = os.environ.get('PROXY_DOMAIN', '')
if not proxy_domain:
    print('ERROR: PROXY_DOMAIN is required', file=sys.stderr)
    sys.exit(1)
if not re.fullmatch(r'[A-Za-z0-9.\-]+', proxy_domain):
    print('ERROR: PROXY_DOMAIN contains disallowed characters', file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Discover instances
# ---------------------------------------------------------------------------
result = subprocess.run([
    'gcloud', 'compute', 'instances', 'list',
    f'--project={project}',
    f'--filter=labels.{label} AND status=RUNNING',
    '--format=csv[no-heading](name,zone)',
], capture_output=True, text=True, check=True)

instances = [
    {'name': r[0], 'zone': r[1]}
    for line in result.stdout.strip().splitlines()
    if line.strip()
    for r in [line.strip().split(',')]
]

if not instances:
    print(f'No instances with label {label} found in {project}', file=sys.stderr)
    sys.exit(1)

print(f'Deploying to {len(instances)} instance(s)')

# ---------------------------------------------------------------------------
# Deploy
# ---------------------------------------------------------------------------
from concurrent.futures import ThreadPoolExecutor, as_completed

def deploy(inst):
    name, zone = inst['name'], inst['zone']
    tag = f'{name}/{zone}'

    for binary in ('vmd', 'boxd', 'proxy'):
        subprocess.run([
            'gcloud', 'compute', 'scp',
            f'bin/{binary}',
            f'{name}:/tmp/{binary}-{sha}',
            f'--zone={zone}',
            f'--project={project}',
            '--quiet',
            '--tunnel-through-iap',
        ], check=True, capture_output=True)
    subprocess.run([
        'gcloud', 'compute', 'scp',
        'deploy/proxy.service',
        f'{name}:/tmp/proxy.service',
        f'--zone={zone}',
        f'--project={project}',
        '--quiet',
        '--tunnel-through-iap',
    ], check=True, capture_output=True)
    print(f'[{tag}] binaries uploaded')

    # Inject updated boxd into the base rootfs atomically:
    #   1. copy ROOTFS -> ROOTFS.new on the same filesystem
    #   2. mount the copy, cp boxd into it, umount
    #   3. mv ROOTFS.new -> ROOTFS (rename is atomic on POSIX)
    inject_script = textwrap.dedent(f'''
        set -euo pipefail

        sudo mv /tmp/vmd-{sha}  {install_dir}/vmd
        sudo mv /tmp/boxd-{sha} {install_dir}/boxd
        sudo chmod +x {install_dir}/vmd {install_dir}/boxd

        ROOTFS=""
        for env_file in /etc/superserve/vmd.env /etc/agentbox/vmd.env; do
            if [ -f "$env_file" ]; then
                candidate=$(grep "^BASE_ROOTFS_PATH=" "$env_file" | head -1 | cut -d= -f2) || true
                if [ -n "$candidate" ]; then
                    ROOTFS="$candidate"
                    break
                fi
            fi
        done

        if [ -n "$ROOTFS" ] && [ -f "$ROOTFS" ]; then
            STAGING="$ROOTFS.new.$$"
            MNT=$(mktemp -d)
            trap 'if mountpoint -q "$MNT" 2>/dev/null; then sudo umount "$MNT" || true; fi; rmdir "$MNT" 2>/dev/null || true; sudo rm -f "$STAGING" 2>/dev/null || true' EXIT

            sudo cp --reflink=auto "$ROOTFS" "$STAGING"
            sudo mount -o loop "$STAGING" "$MNT"
            sudo cp {install_dir}/boxd "$MNT/usr/local/bin/boxd"
            sudo chmod +x "$MNT/usr/local/bin/boxd"
            sudo umount "$MNT"
            rmdir "$MNT"
            sudo mv "$STAGING" "$ROOTFS"
            trap - EXIT
            echo "boxd injected into rootfs atomically"
        else
            echo "WARNING: BASE_ROOTFS_PATH not found or not readable; skipping rootfs inject"
        fi

        sudo systemctl restart {service}
        sleep 3
        sudo systemctl is-active --quiet {service} || (
            echo "ERROR: {service} failed to become active after restart" >&2
            sudo systemctl status --no-pager {service} >&2 || true
            sudo journalctl -u {service} --no-pager -n 40 >&2 || true
            exit 1
        )

        sudo mv /tmp/proxy-{sha} {install_dir}/proxy
        sudo chmod +x {install_dir}/proxy

        sudo mv /tmp/proxy.service /etc/systemd/system/proxy.service
        sudo systemctl daemon-reload
        sudo systemctl enable proxy

        sudo mkdir -p /etc/superserve
        if [ -n "$_PROXY_SEED" ]; then
            sudo tee /etc/superserve/proxy.env > /dev/null <<PROXYENV
        PROXY_DOMAIN={proxy_domain}
        SANDBOX_ACCESS_TOKEN_SEED=$_PROXY_SEED
        TERMINAL_ALLOWED_ORIGINS={terminal_origins}
        REQUIRE_DATA_PLANE={require_data_plane}
        PROXYENV
            sudo chmod 0600 /etc/superserve/proxy.env
        fi

        sudo systemctl restart proxy
        sleep 3
        sudo systemctl is-active --quiet proxy || (
            echo "ERROR: proxy failed to become active after restart" >&2
            sudo systemctl status --no-pager proxy >&2 || true
            sudo journalctl -u proxy --no-pager -n 40 >&2 || true
            exit 1
        )
    ''')
    full_script = f'export _PROXY_SEED={shlex.quote(access_seed)}\n{inject_script}'
    r = subprocess.run([
        'gcloud', 'compute', 'ssh', name,
        f'--zone={zone}', f'--project={project}',
        '--quiet', '--tunnel-through-iap',
        '--command', full_script,
    ], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(
            f'service not healthy\n'
            f'--- stdout ---\n{r.stdout}\n'
            f'--- stderr ---\n{r.stderr}'
        )
    print(f'[{tag}] active')
    if r.stdout.strip():
        print(f'[{tag}] {r.stdout.strip()}')

failed = []
with ThreadPoolExecutor(max_workers=len(instances)) as ex:
    futures = {ex.submit(deploy, inst): inst for inst in instances}
    for f in as_completed(futures):
        inst = futures[f]
        try:
            f.result()
        except Exception as e:
            tag = f"{inst['name']}/{inst['zone']}"
            print(f'[{tag}] FAILED: {e}', file=sys.stderr)
            failed.append(tag)

if failed:
    print(f'Deploy failed on: {", ".join(failed)}', file=sys.stderr)
    sys.exit(1)

print(f'Deployed to {len(instances)} instance(s). sha={sha}')
