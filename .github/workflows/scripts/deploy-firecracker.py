#!/usr/bin/env python3
"""Install a published Firecracker release on every host in a cell.

This builds nothing. The binary is a release artifact built once, and every
host installs those exact bytes after verifying the digest — so fleet
uniformity is a property of the process rather than something to audit
afterwards. Hosts are visited one at a time: a swap only affects VMs launched
after it, so there is no rush, and stopping on the first failure leaves the
rest of the cell untouched.
"""

import argparse
import hashlib
import os
import shlex
import subprocess
import sys
import tarfile
import tempfile

# The one repository the binary is published from. Not configurable: there is
# a single fork, it does not vary by environment, and an unset variable would
# silently become an empty string.
RELEASE_REPO = "superserve-ai/firecracker"

INSTALL_PATH = "/usr/local/bin/firecracker"
# The pre-fork stock binary. It is the floor of any rollback, so a host that
# has lost it must not be deployed to until it is restored.
STOCK_BACKUP = f"{INSTALL_PATH}.v1.15.0.bak"
# Every launch is gated on this capability, so a binary that stopped
# advertising it would disable direct spawn on the next daemon restart
# rather than failing at install time.
REQUIRED_CAPABILITY = "serial-console-cap"


def run_or_die(cmd, context):
    """Run a subprocess, surfacing both streams on failure. Logs reach the
    GitHub Actions UI directly — no need to inspect the runner."""
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(
            f"{context} failed (exit={r.returncode}): {' '.join(cmd[:4])}…\n"
            f"--- stderr ---\n{(r.stderr or '').strip() or '(empty)'}\n"
            f"--- stdout ---\n{(r.stdout or '').strip() or '(empty)'}"
        )
    return r


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch_release(version, workdir):
    """Download and unpack the release, returning (binary_path, sha256).

    The digest is taken from the unpacked binary and cross-checked against the
    published .sha256, so a tampered or truncated download cannot reach a host.
    """
    run_or_die(
        ["gh", "release", "download", version, "--repo", RELEASE_REPO,
         "--pattern", "firecracker.tar.gz", "--pattern", "firecracker.sha256",
         "--dir", workdir],
        f"download release {version}",
    )
    with tarfile.open(os.path.join(workdir, "firecracker.tar.gz")) as tf:
        tf.extract("firecracker", path=workdir)
    binary = os.path.join(workdir, "firecracker")

    digest = sha256_of(binary)
    with open(os.path.join(workdir, "firecracker.sha256")) as f:
        published = f.read().split()[0]
    if digest != published:
        raise RuntimeError(
            f"release {version} digest mismatch: unpacked {digest}, published {published}"
        )
    print(f"{version}: sha256 {digest}")
    return binary, digest


def list_instances(project, region, label):
    result = subprocess.run(
        ["gcloud", "compute", "instances", "list", f"--project={project}",
         f"--filter=labels.{label} AND status=RUNNING",
         "--format=csv[no-heading](name,zone)"],
        capture_output=True, text=True, check=True,
    )
    instances = [
        {"name": parts[0], "zone": parts[1]}
        for line in result.stdout.strip().splitlines() if line.strip()
        for parts in [line.strip().split(",")]
    ]
    # Scope by zone basename rather than in the gcloud filter: matching zone
    # URIs in a filter is easy to get subtly wrong, and a deploy that silently
    # skips a host is exactly the drift this script exists to prevent.
    return [
        i for i in instances if i["zone"].split("/")[-1].startswith(f"{region}-")
    ]


def install_script(version, digest):
    """The remote half of a swap, in the order the checks have to happen."""
    staged = f"/tmp/firecracker-{version}"
    return f"""
set -euo pipefail

staged={shlex.quote(staged)}
live={shlex.quote(INSTALL_PATH)}
stock={shlex.quote(STOCK_BACKUP)}
digest={shlex.quote(digest)}

# Rollback floor. Without it a bad swap has nowhere to fall back to, so
# refuse before touching anything.
test -f "$stock" || {{ echo "stock backup $stock missing — abort"; exit 1; }}

# The bytes that arrived are the bytes that were built.
echo "$digest  $staged" | sha256sum -c -

# Loader pre-check, deliberately while still in /tmp: a binary linked against
# a newer glibc than this host provides fails here, with the live binary
# untouched. This is the failure that is otherwise discovered by a sandbox
# that will not start.
chmod +x "$staged"
"$staged" --version
"$staged" --version | grep -qE '^[[:space:]]*capability: {REQUIRED_CAPABILITY}[[:space:]]*$' \\
  || {{ echo "staged binary does not advertise {REQUIRED_CAPABILITY} — abort"; exit 1; }}

# Already at this version: nothing to do, and re-running must not manufacture
# a second backup of a binary that is already the target.
if [ "$(sha256sum < "$live" | cut -d' ' -f1)" = "$digest" ]; then
  echo "already at $digest — nothing to do"
  rm -f "$staged"
  exit 0
fi

# Name the backup after the digest it preserves, not the version being
# installed. A per-version name is wrong the second time a version is
# deployed: `cp -n` would keep the older file and the predecessor it should
# have saved would be lost. Keyed by content, an existing file with this name
# already holds these exact bytes, so skipping the copy is correct.
backup="$live.pre-$(sha256sum < "$live" | cut -c1-12).bak"

# Backup CHAINED to install: a failed backup must not be followed by an
# install that overwrites the binary it was meant to preserve. `cp -n`, not
# `--update=none`, which needs coreutils >= 9.3.
# The install writes alongside and renames: writing to the live path exposes
# a half-written binary to a launching sandbox, and fails with ETXTBSY while
# one is running from it. A rename in the same directory is atomic.
incoming="$live.incoming"
sudo rm -f "$incoming"
sudo cp -n "$live" "$backup" \\
  && sudo install -m 0755 "$staged" "$incoming" \\
  && sudo mv -f "$incoming" "$live"

# Prove the swap landed, and that what landed still runs here.
installed=$(sha256sum < "$live" | cut -d' ' -f1)
test "$installed" = "$digest" || {{ echo "post-install digest $installed != $digest"; exit 1; }}
"$live" --version
"$live" --version | grep -qE '^[[:space:]]*capability: {REQUIRED_CAPABILITY}[[:space:]]*$'
rm -f "$staged"
echo "installed $digest (previous binary saved at $backup)"
"""


def deploy_to(inst, project, binary, version, digest):
    name, zone = inst["name"], inst["zone"]
    tag = f"{name}/{zone.split('/')[-1]}"
    staged = f"/tmp/firecracker-{version}"

    run_or_die(
        ["gcloud", "compute", "scp", binary, f"{name}:{staged}",
         f"--zone={zone}", f"--project={project}", "--quiet", "--tunnel-through-iap"],
        f"[{tag}] upload binary",
    )
    r = run_or_die(
        ["gcloud", "compute", "ssh", name, f"--zone={zone}", f"--project={project}",
         "--quiet", "--tunnel-through-iap", "--command", install_script(version, digest)],
        f"[{tag}] install",
    )
    for line in (r.stdout or "").strip().splitlines():
        print(f"[{tag}] {line}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", required=True, help="release tag to install")
    args = ap.parse_args()

    project = os.environ["GCP_PROJECT"]
    label = os.environ["VMD_LABEL"]
    # Required, not optional: cells share a project and a label, so an unset
    # region silently widens discovery to every cell at once instead of the
    # one being deployed.
    region = os.environ.get("GCP_REGION", "").strip()
    if not region:
        print("GCP_REGION is unset — refusing to deploy without a region", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as workdir:
        binary, digest = fetch_release(args.version, workdir)

        instances = list_instances(project, region, label)
        where = f"{project} ({region})"
        if not instances:
            print(f"No instances with label {label} found in {where}", file=sys.stderr)
            return 1
        print(f"Installing {args.version} on {len(instances)} instance(s) in {where}")

        # Sequential, and stopping on the first failure: a swap only affects
        # VMs launched after it, so there is nothing to gain from racing, and
        # a host that refuses the binary should halt the rollout rather than
        # let it continue into the rest of the cell.
        for inst in instances:
            deploy_to(inst, project, binary, args.version, digest)

    print("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
