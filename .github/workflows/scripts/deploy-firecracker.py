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
import re
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


def fetch_release(version, workdir, expected_digest=""):
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
    # Release assets can be replaced after the fact, and each cell downloads
    # independently, so agreeing with the checksum published beside them only
    # proves the pair is self-consistent. Pinning the digest verified on
    # staging is what stops untested bytes reaching production.
    if expected_digest and digest != expected_digest:
        raise RuntimeError(
            f"release {version} is {digest}, not the verified {expected_digest}"
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
    # skips a host is exactly the drift this script exists to prevent. The
    # zone's region must match exactly — a prefix test lets a truncated value
    # like "us" pull in every region at once.
    return [
        i for i in instances
        if i["zone"].split("/")[-1].rsplit("-", 1)[0] == region
    ]


def host_digests(inst, project, expected):
    """What a host is running, and whether it still holds a backup of
    `expected`. Read-only, and one round trip rather than two."""
    name, zone = inst["name"], inst["zone"]
    probe = f"""
        live=$(sha256sum < {shlex.quote(INSTALL_PATH)} | cut -d' ' -f1)
        backup={shlex.quote(INSTALL_PATH)}.pre-{expected[:12]}.bak
        if [ -f "$backup" ]; then
          echo "$live $(sha256sum < "$backup" | cut -d' ' -f1)"
        else
          echo "$live none"
        fi
    """
    r = run_or_die(
        ["gcloud", "compute", "ssh", name, f"--zone={zone}", f"--project={project}",
         "--quiet", "--tunnel-through-iap", "--command", probe],
        f"[{name}] read installed digest",
    )
    live, backup = (r.stdout or "").strip().splitlines()[-1].split()
    return live, (None if backup == "none" else backup)


HEX64 = re.compile(r"^[0-9a-f]{64}$")


def host_state(live, backup, expected, target):
    """Whether a host is in a state this rollout may proceed from.

    Two are acceptable, which is what lets a partly-finished rollout be
    retried: a host still on the verified rollback binary, or one already on
    the target — provided it still holds a correct backup of that rollback
    binary, so it has not lost the way back. Anything else is a host nobody
    verified against, and the rollout stops rather than guessing.
    """
    if live == target:
        # Nothing to do here, whichever direction this is. A host that was
        # never updated is already at the target during a rollback, and would
        # have no backup of the binary it never ran; requiring one would let
        # an untouched host block the rollback of the hosts that were changed.
        note = "already on the target"
        if backup != expected:
            note += "; no local backup of {} (break-glass only — a rollback " \
                    "installs a release)".format(expected[:12])
        return True, note
    if live == expected:
        return True, "on the expected binary"
    return False, f"is on {live[:12]}, neither the expected binary nor the target"


def preflight(instances, project, expected, target):
    """Check every host before any of them is changed."""
    problems = []
    for inst in instances:
        live, backup = host_digests(inst, project, expected)
        ok, why = host_state(live, backup, expected, target)
        print(f"  {inst['name']}: {why}")
        if not ok:
            problems.append(f"{inst['name']} {why}")
    if problems:
        raise RuntimeError("; ".join(problems))


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
# Existence is not usability: a truncated or non-executable floor leaves the
# host with no deep rollback at all.
"$stock" --version >/dev/null 2>&1 || {{ echo "stock backup $stock does not run — abort"; exit 1; }}

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

# Named after the digest it preserves, not the version installed: a
# per-version name is wrong on redeploy, where an existing file would be kept
# and the real predecessor lost.
live_digest=$(sha256sum < "$live" | cut -d' ' -f1)
backup="$live.pre-${{live_digest:0:12}}.bak"

# Temp file then rename, and recreate unless the existing one already holds
# the right bytes: skipping on path existence alone would accept a partial
# file from an interrupted copy.
if [ ! -f "$backup" ] || [ "$(sha256sum < "$backup" | cut -d' ' -f1)" != "$live_digest" ]; then
  sudo rm -f "$backup.tmp"
  sudo cp "$live" "$backup.tmp"
  sudo mv -f "$backup.tmp" "$backup"
fi

# Only install against a backup proven to hold what it replaces.
backup_digest=$(sha256sum < "$backup" | cut -d' ' -f1)
if [ "$backup_digest" != "$live_digest" ]; then
  echo "backup $backup holds $backup_digest, not the live $live_digest — abort"
  exit 1
fi

# Write alongside and rename: writing to the live path exposes a half-written
# binary to a launching sandbox and fails with ETXTBSY while one is running.
incoming="$live.incoming"
sudo rm -f "$incoming"
sudo install -m 0755 "$staged" "$incoming"
sudo mv -f "$incoming" "$live"

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
    # Lets every cell be checked before any of them is changed, rather than
    # discovering the second cell's state after the first has been mutated.
    ap.add_argument("--preflight-only", action="store_true",
                    help="verify what the hosts are running and exit")
    args = ap.parse_args()

    project = os.environ["GCP_PROJECT"]
    label = os.environ["VMD_LABEL"]
    # Required: cells share a project and a label, so an unset region widens
    # discovery to every cell at once.
    region = os.environ.get("GCP_REGION", "").strip()
    if not region:
        print("GCP_REGION is unset — refusing to deploy without a region", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as workdir:
        target = os.environ.get("TARGET_SHA256", "").strip()
        if target and not HEX64.match(target):
            print(f"TARGET_SHA256 is not a sha256 digest: {target!r}", file=sys.stderr)
            return 1
        binary, digest = fetch_release(args.version, workdir, target)

        instances = list_instances(project, region, label)
        where = f"{project} ({region})"

        if not instances:
            print(f"No instances with label {label} found in {where}", file=sys.stderr)
            return 1
        print(f"Installing {args.version} on {len(instances)} instance(s) in {where}")
        expected = os.environ.get("EXPECTED_CURRENT_SHA256", "").strip()
        if expected and not HEX64.match(expected):
            print(f"EXPECTED_CURRENT_SHA256 is not a sha256 digest: {expected!r}",
                  file=sys.stderr)
            return 1
        if expected:
            preflight(instances, project, expected, digest)
        elif args.preflight_only:
            print("EXPECTED_CURRENT_SHA256 is unset — nothing to preflight against",
                  file=sys.stderr)
            return 1
        if args.preflight_only:
            print("preflight only — nothing installed")
            return 0

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
