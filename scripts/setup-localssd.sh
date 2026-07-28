#!/bin/sh
# Boot-time local-SSD setup: RAID0 the local NVMe SSDs, mount them, and
# bind-mount rundir/snapshots onto the canonical /var/lib/sandbox paths that
# vmd and the firecracker@ units use. No-op on hosts without local SSD. Local
# SSD is wiped on stop/start, so this runs on every boot to rebuild it.
set -eu

MNT=/mnt/localssd
CANON_RUNDIR=/var/lib/sandbox/rundir
CANON_SNAPS=/var/lib/sandbox/snapshots

root_src=$(findmnt -no SOURCE / 2>/dev/null || true)
boot_dev=$(lsblk -no PKNAME "$root_src" 2>/dev/null | head -1 || true)
local_ssds=$(lsblk -dpno NAME | grep -E '^/dev/nvme[0-9]+n1$' | grep -vx "/dev/$boot_dev" || true)
n=$(printf '%s\n' "$local_ssds" | grep -c . || true)

if [ "${n:-0}" -eq 0 ]; then
    echo "setup-localssd: no local SSD detected; nothing to do."
    exit 0
fi

if mountpoint -q "$MNT" && mountpoint -q "$CANON_RUNDIR" && mountpoint -q "$CANON_SNAPS"; then
    echo "setup-localssd: already set up; nothing to do."
    exit 0
fi

[ -e /dev/md0 ] || mdadm --create /dev/md0 --level=0 --raid-devices="$n" $local_ssds --run
blkid /dev/md0 >/dev/null 2>&1 || mkfs.xfs -f -b size=4096 /dev/md0

mkdir -p "$MNT"
mountpoint -q "$MNT" || mount -o noatime,discard /dev/md0 "$MNT"
mkdir -p "$MNT/rundir" "$MNT/snapshots" "$CANON_RUNDIR" "$CANON_SNAPS"
mountpoint -q "$CANON_RUNDIR" || mount --bind "$MNT/rundir" "$CANON_RUNDIR"
mountpoint -q "$CANON_SNAPS"  || mount --bind "$MNT/snapshots" "$CANON_SNAPS"
echo "setup-localssd: done."
