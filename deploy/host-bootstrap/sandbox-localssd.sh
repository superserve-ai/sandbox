#!/bin/bash
# Stripe the local NVMe into one XFS volume and expose it under the canonical
# sandbox paths. Runs on every boot: local SSD is blank after an instance stop.
#
# Every NVMe namespace except the one holding the root filesystem joins the
# array, so the same script fits any local-SSD shape. XFS with reflink is
# required: pause staging clones files, and a filesystem without reflink
# silently turns every pause into a byte copy. The array is bind-mounted, not
# symlinked, onto rundir and snapshots because the firecracker unit hardcodes
# those paths.
set -euo pipefail

BOOT_DEV=$(lsblk -no PKNAME "$(findmnt -no SOURCE /)")
mapfile -t SSDS < <(lsblk -dpno NAME | grep -E '^/dev/nvme[0-9]+n1$' | grep -vx "/dev/$BOOT_DEV" || true)
if [ "${#SSDS[@]}" -eq 0 ]; then
  echo "no local NVMe present; nothing to mount"
  exit 0
fi

# A surviving array may already be assembled under an automatic name.
MD=$(lsblk -no NAME,TYPE "${SSDS[0]}" | awk '$2 ~ /^raid/ {print "/dev/"$1; exit}')
if [ -z "$MD" ]; then
  MD=/dev/md0
  if mdadm --examine "${SSDS[0]}" >/dev/null 2>&1; then
    mdadm --assemble "$MD" "${SSDS[@]}"
  else
    mdadm --create "$MD" --run --level=0 --raid-devices="${#SSDS[@]}" "${SSDS[@]}"
  fi
fi

if [ "$(blkid -o value -s TYPE "$MD" 2>/dev/null || true)" != "xfs" ]; then
  mkfs.xfs -f -b size=4096 -m reflink=1 "$MD"
fi
xfs_info "$MD" | grep -q 'reflink=1'

mkdir -p /mnt/localssd
mountpoint -q /mnt/localssd || mount -o noatime,discard "$MD" /mnt/localssd
for d in rundir snapshots; do
  mkdir -p "/mnt/localssd/$d" "/var/lib/sandbox/$d"
  mountpoint -q "/var/lib/sandbox/$d" || mount --bind "/mnt/localssd/$d" "/var/lib/sandbox/$d"
done
