#!/bin/bash
# Stripe the local NVMe into one XFS volume and expose it under the canonical
# sandbox paths. Runs on every boot: local SSD is blank after an instance stop.
#
# Persistent disks are NVMe namespaces too on this platform, so membership is
# decided by what the device is, not by its name: local SSDs report the bare
# local-SSD model, persistent disks carry a distinct model and a by-id link
# named after their attachment, and anything already holding a filesystem is
# left alone. The same script then fits any local-SSD shape. XFS with reflink
# is required: pause staging clones files, and a filesystem without reflink
# silently turns every pause into a byte copy. The array is bind-mounted, not
# symlinked, onto rundir and snapshots because the firecracker unit hardcodes
# those paths.
set -euo pipefail

BOOT_DEV=$(lsblk -no PKNAME "$(findmnt -no SOURCE /)")
# Persistent disks get an alias named after their attachment; local SSDs on
# some images get a google-local-* alias of their own, which must not count.
declare -A ATTACHED=()
for link in /dev/disk/by-id/google-*; do
  [ -e "$link" ] || continue
  case "$(basename "$link")" in google-local-*) continue ;; esac
  ATTACHED["$(readlink -f "$link")"]=1
done
SSDS=()
while read -r dev model; do
  [ "$model" = "nvme_card" ] || continue
  [ "$dev" != "/dev/$BOOT_DEV" ] || continue
  [ -z "${ATTACHED[$dev]:-}" ] || continue
  sig=$(blkid -o value -s TYPE "$dev" 2>/dev/null || true)
  if [ -n "$sig" ] && [ "$sig" != "linux_raid_member" ]; then
    echo "skipping $dev: carries a $sig filesystem" >&2
    continue
  fi
  SSDS+=("$dev")
done < <(lsblk -dpno NAME,MODEL | grep -E '^/dev/nvme[0-9]+n1 ')
if [ "${#SSDS[@]}" -eq 0 ]; then
  echo "no local SSD found; refusing to continue" >&2
  exit 1
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
