#!/bin/bash
# Cross-host Tier-3 MIGRATE, validated on one host with full fidelity: an Actor's
# snapshot + mem + /state image are round-tripped through object storage (GCS),
# ALL local copies are evicted (so the restore has zero local cache — the exact
# "different host" condition), then cold-fetched and restored on a fresh
# Firecracker, re-pointing /state to the fetched per-Actor image. The /state data
# must survive the object-store round-trip and cross-host restore.
set +e
RESULT=/tmp/crosshost-result.txt
: > "$RESULT"; log() { echo "$@" >> "$RESULT"; }
BUCKET=gs://rayai-dev-crosshost-state

TAP=tapech0; HOSTIP=172.31.99.13; GUESTIP=172.31.99.14; MASK=255.255.255.252; MAC=06:00:AC:1F:63:0E
S1=/tmp/ch1.sock; S2=/tmp/ch2.sock
ALP=/tmp/alpine-minirootfs-3.20.3-x86_64.tar.gz; FC=/usr/local/bin/firecracker

cleanup() {
  sudo pkill -f "$S1" 2>/dev/null; sudo pkill -f "$S2" 2>/dev/null
  sudo ip link del "$TAP" 2>/dev/null
  sudo rm -f "$S1" "$S2" /tmp/ch-root.ext4 /tmp/ch-placeholder.ext4 /tmp/ch-peractor.ext4 \
    /tmp/ch-snap /tmp/ch-mem /tmp/ch1.log /tmp/ch2.log
  sudo rm -rf /tmp/chroot /tmp/chmarker /tmp/chfetch
  gcloud storage rm --recursive "$BUCKET/migrate" 2>/dev/null
}
trap cleanup EXIT

sudo ip link del "$TAP" 2>/dev/null
sudo ip tuntap add "$TAP" mode tap && sudo ip addr add "$HOSTIP/30" dev "$TAP" && sudo ip link set "$TAP" up

[ -f "$ALP" ] || curl -fsSL -o "$ALP" https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.3-x86_64.tar.gz
sudo rm -rf /tmp/chroot && sudo mkdir -p /tmp/chroot && sudo tar -xzf "$ALP" -C /tmp/chroot
sudo mkdir -p /tmp/chroot/usr/bin
sudo cp /tmp/boxd.linux /tmp/chroot/usr/bin/boxd && sudo chmod 0755 /tmp/chroot/usr/bin/boxd
sudo rm -f /tmp/chroot/sbin/init
sudo tee /tmp/chroot/sbin/init >/dev/null <<EOS
#!/bin/sh
set +e
mkdir -p /proc /sys /dev
mount -t proc proc /proc 2>/dev/null
mount -t devtmpfs dev /dev 2>/dev/null
ip link set eth0 up 2>/dev/null
ip addr add $GUESTIP/30 dev eth0 2>/dev/null
exec /usr/bin/boxd
EOS
sudo chmod 0755 /tmp/chroot/sbin/init
sudo rm -f /tmp/ch-root.ext4 && sudo mke2fs -q -t ext4 -d /tmp/chroot -b 4096 /tmp/ch-root.ext4 300M
mke2fs -F -q -t ext4 /tmp/ch-placeholder.ext4 64M
# Per-Actor /state with durable data — this is what must survive the migrate.
sudo rm -rf /tmp/chmarker && sudo mkdir -p /tmp/chmarker && echo "CROSSHOST-MIGRATE-OK" | sudo tee /tmp/chmarker/marker >/dev/null
sudo rm -f /tmp/ch-peractor.ext4 && sudo mke2fs -q -t ext4 -d /tmp/chmarker -b 4096 /tmp/ch-peractor.ext4 64M
log "host A: built template + per-actor /state image (marker=CROSSHOST-MIGRATE-OK)"

c1() { sudo curl -s --unix-socket "$S1" -X "$1" "http://localhost$2" -H 'Content-Type: application/json' -d "$3"; }
c2() { sudo curl -s --unix-socket "$S2" -X "$1" "http://localhost$2" -H 'Content-Type: application/json' -d "$3"; }

# --- host A: boot template (placeholder /state, unmounted), snapshot ---
sudo rm -f "$S1"; sudo $FC --api-sock "$S1" >/tmp/ch1.log 2>&1 & sleep 1
c1 PUT /boot-source "{\"kernel_image_path\":\"/tmp/fcassets/vmlinux\",\"boot_args\":\"console=ttyS0 reboot=k panic=1 pci=off ip=$GUESTIP::$HOSTIP:$MASK::eth0:off\"}" >/dev/null
c1 PUT /drives/rootfs "{\"drive_id\":\"rootfs\",\"path_on_host\":\"/tmp/ch-root.ext4\",\"is_root_device\":true,\"is_read_only\":false}" >/dev/null
c1 PUT /drives/state "{\"drive_id\":\"state\",\"path_on_host\":\"/tmp/ch-placeholder.ext4\",\"is_root_device\":false,\"is_read_only\":false}" >/dev/null
c1 PUT /network-interfaces/eth0 "{\"iface_id\":\"eth0\",\"host_dev_name\":\"$TAP\",\"guest_mac\":\"$MAC\"}" >/dev/null
c1 PUT /machine-config "{\"vcpu_count\":1,\"mem_size_mib\":256}" >/dev/null
c1 PUT /actions "{\"action_type\":\"InstanceStart\"}" >/dev/null
for i in $(seq 1 25); do curl -s -m2 "http://$GUESTIP:49983/health" >/dev/null 2>&1 && break; sleep 1; done
c1 PATCH /vm '{"state":"Paused"}' >/dev/null
c1 PUT /snapshot/create "{\"snapshot_type\":\"Full\",\"snapshot_path\":\"/tmp/ch-snap\",\"mem_file_path\":\"/tmp/ch-mem\"}" >/dev/null
sudo pkill -f "$S1" 2>/dev/null; sleep 1
log "host A: snapshot taken"

# --- push the per-Actor durable bits to object storage ---
gcloud storage cp /tmp/ch-snap "$BUCKET/migrate/snap" >/dev/null 2>&1
gcloud storage cp /tmp/ch-mem "$BUCKET/migrate/mem" >/dev/null 2>&1
gcloud storage cp /tmp/ch-peractor.ext4 "$BUCKET/migrate/state.ext4" >/dev/null 2>&1
log "pushed snapshot + mem + /state image to object storage"

# --- EVICT all local per-Actor copies: the restoring host has nothing cached ---
sudo rm -f /tmp/ch-snap /tmp/ch-mem /tmp/ch-peractor.ext4
log "evicted local snapshot/mem//state — restoring host has zero local cache"

# --- host B: cold-fetch from object storage, restore, repoint /state, mount ---
sudo rm -rf /tmp/chfetch && mkdir -p /tmp/chfetch
gcloud storage cp "$BUCKET/migrate/snap" /tmp/chfetch/snap >/dev/null 2>&1
gcloud storage cp "$BUCKET/migrate/mem" /tmp/chfetch/mem >/dev/null 2>&1
gcloud storage cp "$BUCKET/migrate/state.ext4" /tmp/chfetch/state.ext4 >/dev/null 2>&1
log "host B: cold-fetched snapshot + mem + /state image from object storage"

sudo rm -f "$S2"; sudo $FC --api-sock "$S2" >/tmp/ch2.log 2>&1 & sleep 1
c2 PUT /snapshot/load "{\"snapshot_path\":\"/tmp/chfetch/snap\",\"mem_backend\":{\"backend_type\":\"File\",\"backend_path\":\"/tmp/chfetch/mem\"},\"resume_vm\":false,\"network_overrides\":[{\"iface_id\":\"eth0\",\"host_dev_name\":\"$TAP\"}]}" >/dev/null
c2 PATCH /drives/state "{\"drive_id\":\"state\",\"path_on_host\":\"/tmp/chfetch/state.ext4\"}" >/dev/null
c2 PATCH /vm '{"state":"Resumed"}' >/dev/null
for i in $(seq 1 25); do curl -s -m2 "http://$GUESTIP:49983/health" >/dev/null 2>&1 && break; sleep 1; done
MOUNT=$(curl -s -m5 -o /dev/null -w "%{http_code}" -X POST "http://$GUESTIP:49983/state/mount?device=/dev/vdb")
log "host B: restored from object storage + re-pointed /state + POST /state/mount → HTTP $MOUNT"

EXEC=$(curl -s -N -m 10 -X POST "http://$GUESTIP:49983/exec/stream" -H 'Content-Type: application/json' \
  -d '{"command":"sh","args":["-c","cat /state/marker 2>&1"]}')
log "host B in-guest cat /state/marker: $EXEC"
if echo "$EXEC" | grep -q "CROSSHOST-MIGRATE-OK"; then
  log "VERDICT: CROSS-HOST /state MIGRATE WORKS — durable state survived the object-store round-trip + cold cross-host restore"
else
  log "VERDICT: migrate incomplete"; sudo tail -8 /tmp/ch2.log >> "$RESULT" 2>/dev/null
fi
sudo pkill -f "$S2" 2>/dev/null
echo DONE
