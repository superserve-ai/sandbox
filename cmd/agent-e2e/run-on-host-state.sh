#!/bin/bash
# Durable-/state agent-loop e2e: boots the Actor's microVM with a SECOND drive
# (a pre-formatted ext4 /state image — exactly what LocalBlockProvider produces),
# boxd mounts it at /state, then drives agent turns whose in-guest harness writes
# each event to /state and reads the whole log back. The final turn's reply must
# still contain turn-1's event → /state persisted across turns in the live loop.
set +e
RESULT=/tmp/agent-e2e-state-result.txt
: > "$RESULT"
log() { echo "$@" >> "$RESULT"; }

TAP=tape2es
HOSTIP=172.31.99.5
GUESTIP=172.31.99.6
MASK=255.255.255.252
MAC=06:00:AC:1F:63:06
SOCK=/tmp/agent-state-fc.sock
ALP=/tmp/alpine-minirootfs-3.20.3-x86_64.tar.gz

cleanup() {
  sudo pkill -f "$SOCK" 2>/dev/null
  sudo ip link del "$TAP" 2>/dev/null
  sudo rm -f "$SOCK" /tmp/agent-state-rootfs.ext4 /tmp/agent-state.ext4 /tmp/agent-state-fc.log
  sudo rm -rf /tmp/asroot
}
trap cleanup EXIT

sudo ip link del "$TAP" 2>/dev/null
sudo ip tuntap add "$TAP" mode tap || { log "FAIL: tap add"; echo DONE; exit 1; }
sudo ip addr add "$HOSTIP/30" dev "$TAP"; sudo ip link set "$TAP" up
log "tap $TAP up at $HOSTIP/30"

[ -f "$ALP" ] || curl -fsSL -o "$ALP" https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.3-x86_64.tar.gz
sudo rm -rf /tmp/asroot && sudo mkdir -p /tmp/asroot && sudo tar -xzf "$ALP" -C /tmp/asroot
sudo mkdir -p /tmp/asroot/usr/bin
sudo cp /tmp/boxd.linux /tmp/asroot/usr/bin/boxd && sudo chmod 0755 /tmp/asroot/usr/bin/boxd
sudo rm -f /tmp/asroot/sbin/init
sudo tee /tmp/asroot/sbin/init >/dev/null <<EOS
#!/bin/sh
set +e
mkdir -p /proc /sys /dev
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sys /sys 2>/dev/null
mount -t devtmpfs dev /dev 2>/dev/null
ip link set eth0 up 2>/dev/null
ip addr show eth0 2>/dev/null | grep -q $GUESTIP || ip addr add $GUESTIP/30 dev eth0 2>/dev/null
exec /usr/bin/boxd
EOS
sudo chmod 0755 /tmp/asroot/sbin/init
sudo rm -f /tmp/agent-state-rootfs.ext4
sudo mke2fs -q -t ext4 -d /tmp/asroot -b 4096 /tmp/agent-state-rootfs.ext4 300M

# The durable /state disk — a pre-formatted ext4 image, exactly what
# LocalBlockProvider.Mount creates for an identity (mke2fs -F -q -t ext4).
rm -f /tmp/agent-state.ext4
mke2fs -F -q -t ext4 /tmp/agent-state.ext4 64M
log "rootfs + pre-formatted /state ext4 built"

sudo rm -f "$SOCK"
sudo /usr/local/bin/firecracker --api-sock "$SOCK" > /tmp/agent-state-fc.log 2>&1 &
sleep 1
j() { sudo curl -s --unix-socket "$SOCK" -X "$1" "http://localhost$2" -H 'Content-Type: application/json' -d "$3" >/dev/null; }
j PUT /boot-source "{\"kernel_image_path\":\"/tmp/fcassets/vmlinux\",\"boot_args\":\"console=ttyS0 reboot=k panic=1 pci=off ip=$GUESTIP::$HOSTIP:$MASK::eth0:off\"}"
j PUT /drives/rootfs "{\"drive_id\":\"rootfs\",\"path_on_host\":\"/tmp/agent-state-rootfs.ext4\",\"is_root_device\":true,\"is_read_only\":false}"
j PUT /drives/state "{\"drive_id\":\"state\",\"path_on_host\":\"/tmp/agent-state.ext4\",\"is_root_device\":false,\"is_read_only\":false}"
j PUT /network-interfaces/eth0 "{\"iface_id\":\"eth0\",\"host_dev_name\":\"$TAP\",\"guest_mac\":\"$MAC\"}"
j PUT /machine-config "{\"vcpu_count\":1,\"mem_size_mib\":256}"
j PUT /actions "{\"action_type\":\"InstanceStart\"}"

UP=0
for i in $(seq 1 30); do curl -s -m 2 "http://$GUESTIP:49983/health" >/dev/null 2>&1 && { UP=1; break; }; sleep 1; done
if [ "$UP" != 1 ]; then log "FAIL: boxd unreachable"; sudo tail -15 /tmp/agent-state-fc.log >> "$RESULT"; echo DONE; exit 1; fi
log "microVM up; boxd reachable; /state drive attached (vdb)"

# Confirm boxd mounted /state, then drive turns that persist to it.
log "boxd /state mount log: $(sudo grep -h 'state:' /tmp/agent-state-fc.log | head -1)"
log "=== agent-e2e (durable /state across turns) ==="
chmod +x /tmp/agent-e2e.linux
/tmp/agent-e2e.linux -boxd-url "http://$GUESTIP:49983/exec/stream" -turns 3 \
  -turn-cmd 'printf "%s\n" "$ACTOR_EVENT" >> /state/agentlog; printf "STATELOG[%s]" "$(tr "\n" "," < /state/agentlog)"' \
  -final-must-contain 'event-1' >> "$RESULT" 2>&1
log "(agent-e2e exit=$?)"
echo DONE
