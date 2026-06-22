#!/bin/bash
# Isolated full-stack agent-loop e2e on the KVM host. Sets up a dedicated TAP
# (172.31.99.0/30 — does NOT collide with vmd's 10.11/10.12), boots ONE networked
# Firecracker microVM running boxd, then drives the real Actor runtime
# (agent-e2e) against it over /exec/stream. Tears everything down at the end.
set +e
RESULT=/tmp/agent-e2e-result.txt
: > "$RESULT"
log() { echo "$@" >> "$RESULT"; }

TAP=tape2e0
HOSTIP=172.31.99.1
GUESTIP=172.31.99.2
MASK=255.255.255.252
MAC=06:00:AC:1F:63:02
ALP=/tmp/alpine-minirootfs-3.20.3-x86_64.tar.gz

cleanup() {
  sudo pkill -f /tmp/agent-fc.sock 2>/dev/null
  sudo ip link del "$TAP" 2>/dev/null
  sudo rm -f /tmp/agent-fc.sock /tmp/agent-rootfs.ext4 /tmp/agent-fc.log
  sudo rm -rf /tmp/aroot
}
trap cleanup EXIT

# 1) Dedicated TAP, isolated subnet.
sudo ip link del "$TAP" 2>/dev/null
sudo ip tuntap add "$TAP" mode tap || { log "FAIL: tap add"; exit 1; }
sudo ip addr add "$HOSTIP/30" dev "$TAP"
sudo ip link set "$TAP" up
log "tap $TAP up at $HOSTIP/30"

# 2) Build an alpine rootfs that runs boxd as init with eth0 configured.
[ -f "$ALP" ] || curl -fsSL -o "$ALP" https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.3-x86_64.tar.gz
sudo rm -rf /tmp/aroot && sudo mkdir -p /tmp/aroot && sudo tar -xzf "$ALP" -C /tmp/aroot
sudo mkdir -p /tmp/aroot/usr/bin
sudo cp /tmp/boxd.linux /tmp/aroot/usr/bin/boxd && sudo chmod 0755 /tmp/aroot/usr/bin/boxd
sudo rm -f /tmp/aroot/sbin/init
sudo tee /tmp/aroot/sbin/init >/dev/null <<EOS
#!/bin/sh
set +e
mkdir -p /proc /sys /dev
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sys /sys 2>/dev/null
mount -t devtmpfs dev /dev 2>/dev/null
# Bring up eth0 (belt-and-suspenders; kernel ip= may have already done it).
ip link set eth0 up 2>/dev/null
ip addr show eth0 2>/dev/null | grep -q $GUESTIP || ip addr add $GUESTIP/30 dev eth0 2>/dev/null
exec /usr/bin/boxd
EOS
sudo chmod 0755 /tmp/aroot/sbin/init
sudo rm -f /tmp/agent-rootfs.ext4
sudo mke2fs -q -t ext4 -d /tmp/aroot -b 4096 /tmp/agent-rootfs.ext4 300M
log "rootfs built (alpine + boxd init, eth0=$GUESTIP)"

# 3) Boot the networked microVM.
SOCK=/tmp/agent-fc.sock; sudo rm -f "$SOCK"
sudo /usr/local/bin/firecracker --api-sock "$SOCK" > /tmp/agent-fc.log 2>&1 &
sleep 1
j() { sudo curl -s --unix-socket "$SOCK" -X "$1" "http://localhost$2" -H 'Content-Type: application/json' -d "$3" >/dev/null; }
j PUT /boot-source "{\"kernel_image_path\":\"/tmp/fcassets/vmlinux\",\"boot_args\":\"console=ttyS0 reboot=k panic=1 pci=off ip=$GUESTIP::$HOSTIP:$MASK::eth0:off\"}"
j PUT /drives/rootfs "{\"drive_id\":\"rootfs\",\"path_on_host\":\"/tmp/agent-rootfs.ext4\",\"is_root_device\":true,\"is_read_only\":false}"
j PUT /network-interfaces/eth0 "{\"iface_id\":\"eth0\",\"host_dev_name\":\"$TAP\",\"guest_mac\":\"$MAC\"}"
j PUT /machine-config "{\"vcpu_count\":1,\"mem_size_mib\":256}"
j PUT /actions "{\"action_type\":\"InstanceStart\"}"
log "microVM started; waiting for boxd at $GUESTIP:49983"

# 4) Wait for boxd health over the TAP.
UP=0
for i in $(seq 1 30); do
  if curl -s -m 2 "http://$GUESTIP:49983/health" >/dev/null 2>&1; then UP=1; break; fi
  sleep 1
done
if [ "$UP" != 1 ]; then
  log "FAIL: boxd never became reachable at $GUESTIP:49983"
  log "--- guest console tail ---"; sudo tail -15 /tmp/agent-fc.log >> "$RESULT" 2>/dev/null
  echo DONE; exit 1
fi
log "boxd reachable; health OK"

# 5) Drive the real Actor agent loop against it.
log "=== agent-e2e ==="
chmod +x /tmp/agent-e2e.linux
/tmp/agent-e2e.linux -boxd-url "http://$GUESTIP:49983/exec/stream" -turns 3 >> "$RESULT" 2>&1
log "(agent-e2e exit=$?)"
echo DONE
