#!/usr/bin/env bash
# One-time per-host migration from the legacy socket-activated vmd to the
# blue-green gateway topology. Run once per host, supervised. Afterwards every
# deploy is a generation handoff (deploy/vmd_handoff.py <version>), and the
# legacy vmd unit is fenced off by /etc/sandbox/gateway-topology.
#
# Prerequisites on the host: /usr/local/bin/vmd-gateway and the initial
# versioned binary /usr/local/bin/vmd-<version> installed, /etc/sandbox/vmd.env
# present, and the local-SSD/rundir layout already provisioned (this only swaps
# the serving topology, not host provisioning). Run from the repo's deploy/ dir.
set -euo pipefail

VERSION="${1:?usage: vmd-gateway-bootstrap.sh <initial-generation-version>}"
BIN=/usr/local/bin
UNITS=/etc/systemd/system

require() { [ -x "$1" ] || { echo "missing required binary: $1" >&2; exit 1; }; }
require "$BIN/vmd-gateway"
require "$BIN/vmd-$VERSION"
[ -f /etc/sandbox/vmd.env ] || { echo "missing /etc/sandbox/vmd.env" >&2; exit 1; }

echo "== installing units =="
install -m0644 superserve-vmd-gateway.service "$UNITS/superserve-vmd-gateway.service"
install -m0644 superserve-vmd@.service "$UNITS/superserve-vmd@.service"
install -d "$UNITS/superserve-vmd.service.d"
install -m0644 superserve-vmd-legacy-guard.conf "$UNITS/superserve-vmd.service.d/30-legacy-guard.conf"
systemctl daemon-reload

echo "== stopping the legacy socket-activated vmd =="
# Free the public ports for the gateway. Existing VMs run under sandboxes.slice
# and survive this stop; paused snapshots are on disk.
systemctl disable --now superserve-vmd.socket 2>/dev/null || true
systemctl stop superserve-vmd.service 2>/dev/null || true

echo "== fencing the legacy unit =="
install -d /etc/sandbox
touch /etc/sandbox/gateway-topology

echo "== starting the gateway =="
systemctl enable --now superserve-vmd-gateway.service

echo "== activating the initial generation ($VERSION) via a handoff =="
# The gateway's controller starts the generation, waits for preflight, acquires
# the lease, and switches routing to it.
python3 vmd_handoff.py "$VERSION"

echo "== bootstrap complete: gateway topology active, generation $VERSION serving =="
