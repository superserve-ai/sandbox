#!/usr/bin/env bash
# One-time per-host migration to the blue-green gateway topology. The normal
# deploy already installs (inertly) the gateway binary, the version-tagged vmd
# binaries, the units, and the legacy guard; this activates them once,
# supervised. Afterwards deploys are handoffs (vmd-handoff <version>) and the
# legacy vmd unit is fenced by /etc/sandbox/gateway-topology.
#
# <version> is the deploy sha of the generation to bring up first — the binary
# installed at /usr/local/bin/vmd-<version>.
#
# On ANY failure the host is rolled back to the legacy topology, so it is never
# left with the legacy unit fenced and no generation serving.
set -euo pipefail

VERSION="${1:?usage: vmd-gateway-bootstrap <initial-generation-version>}"
BIN=/usr/local/bin

require() { [ -x "$1" ] || { echo "missing $1 — run a normal deploy first" >&2; exit 1; }; }
require "$BIN/vmd-gateway"
require "$BIN/vmd-$VERSION"
require "$BIN/vmd-handoff"
[ -f /etc/systemd/system/superserve-vmd-gateway.service ] || { echo "gateway unit not installed — deploy first" >&2; exit 1; }
[ -f /etc/sandbox/vmd.env ] || { echo "missing /etc/sandbox/vmd.env" >&2; exit 1; }

# Roll back to the legacy topology on any failure: unfence, stop the gateway
# (freeing the ports), and bring the legacy service back. Stop the gateway
# BEFORE starting legacy so the port is free.
restore_legacy() {
	echo "== bootstrap failed — restoring legacy topology ==" >&2
	rm -f /etc/sandbox/gateway-topology
	systemctl stop superserve-vmd-gateway.service 2>/dev/null || true
	systemctl enable --now superserve-vmd.socket 2>/dev/null || true
	systemctl start superserve-vmd.service 2>/dev/null || true
}
trap restore_legacy ERR

systemctl daemon-reload

echo "== stopping the legacy socket-activated vmd (VMs survive: they run under sandboxes.slice) =="
systemctl disable --now superserve-vmd.socket 2>/dev/null || true
systemctl stop superserve-vmd.service 2>/dev/null || true

echo "== starting the gateway =="
systemctl enable --now superserve-vmd-gateway.service

echo "== activating the initial generation ($VERSION) via a handoff =="
"$BIN/vmd-handoff" "$VERSION"

# Only now that a generation is confirmed serving do we fence the legacy unit —
# the irreversible step happens last, after the risky ones have succeeded.
echo "== fencing the legacy unit =="
install -d /etc/sandbox
touch /etc/sandbox/gateway-topology

trap - ERR
echo "== bootstrap complete: gateway topology active, generation $VERSION serving =="
