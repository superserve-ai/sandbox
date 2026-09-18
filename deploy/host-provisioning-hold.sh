#!/bin/sh
set -eu
mkdir -p /etc/sandbox
# Creation metadata persists after explicit runtime initialization.
if [ ! -f /etc/sandbox/provisioning-complete ]; then
  touch /etc/sandbox/provisioning-hold
  for unit in superserve-vmd.service superserve-vmd.socket; do
    mkdir -p "/etc/systemd/system/$unit.d"
    printf '[Unit]\nConditionPathExists=!/etc/sandbox/provisioning-hold\n' > "/etc/systemd/system/$unit.d/05-provisioning-hold.conf"
  done
  systemctl daemon-reload
  systemctl stop superserve-vmd.socket superserve-vmd.service || true
fi
