#!/bin/sh
set -eu
# Runtime preparation is operator-owned; this does not start or admit the host.
test -s /etc/sandbox/host-identity.json
test -s /etc/sandbox/host-identity.env
mkdir -p /etc/sandbox
touch /etc/sandbox/provisioning-complete
rm -f /etc/sandbox/provisioning-hold
