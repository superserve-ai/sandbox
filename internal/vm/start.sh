#!/bin/sh
exec ip netns exec  unshare -m -- sh -c 'mount --make-rprivate / && mount -t tmpfs tmpfs '\''template'\'' && ln -s '\'''\'' '\''template/rootfs.ext4'\'' && exec '\'''\'' --api-sock '\'''\'' --id '\''vm-1'\'''
