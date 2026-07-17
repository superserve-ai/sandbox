#!/usr/bin/env bash
# Prepare the persistent XFS data disk used by VMD's mutable runtime and
# snapshot trees. The canonical /var/lib/sandbox paths remain unchanged: two
# subdirectories from the XFS disk are bind-mounted over rundir and snapshots.
#
# The first run performs an atomic, one-time migration. It refuses to proceed
# while any Firecracker unit is active and stops VMD/socket activation while
# the copy and bind switch occur. Pre-commit failures restore the prior state;
# post-commit failures keep the VMD control plane stopped for safe recovery.
set -euo pipefail

readonly CONFIG_FILE=/etc/sandbox/data-disk.env
readonly MOUNT_ROOT=/mnt/sandbox-data
readonly DATA_ROOT="${MOUNT_ROOT}/data-v1"
readonly MIGRATION_MARKER="${DATA_ROOT}/.migration-complete"
readonly ACTIVATION_MARKER="${DATA_ROOT}/.activation-complete"
readonly AUTHORITY_MARKER=/etc/sandbox/data-disk-authoritative
readonly CANON_RUNDIR=/var/lib/sandbox/rundir
readonly CANON_SNAPSHOTS=/var/lib/sandbox/snapshots
readonly VMD_SERVICE=superserve-vmd.service
readonly VMD_SOCKET=superserve-vmd.socket
readonly DEVICE_WAIT_SECONDS=600

log() {
  printf 'setup-sandbox-data-disk: %s\n' "$*"
}

fail() {
  log "ERROR: $*" >&2
  if [[ "${data_authoritative:-0}" == "1" ]]; then
    log "ERROR: XFS data is authoritative; stopping the VMD control plane fail closed" >&2
    stop_vmd_control_plane_fail_closed
  fi
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command is missing: $1"
}

read_config_device() {
  local file_value="" file_count=0 direct_value="${SANDBOX_DATA_DISK_DEVICE:-}"

  if [[ -f "$CONFIG_FILE" ]]; then
    file_count="$(awk '
      /^[[:space:]]*(#|$)/ { next }
      index($0, "SANDBOX_DATA_DISK_DEVICE=") == 1 { count++; next }
      { invalid++ }
      END {
        if (invalid > 0) exit 2
        print count + 0
      }
    ' "$CONFIG_FILE")" || fail "$CONFIG_FILE may contain only SANDBOX_DATA_DISK_DEVICE plus comments/blank lines"
    [[ "$file_count" == "0" || "$file_count" == "1" ]] || fail "$CONFIG_FILE must contain exactly one SANDBOX_DATA_DISK_DEVICE assignment"
    if [[ "$file_count" == "1" ]]; then
      file_value="$(sed -n 's/^SANDBOX_DATA_DISK_DEVICE=//p' "$CONFIG_FILE")"
    fi
  fi

  if [[ -n "$direct_value" && -n "$file_value" && "$direct_value" != "$file_value" ]]; then
    fail "SANDBOX_DATA_DISK_DEVICE conflicts with $CONFIG_FILE"
  fi

  printf '%s' "${direct_value:-$file_value}"
}

active_firecracker_units() {
  systemctl list-units \
    --type=service \
    --state=active,activating,deactivating,reloading \
    --no-legend \
    --plain \
    'firecracker@*.service' 2>/dev/null | awk '{print $1}'
}

stop_vmd_control_plane_fail_closed() {
  # Stop the listeners first so no new VM lifecycle work can enter while the
  # host's authoritative storage is unavailable or inconsistent. Existing
  # Firecracker processes intentionally survive VMD restarts; preserving them
  # avoids turning a verifier/configuration failure into guest disk corruption.
  systemctl stop "$VMD_SOCKET" "$VMD_SERVICE" >/dev/null 2>&1 || true
}

unit_active_state() {
  systemctl show --property=ActiveState --value "$1" 2>/dev/null || printf 'unknown\n'
}

unit_should_restore() {
  case "$(unit_active_state "$1")" in
    active|activating|reloading) return 0 ;;
    *) return 1 ;;
  esac
}

unit_is_quiescent() {
  case "$(unit_active_state "$1")" in
    inactive|failed) return 0 ;;
    *) return 1 ;;
  esac
}

path_identity() {
  stat -Lc '%d:%i' "$1"
}

mount_device_id() {
  findmnt -n -T "$1" -o MAJ:MIN
}

mount_fstype() {
  findmnt -n -T "$1" -o FSTYPE
}

verify_bind_mount() {
  local canonical="$1" intended="$2" data_device_id="$3"
  mountpoint -q "$canonical" || return 1
  [[ "$(path_identity "$canonical")" == "$(path_identity "$intended")" ]] || return 1
  [[ "$(mount_fstype "$canonical")" == "xfs" ]] || return 1
  [[ "$(mount_device_id "$canonical")" == "$data_device_id" ]] || return 1
}

inventory_tree() {
  local root="$1" output="$2"
  (
    cd "$root"
    find . -xdev \
      \( -type f -printf 'f\0%P\0%m\0%U\0%G\0%s\0' \
      -o -type d -printf 'd\0%P\0%m\0%U\0%G\0' \
      -o -type l -printf 'l\0%P\0%U\0%G\0%l\0' \
      -o -printf 'o\0%P\0%y\0%m\0%U\0%G\0' \) |
      LC_ALL=C sort -z
  ) >"$output"
}

trees_match() {
  local source="$1" destination="$2" source_inventory destination_inventory
  local regular_files relative rc=0

  source_inventory="$(mktemp)" || return 1
  destination_inventory="$(mktemp)" || {
    rm -f -- "$source_inventory"
    return 1
  }
  regular_files="$(mktemp)" || {
    rm -f -- "$source_inventory" "$destination_inventory"
    return 1
  }

  inventory_tree "$source" "$source_inventory" || rc=1
  (( rc != 0 )) || inventory_tree "$destination" "$destination_inventory" || rc=1
  if (( rc != 0 )); then
    rm -f -- "$source_inventory" "$destination_inventory" "$regular_files"
    return 1
  fi
  if ! cmp -s "$source_inventory" "$destination_inventory"; then
    rm -f -- "$source_inventory" "$destination_inventory" "$regular_files"
    return 1
  fi
  rm -f -- "$source_inventory" "$destination_inventory"

  (cd "$source" && find . -xdev -type f -print0 >"$regular_files") || {
    rm -f -- "$regular_files"
    return 1
  }
  while IFS= read -r -d '' relative; do
    relative="${relative#./}"
    if ! cmp -s -- "$source/$relative" "$destination/$relative"; then
      rc=1
      break
    fi
  done <"$regular_files"
  rm -f -- "$regular_files"
  return "$rc"
}

verify_reflinks() {
  local run_dir="$1" snapshot_dir="$2" run_probe snapshot_probe_dir rc=0
  run_probe="$(mktemp "$run_dir/.reflink-probe.XXXXXX")" || return 1
  snapshot_probe_dir="$(mktemp -d "$snapshot_dir/.reflink-probe.XXXXXX")" || {
    rm -f -- "$run_probe"
    return 1
  }
  printf '%s\n' superserve-sandbox-data-reflink-probe >"$run_probe" || rc=1

  if (( rc == 0 )); then
    cp --reflink=always --sparse=always -- "$run_probe" "$snapshot_probe_dir/from-rundir" || rc=$?
  fi
  if (( rc == 0 )); then
    cp --reflink=always --sparse=always -- "$snapshot_probe_dir/from-rundir" "$snapshot_probe_dir/within-snapshots" || rc=$?
  fi
  if (( rc == 0 )); then
    cmp -s "$run_probe" "$snapshot_probe_dir/from-rundir" || rc=$?
    cmp -s "$run_probe" "$snapshot_probe_dir/within-snapshots" || rc=$?
  fi
  rm -f -- "$run_probe"
  rm -rf -- "$snapshot_probe_dir"
  return "$rc"
}

install_fail_closed_dependencies() {
  local target tmp
  for target in \
    /etc/systemd/system/superserve-vmd.service.d/sandbox-data-disk.conf \
    /etc/systemd/system/superserve-vmd.socket.d/sandbox-data-disk.conf \
    /etc/systemd/system/firecracker@.service.d/sandbox-data-disk.conf; do
    install -d -m 0755 "$(dirname "$target")"
    tmp="$(mktemp "${target}.XXXXXX")"
    printf '%s\n' \
      '[Unit]' \
      'Requires=sandbox-data-disk.service' \
      'After=sandbox-data-disk.service' >"$tmp"
    chmod 0644 "$tmp"
    if [[ -f "$target" ]] && cmp -s "$tmp" "$target"; then
      rm -f -- "$tmp"
    else
      mv -f -- "$tmp" "$target"
    fi
  done
  # The dependency files must reach stable storage before XFS can become the
  # authoritative copy. After a crash, systemd must never start VMD without
  # first running this data-disk unit.
  sync
  systemctl daemon-reload
}

write_authority_marker() {
  local tmp

  install -d -m 0755 "$(dirname "$AUTHORITY_MARKER")"
  if [[ -f "$AUTHORITY_MARKER" ]] && grep -qxF 'data-v1' "$AUTHORITY_MARKER"; then
    return 0
  fi

  tmp="$(mktemp "${AUTHORITY_MARKER}.XXXXXX")" || return 1
  if ! printf '%s\n' data-v1 >"$tmp"; then
    rm -f -- "$tmp"
    return 1
  fi
  chmod 0644 "$tmp" || {
    rm -f -- "$tmp"
    return 1
  }
  mv -f -- "$tmp" "$AUTHORITY_MARKER" || {
    rm -f -- "$tmp"
    return 1
  }
  sync
}

main() {
  local configured_device resolved_device root_source root_parent root_disk
  local block_type child_count signatures fs_type mounted_targets
  local device_id mount_id canonical_parent_id
  local active_units vmd_was_active=0 socket_was_active=0
  local migration_tmp=""
  local created_rundir_bind=0 created_snapshots_bind=0
  local data_authoritative=0 verify_only=0 run_dir snapshot_dir

  cleanup() {
    local rc=$? restore_failed=0
    trap - EXIT RETURN INT TERM
    set +e

    if [[ -n "$migration_tmp" && -d "$migration_tmp" ]]; then
      rm -rf -- "$migration_tmp"
    fi

    if (( rc != 0 && data_authoritative == 0 )); then
      (( created_snapshots_bind == 1 )) && umount "$CANON_SNAPSHOTS"
      (( created_rundir_bind == 1 )) && umount "$CANON_RUNDIR"
    fi

    if (( rc == 0 || data_authoritative == 0 )); then
      if (( socket_was_active == 1 )); then
        systemctl start --no-block "$VMD_SOCKET" || restore_failed=1
      fi
      if (( vmd_was_active == 1 )); then
        systemctl start --no-block "$VMD_SERVICE" || restore_failed=1
      fi
    else
      stop_vmd_control_plane_fail_closed
      log "ERROR: XFS data is authoritative after commit; leaving the VMD control plane stopped for fail-closed recovery" >&2
    fi
    (( rc != 0 || restore_failed == 0 )) || rc=1
    exit "$rc"
  }

  if [[ "${1:-}" == "--verify-only" ]]; then
    verify_only=1
    # Verification is used only after the storage unit has previously
    # succeeded. Any failed check must therefore stop runtime consumers.
    data_authoritative=1
    shift
  fi
  [[ $# -eq 0 ]] || fail "usage: $0 [--verify-only]"

  [[ "$EUID" -eq 0 ]] || fail "must run as root"

  for command in awk blkid chmod cmp cp dirname find findmnt flock grep install lsblk mkdir mkfs.xfs mktemp mount mountpoint mv pgrep readlink rm sed seq sleep sort stat sync systemctl umount wipefs xfs_info; do
    require_command "$command"
  done

  # RETURN handles successful/explicit returns while main's locals are still
  # in scope; EXIT handles `exit`/errexit paths from inside main.
  trap cleanup EXIT RETURN
  trap 'exit 130' INT
  trap 'exit 143' TERM

  install -d -m 0755 /run/lock
  exec 9>/run/lock/sandbox-data-disk.lock
  flock -n 9 || fail "another data-disk setup is already running"

  if [[ -e "$AUTHORITY_MARKER" || -L "$AUTHORITY_MARKER" ]]; then
    data_authoritative=1
    [[ -f "$AUTHORITY_MARKER" && ! -L "$AUTHORITY_MARKER" ]] ||
      fail "$AUTHORITY_MARKER must be a regular file"
    grep -qxF 'data-v1' "$AUTHORITY_MARKER" ||
      fail "$AUTHORITY_MARKER has unexpected contents"
  fi

  configured_device="$(read_config_device)"
  [[ -n "$configured_device" ]] || fail "SANDBOX_DATA_DISK_DEVICE is not configured"
  [[ "$configured_device" =~ ^/dev/disk/by-id/google-[A-Za-z0-9._-]+$ ]] ||
    fail "device must be a stable Google by-id path, got: $configured_device"
  # On a main-branch rollout the VMD and Terraform workflows start in
  # parallel. Give Terraform enough time to create and attach the first disk;
  # later deploys return immediately because the stable by-id path exists.
  for attempt in $(seq 1 "$DEVICE_WAIT_SECONDS"); do
    [[ -e "$configured_device" ]] && break
    sleep 1
  done
  [[ -e "$configured_device" ]] || fail "configured device did not appear within ${DEVICE_WAIT_SECONDS} seconds: $configured_device"

  [[ -f /etc/sandbox/vmd.env ]] || fail "/etc/sandbox/vmd.env is missing"
  run_dir="$(awk -F= '$1 == "RUN_DIR" {value = substr($0, index($0, "=") + 1)} END {print value}' /etc/sandbox/vmd.env | sed -e 's/^"//; s/"$//' -e "s/^'//; s/'$//")"
  snapshot_dir="$(awk -F= '$1 == "SNAPSHOT_DIR" {value = substr($0, index($0, "=") + 1)} END {print value}' /etc/sandbox/vmd.env | sed -e 's/^"//; s/"$//' -e "s/^'//; s/'$//")"
  run_dir="${run_dir:-$CANON_RUNDIR}"
  snapshot_dir="${snapshot_dir:-$CANON_SNAPSHOTS}"
  [[ "$run_dir" == "$CANON_RUNDIR" ]] || fail "RUN_DIR must remain $CANON_RUNDIR, got: $run_dir"
  [[ "$snapshot_dir" == "$CANON_SNAPSHOTS" ]] || fail "SNAPSHOT_DIR must remain $CANON_SNAPSHOTS, got: $snapshot_dir"

  resolved_device="$(readlink -f -- "$configured_device")"
  [[ -b "$resolved_device" ]] || fail "configured path is not a block device: $configured_device"
  block_type="$(lsblk -dn -o TYPE -- "$resolved_device" | awk 'NF {print; exit}')"
  [[ "$block_type" == "disk" ]] || fail "configured device must be a whole disk, got TYPE=$block_type"
  child_count="$(lsblk -nr -o NAME -- "$resolved_device" | awk 'END {print NR + 0}')"
  [[ "$child_count" == "1" ]] || fail "configured device has partitions or child mappings; refusing to format/mount"

  root_source="$(findmnt -n -T / -o SOURCE)"
  root_parent="$(lsblk -no PKNAME -- "$root_source" 2>/dev/null | awk 'NF {print; exit}')"
  if [[ -n "$root_parent" ]]; then
    root_disk="$(readlink -f -- "/dev/$root_parent")"
  else
    root_disk="$(readlink -f -- "$root_source")"
  fi
  [[ "$resolved_device" != "$root_disk" ]] || fail "configured data device resolves to the root disk"

  if (( verify_only == 1 )) && ! mountpoint -q "$MOUNT_ROOT"; then
    fail "verify-only mode requires an existing $MOUNT_ROOT mount"
  fi

  if ! mountpoint -q "$MOUNT_ROOT"; then
    active_units="$(active_firecracker_units)"
    if [[ -n "$active_units" ]] || pgrep -x firecracker >/dev/null 2>&1; then
      fail "the data disk is not mounted and Firecracker is running; drain the host before setup${active_units:+: $active_units}"
    fi
  fi

  mkdir -p "$MOUNT_ROOT" "$CANON_RUNDIR" "$CANON_SNAPSHOTS"

  if mountpoint -q "$MOUNT_ROOT"; then
    mount_id="$(mount_device_id "$MOUNT_ROOT")"
    device_id="$(lsblk -dn -o MAJ:MIN -- "$resolved_device" | awk 'NF {print; exit}')"
    [[ "$mount_id" == "$device_id" ]] || fail "$MOUNT_ROOT is mounted from an unexpected device"
    [[ "$(mount_fstype "$MOUNT_ROOT")" == "xfs" ]] || fail "$MOUNT_ROOT is not XFS"
  else
    mounted_targets="$(findmnt -rn -S "$resolved_device" -o TARGET 2>/dev/null || true)"
    [[ -z "$mounted_targets" ]] || fail "configured device is already mounted elsewhere: $mounted_targets"

    signatures="$(wipefs --noheadings --output TYPE -- "$resolved_device" 2>/dev/null | awk 'NF {print}')"
    fs_type="$(blkid -s TYPE -o value -- "$resolved_device" 2>/dev/null || true)"
    if [[ -z "$fs_type" ]]; then
      [[ -z "$signatures" ]] || fail "blank-filesystem check found existing signatures: $signatures"
      log "formatting blank data disk $configured_device as reflink-capable XFS"
      mkfs.xfs -m crc=1,reflink=1 -- "$resolved_device"
    else
      [[ "$fs_type" == "xfs" ]] || fail "configured device already contains unsupported filesystem: $fs_type"
      [[ "$(printf '%s\n' "$signatures" | awk 'NF {count++} END {print count + 0}')" == "1" ]] ||
        fail "configured XFS device has multiple filesystem/partition signatures"
    fi

    mount -t xfs -o noatime,discard -- "$resolved_device" "$MOUNT_ROOT"
  fi

  xfs_info "$MOUNT_ROOT" | grep -Eq '(^|[[:space:]])reflink=1([[:space:]]|$)' ||
    fail "$MOUNT_ROOT is XFS but reflink support is not enabled"
  device_id="$(lsblk -dn -o MAJ:MIN -- "$resolved_device" | awk 'NF {print; exit}')"
  [[ -n "$device_id" && "$(mount_device_id "$MOUNT_ROOT")" == "$device_id" ]] ||
    fail "mounted data filesystem does not match the configured device"

  canonical_parent_id="$(mount_device_id /var/lib/sandbox)"
  [[ "$canonical_parent_id" != "$device_id" ]] ||
    fail "the data disk must not cover all of /var/lib/sandbox"

  if [[ -d "$DATA_ROOT" ]]; then
    # A committed tree is authoritative even when activation did not finish.
    # Mark that before any later validation can fail so cleanup never falls
    # back to a divergent ext4 tree.
    data_authoritative=1
    [[ -f "$MIGRATION_MARKER" && -d "$DATA_ROOT/rundir" && -d "$DATA_ROOT/snapshots" ]] ||
      fail "$DATA_ROOT exists without a complete migration marker and directory pair"
    install_fail_closed_dependencies
    write_authority_marker || fail "could not persist $AUTHORITY_MARKER"
    if [[ -f "$ACTIVATION_MARKER" ]] &&
      verify_bind_mount "$CANON_RUNDIR" "$DATA_ROOT/rundir" "$device_id" &&
      verify_bind_mount "$CANON_SNAPSHOTS" "$DATA_ROOT/snapshots" "$device_id"; then
      verify_reflinks "$CANON_RUNDIR" "$CANON_SNAPSHOTS" || fail "mandatory reflink verification failed"
      log "data disk and canonical bind mounts are already ready"
      return 0
    fi
  elif [[ -e "$DATA_ROOT" || -L "$DATA_ROOT" ]]; then
    fail "$DATA_ROOT exists but is not a directory"
  fi

  (( verify_only == 0 )) || fail "data-disk verification requested, but the activated canonical XFS mounts are not ready"

  if mountpoint -q "$CANON_RUNDIR" && ! verify_bind_mount "$CANON_RUNDIR" "$DATA_ROOT/rundir" "$device_id"; then
    fail "$CANON_RUNDIR is already an unexpected mount"
  fi
  if mountpoint -q "$CANON_SNAPSHOTS" && ! verify_bind_mount "$CANON_SNAPSHOTS" "$DATA_ROOT/snapshots" "$device_id"; then
    fail "$CANON_SNAPSHOTS is already an unexpected mount"
  fi

  active_units="$(active_firecracker_units)"
  if [[ -n "$active_units" ]] || pgrep -x firecracker >/dev/null 2>&1; then
    fail "active or transitional Firecracker processes must be paused/drained before migration or mount repair${active_units:+: $active_units}"
  fi

  # A migration that committed but did not activate is recoverable only while
  # every still-unbound ext4 source tree exactly matches its XFS copy. A
  # mismatch means the old location was written after commit; stay failed
  # closed instead of guessing which copy is authoritative.
  unit_should_restore "$VMD_SERVICE" && vmd_was_active=1 || true
  unit_should_restore "$VMD_SOCKET" && socket_was_active=1 || true

  # Stop both units unconditionally. Merely sampling `is-active` and stopping
  # only that state misses activating/deactivating transitions and permits a
  # writer to race the migration copy.
  systemctl stop "$VMD_SOCKET" || fail "could not stop $VMD_SOCKET"
  systemctl stop "$VMD_SERVICE" || fail "could not stop $VMD_SERVICE"
  unit_is_quiescent "$VMD_SOCKET" || fail "$VMD_SOCKET did not become quiescent"
  unit_is_quiescent "$VMD_SERVICE" || fail "$VMD_SERVICE did not become quiescent"

  active_units="$(active_firecracker_units)"
  if [[ -n "$active_units" ]] || pgrep -x firecracker >/dev/null 2>&1; then
    fail "Firecracker became active while quiescing VMD; retry after draining the host"
  fi

  if [[ -d "$DATA_ROOT" && ! -f "$ACTIVATION_MARKER" ]]; then
    if ! mountpoint -q "$CANON_RUNDIR" && ! trees_match "$CANON_RUNDIR" "$DATA_ROOT/rundir"; then
      fail "incomplete migration: ext4 rundir diverged from committed XFS data"
    fi
    if ! mountpoint -q "$CANON_SNAPSHOTS" && ! trees_match "$CANON_SNAPSHOTS" "$DATA_ROOT/snapshots"; then
      fail "incomplete migration: ext4 snapshots diverged from committed XFS data"
    fi
  fi

  if [[ ! -e "$DATA_ROOT" ]]; then
    migration_tmp="${MOUNT_ROOT}/.data-v1.migrate.$$"
    [[ ! -e "$migration_tmp" ]] || fail "temporary migration path already exists: $migration_tmp"
    mkdir -m 0700 "$migration_tmp"

    log "copying existing rundir and snapshot trees to XFS"
    cp -a --one-file-system --sparse=always --reflink=auto -- "$CANON_RUNDIR" "$migration_tmp/rundir"
    cp -a --one-file-system --sparse=always --reflink=auto -- "$CANON_SNAPSHOTS" "$migration_tmp/snapshots"

    trees_match "$CANON_RUNDIR" "$migration_tmp/rundir" || fail "rundir migration checksum/inventory does not match"
    trees_match "$CANON_SNAPSHOTS" "$migration_tmp/snapshots" || fail "snapshot migration checksum/inventory does not match"
    verify_reflinks "$migration_tmp/rundir" "$migration_tmp/snapshots" ||
      fail "mandatory reflink verification failed inside the migration tree"

    : >"$migration_tmp/.migration-complete"
    # Persist the boot dependency and an out-of-filesystem authority marker
    # before the atomic rename. Any crash from this point onward leaves the
    # host gated on successful XFS recovery rather than booting against ext4.
    install_fail_closed_dependencies
    data_authoritative=1
    write_authority_marker || fail "could not persist $AUTHORITY_MARKER"
    sync
    mv -- "$migration_tmp" "$DATA_ROOT"
    migration_tmp=""
    sync
    log "one-time data migration committed"
  fi

  if ! mountpoint -q "$CANON_RUNDIR"; then
    mount --bind "$DATA_ROOT/rundir" "$CANON_RUNDIR"
    created_rundir_bind=1
  fi
  if ! mountpoint -q "$CANON_SNAPSHOTS"; then
    mount --bind "$DATA_ROOT/snapshots" "$CANON_SNAPSHOTS"
    created_snapshots_bind=1
  fi

  verify_bind_mount "$CANON_RUNDIR" "$DATA_ROOT/rundir" "$device_id" || fail "rundir bind mount verification failed"
  verify_bind_mount "$CANON_SNAPSHOTS" "$DATA_ROOT/snapshots" "$device_id" || fail "snapshot bind mount verification failed"
  [[ "$(mount_device_id "$CANON_RUNDIR")" == "$(mount_device_id "$CANON_SNAPSHOTS")" ]] ||
    fail "rundir and snapshots do not share one filesystem"

  verify_reflinks "$CANON_RUNDIR" "$CANON_SNAPSHOTS" || fail "canonical mandatory reflink verification failed"
  : >"$ACTIVATION_MARKER"
  sync

  log "XFS migration, bind mounts, and mandatory reflink probes passed"
}

main "$@"
