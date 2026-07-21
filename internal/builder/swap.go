package builder

import "fmt"

// Guest swap policy. Swap gives a restored sandbox a spill margin so a brief
// memory spike pages out to disk instead of faulting the process (a guest with
// no swap gets SIGBUS/SIGSEGV the moment it touches a page past its RAM
// ceiling). Size scales with RAM because the spike scales with how much memory
// the workload uses, not a constant.
const (
	// SwapModeGuest is the build-time swap policy recorded in build.meta.json.
	// It is a policy label, not a runtime assertion — setup is best-effort and
	// is skipped on a tight rootfs.
	SwapModeGuest = "guest"

	guestSwapRAMDivisor  = 4    // swap = RAM / 4
	guestSwapMinMib      = 128  // floor so small guests still get a margin
	guestSwapMaxMib      = 4096 // cap so large-RAM guests don't over-reserve disk
	guestSwapHeadroomMib = 512  // rootfs free must exceed swap + this to enable
)

// GuestSwapSetupScript is run once in the build VM, after the user's build
// steps and just before the snapshot. Running it here (rather than in the
// guest init) means:
//   - build steps keep the full rootfs — the swap file never competes with
//     them for disk, and the free-space guard reflects real post-build space;
//   - swap is active when the snapshot is captured, so every restored sandbox
//     has it with no per-boot work (create/pause/resume pay nothing).
//
// Best-effort: any failure removes a partial file and the script still exits 0,
// so a swap problem never fails the build. Requires fallocate/mkswap/swapon
// (util-linux) and awk/df — all present in our allowed Debian-family bases.
//
// Sets an explicit system PATH first: this runs with the template's build env,
// whose PATH may omit /sbin (where mkswap/swapon live), which would otherwise
// make them silently not-found and skip swap.
var GuestSwapSetupScript = fmt.Sprintf(`export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:/usr/bin:/bin
if [ ! -f /swapfile ]; then
  mem_mib=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)
  swap_mib=$((mem_mib / %[1]d))
  [ "$swap_mib" -lt %[2]d ] && swap_mib=%[2]d
  [ "$swap_mib" -gt %[3]d ] && swap_mib=%[3]d
  free_kb=$(df -P -k / | awk 'END{print $4}')
  need_kb=$(( (swap_mib + %[4]d) * 1024 ))
  if [ "${free_kb:-0}" -gt "$need_kb" ]; then
    if ! { fallocate -l "${swap_mib}"M /swapfile 2>/dev/null &&
      chmod 600 /swapfile &&
      mkswap /swapfile >/dev/null 2>&1 &&
      swapon /swapfile 2>/dev/null; }; then
      rm -f /swapfile
    fi
  fi
fi`, guestSwapRAMDivisor, guestSwapMinMib, guestSwapMaxMib, guestSwapHeadroomMib)
