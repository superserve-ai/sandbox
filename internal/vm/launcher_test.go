package vm

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/superserve-ai/sandbox/internal/shellquote"
)

// TestBuildLauncherNamespace_Integration exercises the real build + validity
// check on a live kernel. Needs root + Linux + util-linux; opt in with
// VMD_LAUNCHER_INTEGRATION=1 (run in a privileged container).
func TestBuildLauncherNamespace_Integration(t *testing.T) {
	if os.Getenv("VMD_LAUNCHER_INTEGRATION") != "1" {
		t.Skip("set VMD_LAUNCHER_INTEGRATION=1 (root + linux) to run")
	}
	ctx := context.Background()
	pin := "/run/vmd-test/launcher.mntns"
	if err := buildLauncherNamespace(ctx, pin); err != nil {
		t.Fatalf("buildLauncherNamespace: %v", err)
	}
	if !launcherNSValid(ctx, pin) {
		t.Fatal("launcherNSValid = false after a successful build")
	}
	if !pinIsMounted(pin) {
		t.Fatal("pinIsMounted = false after a successful build")
	}
	// A rebuild over an existing pin must also succeed (stale-pin path).
	if err := buildLauncherNamespace(ctx, pin); err != nil {
		t.Fatalf("rebuild over existing pin: %v", err)
	}
}

func TestFCStartScript_LegacyPath(t *testing.T) {
	got := fcStartScript("ns-7", "", "SETUP",
		"/usr/bin/firecracker", "/run/x/fc.sock", "vm-abc")
	if !strings.Contains(got, "ip netns exec ns-7 unshare -m -- sh -c ") {
		t.Errorf("legacy script should use `ip netns exec`; got:\n%s", got)
	}
	if strings.Contains(got, "nsenter") {
		t.Errorf("legacy script must not use nsenter; got:\n%s", got)
	}
	if strings.Contains(got, "mount -t sysfs") {
		t.Errorf("legacy script must not remount /sys (ip netns exec already does); got:\n%s", got)
	}
	if !strings.Contains(got, "/usr/bin/firecracker") {
		t.Errorf("legacy script missing firecracker binary; got:\n%s", got)
	}
}

func TestFCStartScript_LauncherPath(t *testing.T) {
	got := fcStartScript("ns-7", "/run/vmd/launcher.mntns", "SETUP",
		"/usr/bin/firecracker", "/run/x/fc.sock", "vm-abc")
	want := `nsenter --net=/run/netns/ns-7 --mount='/run/vmd/launcher.mntns' -- unshare -m`
	if !strings.Contains(got, want) {
		t.Errorf("launcher script missing %q; got:\n%s", want, got)
	}
	if strings.Contains(got, "ip netns exec") {
		t.Errorf("launcher script must not use `ip netns exec`; got:\n%s", got)
	}
	// launcherNSPath (in the prefix, outside sh -c) must be single-quoted.
	sp := fcStartScript("ns-7", "/run/vmd/a b.mntns", "SETUP", "/fc", "/s", "v")
	if !strings.Contains(sp, `--mount='/run/vmd/a b.mntns'`) {
		t.Errorf("launcher path with spaces not single-quoted; got:\n%s", sp)
	}
	ex := fcStartScript("ns-7", `/run/vmd/$FOO$(x)`, "SETUP", "/fc", "/s", "v")
	if !strings.Contains(ex, `--mount='/run/vmd/$FOO$(x)'`) {
		t.Errorf("launcher path with shell syntax not kept literal; got:\n%s", ex)
	}
	// The launcher path remounts /sys inside sh -c (survives the outer quoting).
	if !strings.Contains(got, "mount -t sysfs sysfs /sys") {
		t.Errorf("launcher script must remount /sys; got:\n%s", got)
	}
}

func TestFCSetupCmds_QuotesCallerPaths(t *testing.T) {
	// A caller-influenced base_path with shell syntax must be single-quoted, not
	// interpolated raw.
	evil := `/data/x$(touch /tmp/pwn)`
	got := fcSetupCmds("/tmpl", evil, "/run/rootfs.ext4")
	if !strings.Contains(got, shellquote.Single(evil)) {
		t.Errorf("base_path not single-quoted; got:\n%s", got)
	}
	if strings.Contains(got, "ln -s "+evil) {
		t.Errorf("base_path interpolated raw (unquoted); got:\n%s", got)
	}
}

// TestFCStartScript_NoShellInjection proves the exact double-quoting fcStartScript
// uses (each value single-quoted, then the whole inner script single-quoted as the
// `sh -c` argument) keeps a hostile path literal — no command substitution runs.
// Requires /bin/sh (runs in CI / the Linux test container).
func TestFCStartScript_NoShellInjection(t *testing.T) {
	marker := "/tmp/vmd_injtest_" + strconv.Itoa(os.Getpid())
	_ = os.Remove(marker)
	payload := "/data/x'$(touch " + marker + ")'`touch " + marker + "`.ext4"

	// Mirror fcStartScript: the value is single-quoted inside the inner script,
	// then the inner script is single-quoted as the `sh -c` argument. printf is
	// a harmless stand-in for `ln -s <path> …`.
	inner := "printf %s " + shellquote.Single(payload)
	line := "sh -c " + shellquote.Single(inner)

	out, err := exec.Command("/bin/sh", "-c", line).CombinedOutput()
	if err != nil {
		t.Fatalf("run: %v (%s)", err, out)
	}
	if string(out) != payload {
		t.Fatalf("path not treated literally:\n got  %q\n want %q", string(out), payload)
	}
	if _, err := os.Stat(marker); err == nil {
		_ = os.Remove(marker)
		t.Fatal("SHELL INJECTION: embedded command substitution executed")
	}
}

func TestPinIsMounted_NotAPin(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("statfs nsfs check (linux only)")
	}
	// Absent path and a plain file both fail the nsfs-magic check.
	if pinIsMounted("/no/such/pin") {
		t.Error("pinIsMounted(absent) = true, want false")
	}
	f, err := os.CreateTemp(t.TempDir(), "pin")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if pinIsMounted(f.Name()) {
		t.Error("pinIsMounted(regular file) = true, want false")
	}
}

func TestMountState(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("mountState reads /proc/self/mountinfo (linux only)")
	}
	// "/" is always a mount point; a made-up path never is.
	if mounted, _, err := mountState("/"); err != nil || !mounted {
		t.Errorf(`mountState("/") mounted = %v, %v; want true, nil`, mounted, err)
	}
	if mounted, _, err := mountState("/no/such/mount/xyz"); err != nil || mounted {
		t.Errorf(`mountState("/no/such/mount/xyz") mounted = %v, %v; want false, nil`, mounted, err)
	}
}

func TestParseMountState(t *testing.T) {
	// A private mount (no propagation tags) vs a shared one, plus an absent dir.
	mountinfo := []byte(
		"36 35 0:1 / /run/vmd rw,relatime - tmpfs tmpfs rw\n" +
			"37 35 0:2 / /run rw,relatime shared:23 - tmpfs tmpfs rw\n" +
			`38 35 0:3 / /run/my\040launcher rw,relatime - tmpfs tmpfs rw` + "\n")
	cases := []struct {
		dir                  string
		wantMounted, private bool
	}{
		{"/run/vmd", true, true},              // dedicated private pin dir
		{"/run", true, false},                 // shared host mount — must not be made private
		{"/run/my launcher", true, true},      // escaped mount point must unescape to match
		{`/run/my\040launcher`, false, false}, // literal escaped form must NOT match
		{"/nope", false, false},               // not present
	}
	for _, tc := range cases {
		mounted, private := parseMountState(mountinfo, tc.dir)
		if mounted != tc.wantMounted || private != tc.private {
			t.Errorf("parseMountState(%q) = (%v, %v); want (%v, %v)",
				tc.dir, mounted, private, tc.wantMounted, tc.private)
		}
	}
}

func TestLauncherNSPath(t *testing.T) {
	cases := []struct {
		name string
		cfg  ManagerConfig
		want string
	}{
		{"disabled", ManagerConfig{LaunchViaLauncherNS: false}, ""},
		{"disabled ignores path", ManagerConfig{LaunchViaLauncherNS: false, LauncherNSPath: "/x"}, ""},
		{"default path", ManagerConfig{LaunchViaLauncherNS: true}, defaultLauncherNSPath},
		{"custom path", ManagerConfig{LaunchViaLauncherNS: true, LauncherNSPath: "/tmp/l.mntns"}, "/tmp/l.mntns"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &Manager{cfg: tc.cfg}
			if got := m.launcherNSPath(); got != tc.want {
				t.Errorf("launcherNSPath() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPrunePaths(t *testing.T) {
	mounts := []byte(`sysfs /sys sysfs rw 0 0
tmpfs /run/netns tmpfs rw 0 0
nsfs /run/netns/ns-1 nsfs rw 0 0
nsfs /run/netns/ns-1 nsfs rw 0 0
nsfs /run/netns/ns-27 nsfs rw 0 0
nsfs /run/netns/odd\040name nsfs rw 0 0
tmpfs /run/netnsx tmpfs rw 0 0
malformed
`)
	got := prunePaths(mounts)
	want := []string{
		"/run/netns/ns-1",
		"/run/netns/ns-1", // stacked layers: one entry per layer, never deduped
		"/run/netns/ns-27",
		"/run/netns/odd name", // kernel octal escape decoded
	}
	if len(got) != len(want) {
		t.Fatalf("prunePaths = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("prunePaths[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
