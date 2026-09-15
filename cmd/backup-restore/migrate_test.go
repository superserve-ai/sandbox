package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/superserve-ai/sandbox/internal/backup"
)

func TestRestoredDiskFollowsTheRestoreMarker(t *testing.T) {
	root := t.TempDir()
	sha := strings.Repeat("a", 64)
	write := func(id string, manifest backup.GenerationManifest, files ...string) {
		dir := filepath.Join(root, id)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(manifest)
		if err := os.WriteFile(filepath.Join(dir, backup.ManifestObject), raw, 0o644); err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if err := os.WriteFile(filepath.Join(dir, f), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := restoredDisk(root, "none"); err == nil {
		t.Fatal("missing restore accepted")
	}
	write("overlay", backup.GenerationManifest{Files: []backup.ManifestFile{{Name: "rootfs.ext4", BaseSHA256: sha}}}, "rootfs.ext4")
	if _, err := restoredDisk(root, "overlay"); err == nil {
		t.Fatal("overlay without its base accepted")
	}
	write("overlay", backup.GenerationManifest{Files: []backup.ManifestFile{{Name: "rootfs.ext4", BaseSHA256: sha}}}, "rootfs.ext4", backup.SharedBaseName(sha))
	r, err := restoredDisk(root, "overlay")
	if err != nil || r.standalone || filepath.Base(r.disk) != "rootfs.ext4" || filepath.Base(r.base) != backup.SharedBaseName(sha) {
		t.Fatalf("overlay: %+v %v", r, err)
	}
	write("full", backup.GenerationManifest{Files: []backup.ManifestFile{{Name: "rootfs.ext4"}}}, "rootfs.ext4")
	r, err = restoredDisk(root, "full")
	if err != nil || !r.standalone || r.base != "" || filepath.Base(r.disk) != "rootfs.ext4" {
		t.Fatalf("full image: %+v %v", r, err)
	}
	write("norootfs", backup.GenerationManifest{Files: []backup.ManifestFile{{Name: "vmstate.snap"}}}, "vmstate.snap")
	if _, err := restoredDisk(root, "norootfs"); err == nil {
		t.Fatal("marker without a rootfs accepted")
	}
}

func TestLoadSkipSetReadsFirstField(t *testing.T) {
	p := filepath.Join(t.TempDir(), "failed.txt")
	if err := os.WriteFile(p, []byte("x reason one\n\ny another reason\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := loadSkipSet(p)
	if len(got) != 2 || !got["x"] || !got["y"] {
		t.Fatalf("got %v", got)
	}
	if len(loadSkipSet(filepath.Join(t.TempDir(), "none"))) != 0 {
		t.Fatal("missing file should be empty")
	}
}

func TestParseEgressRulesMirrorsPersistedShape(t *testing.T) {
	r, err := parseEgressRules(nil)
	if err != nil || len(r.allowedCIDRs)+len(r.deniedCIDRs)+len(r.allowedDomains) != 0 {
		t.Fatalf("empty config: %+v %v", r, err)
	}
	r, err = parseEgressRules([]byte(`{"egress":{"allowed_cidrs":["10.0.0.0/8"],"denied_cidrs":["10.1.0.0/16"],"allowed_domains":["example.com"]}}`))
	if err != nil || r.allowedCIDRs[0] != "10.0.0.0/8" || r.deniedCIDRs[0] != "10.1.0.0/16" || r.allowedDomains[0] != "example.com" {
		t.Fatalf("got %+v %v", r, err)
	}
	if _, err := parseEgressRules([]byte(`{`)); err == nil {
		t.Fatal("malformed config accepted")
	}
}

func TestRestoredCurrentRequiresRecordedDigests(t *testing.T) {
	r := restored{manifest: backup.GenerationManifest{Files: []backup.ManifestFile{
		{Name: "vmstate.snap", SHA256: "aa"}, {Name: "rootfs.ext4", SHA256: "bb"},
	}}}
	if !r.current(map[string]string{"vmstate.snap": "aa"}) {
		t.Fatal("recorded digest present, rejected")
	}
	if !r.current(map[string]string{"vmstate.snap": "aa", "rootfs.ext4": "bb"}) {
		t.Fatal("full digest set present, rejected")
	}
	if r.current(map[string]string{"vmstate.snap": "cc"}) {
		t.Fatal("newer pause accepted by digest")
	}
	if r.current(map[string]string{"vmstate.snap": "aa", "rootfs.ext4": "zz"}) {
		t.Fatal("partial match accepted")
	}
	if r.current(nil) {
		t.Fatal("unanchored snapshot accepted")
	}
}

func TestJournalPendingUntilDone(t *testing.T) {
	f, err := os.OpenFile(filepath.Join(t.TempDir(), "journal"), os.O_APPEND|os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	v := int32(300)
	at := time.Unix(1700000000, 0)
	for _, step := range []func() error{
		func() error { return journalTimeout(f, "a", nil, at, "h", 60) },
		func() error { return journalTimeout(f, "b", &v, at, "h", 60) },
		func() error { return journalTimeout(f, "c", nil, at.Add(time.Hour), "h", 60) },
		func() error { return journalDone(f, "b") },
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
	pending, err := pendingJournal(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 2 || pending["a"].orig != nil || !pending["a"].since.Equal(at) || pending["a"].toHost != "h" || pending["a"].tmp != 60 {
		t.Fatalf("pending = %+v", pending)
	}
	if c, ok := pending["c"]; !ok || !c.since.Equal(at.Add(time.Hour)) {
		t.Fatalf("c = %+v", c)
	}
	if err := journalTimeout(f, "b", &v, at, "h", 60); err != nil {
		t.Fatal(err)
	}
	pending, _ = pendingJournal(f)
	if got := pending["b"].orig; got == nil || *got != 300 {
		t.Fatalf("re-journaled b = %v", got)
	}
	// Appends still land at the end after the read.
	data, _ := os.ReadFile(f.Name())
	if !strings.HasSuffix(string(data), "b 300 1700000000 h 60\n") {
		t.Fatalf("journal tail = %q", data)
	}
}
