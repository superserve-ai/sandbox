package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRestoredDiskRequiresOverlayAndOneBase(t *testing.T) {
	root := t.TempDir()
	touch := func(parts ...string) {
		p := filepath.Join(append([]string{root}, parts...)...)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := restoredDisk(root, "a"); err == nil {
		t.Fatal("missing restore accepted")
	}
	touch("a", "manifest.json")
	touch("a", "rootfs.ext4")
	if _, _, err := restoredDisk(root, "a"); err == nil {
		t.Fatal("overlay without base accepted")
	}
	touch("a", "base-1111.ext4")
	disk, base, err := restoredDisk(root, "a")
	if err != nil || filepath.Base(disk) != "rootfs.ext4" || filepath.Base(base) != "base-1111.ext4" {
		t.Fatalf("got %q %q %v", disk, base, err)
	}
	touch("a", "base-2222.ext4")
	if _, _, err := restoredDisk(root, "a"); err == nil {
		t.Fatal("ambiguous base accepted")
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
