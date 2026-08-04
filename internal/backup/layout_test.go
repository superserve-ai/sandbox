package backup

import "testing"

func TestObjectNames(t *testing.T) {
	got, err := SandboxObject("sb-123", "abcd1234", "overlay.ext4")
	if err != nil || got != "sandboxes/sb-123/abcd1234/overlay.ext4" {
		t.Fatalf("sandbox object = %q err=%v", got, err)
	}
	got, err = TemplateObject("tpl-1", "build-9", "abcd1234", "base.ext4")
	if err != nil || got != "templates/tpl-1/build-9/abcd1234/base.ext4" {
		t.Fatalf("template object = %q err=%v", got, err)
	}
}

func TestObjectNameRejectsTraversal(t *testing.T) {
	for _, bad := range []string{"", "..", "a/b", `a\b`, "."} {
		if _, err := SandboxObject("sb", bad, "f"); err == nil {
			t.Errorf("generation %q accepted", bad)
		}
		if _, err := SandboxObject(bad, "gen", "f"); err == nil {
			t.Errorf("sandbox id %q accepted", bad)
		}
		if _, err := SandboxObject("sb", "gen", bad); err == nil {
			t.Errorf("file %q accepted", bad)
		}
	}
}

func TestGenerationKey(t *testing.T) {
	base := []TaskFile{
		{Name: "rootfs.ext4", SHA256: "aaaa"},
		{Name: "vmstate.snap", SHA256: "bbbb"},
	}
	k1 := GenerationKey(base)
	// Order-insensitive, deterministic.
	k2 := GenerationKey([]TaskFile{base[1], base[0]})
	if k1 != k2 || len(k1) != 64 {
		t.Fatalf("keys differ or malformed: %q vs %q", k1, k2)
	}
	// Any changed artifact digest changes the generation, vmstate included.
	changed := GenerationKey([]TaskFile{base[0], {Name: "vmstate.snap", SHA256: "cccc"}})
	if changed == k1 {
		t.Fatal("changed vmstate digest did not change the generation key")
	}
	// A re-based overlay with unchanged bytes is a different generation:
	// the manifest pairs it with a different base image.
	rebased := GenerationKey([]TaskFile{
		{Name: "rootfs.ext4", SHA256: "aaaa", BasePath: "/templates/t/b2/base.ext4"},
		base[1],
	})
	if rebased == k1 {
		t.Fatal("changed base dependency did not change the generation key")
	}
	// Size is a restore-side resource bound, so it must be key-covered:
	// a tampered manifest inflating it has to fail the key check.
	resized := GenerationKey([]TaskFile{
		{Name: "rootfs.ext4", SHA256: "aaaa", Size: 1 << 60},
		base[1],
	})
	if resized == k1 {
		t.Fatal("changed size did not change the generation key")
	}
	// A base rebuilt in place: same path, different bytes. The path
	// cannot see it; the base content digest must.
	rebuilt := GenerationKey([]TaskFile{
		{Name: "rootfs.ext4", SHA256: "aaaa", BasePath: "/templates/t/b1/base.ext4", BaseSHA256: "ffff"},
		base[1],
	})
	if rebuilt == k1 {
		t.Fatal("changed base contents did not change the generation key")
	}
}
