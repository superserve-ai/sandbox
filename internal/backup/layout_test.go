package backup

import "testing"

func TestObjectNames(t *testing.T) {
	got, err := SandboxObject("sb-123", "abcd1234", "overlay.ext4")
	if err != nil || got != "sandboxes/sb-123/abcd1234/overlay.ext4" {
		t.Fatalf("sandbox object = %q err=%v", got, err)
	}
	got, err = TemplateObject("tpl-1", "build-9", "base.ext4")
	if err != nil || got != "templates/tpl-1/build-9/base.ext4" {
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
