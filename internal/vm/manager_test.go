package vm

import (
	"testing"
)

func TestTemplateRunDir(t *testing.T) {
	cfg := ManagerConfig{RunDir: "/var/lib/sandbox/rundir"}
	mgr := &Manager{cfg: cfg}

	got := mgr.templateRunDir()
	want := "/var/lib/sandbox/rundir/template"
	if got != want {
		t.Errorf("templateRunDir() = %q, want %q", got, want)
	}
}

func TestTemplateDirNameIsFixed(t *testing.T) {
	if templateDirName != "template" {
		t.Errorf("templateDirName = %q, want %q", templateDirName, "template")
	}
}
