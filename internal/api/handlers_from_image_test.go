package api

import (
	"reflect"
	"testing"

	"github.com/superserve-ai/sandbox/internal/start"
)

func TestResolveImageStartSpec(t *testing.T) {
	// A realistic python image config as it would be stored in image_config jsonb.
	pyConfig := []byte(`{
		"entrypoint": ["/usr/local/bin/python"],
		"cmd": ["app.py"],
		"env": {"PATH": "/usr/local/bin:/usr/bin", "LANG": "C.UTF-8"},
		"working_dir": "/app",
		"user": "1000:1000"
	}`)

	t.Run("bare image runs entrypoint+cmd", func(t *testing.T) {
		spec, err := resolveImageStartSpec(pyConfig, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"/usr/local/bin/python", "app.py"}; !reflect.DeepEqual(spec.Argv, want) {
			t.Errorf("argv = %v, want %v", spec.Argv, want)
		}
		if spec.WorkingDir != "/app" || spec.User != "1000:1000" {
			t.Errorf("workdir/user = %q/%q", spec.WorkingDir, spec.User)
		}
		if spec.Env["LANG"] != "C.UTF-8" {
			t.Errorf("env not carried: %v", spec.Env)
		}
		if !spec.IsRunnable() {
			t.Error("should be runnable")
		}
	})

	t.Run("command overrides entrypoint+cmd (docker run IMG CMD)", func(t *testing.T) {
		spec, err := resolveImageStartSpec(pyConfig, []string{"bash", "-c", "echo hi"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"bash", "-c", "echo hi"}; !reflect.DeepEqual(spec.Argv, want) {
			t.Errorf("argv = %v, want %v", spec.Argv, want)
		}
		// image workdir/user still apply when not overridden
		if spec.WorkingDir != "/app" {
			t.Errorf("workdir = %q", spec.WorkingDir)
		}
	})

	t.Run("request env overrides image env", func(t *testing.T) {
		spec, err := resolveImageStartSpec(pyConfig, nil, map[string]string{"LANG": "en_US.UTF-8", "EXTRA": "1"})
		if err != nil {
			t.Fatal(err)
		}
		if spec.Env["LANG"] != "en_US.UTF-8" {
			t.Errorf("request env should win: LANG=%q", spec.Env["LANG"])
		}
		if spec.Env["EXTRA"] != "1" {
			t.Errorf("request env not added: %v", spec.Env)
		}
		if spec.Env["PATH"] != "/usr/local/bin:/usr/bin" {
			t.Errorf("image env should remain: PATH=%q", spec.Env["PATH"])
		}
	})

	t.Run("nil image config, no command -> not runnable", func(t *testing.T) {
		spec, err := resolveImageStartSpec(nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if spec.IsRunnable() {
			t.Errorf("legacy template with no image config should not auto-start, got argv %v", spec.Argv)
		}
	})

	t.Run("nil image config + command -> runs command", func(t *testing.T) {
		spec, err := resolveImageStartSpec(nil, []string{"python", "agent.py"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"python", "agent.py"}; !reflect.DeepEqual(spec.Argv, want) {
			t.Errorf("argv = %v, want %v", spec.Argv, want)
		}
	})

	t.Run("restart defaults to on-failure", func(t *testing.T) {
		spec, _ := resolveImageStartSpec(pyConfig, nil, nil)
		if spec.Restart != start.RestartOnFailure {
			t.Errorf("restart = %q, want on-failure", spec.Restart)
		}
	})

	t.Run("malformed image config errors", func(t *testing.T) {
		if _, err := resolveImageStartSpec([]byte(`{not json`), nil, nil); err == nil {
			t.Error("expected error for malformed image config")
		}
	})
}
