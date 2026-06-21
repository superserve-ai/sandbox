package start

import (
	"reflect"
	"testing"
)

func TestResolveArgv(t *testing.T) {
	tests := []struct {
		name string
		img  Image
		ov   Overrides
		want []string
	}{
		{
			name: "command override replaces entrypoint and cmd",
			img:  Image{Entrypoint: []string{"/bin/entry"}, Cmd: []string{"default", "arg"}},
			ov:   Overrides{Command: []string{"run", "me"}},
			want: []string{"run", "me"},
		},
		{
			name: "entrypoint and cmd concatenated",
			img:  Image{Entrypoint: []string{"/bin/entry", "--flag"}, Cmd: []string{"sub", "cmd"}},
			want: []string{"/bin/entry", "--flag", "sub", "cmd"},
		},
		{
			name: "entrypoint only",
			img:  Image{Entrypoint: []string{"/bin/entry"}},
			want: []string{"/bin/entry"},
		},
		{
			name: "cmd only",
			img:  Image{Cmd: []string{"echo", "hi"}},
			want: []string{"echo", "hi"},
		},
		{
			name: "empty everything yields nil argv (not runnable)",
			img:  Image{},
			ov:   Overrides{},
			want: nil,
		},
		{
			name: "command override does not append image cmd",
			img:  Image{Entrypoint: []string{"/bin/entry"}, Cmd: []string{"keep", "out"}},
			ov:   Overrides{Command: []string{"only"}},
			want: []string{"only"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Resolve(tt.img, tt.ov)
			if !reflect.DeepEqual(got.Argv, tt.want) {
				t.Fatalf("Argv = %#v, want %#v", got.Argv, tt.want)
			}
			if got.IsRunnable() != (len(tt.want) > 0) {
				t.Fatalf("IsRunnable() = %v, want %v", got.IsRunnable(), len(tt.want) > 0)
			}
		})
	}
}

func TestResolveEnvThreeLayerMerge(t *testing.T) {
	img := Image{Env: map[string]string{
		"SHARED": "from-image",
		"IMG":    "i",
	}}
	ov := Overrides{
		BuildEnv: map[string]string{
			"SHARED": "from-build",
			"BUILD":  "b",
		},
		SandboxEnv: map[string]string{
			"SHARED":  "from-sandbox",
			"SANDBOX": "s",
		},
	}
	got := Resolve(img, ov).Env
	want := map[string]string{
		"SHARED":  "from-sandbox", // sandbox wins over build wins over image
		"IMG":     "i",
		"BUILD":   "b",
		"SANDBOX": "s",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Env = %#v, want %#v", got, want)
	}
}

func TestResolveEnvBuildBeatsImageSandboxBeatsBuild(t *testing.T) {
	img := Image{Env: map[string]string{"K": "image"}}
	// BuildEnv overrides image when sandbox absent.
	if got := Resolve(img, Overrides{BuildEnv: map[string]string{"K": "build"}}).Env["K"]; got != "build" {
		t.Fatalf("K = %q, want build", got)
	}
	// SandboxEnv overrides build.
	ov := Overrides{
		BuildEnv:   map[string]string{"K": "build"},
		SandboxEnv: map[string]string{"K": "sandbox"},
	}
	if got := Resolve(img, ov).Env["K"]; got != "sandbox" {
		t.Fatalf("K = %q, want sandbox", got)
	}
}

func TestResolveEnvNilWhenAllEmpty(t *testing.T) {
	if env := Resolve(Image{}, Overrides{}).Env; env != nil {
		t.Fatalf("Env = %#v, want nil", env)
	}
}

func TestResolveDoesNotMutateInputs(t *testing.T) {
	imgEnv := map[string]string{"K": "image"}
	buildEnv := map[string]string{"B": "build"}
	sandboxEnv := map[string]string{"K": "sandbox"} // collides with image key
	entrypoint := []string{"/bin/entry"}
	cmd := []string{"sub"}
	command := []string{"override"}

	img := Image{Entrypoint: entrypoint, Cmd: cmd, Env: imgEnv}
	ov := Overrides{Command: command, BuildEnv: buildEnv, SandboxEnv: sandboxEnv}

	got := Resolve(img, ov)

	// Original maps unchanged.
	if !reflect.DeepEqual(imgEnv, map[string]string{"K": "image"}) {
		t.Fatalf("img.Env mutated: %#v", imgEnv)
	}
	if !reflect.DeepEqual(buildEnv, map[string]string{"B": "build"}) {
		t.Fatalf("ov.BuildEnv mutated: %#v", buildEnv)
	}
	if !reflect.DeepEqual(sandboxEnv, map[string]string{"K": "sandbox"}) {
		t.Fatalf("ov.SandboxEnv mutated: %#v", sandboxEnv)
	}

	// Original slices unchanged and result does not alias them.
	if !reflect.DeepEqual(entrypoint, []string{"/bin/entry"}) {
		t.Fatalf("img.Entrypoint mutated: %#v", entrypoint)
	}
	if !reflect.DeepEqual(command, []string{"override"}) {
		t.Fatalf("ov.Command mutated: %#v", command)
	}
	// Mutating the returned Spec must not bleed into inputs.
	got.Argv[0] = "TAMPERED"
	if command[0] != "override" {
		t.Fatalf("Argv aliases ov.Command: %#v", command)
	}
	got.Env["K"] = "TAMPERED"
	if sandboxEnv["K"] != "sandbox" {
		t.Fatalf("Env aliases ov.SandboxEnv: %#v", sandboxEnv)
	}
}

func TestResolveArgvFromImageDoesNotAlias(t *testing.T) {
	entrypoint := []string{"/bin/entry"}
	cmd := []string{"sub"}
	img := Image{Entrypoint: entrypoint, Cmd: cmd}
	got := Resolve(img, Overrides{})
	got.Argv[0] = "X"
	got.Argv[1] = "Y"
	if entrypoint[0] != "/bin/entry" || cmd[0] != "sub" {
		t.Fatalf("resolved Argv aliases image slices: entrypoint=%#v cmd=%#v", entrypoint, cmd)
	}
}

func TestResolveUserPrecedence(t *testing.T) {
	tests := []struct {
		name string
		img  Image
		ov   Overrides
		want string
	}{
		{"override wins", Image{User: "img-user"}, Overrides{User: "ov-user"}, "ov-user"},
		{"fall through to image", Image{User: "img-user"}, Overrides{}, "img-user"},
		{"empty means root", Image{}, Overrides{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Resolve(tt.img, tt.ov).User; got != tt.want {
				t.Fatalf("User = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveWorkingDirPrecedence(t *testing.T) {
	tests := []struct {
		name string
		img  Image
		ov   Overrides
		want string
	}{
		{"override wins", Image{WorkingDir: "/img"}, Overrides{WorkingDir: "/ov"}, "/ov"},
		{"fall through to image", Image{WorkingDir: "/img"}, Overrides{}, "/img"},
		{"empty means root", Image{}, Overrides{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Resolve(tt.img, tt.ov).WorkingDir; got != tt.want {
				t.Fatalf("WorkingDir = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveRestartNormalization(t *testing.T) {
	tests := []struct {
		name string
		in   RestartPolicy
		want RestartPolicy
	}{
		{"empty defaults to on-failure", "", RestartOnFailure},
		{"always preserved", RestartAlways, RestartAlways},
		{"no preserved", RestartNo, RestartNo},
		{"on-failure preserved", RestartOnFailure, RestartOnFailure},
		{"garbage defaults to on-failure", RestartPolicy("bogus"), RestartOnFailure},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Resolve(Image{}, Overrides{Restart: tt.in}).Restart; got != tt.want {
				t.Fatalf("Restart = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveReadyPassthrough(t *testing.T) {
	if got := Resolve(Image{}, Overrides{Ready: "http://localhost:8080/healthz"}).Ready; got != "http://localhost:8080/healthz" {
		t.Fatalf("Ready = %q, want passthrough", got)
	}
	if got := Resolve(Image{}, Overrides{}).Ready; got != "" {
		t.Fatalf("Ready = %q, want empty", got)
	}
}

func TestResolveFullSpec(t *testing.T) {
	img := Image{
		Entrypoint: []string{"/bin/agent"},
		Cmd:        []string{"--serve"},
		Env:        map[string]string{"PATH": "/usr/bin", "OWNER": "image"},
		WorkingDir: "/img",
		User:       "1000",
	}
	ov := Overrides{
		BuildEnv:   map[string]string{"OWNER": "build", "BUILT": "1"},
		SandboxEnv: map[string]string{"OWNER": "sandbox"},
		WorkingDir: "/work",
		Restart:    RestartAlways,
		Ready:      "/healthz",
	}
	got := Resolve(img, ov)
	want := Spec{
		Argv:       []string{"/bin/agent", "--serve"},
		Env:        map[string]string{"PATH": "/usr/bin", "OWNER": "sandbox", "BUILT": "1"},
		User:       "1000",
		WorkingDir: "/work",
		Restart:    RestartAlways,
		Ready:      "/healthz",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Resolve() = %#v\nwant %#v", got, want)
	}
	if !got.IsRunnable() {
		t.Fatal("expected runnable spec")
	}
}
