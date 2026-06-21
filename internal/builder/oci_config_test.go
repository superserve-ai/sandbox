package builder

import (
	"encoding/json"
	"reflect"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// TestImageDefaultsJSONRoundTrip guards the on-wire contract: ImageDefaults is
// serialized into build.meta.json by template-builder under the "image_config"
// key and read back by vmd. Both sides embed this type, so a stable JSON shape
// is what keeps the captured config intact across the build subprocess boundary.
func TestImageDefaultsJSONRoundTrip(t *testing.T) {
	in := ImageDefaults{
		Entrypoint: []string{"/usr/bin/python", "-u"},
		Cmd:        []string{"app.py", "--serve"},
		Env:        map[string]string{"LANG": "C.UTF-8", "PORT": "8080"},
		WorkingDir: "/app",
		User:       "1000:1000",
	}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Field names callers (vmd, controlplane) depend on.
	for _, key := range []string{"entrypoint", "cmd", "env", "working_dir", "user"} {
		if !contains(string(data), `"`+key+`"`) {
			t.Errorf("serialized image config missing key %q: %s", key, data)
		}
	}
	var out ImageDefaults
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round-trip mismatch:\n in=%#v\nout=%#v", in, out)
	}
}

// TestImageDefaultsZeroJSON confirms a zero ImageDefaults serializes to an empty
// object (all fields omitempty), so a base image with no runtime config doesn't
// write noise into build.meta.json.
func TestImageDefaultsZeroJSON(t *testing.T) {
	data, err := json.Marshal(ImageDefaults{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(data) != "{}" {
		t.Fatalf("zero ImageDefaults should be {}, got %s", data)
	}
	var out ImageDefaults
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !out.IsZero() {
		t.Fatalf("round-tripped zero should be zero, got %#v", out)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestParseEnv(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want map[string]string
	}{
		{name: "nil input", in: nil, want: nil},
		{name: "empty input", in: []string{}, want: nil},
		{
			name: "simple pairs",
			in:   []string{"PATH=/usr/bin", "HOME=/root"},
			want: map[string]string{"PATH": "/usr/bin", "HOME": "/root"},
		},
		{
			name: "value contains equals",
			in:   []string{"FLAGS=--a=1 --b=2"},
			want: map[string]string{"FLAGS": "--a=1 --b=2"},
		},
		{
			name: "bare key without equals",
			in:   []string{"DEBUG"},
			want: map[string]string{"DEBUG": ""},
		},
		{
			name: "explicit empty value",
			in:   []string{"EMPTY="},
			want: map[string]string{"EMPTY": ""},
		},
		{
			name: "later duplicate wins",
			in:   []string{"K=first", "K=second"},
			want: map[string]string{"K": "second"},
		},
		{
			name: "malformed leading equals skipped",
			in:   []string{"=orphan", "GOOD=1"},
			want: map[string]string{"GOOD": "1"},
		},
		{
			name: "all malformed yields nil",
			in:   []string{"=a", "="},
			want: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseEnv(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("parseEnv(%#v) = %#v, want %#v", tc.in, got, tc.want)
			}
		})
	}
}

func TestImageDefaultsFromConfig(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		if got := imageDefaultsFromConfig(nil); !got.IsZero() {
			t.Fatalf("nil config should yield zero defaults, got %#v", got)
		}
	})

	t.Run("full config", func(t *testing.T) {
		cfg := &v1.ConfigFile{
			Config: v1.Config{
				Entrypoint: []string{"/usr/bin/python"},
				Cmd:        []string{"app.py"},
				Env:        []string{"PATH=/usr/bin", "LANG=C.UTF-8"},
				WorkingDir: "/app",
				User:       "1000:1000",
			},
		}
		got := imageDefaultsFromConfig(cfg)
		want := ImageDefaults{
			Entrypoint: []string{"/usr/bin/python"},
			Cmd:        []string{"app.py"},
			Env:        map[string]string{"PATH": "/usr/bin", "LANG": "C.UTF-8"},
			WorkingDir: "/app",
			User:       "1000:1000",
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("imageDefaultsFromConfig = %#v, want %#v", got, want)
		}
		if got.IsZero() {
			t.Fatal("full config should not be zero")
		}
	})

	t.Run("empty config is zero", func(t *testing.T) {
		got := imageDefaultsFromConfig(&v1.ConfigFile{})
		if !got.IsZero() {
			t.Fatalf("empty config should be zero, got %#v", got)
		}
	})
}

func TestValidatePlatformConfig(t *testing.T) {
	base := func() *v1.ConfigFile {
		return &v1.ConfigFile{OS: "linux", Architecture: "amd64"}
	}

	t.Run("matching platform passes", func(t *testing.T) {
		if err := validatePlatformConfig(base(), "linux", "amd64"); err != nil {
			t.Fatalf("expected pass, got %v", err)
		}
	})
	t.Run("nil config errors", func(t *testing.T) {
		if err := validatePlatformConfig(nil, "linux", "amd64"); err == nil {
			t.Fatal("expected error for nil config")
		}
	})
	t.Run("wrong os errors", func(t *testing.T) {
		cfg := base()
		cfg.OS = "windows"
		if err := validatePlatformConfig(cfg, "linux", "amd64"); err == nil {
			t.Fatal("expected os mismatch error")
		}
	})
	t.Run("wrong arch errors", func(t *testing.T) {
		cfg := base()
		cfg.Architecture = "arm64"
		if err := validatePlatformConfig(cfg, "linux", "amd64"); err == nil {
			t.Fatal("expected arch mismatch error")
		}
	})
	t.Run("alpine-style minimal PATH is accepted (musl boot validated)", func(t *testing.T) {
		// Alpine/busybox images boot fine — static boxd+tini behind a POSIX-sh
		// init wrapper, validated on a real Alpine microVM — so a minimal PATH
		// must NOT be rejected (it used to be).
		cfg := base()
		cfg.Config.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin"}
		if err := validatePlatformConfig(cfg, "linux", "amd64"); err != nil {
			t.Fatalf("alpine-style minimal PATH should be accepted, got %v", err)
		}
	})
	t.Run("debian-style PATH passes", func(t *testing.T) {
		cfg := base()
		cfg.Config.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
		if err := validatePlatformConfig(cfg, "linux", "amd64"); err != nil {
			t.Fatalf("expected debian-style PATH to pass, got %v", err)
		}
	})
}
