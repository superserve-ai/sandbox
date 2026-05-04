package builder

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRewriteAptSources covers the apt-source rewrite path: hosts in the
// canonical Ubuntu list get redirected to the GCE regional mirror, unrelated
// URLs and HTTPS sources stay put, files without canonical references aren't
// touched, the rewrite is idempotent, and the function is a no-op on
// non-Ubuntu rootfs trees.
func TestRewriteAptSources(t *testing.T) {
	t.Run("rewrites archive and security hosts in classic sources.list", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, filepath.Join(root, "etc/apt/sources.list"), ""+
			"deb http://archive.ubuntu.com/ubuntu noble main\n"+
			"deb http://security.ubuntu.com/ubuntu noble-security main\n")

		if err := rewriteAptSources(root); err != nil {
			t.Fatalf("rewriteAptSources: %v", err)
		}

		got := readFile(t, filepath.Join(root, "etc/apt/sources.list"))
		if !strings.HasPrefix(got, aptRewriteHeader) {
			t.Errorf("expected file to begin with rewrite header; got:\n%s", got)
		}
		// Match on protocol+host so we don't false-positive on the GCE
		// mirror's own hostname (which contains "archive.ubuntu.com" as
		// a substring).
		body := strings.TrimPrefix(got, aptRewriteHeader)
		for _, stale := range []string{"http://archive.ubuntu.com", "http://security.ubuntu.com"} {
			if strings.Contains(body, stale) {
				t.Errorf("stale URL %q still present after rewrite:\n%s", stale, body)
			}
		}
		if strings.Count(body, gceUbuntuMirrorHost) != 2 {
			t.Errorf("expected GCE mirror hostname in 2 deb lines, got %d:\n%s",
				strings.Count(body, gceUbuntuMirrorHost), body)
		}
	})

	t.Run("rewrites deb822 .sources file in sources.list.d", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, filepath.Join(root, "etc/apt/sources.list.d/ubuntu.sources"), ""+
			"Types: deb deb-src\n"+
			"URIs: http://archive.ubuntu.com/ubuntu/\n"+
			"Suites: noble noble-updates\n"+
			"Components: main universe\n")

		if err := rewriteAptSources(root); err != nil {
			t.Fatalf("rewriteAptSources: %v", err)
		}

		got := readFile(t, filepath.Join(root, "etc/apt/sources.list.d/ubuntu.sources"))
		if !strings.Contains(got, "URIs: http://"+gceUbuntuMirrorHost+"/ubuntu/") {
			t.Errorf("URIs line not rewritten:\n%s", got)
		}
	})

	t.Run("leaves unrelated PPA and HTTPS sources untouched", func(t *testing.T) {
		root := t.TempDir()
		original := "" +
			"deb http://ppa.launchpad.net/some/ppa/ubuntu noble main\n" +
			"deb https://archive.ubuntu.com/ubuntu noble main\n" + // HTTPS — not rewritten
			"deb http://my.private.mirror/ubuntu noble main\n"
		writeFile(t, filepath.Join(root, "etc/apt/sources.list"), original)

		if err := rewriteAptSources(root); err != nil {
			t.Fatalf("rewriteAptSources: %v", err)
		}

		got := readFile(t, filepath.Join(root, "etc/apt/sources.list"))
		if got != original {
			t.Errorf("expected file untouched (no http canonical refs), got:\n%s", got)
		}
	})

	t.Run("idempotent — rewriting twice does not double-prepend the header", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, filepath.Join(root, "etc/apt/sources.list"),
			"deb http://archive.ubuntu.com/ubuntu noble main\n")

		if err := rewriteAptSources(root); err != nil {
			t.Fatalf("first rewrite: %v", err)
		}
		first := readFile(t, filepath.Join(root, "etc/apt/sources.list"))

		if err := rewriteAptSources(root); err != nil {
			t.Fatalf("second rewrite: %v", err)
		}
		second := readFile(t, filepath.Join(root, "etc/apt/sources.list"))

		if first != second {
			t.Errorf("rewrite is not idempotent.\nfirst:\n%s\nsecond:\n%s", first, second)
		}
	})

	t.Run("no-op when /etc/apt is absent", func(t *testing.T) {
		root := t.TempDir() // empty
		if err := rewriteAptSources(root); err != nil {
			t.Errorf("expected nil error for missing /etc/apt, got: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
