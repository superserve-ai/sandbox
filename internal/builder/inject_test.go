package builder

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRewriteAptSources covers the apt-source rewrite path: canonical hosts
// get redirected to the GCE regional mirror over both http:// and https://
// (downgraded to http://), unrelated URLs are left alone, the rewrite is
// idempotent, and the function is a no-op on non-Ubuntu rootfs trees.
func TestRewriteAptSources(t *testing.T) {
	t.Run("rewrites archive and security hosts in classic sources.list", func(t *testing.T) {
		root := t.TempDir()
		writeTestFile(t, filepath.Join(root, "etc/apt/sources.list"), ""+
			"deb http://archive.ubuntu.com/ubuntu noble main\n"+
			"deb http://security.ubuntu.com/ubuntu noble-security main\n")

		if err := rewriteAptSources(root, nil); err != nil {
			t.Fatalf("rewriteAptSources: %v", err)
		}

		got := readTestFile(t, filepath.Join(root, "etc/apt/sources.list"))
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
		writeTestFile(t, filepath.Join(root, "etc/apt/sources.list.d/ubuntu.sources"), ""+
			"Types: deb deb-src\n"+
			"URIs: http://archive.ubuntu.com/ubuntu/\n"+
			"Suites: noble noble-updates\n"+
			"Components: main universe\n")

		if err := rewriteAptSources(root, nil); err != nil {
			t.Fatalf("rewriteAptSources: %v", err)
		}

		got := readTestFile(t, filepath.Join(root, "etc/apt/sources.list.d/ubuntu.sources"))
		if !strings.Contains(got, "URIs: http://"+gceUbuntuMirrorHost+"/ubuntu/") {
			t.Errorf("URIs line not rewritten:\n%s", got)
		}
	})

	t.Run("leaves PPA and customer-private mirrors untouched", func(t *testing.T) {
		root := t.TempDir()
		original := "" +
			"deb http://ppa.launchpad.net/some/ppa/ubuntu noble main\n" +
			"deb http://my.private.mirror/ubuntu noble main\n" +
			"deb https://my.private.mirror/ubuntu noble main\n"
		writeTestFile(t, filepath.Join(root, "etc/apt/sources.list"), original)

		if err := rewriteAptSources(root, nil); err != nil {
			t.Fatalf("rewriteAptSources: %v", err)
		}

		got := readTestFile(t, filepath.Join(root, "etc/apt/sources.list"))
		if got != original {
			t.Errorf("expected file untouched (no canonical refs), got:\n%s", got)
		}
	})

	t.Run("rewrites https:// canonical sources to http:// GCE mirror", func(t *testing.T) {
		root := t.TempDir()
		writeTestFile(t, filepath.Join(root, "etc/apt/sources.list"),
			"deb https://archive.ubuntu.com/ubuntu noble main\n"+
				"deb https://security.ubuntu.com/ubuntu noble-security main\n")

		if err := rewriteAptSources(root, nil); err != nil {
			t.Fatalf("rewriteAptSources: %v", err)
		}

		got := readTestFile(t, filepath.Join(root, "etc/apt/sources.list"))
		body := strings.TrimPrefix(got, aptRewriteHeader)
		for _, stale := range []string{
			"https://archive.ubuntu.com", "https://security.ubuntu.com",
			"http://archive.ubuntu.com", "http://security.ubuntu.com",
		} {
			if strings.Contains(body, stale) {
				t.Errorf("stale URL %q still present after rewrite:\n%s", stale, body)
			}
		}
		if strings.Count(body, "http://"+gceUbuntuMirrorHost) != 2 {
			t.Errorf("expected http://%s twice in body (HTTPS downgraded), got %d:\n%s",
				gceUbuntuMirrorHost, strings.Count(body, "http://"+gceUbuntuMirrorHost), body)
		}
	})

	t.Run("rewrites canonical lines and leaves non-canonical lines alone in one file", func(t *testing.T) {
		root := t.TempDir()
		writeTestFile(t, filepath.Join(root, "etc/apt/sources.list"),
			"deb http://archive.ubuntu.com/ubuntu noble main\n"+
				"deb http://ppa.launchpad.net/some/ppa/ubuntu noble main\n"+
				"deb http://security.ubuntu.com/ubuntu noble-security main\n"+
				"deb http://my.private.mirror/ubuntu noble main\n")

		if err := rewriteAptSources(root, nil); err != nil {
			t.Fatalf("rewriteAptSources: %v", err)
		}

		got := readTestFile(t, filepath.Join(root, "etc/apt/sources.list"))
		body := strings.TrimPrefix(got, aptRewriteHeader)
		for _, stale := range []string{"http://archive.ubuntu.com", "http://security.ubuntu.com"} {
			if strings.Contains(body, stale) {
				t.Errorf("canonical %q still present after rewrite:\n%s", stale, body)
			}
		}
		for _, kept := range []string{"http://ppa.launchpad.net/some/ppa/ubuntu", "http://my.private.mirror/ubuntu"} {
			if !strings.Contains(body, kept) {
				t.Errorf("non-canonical %q was dropped or rewritten:\n%s", kept, body)
			}
		}
	})

	t.Run("idempotent — rewriting twice does not double-prepend the header", func(t *testing.T) {
		root := t.TempDir()
		writeTestFile(t, filepath.Join(root, "etc/apt/sources.list"),
			"deb http://archive.ubuntu.com/ubuntu noble main\n")

		if err := rewriteAptSources(root, nil); err != nil {
			t.Fatalf("first rewrite: %v", err)
		}
		first := readTestFile(t, filepath.Join(root, "etc/apt/sources.list"))

		if err := rewriteAptSources(root, nil); err != nil {
			t.Fatalf("second rewrite: %v", err)
		}
		second := readTestFile(t, filepath.Join(root, "etc/apt/sources.list"))

		if first != second {
			t.Errorf("rewrite is not idempotent.\nfirst:\n%s\nsecond:\n%s", first, second)
		}
	})

	t.Run("no-op when /etc/apt is absent", func(t *testing.T) {
		root := t.TempDir() // empty
		if err := rewriteAptSources(root, nil); err != nil {
			t.Errorf("expected nil error for missing /etc/apt, got: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func writeTestFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
