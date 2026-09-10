package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestEnsureParentDir(t *testing.T) {
	root := t.TempDir()

	t.Run("creates a missing parent", func(t *testing.T) {
		p := filepath.Join(root, "a", "b", "f.txt")
		if err := ensureParentDir(p); err != nil {
			t.Fatal(err)
		}
		if fi, err := os.Stat(filepath.Dir(p)); err != nil || !fi.IsDir() {
			t.Fatalf("parent not created: %v", err)
		}
	})

	t.Run("leaves an existing parent alone", func(t *testing.T) {
		if err := ensureParentDir(filepath.Join(root, "f.txt")); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("does not mkdir over a symlinked parent", func(t *testing.T) {
		target := filepath.Join(root, "target")
		if err := os.Mkdir(target, 0o755); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(root, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if err := ensureParentDir(filepath.Join(link, "f.txt")); err != nil {
			t.Fatal(err)
		}
		if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("symlink was replaced: %v %v", fi, err)
		}
	})

	t.Run("defers a dangling symlink to the open", func(t *testing.T) {
		link := filepath.Join(root, "dangling")
		if err := os.Symlink(filepath.Join(root, "nowhere"), link); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(link, "f.txt")
		if err := ensureParentDir(p); err != nil {
			t.Fatalf("helper should not fail on an existing link: %v", err)
		}
		_, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE, 0o644)
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("open should surface the real error, got %v", err)
		}
	})
}

func TestResolveByName(t *testing.T) {
	// Canonicalize first: on some systems the temp root is itself behind a
	// symlink, which the resolver correctly expands.
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(root, "abs")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(root, "rel")); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(root, "missing-mount")
	if err := os.Symlink(missing, filepath.Join(root, "broken")); err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		filepath.Join(root, "abs", "x", "y"):      filepath.Join(real, "x", "y"),
		filepath.Join(root, "rel", "x"):           filepath.Join(real, "x"),
		filepath.Join(root, "broken", "out", "f"): filepath.Join(missing, "out", "f"),
		filepath.Join(root, "real", "plain"):      filepath.Join(real, "plain"),
	}
	for in, want := range cases {
		if got := resolveByName(in, nil); got != want {
			t.Errorf("resolveByName(%q) = %q, want %q", in, got, want)
		}
	}

	// A mount is never looked inside: a link within it stays unresolved,
	// while a link from outside that points into it still lands there.
	mnt := filepath.Join(root, "mnt")
	if err := os.Mkdir(mnt, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(mnt, "inner")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(mnt, "sub"), filepath.Join(root, "into")); err != nil {
		t.Fatal(err)
	}
	mounts := []fsErrorMount{{Mountpoint: "/", Fstype: "ext4"}, {Mountpoint: mnt, Fstype: "fuse.example"}}
	if got, want := resolveByName(filepath.Join(mnt, "inner", "f"), mounts), filepath.Join(mnt, "inner", "f"); got != want {
		t.Errorf("walked inside the mount: got %q, want %q", got, want)
	}
	if got, want := resolveByName(filepath.Join(root, "into", "f"), mounts), filepath.Join(mnt, "sub", "f"); got != want {
		t.Errorf("link into the mount: got %q, want %q", got, want)
	}
}

func TestMountForIn(t *testing.T) {
	const info = `22 1 0:21 / / rw,relatime shared:1 - ext4 /dev/root rw
40 22 0:35 / /mnt rw,relatime shared:2 - tmpfs tmpfs rw
41 40 0:36 / /mnt/data rw,nosuid shared:3 master:1 - fuse.example example rw,user_id=0
42 22 0:37 / /with\040space rw - nfs4 host:/x rw
43 22 0:38 / /back\134slash rw - ext4 /dev/x rw
`
	cases := []struct {
		path string
		want *fsErrorMount
	}{
		{"/mnt/data/out/f.json", &fsErrorMount{"/mnt/data", "fuse.example"}},
		{"/mnt/data", &fsErrorMount{"/mnt/data", "fuse.example"}},
		{"/mnt/datastore/f", &fsErrorMount{"/mnt", "tmpfs"}},
		{"/with space/f", &fsErrorMount{"/with space", "nfs4"}},
		{`/back\slash/f`, &fsErrorMount{`/back\slash`, "ext4"}},
		{"/etc/hosts", &fsErrorMount{"/", "ext4"}},
	}
	for _, c := range cases {
		got := mountForIn(info, c.path)
		if got == nil || *got != *c.want {
			t.Errorf("mountForIn(%q) = %+v, want %+v", c.path, got, c.want)
		}
	}
	if got := mountForIn("bad line\n", "/x"); got != nil {
		t.Errorf("unparseable mountinfo should yield nil, got %+v", got)
	}
}

func TestWriteFSError(t *testing.T) {
	stale := &os.PathError{Op: "write", Path: "/m/f", Err: syscall.ESTALE}
	rec := httptest.NewRecorder()
	writeFSError(rec, "/m/f", stale)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rec.Code)
	}
	var got struct{ Error fsErrorBody }
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}
	if got.Error.Code != fsErrorCode || got.Error.Errno != "ESTALE" || got.Error.Path != "/m/f" {
		t.Fatalf("unexpected body: %+v", got.Error)
	}

	for _, err := range []error{
		errors.New("boom"),
		&os.PathError{Op: "open", Path: "/m/f", Err: syscall.EACCES},
	} {
		rec := httptest.NewRecorder()
		writeFSError(rec, "/m/f", err)
		var plain map[string]string
		if jerr := json.Unmarshal(rec.Body.Bytes(), &plain); jerr != nil || plain["error"] != err.Error() {
			t.Fatalf("%v should keep the plain body, got %q", err, rec.Body.String())
		}
	}
}
