package main

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// zipFilesGet drives a GET /files request through the real handleFiles entry
// point (so safePath and the file-vs-dir dispatch are exercised) and returns
// the recorder. An empty format omits the query flag entirely.
func zipFilesGet(t *testing.T, path, format string) *httptest.ResponseRecorder {
	t.Helper()
	target := "/files?path=" + url.QueryEscape(path)
	if format != "" {
		target += "&format=" + url.QueryEscape(format)
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	w := httptest.NewRecorder()
	handleFiles(w, req)
	return w
}

// readZipEntries parses an archive body into a name→contents map, failing the
// test if the bytes are not a valid zip.
func readZipEntries(t *testing.T, b []byte) map[string][]byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("open zip: %v (body is %d bytes)", err, len(b))
	}
	out := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open entry %s: %v", f.Name, err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("read entry %s: %v", f.Name, err)
		}
		out[f.Name] = data
	}
	return out
}

func zipEntryNames(m map[string][]byte) []string {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	return names
}

// Regression: a plain file download is unchanged (no format flag).
func TestFileDownload_File_Unchanged(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(p, []byte("hi there"), 0o644); err != nil {
		t.Fatal(err)
	}
	w := zipFilesGet(t, p, "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", w.Code, w.Body.String())
	}
	if got := w.Body.String(); got != "hi there" {
		t.Errorf("body = %q, want %q", got, "hi there")
	}
}

// Regression / SDK contract: a directory without format=zip still 400s, so
// files.read()/readText() keep throwing on a directory.
func TestFileDownload_Directory_NoFormat_Rejected(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	w := zipFilesGet(t, dir, "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (directory without format=zip); body %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "director") {
		t.Errorf("body = %q, want a directory error", w.Body.String())
	}
}

// New: a directory with format=zip streams a zip of its contents, with entries
// prefixed by the directory's base name.
func TestFileDownload_Directory_Zip(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Base(dir)
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("aaa"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "b.txt"), []byte("bbb"), 0o644); err != nil {
		t.Fatal(err)
	}

	w := zipFilesGet(t, dir, "zip")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/zip" {
		t.Errorf("Content-Type = %q, want application/zip", ct)
	}
	wantCD := `attachment; filename="` + base + `.zip"`
	if cd := w.Header().Get("Content-Disposition"); cd != wantCD {
		t.Errorf("Content-Disposition = %q, want %q", cd, wantCD)
	}

	entries := readZipEntries(t, w.Body.Bytes())
	if got := string(entries[base+"/a.txt"]); got != "aaa" {
		t.Errorf("%s/a.txt = %q, want %q (entries: %v)", base, got, "aaa", zipEntryNames(entries))
	}
	if got := string(entries[base+"/sub/b.txt"]); got != "bbb" {
		t.Errorf("%s/sub/b.txt = %q, want %q (entries: %v)", base, got, "bbb", zipEntryNames(entries))
	}
}

// New: symlinks are skipped entirely (no follow) to avoid escape/loops.
func TestFileDownload_Zip_SkipsSymlinks(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Base(dir)
	if err := os.WriteFile(filepath.Join(dir, "real.txt"), []byte("real"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "real.txt"), filepath.Join(dir, "link.txt")); err != nil {
		t.Skipf("symlinks unsupported on this platform: %v", err)
	}

	w := zipFilesGet(t, dir, "zip")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", w.Code, w.Body.String())
	}
	entries := readZipEntries(t, w.Body.Bytes())
	if _, ok := entries[base+"/link.txt"]; ok {
		t.Errorf("symlink link.txt should be skipped, but it is in the archive (entries: %v)", zipEntryNames(entries))
	}
	if _, ok := entries[base+"/real.txt"]; !ok {
		t.Errorf("real.txt should be present (entries: %v)", zipEntryNames(entries))
	}
}

// New: an empty directory yields a valid (empty) zip, not an error.
func TestFileDownload_Zip_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	w := zipFilesGet(t, dir, "zip")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", w.Code, w.Body.String())
	}
	readZipEntries(t, w.Body.Bytes()) // must parse as a valid zip
}

// New (clarification): a single file requested with format=zip is returned
// as-is, not wrapped in a zip.
func TestFileDownload_File_Zip_ReturnedAsIs(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "data.bin")
	if err := os.WriteFile(p, []byte("rawbytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	w := zipFilesGet(t, p, "zip")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); strings.Contains(ct, "application/zip") {
		t.Errorf("a single file must not be zipped; Content-Type = %q", ct)
	}
	if got := w.Body.String(); got != "rawbytes" {
		t.Errorf("body = %q, want %q", got, "rawbytes")
	}
}

// Blocklisted paths are rejected before any streaming, even with format=zip —
// safePath gates the top-level argument in handleFiles.
func TestFileDownload_Zip_BlocklistedRejected(t *testing.T) {
	for _, p := range []string{"/proc", "/proc/1/mem", "/sys/kernel", "/dev/mem", "/usr/local/bin/boxd"} {
		w := zipFilesGet(t, p, "zip")
		if w.Code != http.StatusBadRequest {
			t.Errorf("path %q: status = %d, want 400 (blocklisted); body %s", p, w.Code, w.Body.String())
		}
	}
}

// Filename sanitization: a directory name containing a double-quote must not
// break the quoted Content-Disposition filename.
func TestFileDownload_Zip_FilenameSanitized(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, `weird"name`)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Skipf("cannot create dir with quote in name: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	w := zipFilesGet(t, dir, "zip")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", w.Code, w.Body.String())
	}
	cd := w.Header().Get("Content-Disposition")
	if strings.Count(cd, `"`) != 2 {
		t.Errorf("Content-Disposition has unbalanced quotes: %q", cd)
	}
	if !strings.HasSuffix(strings.TrimSuffix(cd, `"`), `.zip`) {
		t.Errorf("Content-Disposition should end with .zip before the closing quote: %q", cd)
	}
}

// Non-regular files (FIFOs, sockets, device nodes) must be skipped before any
// open — opening a FIFO O_RDONLY would otherwise block the download forever.
func TestFileDownload_Zip_SkipsNonRegularFiles(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Base(dir)
	if err := os.WriteFile(filepath.Join(dir, "real.txt"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe"), 0o644); err != nil {
		t.Skipf("mkfifo unsupported on this platform: %v", err)
	}

	// Must complete, not block on the FIFO.
	w := zipFilesGet(t, dir, "zip")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", w.Code, w.Body.String())
	}
	entries := readZipEntries(t, w.Body.Bytes())
	if _, ok := entries[base+"/pipe"]; ok {
		t.Errorf("FIFO should be skipped, but it is in the archive (entries: %v)", zipEntryNames(entries))
	}
	if _, ok := entries[base+"/real.txt"]; !ok {
		t.Errorf("real.txt should still be archived (entries: %v)", zipEntryNames(entries))
	}
}

// A symlink whose target is outside the requested directory is skipped — its
// target content never lands in the archive (no escape via symlink).
func TestFileDownload_Zip_SymlinkEscapeNotArchived(t *testing.T) {
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("TOPSECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	base := filepath.Base(dir)
	if err := os.WriteFile(filepath.Join(dir, "ok.txt"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(dir, "escape")); err != nil {
		t.Skipf("symlinks unsupported on this platform: %v", err)
	}

	w := zipFilesGet(t, dir, "zip")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", w.Code, w.Body.String())
	}
	entries := readZipEntries(t, w.Body.Bytes())
	if _, ok := entries[base+"/escape"]; ok {
		t.Errorf("escaping symlink should not be archived (entries: %v)", zipEntryNames(entries))
	}
	for name, data := range entries {
		if strings.Contains(string(data), "TOPSECRET") {
			t.Errorf("secret content leaked via symlink in entry %q", name)
		}
	}
	if _, ok := entries[base+"/ok.txt"]; !ok {
		t.Errorf("ok.txt should be archived (entries: %v)", zipEntryNames(entries))
	}
}
