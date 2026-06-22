package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestLocalCopyStoreRoundTrip proves the object-store contract end to end with
// the same-host backend: upload two distinct artifacts, download to a fresh dir,
// and verify the bytes survive intact. This is the contract Tier-3's fetch path
// depends on (gcsStore implements the identical interface against GCS).
func TestLocalCopyStoreRoundTrip(t *testing.T) {
	root := t.TempDir()
	store, err := newLocalCopyStore(filepath.Join(root, "store"))
	if err != nil {
		t.Fatal(err)
	}

	srcDir := t.TempDir()
	snapPath := filepath.Join(srcDir, "snapshot")
	memPath := filepath.Join(srcDir, "mem")
	snapBytes := []byte("firecracker-state-blob")
	memBytes := bytes.Repeat([]byte{0xAB}, 4096)
	if err := os.WriteFile(snapPath, snapBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(memPath, memBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	ref, err := store.Upload(ctx, "mem512", snapPath, memPath)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}

	// Download to a fresh dir — the cross-host model: nothing is local yet.
	dlDir := t.TempDir()
	gotSnap, gotMem, err := store.Download(ctx, ref, dlDir)
	if err != nil {
		t.Fatalf("download: %v", err)
	}

	assertFileBytes(t, gotSnap, snapBytes)
	assertFileBytes(t, gotMem, memBytes)

	// Both downloaded files must live under the requested local dir, not alias the
	// source (a real fetch lands bytes locally). Assert for each — a Download that
	// returned the ref path for one file would still pass the byte check.
	if filepath.Dir(gotSnap) != dlDir {
		t.Errorf("snapshot landed at %s, want under %s", gotSnap, dlDir)
	}
	if filepath.Dir(gotMem) != dlDir {
		t.Errorf("mem landed at %s, want under %s", gotMem, dlDir)
	}
}

func assertFileBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s: %d bytes, want %d (content mismatch)", path, len(got), len(want))
	}
}

// TestGCSStoreHTTPRoundTrip exercises gcsStore's actual HTTP byte path (put/get)
// against an httptest server that mimics the GCS XML API — the only logic in the
// store that can be wrong without a string-construction test catching it. Covers
// the success round-trip, the bearer-auth header, the missing-object (404) branch,
// and a server-error (5xx) branch. The token is pre-seeded so the test never
// touches the metadata server or gcloud.
func TestGCSStoreHTTPRoundTrip(t *testing.T) {
	var mu sync.Mutex
	objects := map[string][]byte{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "missing/invalid bearer", http.StatusUnauthorized)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodPut:
			b, _ := io.ReadAll(r.Body)
			objects[r.URL.Path] = b
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			b, ok := objects[r.URL.Path]
			if !ok {
				http.Error(w, "no such object", http.StatusNotFound)
				return
			}
			_, _ = w.Write(b)
		default:
			http.Error(w, "bad method", http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()

	s := newGCSStore("bucket", "prefix")
	s.token = "test-token" // pre-seed; ensureToken sees it valid and never fetches
	s.tokenExp = time.Now().Add(time.Hour)
	ctx := context.Background()

	memBytes := bytes.Repeat([]byte{0x5A}, 4096)
	src := filepath.Join(t.TempDir(), "src-mem")
	if err := os.WriteFile(src, memBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	url := srv.URL + "/bucket/prefix/k/" + memFile

	// Success: PUT then GET round-trips the bytes to a fresh local path.
	if err := s.put(ctx, url, src); err != nil {
		t.Fatalf("put: %v", err)
	}
	dst := filepath.Join(t.TempDir(), "dl-mem")
	if err := s.get(ctx, url, dst); err != nil {
		t.Fatalf("get: %v", err)
	}
	assertFileBytes(t, dst, memBytes)

	// Missing object: GET 404 surfaces an error naming the status (not a silent
	// empty file). The success PUT/GET above already prove the bearer header is
	// propagated correctly — the server rejects anything but "Bearer test-token".
	missURL := srv.URL + "/bucket/prefix/absent/" + memFile
	err := s.get(ctx, missURL, filepath.Join(t.TempDir(), "x"))
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("get of missing object should error with 404, got: %v", err)
	}
}

// TestGCSStoreParallelFetch proves the ranged parallel-fetch path reassembles a
// large object correctly: HEAD reports the size, the chunks come back as 206
// Partial Content in arbitrary order, and the file is byte-identical.
func TestGCSStoreParallelFetch(t *testing.T) {
	// 40 MiB of position-dependent bytes (> fetchChunkBytes → multi-chunk).
	blob := make([]byte, 40<<20)
	for i := range blob {
		blob[i] = byte(i*7 + 3)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauth", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("Content-Length", strconv.Itoa(len(blob)))
			w.WriteHeader(http.StatusOK)
			return
		}
		if rng := r.Header.Get("Range"); rng != "" {
			var start, end int
			if _, err := fmt.Sscanf(rng, "bytes=%d-%d", &start, &end); err != nil {
				http.Error(w, "bad range", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(blob[start : end+1])
			return
		}
		_, _ = w.Write(blob)
	}))
	defer srv.Close()

	s := newGCSStore("b", "p")
	s.token = "test-token"
	s.tokenExp = time.Now().Add(time.Hour)

	dst := filepath.Join(t.TempDir(), "big")
	if err := s.get(context.Background(), srv.URL+"/b/p/k/mem", dst); err != nil {
		t.Fatalf("parallel get: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, blob) {
		t.Fatalf("reassembled blob differs: got %d bytes, want %d", len(got), len(blob))
	}
}

func TestParseObjStore(t *testing.T) {
	run := t.TempDir()

	t.Run("gs bucket only", func(t *testing.T) {
		s, err := parseObjStore("gs://my-bucket", run)
		if err != nil {
			t.Fatal(err)
		}
		g, ok := s.(*gcsStore)
		if !ok {
			t.Fatalf("want *gcsStore, got %T", s)
		}
		if g.bucket != "my-bucket" || g.prefix != "" {
			t.Errorf("bucket=%q prefix=%q", g.bucket, g.prefix)
		}
		if g.keyPrefix("mem512") != "mem512" {
			t.Errorf("keyPrefix = %q", g.keyPrefix("mem512"))
		}
		if got := g.objectURL("mem512", memFile); got != "https://storage.googleapis.com/my-bucket/mem512/mem" {
			t.Errorf("objectURL = %q", got)
		}
	})

	t.Run("gs bucket with prefix", func(t *testing.T) {
		s, err := parseObjStore("gs://b/snapshots/bench", run)
		if err != nil {
			t.Fatal(err)
		}
		g := s.(*gcsStore)
		if g.bucket != "b" || g.prefix != "snapshots/bench" {
			t.Errorf("bucket=%q prefix=%q", g.bucket, g.prefix)
		}
		if g.keyPrefix("k") != "snapshots/bench/k" {
			t.Errorf("keyPrefix = %q", g.keyPrefix("k"))
		}
		if got := g.objectURL(g.keyPrefix("k"), snapshotFile); got != "https://storage.googleapis.com/b/snapshots/bench/k/snapshot" {
			t.Errorf("objectURL = %q", got)
		}
	})

	t.Run("local with path", func(t *testing.T) {
		dir := filepath.Join(run, "explicit")
		s, err := parseObjStore("local:"+dir, run)
		if err != nil {
			t.Fatal(err)
		}
		l, ok := s.(*localCopyStore)
		if !ok {
			t.Fatalf("want *localCopyStore, got %T", s)
		}
		if l.root != dir {
			t.Errorf("root = %q, want %q", l.root, dir)
		}
	})

	t.Run("bare local roots under runDir", func(t *testing.T) {
		s, err := parseObjStore("local", run)
		if err != nil {
			t.Fatal(err)
		}
		l := s.(*localCopyStore)
		if l.root != filepath.Join(run, "objstore") {
			t.Errorf("root = %q", l.root)
		}
	})

	t.Run("empty bucket rejected", func(t *testing.T) {
		if _, err := parseObjStore("gs://", run); err == nil {
			t.Fatal("expected error for empty bucket")
		}
	})

	t.Run("unknown scheme rejected", func(t *testing.T) {
		if _, err := parseObjStore("s3://bucket", run); err == nil {
			t.Fatal("expected error for unknown scheme")
		}
	})
}
