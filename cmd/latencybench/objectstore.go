package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// objectStore round-trips the two Tier-3 snapshot artifacts — the Firecracker
// state file and the guest memory file — through storage that a *different* host
// would read from on a cold cross-host wake. Upload runs once per snapshot;
// Download is the per-wake T_fetch long pole the Tier-3 gate (p50<1s, p99<2s) is
// decided on.
//
// Two implementations:
//   - gcsStore:       shells out to `gcloud storage cp` against a real GCS bucket
//     — the faithful cross-host fetch (bytes leave the host and
//     come back over the network).
//   - localCopyStore: a same-host file copy — the fetch-cost FLOOR (no network),
//     used for unit tests and for isolating restore cost from
//     network cost. Its numbers are a lower bound, not the gate.
type objectStore interface {
	// Upload publishes the snapshot+mem files under a logical name and returns a
	// reference that a later Download resolves.
	Upload(ctx context.Context, name, snapPath, memPath string) (string, error)
	// Download fetches a previously-uploaded snapshot into localDir, returning the
	// local snapshot and mem paths.
	Download(ctx context.Context, ref, localDir string) (snapPath, memPath string, err error)
	// Label identifies the store in output and makes clear whether its fetch
	// numbers are real (network) or a same-host floor.
	Label() string
}

// snapshotFile and memFile are the two object names a snapshot decomposes into.
const (
	snapshotFile = "snapshot"
	memFile      = "mem"
)

// -----------------------------------------------------------------------------
// gcsStore — real cross-host fetch via `gcloud storage cp`
// -----------------------------------------------------------------------------

// gcsStore round-trips snapshots through a GCS bucket using in-process HTTP
// against the JSON/XML object API. It deliberately does NOT shell out to
// `gcloud storage cp`: that spawns a Python CLI (~1.1s of process+auth startup
// per call) which would dominate and corrupt the T_fetch measurement. A resident
// HTTP client with a cached bearer token is what a production wake path would
// use, so it is what this benchmark measures. Using net/http (rather than
// cloud.google.com/go/storage) keeps the tool a leaf with no new module
// dependency.
type gcsStore struct {
	bucket string
	prefix string
	client *http.Client

	mu       sync.Mutex
	token    string
	tokenExp time.Time // when the cached token expires
}

// tokenRefreshSkew refreshes the token this long before its stated expiry, so a
// long sweep (>1h, easily reached at the plan's ≥1000 iters × multi-second cold
// fetches) never issues a request with an about-to-expire token.
const tokenRefreshSkew = 5 * time.Minute

// gcloudTokenTTL is the assumed lifetime when the source can't tell us (the
// gcloud CLI fallback prints no expiry); GCP access tokens live ~1h.
const gcloudTokenTTL = 50 * time.Minute

func newGCSStore(bucket, prefix string) *gcsStore {
	return &gcsStore{
		bucket: bucket,
		prefix: strings.Trim(prefix, "/"),
		// No client-level timeout: a cold 512MiB mem-file fetch is the whole point;
		// cancellation rides on the context instead.
		client: &http.Client{},
	}
}

// keyPrefix is the object-key prefix for a named snapshot ("<prefix>/<name>").
func (s *gcsStore) keyPrefix(name string) string {
	if s.prefix != "" {
		return s.prefix + "/" + name
	}
	return name
}

// objectURL is the XML-API URL for one file under a snapshot ref.
func (s *gcsStore) objectURL(ref, file string) string {
	return "https://storage.googleapis.com/" + s.bucket + "/" + ref + "/" + file
}

func (s *gcsStore) Upload(ctx context.Context, name, snapPath, memPath string) (string, error) {
	ref := s.keyPrefix(name)
	if err := s.put(ctx, s.objectURL(ref, snapshotFile), snapPath); err != nil {
		return "", err
	}
	if err := s.put(ctx, s.objectURL(ref, memFile), memPath); err != nil {
		return "", err
	}
	return ref, nil
}

func (s *gcsStore) Download(ctx context.Context, ref, localDir string) (string, string, error) {
	snapPath := filepath.Join(localDir, snapshotFile)
	memPath := filepath.Join(localDir, memFile)
	if err := s.get(ctx, s.objectURL(ref, snapshotFile), snapPath); err != nil {
		return "", "", err
	}
	if err := s.get(ctx, s.objectURL(ref, memFile), memPath); err != nil {
		return "", "", err
	}
	return snapPath, memPath, nil
}

// put streams a local file to the object URL with a single PUT (XML API; fine
// for objects up to 5GiB — a guest mem file larger than that can't be staged
// this way, which caps Tier-3 at ~5GiB mem; see RESULTS.md).
func (s *gcsStore) put(ctx context.Context, url, localPath string) error {
	// build opens a FRESH file each attempt: the http client consumes+closes the
	// body, so a 401-retry needs a new reader, not a rewound one.
	resp, err := s.doAuthed(ctx, func(tok string) (*http.Request, error) {
		f, err := os.Open(localPath)
		if err != nil {
			return nil, err
		}
		st, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, f)
		if err != nil {
			f.Close()
			return nil, err
		}
		req.ContentLength = st.Size()
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/octet-stream")
		return req, nil // f is closed by the http client after the request
	})
	if err != nil {
		return fmt.Errorf("PUT %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("PUT %s: status %d: %s", url, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// get streams the object URL to a local file. This is the T_fetch long pole.
func (s *gcsStore) get(ctx context.Context, url, localPath string) error {
	resp, err := s.doAuthed(ctx, func(tok string) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		return req, nil
	})
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("GET %s: status %d: %s", url, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	out, err := os.Create(localPath)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, resp.Body); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// doAuthed performs an authenticated request, force-refreshing the token and
// retrying ONCE on a 401/403. build must produce a fresh *http.Request each call
// (its body is consumed by the first attempt). This is the safety net for a
// token that expired mid-sweep despite the proactive refresh in ensureToken.
func (s *gcsStore) doAuthed(ctx context.Context, build func(tok string) (*http.Request, error)) (*http.Response, error) {
	tok, err := s.ensureToken(ctx, false)
	if err != nil {
		return nil, err
	}
	req, err := build(tok)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		resp.Body.Close()
		if tok, err = s.ensureToken(ctx, true); err != nil { // force refresh
			return nil, err
		}
		req, err = build(tok)
		if err != nil {
			return nil, err
		}
		if resp, err = s.client.Do(req); err != nil {
			return nil, err
		}
	}
	return resp, nil
}

// ensureToken returns a valid OAuth access token, refreshing it when forced or
// within tokenRefreshSkew of expiry. Cached under a mutex so a sweep does not
// re-fetch per request, but does refresh before the ~1h token would expire.
func (s *gcsStore) ensureToken(ctx context.Context, force bool) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !force && s.token != "" && time.Until(s.tokenExp) > tokenRefreshSkew {
		return s.token, nil
	}
	tok, ttl, err := fetchAccessToken(ctx, s.client)
	if err != nil {
		return "", err
	}
	s.token = tok
	s.tokenExp = time.Now().Add(ttl)
	return tok, nil
}

// fetchAccessToken gets a bearer token and its lifetime, preferring the GCE
// metadata server (the benchmark's real home — zero extra process) and falling
// back to the gcloud CLI (off-GCE dev). The CLI is only ever spawned here, never
// on the fetch path.
func fetchAccessToken(ctx context.Context, client *http.Client) (string, time.Duration, error) {
	if tok, ttl, ok := metadataToken(ctx, client); ok {
		return tok, ttl, nil
	}
	out, err := exec.CommandContext(ctx, "gcloud", "auth", "print-access-token").Output()
	if err != nil {
		return "", 0, fmt.Errorf("no GCE metadata token and gcloud fallback failed: %w", err)
	}
	return strings.TrimSpace(string(out)), gcloudTokenTTL, nil
}

// metadataToken fetches a token from the GCE metadata server. It closes the
// response body before returning so the connection is never held open across the
// gcloud fallback exec. Returns ok=false (not an error) so the caller falls back.
func metadataToken(ctx context.Context, client *http.Client) (string, time.Duration, bool) {
	mctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(mctx, http.MethodGet,
		"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", nil)
	if err != nil {
		return "", 0, false
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", 0, false
	}
	var t struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if json.NewDecoder(resp.Body).Decode(&t) != nil || t.AccessToken == "" {
		return "", 0, false
	}
	ttl := time.Duration(t.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = gcloudTokenTTL
	}
	return t.AccessToken, ttl, true
}

func (s *gcsStore) Label() string {
	return "gcs://" + s.bucket + " (REAL network fetch, in-process HTTP)"
}

// -----------------------------------------------------------------------------
// localCopyStore — same-host fetch floor (no network)
// -----------------------------------------------------------------------------

// localCopyStore stages snapshots under a local root and "fetches" them with a
// plain file copy. It carries no network latency, so its T_fetch is a FLOOR
// (restore-only cost). Useful for unit tests and for separating restore cost
// from network cost; not a substitute for the gcsStore gate run.
type localCopyStore struct {
	root string
}

func newLocalCopyStore(root string) (*localCopyStore, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	return &localCopyStore{root: root}, nil
}

func (s *localCopyStore) Upload(_ context.Context, name, snapPath, memPath string) (string, error) {
	dir := filepath.Join(s.root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	if err := copyFile(snapPath, filepath.Join(dir, snapshotFile)); err != nil {
		return "", err
	}
	if err := copyFile(memPath, filepath.Join(dir, memFile)); err != nil {
		return "", err
	}
	return dir, nil
}

func (s *localCopyStore) Download(_ context.Context, ref, localDir string) (string, string, error) {
	snapPath := filepath.Join(localDir, snapshotFile)
	memPath := filepath.Join(localDir, memFile)
	if err := copyFile(filepath.Join(ref, snapshotFile), snapPath); err != nil {
		return "", "", err
	}
	if err := copyFile(filepath.Join(ref, memFile), memPath); err != nil {
		return "", "", err
	}
	return snapPath, memPath, nil
}

func (s *localCopyStore) Label() string { return "local-copy (same-host FLOOR, no network)" }

// copyFile copies src to dst, preserving nothing but the bytes (the benchmark
// only cares that the restore sees identical content).
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// -----------------------------------------------------------------------------
// flag parsing
// -----------------------------------------------------------------------------

// parseObjStore builds an objectStore from the -objstore flag:
//
//	gs://bucket            -> gcsStore (real cross-host fetch)
//	gs://bucket/some/prefix-> gcsStore under that prefix
//	local:/path            -> localCopyStore rooted at /path (same-host floor)
//	local                  -> localCopyStore rooted at <runDir>/objstore
//
// runDir is used only to root a bare "local" store.
func parseObjStore(spec, runDir string) (objectStore, error) {
	switch {
	case strings.HasPrefix(spec, "gs://"):
		rest := strings.TrimPrefix(spec, "gs://")
		bucket, prefix, _ := strings.Cut(rest, "/")
		if bucket == "" {
			return nil, fmt.Errorf("gs:// spec %q has no bucket", spec)
		}
		return newGCSStore(bucket, prefix), nil
	case spec == "local":
		return newLocalCopyStore(filepath.Join(runDir, "objstore"))
	case strings.HasPrefix(spec, "local:"):
		return newLocalCopyStore(strings.TrimPrefix(spec, "local:"))
	default:
		return nil, fmt.Errorf("unknown objstore spec %q (want gs://bucket[/prefix] or local[:/path])", spec)
	}
}
