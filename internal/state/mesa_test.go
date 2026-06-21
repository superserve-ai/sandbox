package state

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// fakeMesa is a minimal stateful stand-in for the Mesa REST API: enough to drive
// the adapter's repo + bookmark lifecycle and assert it speaks the documented
// shapes (POST /{org}/repos, GET/POST /{org}/{repo}/bookmarks, PATCH a bookmark).
type fakeMesa struct {
	org       string
	head      string            // repo head change id (empty until repo created)
	bookmarks map[string]string // name -> change_id
	calls     []string          // "METHOD path" log
	authSeen  string
}

func newFakeMesa(org string) *fakeMesa {
	return &fakeMesa{org: org, bookmarks: map[string]string{}}
}

func (f *fakeMesa) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.authSeen = r.Header.Get("Authorization")
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		// /{org}/repos
		if len(parts) == 2 && parts[0] == f.org && parts[1] == "repos" && r.Method == http.MethodPost {
			var body mesaCreateRepo
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.head = "chg-initial"
			if body.DefaultBookmark != "" {
				f.bookmarks[body.DefaultBookmark] = f.head
			}
			writeJSON(w, 201, mesaRepo{ID: "r1", Name: body.Name, DefaultBookmark: body.DefaultBookmark, HeadChangeID: f.head})
			return
		}
		// /{org}/{repo}
		if len(parts) == 2 && parts[0] == f.org && r.Method == http.MethodGet {
			if f.head == "" {
				w.WriteHeader(404)
				return
			}
			writeJSON(w, 200, mesaRepo{ID: "r1", Name: parts[1], DefaultBookmark: "main", HeadChangeID: f.head})
			return
		}
		// /{org}/{repo}/bookmarks  (list / create)
		if len(parts) == 3 && parts[2] == "bookmarks" {
			switch r.Method {
			case http.MethodGet:
				var bms []mesaBookmark
				for n, c := range f.bookmarks {
					bms = append(bms, mesaBookmark{Name: n, ChangeID: c, IsDefault: n == "main"})
				}
				writeJSON(w, 200, mesaListBookmarks{Bookmarks: bms})
				return
			case http.MethodPost:
				var body mesaCreateBookmark
				_ = json.NewDecoder(r.Body).Decode(&body)
				f.bookmarks[body.Name] = body.ChangeID
				writeJSON(w, 201, mesaBookmark{Name: body.Name, ChangeID: body.ChangeID})
				return
			}
		}
		// /{org}/{repo}/bookmarks/{name}  (get / move)
		if len(parts) == 4 && parts[2] == "bookmarks" {
			name := parts[3]
			switch r.Method {
			case http.MethodGet:
				c, ok := f.bookmarks[name]
				if !ok {
					w.WriteHeader(404)
					return
				}
				writeJSON(w, 200, mesaBookmark{Name: name, ChangeID: c, IsDefault: name == "main"})
				return
			case http.MethodPatch:
				var body mesaMoveBookmark
				_ = json.NewDecoder(r.Body).Decode(&body)
				f.bookmarks[name] = body.ChangeID
				writeJSON(w, 200, mesaBookmark{Name: name, ChangeID: body.ChangeID})
				return
			}
		}
		w.WriteHeader(http.StatusBadRequest)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func newTestMesa(t *testing.T) (*MesaProvider, *fakeMesa) {
	t.Helper()
	fake := newFakeMesa("acme")
	srv := httptest.NewServer(fake.handler())
	t.Cleanup(srv.Close)
	return NewMesaProvider(MesaConfig{APIKey: "k-test", Org: "acme", BaseURL: srv.URL}), fake
}

func TestMesaNotConfigured(t *testing.T) {
	p := NewMesaProvider(MesaConfig{}) // no key/org
	if _, err := p.Mount(context.Background(), "act-1", "/state"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("want ErrNotConfigured, got %v", err)
	}
}

func TestMesaMountCreatesRepoThenReuses(t *testing.T) {
	p, fake := newTestMesa(t)
	ctx := context.Background()

	m, err := p.Mount(ctx, "act-1", "/state")
	if err != nil {
		t.Fatal(err)
	}
	if m.IsBlockDevice {
		t.Error("Mesa is a directory/FUSE provider; IsBlockDevice must be false")
	}
	if !strings.HasPrefix(fake.authSeen, "Bearer k-test") {
		t.Errorf("missing/incorrect bearer auth: %q", fake.authSeen)
	}
	// First mount: GET repo (404) then POST /acme/repos.
	if !contains(fake.calls, "POST /acme/repos") {
		t.Fatalf("first mount should create the repo; calls=%v", fake.calls)
	}
	// Second mount reuses (GET repo 200, no second create).
	fake.calls = nil
	if _, err := p.Mount(ctx, "act-1", "/state"); err != nil {
		t.Fatal(err)
	}
	if contains(fake.calls, "POST /acme/repos") {
		t.Fatalf("second mount must not re-create the repo; calls=%v", fake.calls)
	}
}

func TestMesaCheckpointBranchRollbackLifecycle(t *testing.T) {
	p, fake := newTestMesa(t)
	ctx := context.Background()
	if _, err := p.Mount(ctx, "act-1", "/state"); err != nil {
		t.Fatal(err)
	}

	// Checkpoint bookmarks the current head change.
	cp, err := p.Checkpoint(ctx, "act-1", "cp1")
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if cp.ID != "chg-initial" {
		t.Errorf("checkpoint should point at head change, got %q", cp.ID)
	}

	// List shows cp1 but not the default bookmark.
	cps, err := p.ListCheckpoints(ctx, "act-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(cps) != 1 || cps[0].Name != "cp1" {
		t.Fatalf("ListCheckpoints = %+v, want just [cp1] (default excluded)", cps)
	}

	// Branch b1 from cp1 → a new bookmark at cp1's change.
	if err := p.Branch(ctx, "act-1", "cp1", "b1"); err != nil {
		t.Fatalf("branch: %v", err)
	}
	if fake.bookmarks["b1"] != "chg-initial" {
		t.Errorf("branch b1 should point at cp1's change, got %q", fake.bookmarks["b1"])
	}

	// Rollback moves the default bookmark onto cp1's change.
	if err := p.Rollback(ctx, "act-1", "cp1"); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if fake.bookmarks["main"] != "chg-initial" {
		t.Errorf("rollback should move main to cp1's change, got %q", fake.bookmarks["main"])
	}
}

func TestMesaMissingCheckpointErrors(t *testing.T) {
	p, _ := newTestMesa(t)
	ctx := context.Background()
	if _, err := p.Mount(ctx, "act-1", "/state"); err != nil {
		t.Fatal(err)
	}
	if err := p.Branch(ctx, "act-1", "nope", "b1"); !errors.Is(err, ErrCheckpointNotFound) {
		t.Errorf("branch from missing checkpoint: want ErrCheckpointNotFound, got %v", err)
	}
	if err := p.Rollback(ctx, "act-1", "nope"); !errors.Is(err, ErrCheckpointNotFound) {
		t.Errorf("rollback to missing checkpoint: want ErrCheckpointNotFound, got %v", err)
	}
}

// TestMesaLiveLifecycle exercises the REAL Mesa API. Gated on MESA_LIVE_API_KEY
// (+ optional MESA_LIVE_ORG; whoami-derivable). It creates a throwaway repo, runs
// the full checkpoint/branch/rollback lifecycle, and deletes the repo.
func TestMesaLiveLifecycle(t *testing.T) {
	key := os.Getenv("MESA_LIVE_API_KEY")
	org := os.Getenv("MESA_LIVE_ORG")
	if key == "" || org == "" {
		t.Skip("set MESA_LIVE_API_KEY and MESA_LIVE_ORG to run the live Mesa test")
	}
	p := NewMesaProvider(MesaConfig{APIKey: key, Org: org})
	ctx := context.Background()
	repo := "ss-it-live"
	mesaLiveDelete(key, org, repo) // ensure a clean slate
	defer mesaLiveDelete(key, org, repo)

	m, err := p.Mount(ctx, repo, "/state")
	if err != nil {
		t.Fatalf("Mount: %v", err)
	}
	if m.IsBlockDevice {
		t.Error("Mesa mount should be directory-model")
	}
	cp, err := p.Checkpoint(ctx, repo, "cp1")
	if err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	if cp.ID == "" {
		t.Error("checkpoint should carry the head change id")
	}
	cps, err := p.ListCheckpoints(ctx, repo)
	if err != nil {
		t.Fatalf("ListCheckpoints: %v", err)
	}
	if !checkpointNamed(cps, "cp1") {
		t.Fatalf("cp1 not listed: %+v", cps)
	}
	if err := p.Branch(ctx, repo, "cp1", "b1"); err != nil {
		t.Fatalf("Branch: %v", err)
	}
	if err := p.Rollback(ctx, repo, "cp1"); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if err := p.Branch(ctx, repo, "ghost", "b2"); !errors.Is(err, ErrCheckpointNotFound) {
		t.Errorf("branch from missing checkpoint: want ErrCheckpointNotFound, got %v", err)
	}
}

func mesaLiveDelete(key, org, repo string) {
	req, _ := http.NewRequest(http.MethodDelete, defaultMesaBaseURL+"/"+org+"/"+repo, nil)
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
}

func checkpointNamed(cps []Checkpoint, name string) bool {
	for _, c := range cps {
		if c.Name == name {
			return true
		}
	}
	return false
}

func contains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}
