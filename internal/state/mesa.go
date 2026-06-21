package state

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// MesaConfig configures the Mesa adapter. Values are sourced from
// .context/secrets.env (see secrets.env.example):
//
//	MESA_API_KEY -> APIKey
//	MESA_ORG     -> Org
//
// Mesa is a versioned, git-compatible filesystem (https://docs.mesa.dev): a repo
// is the durable FS, a "change" is a commit, and a "bookmark" is a named ref —
// which maps cleanly onto the durable /state contract (checkpoint = bookmark a
// change, branch = bookmark a change under a new name, rollback = move the
// default bookmark back to a change).
type MesaConfig struct {
	// APIKey is the bearer token for api.mesa.dev. Empty => stub (ErrNotConfigured).
	APIKey string
	// Org is the Mesa organization slug that owns the repos. Required when APIKey
	// is set.
	Org string
	// BaseURL overrides the API base (default https://api.mesa.dev/v1). Used by
	// tests to point at an httptest server.
	BaseURL string
	// DefaultBookmark is the repo's live ref (Mesa's default is "main"); rollback
	// re-homes it onto a checkpoint's change.
	DefaultBookmark string
}

// MesaProvider is the Mesa-backed durable /state adapter. It speaks the Mesa REST
// API (Bearer auth) and maps one repo per durable identity, so state follows the
// identity, not the VM. Mesa exposes the repo as a FUSE/in-process mount; the
// guest-side Mesa client realizes the actual /state mount (the directory model —
// Mount.IsBlockDevice is false), while this adapter owns the repo + version
// lifecycle.
type MesaProvider struct {
	cfg     MesaConfig
	baseURL string
	client  *http.Client
}

const defaultMesaBaseURL = "https://api.mesa.dev/v1"
const defaultMesaBookmark = "main"

// NewMesaProvider returns the Mesa adapter. It always succeeds; methods report
// ErrNotConfigured until APIKey (and Org) are set.
func NewMesaProvider(cfg MesaConfig) *MesaProvider {
	base := cfg.BaseURL
	if base == "" {
		base = defaultMesaBaseURL
	}
	if cfg.DefaultBookmark == "" {
		cfg.DefaultBookmark = defaultMesaBookmark
	}
	return &MesaProvider{
		cfg:     cfg,
		baseURL: strings.TrimRight(base, "/"),
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

var _ Provider = (*MesaProvider)(nil)

func (p *MesaProvider) configured() error {
	if p.cfg.APIKey == "" || p.cfg.Org == "" {
		return ErrNotConfigured
	}
	return nil
}

// Mount ensures the identity's repo exists (creating it on first use) and returns
// a directory-model handle. The guest-side Mesa client mounts the repo at
// mountpoint over FUSE; the durable state persists in the repo regardless of any
// single mount.
func (p *MesaProvider) Mount(ctx context.Context, identity, mountpoint string) (*Mount, error) {
	if err := p.configured(); err != nil {
		return nil, err
	}
	if err := validateName(identity); err != nil {
		return nil, fmt.Errorf("%w: identity %q: %s", ErrInvalidIdentity, identity, err)
	}
	if _, err := p.ensureRepo(ctx, identity); err != nil {
		return nil, err
	}
	return &Mount{
		Identity:      identity,
		Path:          mountpoint,
		IsBlockDevice: false,
		unmount:       func() error { return nil },
	}, nil
}

// Checkpoint names the repo's current head change as bookmark <name>. Because
// Mesa captures every write in history, the current head IS the live state, so a
// checkpoint is a label over it.
func (p *MesaProvider) Checkpoint(ctx context.Context, identity, name string) (Checkpoint, error) {
	if err := p.configured(); err != nil {
		return Checkpoint{}, err
	}
	if err := validateName(name); err != nil {
		return Checkpoint{}, fmt.Errorf("state: checkpoint name %q: %w", name, err)
	}
	repo, err := p.getRepo(ctx, identity)
	if err != nil {
		return Checkpoint{}, err
	}
	if repo.HeadChangeID == "" {
		return Checkpoint{}, fmt.Errorf("state: checkpoint %q: repo has no head change", identity)
	}
	createdAt := time.Now().UTC()
	var bm mesaBookmark
	if err := p.do(ctx, http.MethodPost, p.repoPath(identity, "bookmarks"),
		mesaCreateBookmark{Name: name, ChangeID: repo.HeadChangeID}, &bm); err != nil {
		return Checkpoint{}, fmt.Errorf("state: checkpoint %q/%q: %w", identity, name, err)
	}
	return Checkpoint{Name: name, ID: bm.ChangeID, CreatedAt: createdAt}, nil
}

// Branch creates bookmark <newBranch> at the change that <fromCheckpoint> points
// at — Mesa's COW fork. Returns ErrCheckpointNotFound if fromCheckpoint is absent.
func (p *MesaProvider) Branch(ctx context.Context, identity, fromCheckpoint, newBranch string) error {
	if err := p.configured(); err != nil {
		return err
	}
	if err := validateName(fromCheckpoint); err != nil {
		return fmt.Errorf("state: from-checkpoint %q: %w", fromCheckpoint, err)
	}
	if err := validateName(newBranch); err != nil {
		return fmt.Errorf("state: branch name %q: %w", newBranch, err)
	}
	from, err := p.getBookmark(ctx, identity, fromCheckpoint)
	if err != nil {
		return err // already maps 404 -> ErrCheckpointNotFound
	}
	if err := p.do(ctx, http.MethodPost, p.repoPath(identity, "bookmarks"),
		mesaCreateBookmark{Name: newBranch, ChangeID: from.ChangeID}, nil); err != nil {
		return fmt.Errorf("state: branch %q/%q: %w", identity, newBranch, err)
	}
	return nil
}

// Rollback re-homes the repo's default bookmark onto the change <toCheckpoint>
// points at. Returns ErrCheckpointNotFound if toCheckpoint is absent.
func (p *MesaProvider) Rollback(ctx context.Context, identity, toCheckpoint string) error {
	if err := p.configured(); err != nil {
		return err
	}
	if err := validateName(toCheckpoint); err != nil {
		return fmt.Errorf("state: to-checkpoint %q: %w", toCheckpoint, err)
	}
	to, err := p.getBookmark(ctx, identity, toCheckpoint)
	if err != nil {
		return err
	}
	if err := p.do(ctx, http.MethodPatch, p.repoPath(identity, "bookmarks/"+p.cfg.DefaultBookmark),
		mesaMoveBookmark{ChangeID: to.ChangeID}, nil); err != nil {
		return fmt.Errorf("state: rollback %q/%q: %w", identity, toCheckpoint, err)
	}
	return nil
}

// ListCheckpoints lists the identity's bookmarks, excluding the default (live)
// bookmark, which is not a checkpoint.
func (p *MesaProvider) ListCheckpoints(ctx context.Context, identity string) ([]Checkpoint, error) {
	if err := p.configured(); err != nil {
		return nil, err
	}
	if err := validateName(identity); err != nil {
		return nil, fmt.Errorf("%w: identity %q: %s", ErrInvalidIdentity, identity, err)
	}
	var resp mesaListBookmarks
	if err := p.do(ctx, http.MethodGet, p.repoPath(identity, "bookmarks"), nil, &resp); err != nil {
		return nil, fmt.Errorf("state: list checkpoints %q: %w", identity, err)
	}
	out := make([]Checkpoint, 0, len(resp.Bookmarks))
	for _, b := range resp.Bookmarks {
		if b.IsDefault || b.Name == p.cfg.DefaultBookmark {
			continue
		}
		// Mesa's list omits per-bookmark timestamps; the ID carries the change.
		out = append(out, Checkpoint{Name: b.Name, ID: b.ChangeID})
	}
	return out, nil
}

// --- Mesa REST plumbing ------------------------------------------------------

type mesaRepo struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	DefaultBookmark string `json:"default_bookmark"`
	HeadChangeID    string `json:"head_change_id"`
}

type mesaBookmark struct {
	Name      string `json:"name"`
	ChangeID  string `json:"change_id"`
	IsDefault bool   `json:"is_default"`
}

type mesaListBookmarks struct {
	Bookmarks  []mesaBookmark `json:"bookmarks"`
	NextCursor string         `json:"next_cursor"`
	HasMore    bool           `json:"has_more"`
}

type mesaCreateRepo struct {
	Name            string `json:"name"`
	DefaultBookmark string `json:"default_bookmark,omitempty"`
}

type mesaCreateBookmark struct {
	Name     string `json:"name"`
	ChangeID string `json:"change_id"`
}

type mesaMoveBookmark struct {
	ChangeID string `json:"change_id"`
}

func (p *MesaProvider) repoPath(identity, sub string) string {
	return "/" + p.cfg.Org + "/" + identity + "/" + sub
}

// ensureRepo returns the identity's repo, creating it if it does not exist.
func (p *MesaProvider) ensureRepo(ctx context.Context, identity string) (*mesaRepo, error) {
	repo, err := p.getRepo(ctx, identity)
	if err == nil {
		return repo, nil
	}
	if !isMesaNotFound(err) {
		return nil, err
	}
	var created mesaRepo
	if cerr := p.do(ctx, http.MethodPost, "/"+p.cfg.Org+"/repos",
		mesaCreateRepo{Name: identity, DefaultBookmark: p.cfg.DefaultBookmark}, &created); cerr != nil {
		return nil, fmt.Errorf("state: create repo %q: %w", identity, cerr)
	}
	return &created, nil
}

func (p *MesaProvider) getRepo(ctx context.Context, identity string) (*mesaRepo, error) {
	var repo mesaRepo
	if err := p.do(ctx, http.MethodGet, "/"+p.cfg.Org+"/"+identity, nil, &repo); err != nil {
		return nil, err
	}
	return &repo, nil
}

func (p *MesaProvider) getBookmark(ctx context.Context, identity, name string) (*mesaBookmark, error) {
	var bm mesaBookmark
	if err := p.do(ctx, http.MethodGet, p.repoPath(identity, "bookmarks/"+name), nil, &bm); err != nil {
		if isMesaNotFound(err) {
			return nil, fmt.Errorf("state: %q/%q: %w", identity, name, ErrCheckpointNotFound)
		}
		return nil, err
	}
	return &bm, nil
}

// mesaError carries the HTTP status so callers can branch on 404.
type mesaError struct {
	status int
	body   string
}

func (e *mesaError) Error() string {
	return fmt.Sprintf("mesa api: status %d: %s", e.status, e.body)
}

func isMesaNotFound(err error) bool {
	var me *mesaError
	if errors.As(err, &me) {
		return me.status == http.StatusNotFound
	}
	return false
}

// do performs a JSON request against the Mesa API. reqBody may be nil (no body);
// out may be nil (response ignored). Non-2xx returns a *mesaError.
func (p *MesaProvider) do(ctx context.Context, method, path string, reqBody, out any) error {
	var body io.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.baseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.cfg.APIKey)
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return &mesaError{status: resp.StatusCode, body: strings.TrimSpace(string(b))}
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}
