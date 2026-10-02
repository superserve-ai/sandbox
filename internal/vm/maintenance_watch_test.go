package vm

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

// The maintenance watcher is a deploy-time shell script; these tests run the
// real file against fake metadata and webhook endpoints, the same way the
// rollback-guard tests exercise their script.
type watchWorld struct {
	t         *testing.T
	script    string
	state     string
	body      string // what the metadata endpoint returns
	code      int
	mu        sync.Mutex
	delivered []string
	webhook   *httptest.Server
	metadata  *httptest.Server
}

func newWatchWorld(t *testing.T) *watchWorld {
	t.Helper()
	w := &watchWorld{
		t:      t,
		script: filepath.Join("..", "..", "deploy", "maintenance-watch.sh"),
		state:  filepath.Join(t.TempDir(), "maintenance-notice"),
		code:   200,
	}
	if _, err := os.Stat(w.script); err != nil {
		t.Fatalf("watcher script: %v", err)
	}
	w.metadata = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		w.mu.Lock()
		code, body := w.code, w.body
		w.mu.Unlock()
		rw.WriteHeader(code)
		_, _ = rw.Write([]byte(body))
	}))
	t.Cleanup(w.metadata.Close)
	w.webhook = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		w.mu.Lock()
		w.delivered = append(w.delivered, string(buf))
		w.mu.Unlock()
		rw.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(w.webhook.Close)
	return w
}

// poll runs one watcher invocation against the current fake metadata body.
func (w *watchWorld) poll(body string) {
	w.t.Helper()
	w.mu.Lock()
	w.body = body
	w.mu.Unlock()
	cmd := exec.Command("/bin/sh", w.script)
	cmd.Env = append(os.Environ(),
		"MAINTENANCE_WATCH_ENDPOINT="+w.metadata.URL,
		"MAINTENANCE_WATCH_STATE="+w.state,
		"MAINTENANCE_ALERT_WEBHOOK="+w.webhook.URL,
	)
	_ = cmd.Run() // non-zero is a delivery failure, asserted via posts()
}

func (w *watchWorld) posts() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.delivered...)
}

// alt=json makes the metadata server return the JSON-encoded value, so "no
// maintenance scheduled" arrives as a QUOTED "NONE". Treating that as a live
// notice pages every host for nothing — the bug this guards.
func TestMaintenanceWatchQuotedNoneIsSilent(t *testing.T) {
	w := newWatchWorld(t)
	w.poll(`"NONE"`)
	if got := w.posts(); len(got) != 0 {
		t.Fatalf("quoted NONE must not alert, got %v", got)
	}
	w.poll("NONE") // the unquoted form must stay silent too
	if got := w.posts(); len(got) != 0 {
		t.Fatalf("bare NONE must not alert, got %v", got)
	}
}

// A real notice alerts once, repeats stay quiet, and the clear reports as
// cleared rather than as a fresh notice.
func TestMaintenanceWatchNoticeLifecycle(t *testing.T) {
	w := newWatchWorld(t)
	notice := `{"maintenanceStatus":"PENDING","windowStartTime":"2026-08-12T02:00:00Z"}`

	w.poll(notice)
	if got := w.posts(); len(got) != 1 {
		t.Fatalf("a real notice must alert once, got %d: %v", len(got), got)
	}
	w.poll(notice)
	if got := w.posts(); len(got) != 1 {
		t.Fatalf("an unchanged notice must not re-alert, got %d", len(got))
	}

	w.poll(`"NONE"`)
	got := w.posts()
	if len(got) != 2 {
		t.Fatalf("the clear must alert, got %d: %v", len(got), got)
	}
	if !contains(got[1], "cleared") {
		t.Errorf("clear message must say cleared, got %q", got[1])
	}
	if contains(got[1], "NONE") {
		t.Errorf("clear message must not carry the NONE sentinel, got %q", got[1])
	}
}

// A non-200 is a transient metadata failure: skip the poll rather than read it
// as "notice cleared" and page on it.
func TestMaintenanceWatchIgnoresMetadataFailure(t *testing.T) {
	w := newWatchWorld(t)
	w.poll(`{"maintenanceStatus":"PENDING"}`)
	w.mu.Lock()
	w.code = 500
	w.mu.Unlock()
	w.poll("")
	if got := w.posts(); len(got) != 1 {
		t.Fatalf("a metadata failure must not alert, got %d: %v", len(got), got)
	}
}

func contains(hay, needle string) bool {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
