package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/felixge/httpsnoop"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/requestlog"
)

type requestLogKey struct{}
type peerRequestIDKey struct{}

const peerRequestIDHeader = "X-Superserve-Log-Request-Id"

// PeerRequestLogging accepts correlation only on the private peer target. It
// conveys no identity or authorization; the owner still verifies the token.
func PeerRequestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, err := uuid.Parse(r.Header.Get(peerRequestIDHeader)); err == nil && id != uuid.Nil {
			r = r.WithContext(context.WithValue(r.Context(), peerRequestIDKey{}, id.String()))
		}
		r.Header.Del(peerRequestIDHeader)
		next.ServeHTTP(w, r)
	})
}

type requestRecord struct {
	mu                           sync.Mutex
	log                          zerolog.Logger
	started                      time.Time
	id, method, route, sandboxID string
	identity                     requestlog.Identity
	status                       int
	written                      int64
	hijacked, session, forwarded bool
	outcome                      string
}

func requestRecordFrom(ctx context.Context) *requestRecord {
	s, _ := ctx.Value(requestLogKey{}).(*requestRecord)
	return s
}

func logSandboxID(id string) string {
	if parsed, err := uuid.Parse(id); err == nil {
		return parsed.String()
	}
	return ""
}

func boxdLogRoute(path string) string {
	switch path {
	case filesPath, execPath, execStreamPath, execConnectPath, terminalPath,
		desktopScreenshotPath, desktopStreamPath, desktopSendPointerPath,
		desktopSendKeyPath, desktopScrollPath, desktopResizePath, desktopSendActionsPath, desktopStepPath:
		return path
	default:
		return "__unmatched__"
	}
}

func logBoxdRequest(log zerolog.Logger, domains []string, w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if requestRecordFrom(r.Context()) != nil {
		next(w, r)
		return
	}
	port, sandboxID, err := ParseRequest(r.Host, r.Header, domains)
	if port != boxdPort && !(err != nil && (isSharedHost(r.Host, domains) || strings.HasPrefix(r.Host, "boxd-"))) {
		next(w, r)
		return
	}
	// Public callers cannot choose correlation IDs, including on forwarded
	// requests. Only PeerRequestLogging can establish the private context value.
	r.Header.Del(peerRequestIDHeader)
	id, _ := r.Context().Value(peerRequestIDKey{}).(string)
	if id == "" {
		id = uuid.NewString()
	}
	sandboxID = logSandboxID(sandboxID)
	s := &requestRecord{log: log, started: time.Now(), id: id,
		method: requestlog.Method(r.Method), route: boxdLogRoute(r.URL.Path), sandboxID: sandboxID,
		identity: requestlog.Unresolved("not_evaluated")}
	r = r.WithContext(context.WithValue(r.Context(), requestLogKey{}, s))
	completed := false
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if !completed {
			s.outcome = "aborted"
		} else if r.Context().Err() != nil && s.outcome == "" {
			s.outcome = "canceled"
		}
		event := "request"
		if s.forwarded {
			event = "proxy_forward"
		} else if s.session {
			event = "session_complete"
		}
		if s.status == 0 && !s.hijacked {
			if completed {
				s.status = http.StatusOK
			} else {
				s.status = http.StatusInternalServerError
			}
		}
		s.emit(event)
	}()
	// httpsnoop preserves the exact optional interfaces of the writer, including
	// Flush/Hijack/ReadFrom; a plain wrapper would break streaming and upgrades.
	wrapped := httpsnoop.Wrap(w, httpsnoop.Hooks{
		WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
			return func(code int) {
				s.mu.Lock()
				if s.status == 0 && (code >= 200 || code == http.StatusSwitchingProtocols) {
					s.status = code
				}
				s.mu.Unlock()
				next(code)
			}
		},
		Write: func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
			return func(b []byte) (int, error) {
				n, err := next(b)
				s.recordWrite(int64(n), err)
				return n, err
			}
		},
		ReadFrom: func(next httpsnoop.ReadFromFunc) httpsnoop.ReadFromFunc {
			return func(src io.Reader) (int64, error) {
				n, err := next(src)
				s.recordWrite(n, err)
				return n, err
			}
		},
		Flush: func(next httpsnoop.FlushFunc) httpsnoop.FlushFunc {
			return func() { s.recordWrite(0, nil); next() }
		},
		Hijack: func(next httpsnoop.HijackFunc) httpsnoop.HijackFunc {
			return func() (net.Conn, *bufio.ReadWriter, error) {
				conn, rw, err := next()
				if err == nil {
					s.mu.Lock()
					s.hijacked = true
					s.mu.Unlock()
				}
				return conn, rw, err
			}
		},
	})
	next(wrapped, r)
	completed = true
}

func (s *requestRecord) recordWrite(n int64, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status == 0 {
		s.status = http.StatusOK
	}
	s.written += n
	if err != nil {
		s.outcome = "transport_error"
	}
}

// emit is called with mu held. Only structured metadata reaches this event.
func (s *requestRecord) emit(event string) {
	e := s.log.Info()
	if s.status >= 500 || s.outcome == "aborted" || s.outcome == "transport_error" {
		e = s.log.Error()
	} else if s.status >= 400 {
		e = s.log.Warn()
	}
	s.identity.Log(e).Str("plane", "data").Str("event_type", event).
		Str("request_id", s.id).Str("method", s.method).Str("route", s.route).
		Str("path", s.route).Dur("latency", time.Since(s.started))
	if s.sandboxID != "" {
		e.Str("sandbox_id", s.sandboxID)
	}
	if s.status != 0 {
		e.Int("status", s.status)
	}
	if !s.hijacked {
		e.Int64("body_size", s.written)
	}
	outcome := s.outcome
	if outcome == "" {
		switch {
		case event == "session_start":
			outcome = "established"
		case s.session || s.forwarded:
			outcome = "closed"
		case s.status >= 400:
			outcome = "rejected"
		default:
			outcome = "completed"
		}
	}
	e.Str("outcome", outcome).Msg("request")
}

func logSandboxAuth(ctx context.Context, outcome, team string) {
	if s := requestRecordFrom(ctx); s != nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.identity = requestlog.Unresolved(outcome)
		if outcome == "authenticated" {
			s.identity.ActorType, s.identity.AttributionStatus = "sandbox_capability", "sandbox_only"
			s.identity.ResourceTeamID = team
		}
	}
}

func logSessionStart(ctx context.Context, status int) {
	if s := requestRecordFrom(ctx); s != nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		if !s.session {
			s.session, s.status = true, status
			s.emit("session_start")
		}
	}
}

func logRequestOutcome(ctx context.Context, outcome string) {
	if s := requestRecordFrom(ctx); s != nil {
		s.mu.Lock()
		s.outcome = outcome
		s.mu.Unlock()
	}
}
