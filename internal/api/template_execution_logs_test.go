package api

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type retryLogClient struct {
	*stubVMD
	calls             int
	firstCallNotFound bool
}

type terminalLogClient struct {
	*stubVMD
	refreshStarted <-chan struct{}
	logsQueued     chan struct{}
	done           chan struct{}
}

func (v *terminalLogClient) StreamBuildLogs(ctx context.Context, _ string, emit func(vmdclient.BuildLogEvent) error) error {
	defer close(v.done)
	select {
	case <-v.refreshStarted:
	case <-ctx.Done():
		return ctx.Err()
	}
	for i := 1; i <= 5; i++ {
		if err := emit(vmdclient.BuildLogEvent{Sequence: uint64(i), Stream: "stderr", Text: fmt.Sprintf("final line %d", i)}); err != nil {
			return err
		}
	}
	close(v.logsQueued)
	<-ctx.Done()
	return ctx.Err()
}

func TestStreamAttemptLogsFlushesQueuedLogsBeforeLogicalCompletion(t *testing.T) {
	for _, terminal := range []db.TemplateBuildStatus{db.TemplateBuildStatusReady, db.TemplateBuildStatusFailed, db.TemplateBuildStatusCancelled} {
		t.Run(string(terminal), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			buildID, templateID, teamID, attemptID, incarnationID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
			refreshStarted, logsQueued := make(chan struct{}), make(chan struct{})
			reads := 0
			q := &mockDBTX{queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
				return &mockRow{scanFn: func(dest ...any) error {
					switch {
					case strings.Contains(sql, "-- name: GetTemplateBuild"):
						reads++
						*dest[0].(*uuid.UUID) = buildID
						*dest[1].(*uuid.UUID) = templateID
						*dest[2].(*uuid.UUID) = teamID
						*dest[3].(*db.TemplateBuildStatus) = db.TemplateBuildStatusBuilding
						if reads == 2 {
							// Hold the status refresh until the stream has queued its tail.
							close(refreshStarted)
							select {
							case <-logsQueued:
							case <-ctx.Done():
								return ctx.Err()
							}
							*dest[3].(*db.TemplateBuildStatus) = terminal
						}
					case strings.Contains(sql, "FROM template_build_execution e"):
						*dest[0].(*uuid.UUID) = buildID
						*dest[1].(**uuid.UUID) = &attemptID
					case strings.Contains(sql, "FROM template_build_attempt a JOIN template_build b"):
						*dest[0].(*uuid.UUID) = attemptID
						*dest[1].(*uuid.UUID) = buildID
						*dest[2].(*uuid.UUID) = templateID
						*dest[3].(*string) = "host"
						*dest[4].(*uuid.UUID) = incarnationID
						*dest[5].(*string) = "vm"
					case strings.Contains(sql, "SELECT NOT EXISTS(SELECT 1 FROM host"):
						*dest[0].(*bool) = false
					default:
						t.Errorf("unexpected query: %s", sql)
					}
					return nil
				}}
			}}
			client := &terminalLogClient{stubVMD: &stubVMD{}, refreshStarted: refreshStarted, logsQueued: logsQueued, done: make(chan struct{})}
			h := &Handlers{DB: db.New(q), Hosts: &stubHosts{resolve: func() (vmdclient.Client, error) { return client, nil }}}
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("GET", "/", nil).WithContext(ctx)
			h.streamAttemptLogs(c, db.TemplateBuild{ID: buildID, TemplateID: templateID, TeamID: teamID})
			select {
			case <-client.done:
			case <-ctx.Done():
				t.Fatal("terminal stream did not stop its log subscription")
			}
			body := w.Body.String()
			finished := strings.Index(body, `"finished":true`)
			previous := -1
			for i := 1; i <= 5; i++ {
				line := fmt.Sprintf("final line %d", i)
				at := strings.Index(body, line)
				if at <= previous || at >= finished || strings.Count(body, line) != 1 {
					t.Fatalf("queued log %q missing or out of order before completion: %s", line, body)
				}
				previous = at
			}
			if !strings.Contains(body, `"status":"`+string(terminal)+`"`) {
				t.Fatalf("missing terminal status: %s", body)
			}
		})
	}
}

func (v *retryLogClient) StreamBuildLogs(ctx context.Context, _ string, emit func(vmdclient.BuildLogEvent) error) error {
	v.calls++
	first := vmdclient.BuildLogEvent{Sequence: 1, TimestampUnixNanos: 2, Stream: "stdout", Text: "first log"}
	if v.calls == 1 {
		if v.firstCallNotFound {
			return status.Error(codes.NotFound, "build not registered yet")
		}
		if err := emit(first); err != nil {
			return err
		}
		return errors.New("stream interrupted")
	}
	if err := emit(first); err != nil {
		return err
	}
	if err := emit(vmdclient.BuildLogEvent{Sequence: 2, TimestampUnixNanos: 1, Stream: "stdout", Text: "second log"}); err != nil {
		return err
	}
	if err := emit(vmdclient.BuildLogEvent{Sequence: 3, TimestampUnixNanos: 1, Stream: "stdout", Text: "third log"}); err != nil {
		return err
	}
	<-ctx.Done()
	return ctx.Err()
}

type logNotifyWriter struct {
	*httptest.ResponseRecorder
	seen  chan struct{}
	once  sync.Once
	match string
}

func (w *logNotifyWriter) Write(p []byte) (int, error) {
	match := w.match
	if match == "" {
		match = "second log"
	}
	if strings.Contains(string(p), match) {
		w.once.Do(func() { close(w.seen) })
	}
	return w.ResponseRecorder.Write(p)
}

type handoffLogClient struct {
	*stubVMD
	firstStarted  chan struct{}
	secondStarted chan struct{}
	releaseStale  chan struct{}
	staleSent     chan int
	releaseMarker chan struct{}
}

func (v *handoffLogClient) StreamBuildLogs(ctx context.Context, vmID string, emit func(vmdclient.BuildLogEvent) error) error {
	if vmID == "first-vm" {
		close(v.firstStarted)
		if err := emit(vmdclient.BuildLogEvent{TimestampUnixNanos: 1, Stream: "stdout", Text: "first attempt log"}); err != nil {
			return err
		}
		<-v.releaseStale
		sent := 0
		for i := 0; i < 100; i++ {
			if emit(vmdclient.BuildLogEvent{TimestampUnixNanos: int64(i + 2), Stream: "stdout", Text: "stale attempt log"}) == nil {
				sent++
			}
		}
		v.staleSent <- sent
		return nil
	}
	close(v.secondStarted)
	if err := emit(vmdclient.BuildLogEvent{TimestampUnixNanos: 1, Stream: "stdout", Text: "second attempt log"}); err != nil {
		return err
	}
	select {
	case <-v.releaseMarker:
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := emit(vmdclient.BuildLogEvent{TimestampUnixNanos: 2, Stream: "stdout", Text: "second attempt marker"}); err != nil {
		return err
	}
	<-ctx.Done()
	return ctx.Err()
}

func TestStreamAttemptLogsSwitchesAttemptsAndEndsOnLogicalStatus(t *testing.T) {
	buildID, templateID, teamID := uuid.New(), uuid.New(), uuid.New()
	first, second, incarnationID := uuid.New(), uuid.New(), uuid.New()
	var stateMu sync.Mutex
	current, buildStatus := first, db.TemplateBuildStatusBuilding
	q := &mockDBTX{queryRowFn: func(_ context.Context, sql string, args ...any) pgx.Row {
		return &mockRow{scanFn: func(dest ...any) error {
			stateMu.Lock()
			defer stateMu.Unlock()
			switch {
			case strings.Contains(sql, "-- name: GetTemplateBuild"):
				*dest[0].(*uuid.UUID) = buildID
				*dest[1].(*uuid.UUID) = templateID
				*dest[2].(*uuid.UUID) = teamID
				*dest[3].(*db.TemplateBuildStatus) = buildStatus
				*dest[4].(*string) = "hash"
				*dest[10].(*time.Time) = time.Now()
				*dest[11].(*time.Time) = time.Now()
			case strings.Contains(sql, "FROM template_build_execution e"):
				*dest[0].(*uuid.UUID) = buildID
				attempt := current
				*dest[1].(**uuid.UUID) = &attempt
				*dest[4].(*string) = "building"
			case strings.Contains(sql, "FROM template_build_attempt a JOIN template_build b"):
				id := args[0].(uuid.UUID)
				*dest[0].(*uuid.UUID) = id
				*dest[1].(*uuid.UUID) = buildID
				*dest[2].(*uuid.UUID) = templateID
				*dest[3].(*string) = "host"
				*dest[4].(*uuid.UUID) = incarnationID
				if id == first {
					*dest[5].(*string) = "first-vm"
				} else {
					*dest[5].(*string) = "second-vm"
				}
			case strings.Contains(sql, "SELECT NOT EXISTS(SELECT 1 FROM host"):
				*dest[0].(*bool) = false
			default:
				t.Errorf("unexpected query: %s", sql)
			}
			return nil
		}}
	}}
	client := &handoffLogClient{stubVMD: &stubVMD{}, firstStarted: make(chan struct{}), secondStarted: make(chan struct{}), releaseStale: make(chan struct{}), staleSent: make(chan int, 1), releaseMarker: make(chan struct{})}
	h := &Handlers{DB: db.New(q), Hosts: &stubHosts{resolve: func() (vmdclient.Client, error) { return client, nil }}}
	w := &logNotifyWriter{ResponseRecorder: httptest.NewRecorder(), seen: make(chan struct{}), match: "second attempt marker"}
	c, _ := gin.CreateTestContext(w)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.Request = httptest.NewRequest("GET", "/", nil).WithContext(ctx)
	done := make(chan struct{})
	go func() {
		h.streamAttemptLogs(c, db.TemplateBuild{ID: buildID, TemplateID: templateID, TeamID: teamID})
		close(done)
	}()
	wait := func(ch <-chan struct{}, name string) {
		t.Helper()
		select {
		case <-ch:
		case <-time.After(7 * time.Second):
			cancel()
			<-done
			t.Fatalf("timed out waiting for %s", name)
		}
	}
	wait(client.firstStarted, "first stream")
	stateMu.Lock()
	current = second
	stateMu.Unlock()
	wait(client.secondStarted, "replacement stream")
	close(client.releaseStale)
	select {
	case n := <-client.staleSent:
		if n == 0 {
			t.Fatal("old stream did not deliver a late callback")
		}
	case <-time.After(7 * time.Second):
		t.Fatal("old stream did not finish sending late callbacks")
	}
	close(client.releaseMarker)
	wait(w.seen, "replacement log")
	stateMu.Lock()
	buildStatus = db.TemplateBuildStatusReady
	stateMu.Unlock()
	wait(done, "logical terminal status")
	body := w.Body.String()
	if strings.Contains(body, "stale attempt log") || !strings.Contains(body, "second attempt log") || !strings.Contains(body, "second attempt marker") {
		t.Fatalf("incorrect attempt logs in SSE stream: %s", body)
	}
	if !strings.Contains(body, `"status":"ready"`) || !strings.Contains(body, `"finished":true`) {
		t.Fatalf("missing logical terminal event: %s", body)
	}
}

func TestStreamAttemptLogsReconnectsWithReplay(t *testing.T) {
	for _, tc := range []struct {
		name              string
		firstCallNotFound bool
	}{
		{name: "registration race", firstCallNotFound: true},
		{name: "mid-stream failure"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testStreamAttemptLogsReconnectsWithReplay(t, tc.firstCallNotFound)
		})
	}
}

func testStreamAttemptLogsReconnectsWithReplay(t *testing.T, firstCallNotFound bool) {
	buildID, templateID, teamID, attemptID, incarnationID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	q := &mockDBTX{queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
		return &mockRow{scanFn: func(dest ...any) error {
			switch {
			case strings.Contains(sql, "-- name: GetTemplateBuild"):
				*dest[0].(*uuid.UUID) = buildID
				*dest[1].(*uuid.UUID) = templateID
				*dest[2].(*uuid.UUID) = teamID
				*dest[3].(*db.TemplateBuildStatus) = db.TemplateBuildStatusBuilding
				*dest[4].(*string) = "hash"
				*dest[8].(*pgtype.Timestamptz) = pgtype.Timestamptz{}
				*dest[9].(*pgtype.Timestamptz) = pgtype.Timestamptz{}
				*dest[10].(*time.Time) = time.Now()
				*dest[11].(*time.Time) = time.Now()
			case strings.Contains(sql, "FROM template_build_execution e"):
				*dest[0].(*uuid.UUID) = buildID
				*dest[1].(**uuid.UUID) = &attemptID
				*dest[4].(*string) = "building"
			case strings.Contains(sql, "FROM template_build_attempt a JOIN template_build b"):
				*dest[0].(*uuid.UUID) = attemptID
				*dest[1].(*uuid.UUID) = buildID
				*dest[2].(*uuid.UUID) = templateID
				*dest[3].(*string) = "host"
				*dest[4].(*uuid.UUID) = incarnationID
				*dest[5].(*string) = "vm"
			case strings.Contains(sql, "SELECT NOT EXISTS(SELECT 1 FROM host"):
				*dest[0].(*bool) = false
			default:
				t.Errorf("unexpected query: %s", sql)
			}
			return nil
		}}
	}}
	client := &retryLogClient{stubVMD: &stubVMD{}, firstCallNotFound: firstCallNotFound}
	h := &Handlers{DB: db.New(q), Hosts: &stubHosts{resolve: func() (vmdclient.Client, error) { return client, nil }}}
	w := &logNotifyWriter{ResponseRecorder: httptest.NewRecorder(), seen: make(chan struct{})}
	c, _ := gin.CreateTestContext(w)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.Request = httptest.NewRequest("GET", "/", nil).WithContext(ctx)
	done := make(chan struct{})
	go func() {
		h.streamAttemptLogs(c, db.TemplateBuild{ID: buildID, TemplateID: templateID, TeamID: teamID})
		close(done)
	}()
	select {
	case <-w.seen:
	case <-time.After(5 * time.Second):
		cancel()
		<-done
		t.Fatal("log stream did not reconnect")
	}
	cancel()
	<-done
	if client.calls != 2 {
		t.Fatalf("stream calls = %d, want 2", client.calls)
	}
	if n := strings.Count(w.Body.String(), "first log"); n != 1 {
		t.Fatalf("first log forwarded %d times, want once", n)
	}
	if n := strings.Count(w.Body.String(), "second log"); n != 1 {
		t.Fatalf("second log forwarded %d times, want once", n)
	}
	if n := strings.Count(w.Body.String(), "third log"); n != 1 {
		t.Fatalf("third log forwarded %d times, want once", n)
	}
}
