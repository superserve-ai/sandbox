package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getsentry/sentry-go"
	sentrygin "github.com/getsentry/sentry-go/gin"
	"github.com/gin-gonic/gin"
	"github.com/superserve-ai/sandbox/internal/abuse"
	"github.com/superserve-ai/sandbox/internal/telemetry"
)

type signupDecisionCapture struct {
	telemetry.Recorder
	decisions [][3]string
}

func TestSignupEvaluationExceptionOmitsSubjectFromSentry(t *testing.T) {
	const visitorID = "visitor-secret"
	var captured []byte
	var capturedRequest bool
	client, err := sentry.NewClient(sentry.ClientOptions{
		Dsn:                    "https://public@example.com/1",
		DisableTelemetryBuffer: true,
		BeforeSend: func(event *sentry.Event, _ *sentry.EventHint) *sentry.Event {
			capturedRequest = event.Request != nil
			serialized, err := json.Marshal(event)
			if err == nil {
				captured = serialized
			} else {
				t.Errorf("marshal Sentry event: %v", err)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)

	h := &Handlers{SignupRestrictions: &abuse.SignupEvaluator{Source: abuse.NewConfigComputeSource("", nil, nil)}}
	r := gin.New()
	r.Use(sentrygin.New(sentrygin.Options{}))
	r.POST("/internal/signup/evaluate", func(c *gin.Context) {
		h.EvaluateSignup(c)
		if c.Writer.Status() != http.StatusOK {
			t.Errorf("signup evaluation returned %d", c.Writer.Status())
			return
		}
		sentrygin.GetHubFromContext(c).CaptureException(errors.New("after signup evaluation"))
	})
	request := httptest.NewRequest(http.MethodPost, "/internal/signup/evaluate", strings.NewReader(`{"subjects":[{"type":"fingerprint","value":"`+visitorID+`"}]}`))
	request = request.WithContext(sentry.SetHubOnContext(request.Context(), sentry.NewHub(client, sentry.NewScope())))
	r.ServeHTTP(httptest.NewRecorder(), request)
	if len(captured) == 0 {
		t.Fatal("no exception event captured")
	}
	if !capturedRequest {
		t.Fatal("exception event omitted request context")
	}
	if strings.Contains(string(captured), visitorID) {
		t.Fatal("signup subject leaked in Sentry event")
	}
}

func (r *signupDecisionCapture) RecordSignupDecision(_ context.Context, mode, decision, subject string) {
	r.decisions = append(r.decisions, [3]string{mode, decision, subject})
}

func TestSignupEvaluationInternalAuthAndBoundary(t *testing.T) {
	t.Setenv("INTERNAL_API_TOKEN", "server-secret")
	rec := &signupDecisionCapture{Recorder: telemetry.NewNoopRecorder()}
	previous := currentTelemetryRecorder()
	SetTelemetryRecorder(rec)
	t.Cleanup(func() { SetTelemetryRecorder(previous) })
	path := filepath.Join(t.TempDir(), "restrictions.json")
	if err := os.WriteFile(path, []byte(`{"mode":"enforce","restrictions":[{"subject_type":"fingerprint","subject_value":"visitor-secret","actions":["signup"]}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	source := abuse.NewConfigComputeSource(path, nil, nil)
	source.Refresh(context.Background())
	h := &Handlers{SignupRestrictions: &abuse.SignupEvaluator{Source: source}}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	r := SetupRouter(ctx, h, nil)
	request := func(token, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/internal/signup/evaluate", strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	valid := `{"subjects":[{"type":"fingerprint","value":"visitor-secret"}]}`
	for _, token := range []string{"", "wrong"} {
		if w := request(token, valid); w.Code != http.StatusUnauthorized {
			t.Fatalf("token %q: %d", token, w.Code)
		}
	}
	if w := request("server-secret", valid); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"decision":"blocked"`) || !strings.Contains(w.Body.String(), `"matched_subject_type":"fingerprint"`) || strings.Contains(w.Body.String(), "visitor-secret") {
		t.Fatalf("valid request: %d %s", w.Code, w.Body.String())
	}
	if want := [3]string{"enforce", "blocked", "fingerprint"}; len(rec.decisions) != 1 || rec.decisions[0] != want {
		t.Fatalf("signup decisions = %v, want exactly [%v]", rec.decisions, want)
	}
	oversized := valid + strings.Repeat(" ", 4097-len(valid))
	if w := request("server-secret", oversized); w.Code != http.StatusBadRequest {
		t.Fatalf("oversized request: %d %s", w.Code, w.Body.String())
	}
	if len(rec.decisions) != 1 {
		t.Fatalf("oversized request recorded signup decision: %v", rec.decisions)
	}
	for _, body := range []string{
		`null`, `{}`, `{"subjects":[]}`, `{"subjects":null}`,
		`{"subjects":[{"type":"user","value":"visitor-secret"}]}`,
		`{"subjects":[{"type":"fingerprint","value":""}]}`,
		`{"subjects":[{"type":"fingerprint","value":"visitor-secret"},{"type":"fingerprint","value":"other"}]}`,
		`{"subjects":[{"type":"fingerprint","value":"visitor-secret","other":true}]}`,
		valid + valid,
		`{"subjects":[{"type":"fingerprint","value":"` + strings.Repeat("x", abuse.MaxFingerprintBytes+1) + `"}]}`,
	} {
		if w := request("server-secret", body); w.Code != http.StatusBadRequest {
			t.Fatalf("accepted %s: %d", body, w.Code)
		}
	}
	if len(rec.decisions) != 1 {
		t.Fatalf("invalid requests recorded signup decisions: %v", rec.decisions)
	}
}
