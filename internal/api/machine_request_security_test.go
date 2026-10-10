package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"
	sentrygin "github.com/getsentry/sentry-go/gin"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/auth"
)

type machineRequestResolverFunc func(context.Context, string) (auth.CallerContext, error)

func (f machineRequestResolverFunc) ResolveMachineCredential(ctx context.Context, raw string) (auth.CallerContext, error) {
	return f(ctx, raw)
}

func machineRequestCaller(now time.Time) auth.CallerContext {
	return auth.CallerContext{PrincipalID: uuid.New(), CredentialID: uuid.New(), LineageID: uuid.New(), TeamID: uuid.New(), HostedTenantID: uuid.New(), Audience: "sandbox-api", ExpiresAt: now.Add(time.Hour), RevocationGeneration: 1, Permissions: []auth.MachineOperation{auth.MachineOperationCreate}, Policy: auth.NewMachinePolicy(auth.MachineOperationCreate)}
}

type revokingMachineBody struct {
	io.Reader
	revoked *bool
}

func (b *revokingMachineBody) Read(p []byte) (int, error) { *b.revoked = true; return b.Reader.Read(p) }
func (b *revokingMachineBody) Close() error               { return nil }

func TestMachineRequestReadsBodyBeforeResolvingAuthority(t *testing.T) {
	revoked, mutated, resolved := false, false, false
	router := gin.New()
	router.Use(MachineCredentialAuth(machineRequestResolverFunc(func(context.Context, string) (auth.CallerContext, error) {
		resolved = true
		if revoked {
			return auth.CallerContext{}, auth.ErrInvalidMachineIdentity
		}
		return machineRequestCaller(time.Now()), nil
	})))
	router.POST("/sandboxes", func(c *gin.Context) { _, _ = io.ReadAll(c.Request.Body); mutated = true; c.Status(http.StatusCreated) })
	request := httptest.NewRequest("POST", "/sandboxes", nil)
	request.Header.Set("X-QM-Machine-Credential", "runtime-fixture")
	request.Body = &revokingMachineBody{Reader: strings.NewReader(`{"name":"example"}`), revoked: &revoked}
	writer := &deadlineTeamWriter{ResponseRecorder: httptest.NewRecorder()}
	router.ServeHTTP(writer, request)
	if writer.Code != http.StatusUnauthorized || !resolved || !revoked || mutated {
		t.Fatalf("slow body retained old authority: status=%d resolved=%v revoked=%v mutated=%v", writer.Code, resolved, revoked, mutated)
	}
}

func TestMachineRequestBodyBoundsAndLifecycleDeadline(t *testing.T) {
	for _, kind := range []string{"oversize", "timeout", "success"} {
		t.Run(kind, func(t *testing.T) {
			resolved, mutated := false, false
			router := gin.New()
			router.Use(MachineCredentialAuth(machineRequestResolverFunc(func(ctx context.Context, _ string) (auth.CallerContext, error) {
				resolved = true
				if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > machineAuthorityTimeout {
					t.Fatal("authority lookup lacks bounded deadline")
				}
				return machineRequestCaller(time.Now()), nil
			})))
			router.POST("/sandboxes", func(c *gin.Context) {
				mutated = true
				if _, ok := c.Request.Context().Deadline(); ok {
					t.Fatal("body or lookup deadline leaked into lifecycle")
				}
				body, _ := io.ReadAll(c.Request.Body)
				if string(body) != `{"name":"example"}` {
					t.Fatalf("body was not restored: %q", body)
				}
				c.Status(http.StatusCreated)
			})
			writer := &deadlineTeamWriter{ResponseRecorder: httptest.NewRecorder()}
			request := httptest.NewRequest("POST", "/sandboxes", strings.NewReader(`{"name":"example"}`))
			request.Header.Set("X-QM-Machine-Credential", "runtime-fixture")
			want := http.StatusCreated
			switch kind {
			case "oversize":
				request.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", machineRequestBodyLimit+1)))
				want = http.StatusRequestEntityTooLarge
			case "timeout":
				request.Body = &deadlineTeamBody{writer: writer}
				want = http.StatusRequestTimeout
			}
			router.ServeHTTP(writer, request)
			if writer.Code != want || len(writer.deadlines) != 2 || writer.deadlines[0].IsZero() {
				t.Fatalf("status=%d deadlines=%v", writer.Code, writer.deadlines)
			}
			if kind == "success" {
				if !resolved || !mutated || !writer.deadlines[1].IsZero() {
					t.Fatal("successful request did not clear transport deadline")
				}
			} else if resolved || mutated || writer.deadlines[1].IsZero() || !request.Close {
				t.Fatal("rejected body reached authority or left unbounded read")
			}
		})
	}
}

func TestMachineAuthorityRejectsStaleLookup(t *testing.T) {
	now := time.Now()
	caller := machineRequestCaller(now)
	mutated := false
	router := gin.New()
	router.Use(machineCredentialAuthWithClock(machineRequestResolverFunc(func(context.Context, string) (auth.CallerContext, error) {
		now = now.Add(31 * time.Second)
		return caller, nil
	}), func() time.Time { return now }))
	router.POST("/sandboxes", func(c *gin.Context) { mutated = true; c.Status(http.StatusCreated) })
	request := httptest.NewRequest("POST", "/sandboxes", nil)
	request.Header.Set("X-QM-Machine-Credential", "runtime-fixture")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || mutated {
		t.Fatalf("stale lookup authorized mutation: status=%d mutation=%v", response.Code, mutated)
	}
}

func TestMachineRuntimeCredentialExcludedFromSentry(t *testing.T) {
	for _, header := range []string{"X-QM-Machine-Credential", "x-qm-machine-credential"} {
		t.Run(header, func(t *testing.T) {
			var captured *sentry.Event
			client, err := sentry.NewClient(sentry.ClientOptions{Dsn: "https://example@example.com/1", BeforeSend: func(event *sentry.Event, _ *sentry.EventHint) *sentry.Event { captured = event; return nil }})
			if err != nil {
				t.Fatal(err)
			}
			router := gin.New()
			router.Use(func(c *gin.Context) {
				c.Request = c.Request.WithContext(sentry.SetHubOnContext(c.Request.Context(), sentry.NewHub(client, sentry.NewScope())))
			}, sentrygin.New(sentrygin.Options{Repanic: true}), machineAdministrationPrivacy())
			router.POST("/sandboxes", func(c *gin.Context) {
				sentrygin.GetHubFromContext(c).CaptureMessage("synthetic runtime failure")
				c.Status(http.StatusInternalServerError)
			})
			marker := "synthetic-runtime-private-marker"
			request := httptest.NewRequest("POST", "/sandboxes", nil)
			request.Header[header] = []string{marker}
			router.ServeHTTP(httptest.NewRecorder(), request)
			if captured == nil {
				t.Fatal("diagnostic event missing")
			}
			encoded, err := json.Marshal(captured)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(encoded, []byte(marker)) || captured.Request != nil {
				t.Fatal("runtime credential captured in diagnostic event")
			}
		})
	}
}
