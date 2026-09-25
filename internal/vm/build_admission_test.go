package vm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/superserve-ai/sandbox/internal/backup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestBuildAdmissionRequiresInstalledIncarnation(t *testing.T) {
	incarnation := uuid.NewString()
	attempt := uuid.NewString()
	calls := 0
	expectedHost := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Host != expectedHost || r.URL.Path != "/internal/hosts/example-host/template-attempts/admit" {
			t.Errorf("admission destination = %s%s", r.Host, r.URL.Path)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode admission request: %v", err)
		} else if len(body) != 2 || body["attempt_id"] != attempt || body["incarnation_id"] != incarnation {
			t.Errorf("admission identity = %#v", body)
		}
		if r.Header.Get("Authorization") != "Bearer example-token" {
			t.Error("missing admission authentication")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	expectedHost = strings.TrimPrefix(server.URL, "http://")
	a := &GRPCAdapter{buildAdmission: BuildAdmission{IncarnationID: incarnation, HostID: "example-host", ControlPlaneURL: server.URL, Token: "example-token"}}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("template-build-attempt", attempt, "template-build-incarnation", uuid.NewString()))
	if _, err := a.buildAdmissionCallback(ctx, "build-"+attempt); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("incarnation mismatch: %v", err)
	}
	if calls != 0 {
		t.Fatal("foreign incarnation reached admission")
	}
	ctx = metadata.NewIncomingContext(context.Background(), metadata.Pairs("template-build-attempt", attempt, "template-build-incarnation", incarnation))
	admit, err := a.buildAdmissionCallback(ctx, "build-"+attempt)
	if err != nil {
		t.Fatal(err)
	}
	if err := admit(); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("did not recheck admission")
	}
}
func TestTemplateReportNeverDowngradesPublicationProof(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`unknown field "template_runtime"`))
	}))
	defer server.Close()
	reporter := BackupReporter{ControlPlaneURL: server.URL, HostID: "example-host", Token: "example-token"}
	err := reporter.Deliver(backup.Task{TemplateID: "example-template", BuildID: "build-example", TemplateRuntime: &backup.TemplateRuntime{RootfsPath: "/immutable/rootfs"}})
	if !errors.Is(err, backup.ErrNotificationDeferred) || calls != 1 {
		t.Fatalf("publication proof dropped/downgraded: calls=%d err=%v", calls, err)
	}
}
