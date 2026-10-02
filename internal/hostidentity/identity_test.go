package hostidentity

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadIdentityRestartAndClone(t *testing.T) {
	id := Identity{HostID: "example-region-2-unique", IncarnationID: uuid.NewString(), ProjectID: "example-project", InstanceID: "123456"}
	path := filepath.Join(t.TempDir(), "identity.json")
	data, _ := json.Marshal(id)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	metadata := func(_ context.Context, key string) (string, error) {
		if key == "instance/id" {
			return id.InstanceID, nil
		}
		return id.ProjectID, nil
	}
	for range 2 {
		got, err := Load(path, id.HostID, metadata)
		if err != nil || got != id {
			t.Fatalf("restart identity = %+v, %v", got, err)
		}
	}
	if _, err := Load(path, id.HostID, func(context.Context, string) (string, error) { return "another-machine", nil }); err == nil {
		t.Fatal("clone accepted")
	}
	if _, err := Load(path, "another-host", metadata); err == nil {
		t.Fatal("wrong host accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, id.HostID, metadata); err == nil {
		t.Fatal("missing state accepted")
	}
	if err := os.WriteFile(path, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, id.HostID, metadata); err == nil {
		t.Fatal("corrupt state accepted")
	}
}

func TestLoadSharesVerificationDeadline(t *testing.T) {
	id := Identity{HostID: "example-host", IncarnationID: uuid.NewString(), ProjectID: "example-project", InstanceID: "123456"}
	path := filepath.Join(t.TempDir(), "identity.json")
	data, err := json.Marshal(id)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	var first context.Context
	calls := 0
	got, err := Load(path, id.HostID, func(ctx context.Context, key string) (string, error) {
		calls++
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > VerificationTimeout {
			t.Fatal("missing shared verification budget")
		}
		if calls == 1 {
			first = ctx
			if key == "instance/id" {
				return id.InstanceID, nil
			}
			return id.ProjectID, nil
		}
		if ctx != first {
			t.Fatal("second metadata lookup received a fresh budget")
		}
		<-ctx.Done()
		return "", ctx.Err()
	})
	if calls != 2 || !errors.Is(err, context.DeadlineExceeded) || got != (Identity{}) {
		t.Fatalf("verification = %+v, %v; calls = %d", got, err, calls)
	}
}

func TestMetadataHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Metadata(ctx, "instance/id"); !errors.Is(err, context.Canceled) {
		t.Fatalf("metadata error = %v, want context cancellation", err)
	}
}
