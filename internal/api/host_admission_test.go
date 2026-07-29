package api

import (
	"context"
	"errors"
	"testing"

	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

type admissionHostRegistry struct {
	client      vmdclient.Client
	activeErr   error
	activeCalls int
	clientCalls int
}

func (r *admissionHostRegistry) ClientFor(context.Context, string) (vmdclient.Client, error) {
	r.clientCalls++
	return r.client, nil
}

func (r *admissionHostRegistry) ActiveClientFor(context.Context, string) (vmdclient.Client, error) {
	r.activeCalls++
	if r.activeErr != nil {
		return nil, r.activeErr
	}
	return r.client, nil
}

type legacyHostRegistry struct {
	client vmdclient.Client
	calls  int
}

func (r *legacyHostRegistry) ClientFor(context.Context, string) (vmdclient.Client, error) {
	r.calls++
	return r.client, nil
}

func TestActiveVMDForHostEnforcesLifecycleStatus(t *testing.T) {
	t.Parallel()

	vmd := &stubVMD{}
	draining := errors.New("host is draining")
	registry := &admissionHostRegistry{client: vmd, activeErr: draining}
	h := &Handlers{VMD: vmd, Hosts: registry}

	got, err := h.activeVMDForHost(context.Background(), "host-a")
	if !errors.Is(err, draining) {
		t.Fatalf("activeVMDForHost() error = %v, want %v", err, draining)
	}
	if got != nil {
		t.Fatalf("activeVMDForHost() client = %T, want nil", got)
	}
	if registry.activeCalls != 1 || registry.clientCalls != 0 {
		t.Fatalf("resolver calls active=%d client=%d, want 1/0", registry.activeCalls, registry.clientCalls)
	}
}

func TestActiveVMDForHostSupportsLegacyRegistry(t *testing.T) {
	t.Parallel()

	vmd := &stubVMD{}
	registry := &legacyHostRegistry{client: vmd}
	h := &Handlers{VMD: vmd, Hosts: registry}

	got, err := h.activeVMDForHost(context.Background(), "legacy")
	if err != nil {
		t.Fatalf("activeVMDForHost() error = %v", err)
	}
	if got != vmd {
		t.Fatalf("activeVMDForHost() client = %T, want stubVMD", got)
	}
	if registry.calls != 1 {
		t.Fatalf("ClientFor calls = %d, want 1", registry.calls)
	}
}
