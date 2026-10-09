package supervisor

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/db"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

// Builds are dispatched to any eligible host in the cell, so a reconciler that
// walks one configured host leaves every other host's artifacts behind. A
// registry can hold more than one cell's hosts, and a supervisor must not
// reach into a cell that is not its own.
func TestHostsInCell(t *testing.T) {
	hosts := []db.Host{
		{ID: "a", Region: "cell-1"},
		{ID: "b", Region: "cell-2"},
		{ID: "c", Region: "cell-1"},
	}
	if got := hostsInCell(hosts, "cell-1"); !reflect.DeepEqual(got, []string{"a", "c"}) {
		t.Fatalf("hostsInCell(cell-1) = %v", got)
	}
	if got := hostsInCell(hosts, ""); got != nil {
		t.Fatalf("an unset cell claimed hosts: %v", got)
	}
}

type hostReconcileClient struct {
	vmdclient.Client
	onDisk  []vmdclient.BuildArtifactEntry
	deleted *[]string
	stall   bool
}

func (c hostReconcileClient) ListBuildArtifacts(ctx context.Context) ([]vmdclient.BuildArtifactEntry, error) {
	if c.stall {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return c.onDisk, nil
}

func (c hostReconcileClient) DeleteBuildArtifacts(_ context.Context, templateID, buildID string) error {
	*c.deleted = append(*c.deleted, templateID+"/"+buildID)
	return nil
}

// A host that cannot be reached this pass must not cost the other hosts their
// reclamation, and each host spends its own deletion budget so one host's
// backlog cannot starve the rest.
func TestReconcileHostsPassIsIndependentPerHost(t *testing.T) {
	stale := time.Now().Add(-time.Hour)
	entriesFor := func(host string) []vmdclient.BuildArtifactEntry {
		return []vmdclient.BuildArtifactEntry{
			{TemplateID: "tpl", BuildID: "build-" + host + "-1", MTimeUnix: stale.Unix()},
			{TemplateID: "tpl", BuildID: "build-" + host + "-2", MTimeUnix: stale.Unix()},
		}
	}
	var deleted []string
	s := &BuildSupervisor{
		cfg: BuildSupervisorConfig{Cell: "cell-1", MaxDeletesPerReconcile: 1},
		log: zerolog.Nop(),
		resolve: func(_ context.Context, hostID string) (vmdclient.Client, error) {
			if hostID == "unreachable" {
				return nil, errors.New("dial failed")
			}
			return hostReconcileClient{onDisk: entriesFor(hostID), deleted: &deleted}, nil
		},
	}

	live := map[string]struct{}{}
	s.reconcileHostsPass(context.Background(), []string{"a", "unreachable", "b"}, live, time.Now(), time.Minute)

	want := []string{"tpl/build-a-1", "tpl/build-b-1"}
	if !reflect.DeepEqual(deleted, want) {
		t.Fatalf("deleted = %v, want %v", deleted, want)
	}
}

// A daemon that accepts the connection and then never answers is the case the
// unreachable check cannot catch: without a deadline of its own it holds the
// whole pass on the supervisor's process-lifetime context, and every replica
// that takes the lease after it expires stalls on the same host, so the rest
// of the cell is never reclaimed.
func TestReconcileHostsPassBoundsEachHost(t *testing.T) {
	stale := time.Now().Add(-time.Hour)
	var deleted []string
	s := &BuildSupervisor{
		cfg: BuildSupervisorConfig{Cell: "cell-1"},
		log: zerolog.Nop(),
		resolve: func(_ context.Context, hostID string) (vmdclient.Client, error) {
			return hostReconcileClient{
				stall:   hostID == "stalled",
				onDisk:  []vmdclient.BuildArtifactEntry{{TemplateID: "tpl", BuildID: "build-" + hostID, MTimeUnix: stale.Unix()}},
				deleted: &deleted,
			}, nil
		},
	}

	done := make(chan struct{})
	go func() {
		s.reconcileHostsPass(context.Background(), []string{"a", "stalled", "b"}, map[string]struct{}{}, time.Now(), 50*time.Millisecond)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a stalled host held the pass")
	}

	want := []string{"tpl/build-a", "tpl/build-b"}
	if !reflect.DeepEqual(deleted, want) {
		t.Fatalf("deleted = %v, want %v", deleted, want)
	}
}
