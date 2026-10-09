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
}

func (c hostReconcileClient) ListBuildArtifacts(context.Context) ([]vmdclient.BuildArtifactEntry, error) {
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
	s.reconcileHostsPass(context.Background(), []string{"a", "unreachable", "b"}, live, time.Now())

	want := []string{"tpl/build-a-1", "tpl/build-b-1"}
	if !reflect.DeepEqual(deleted, want) {
		t.Fatalf("deleted = %v, want %v", deleted, want)
	}
}
