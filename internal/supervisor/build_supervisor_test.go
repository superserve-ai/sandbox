package supervisor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

func TestReconcileDecision(t *testing.T) {
	tplA := "11111111-1111-1111-1111-111111111111"
	tplB := "22222222-2222-2222-2222-222222222222"
	bldX := "build-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	bldY := "build-bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	bldZ := "build-cccccccc-cccc-cccc-cccc-cccccccccccc"

	snapshot := time.Unix(1_000_000_000, 0)
	old := snapshot.Add(-time.Hour).Unix()
	newer := snapshot.Add(time.Minute).Unix()

	tests := []struct {
		name      string
		onDisk    []vmdclient.BuildArtifactEntry
		live      []string
		wantDelta []string
	}{
		{
			name: "live build kept",
			onDisk: []vmdclient.BuildArtifactEntry{
				{TemplateID: tplA, BuildID: bldX, MTimeUnix: old},
			},
			live: []string{tplA + "/" + bldX},
		},
		{
			name: "orphan reclaimed",
			onDisk: []vmdclient.BuildArtifactEntry{
				{TemplateID: tplA, BuildID: bldX, MTimeUnix: old},
			},
			live:      nil,
			wantDelta: []string{tplA + "/" + bldX},
		},
		{
			name: "newer-than-snapshot dir skipped (race-protect grace)",
			onDisk: []vmdclient.BuildArtifactEntry{
				{TemplateID: tplA, BuildID: bldX, MTimeUnix: newer},
			},
			live: nil,
		},
		{
			name: "mixed: live + orphan + newer",
			onDisk: []vmdclient.BuildArtifactEntry{
				{TemplateID: tplA, BuildID: bldX, MTimeUnix: old},     // live
				{TemplateID: tplA, BuildID: bldY, MTimeUnix: old},     // orphan
				{TemplateID: tplB, BuildID: bldZ, MTimeUnix: newer},   // grace
			},
			live:      []string{tplA + "/" + bldX},
			wantDelta: []string{tplA + "/" + bldY},
		},
		{
			name: "superseded ready build reclaimed",
			onDisk: []vmdclient.BuildArtifactEntry{
				{TemplateID: tplA, BuildID: bldX, MTimeUnix: old}, // current
				{TemplateID: tplA, BuildID: bldY, MTimeUnix: old}, // superseded
				{TemplateID: tplA, BuildID: bldZ, MTimeUnix: old}, // older
			},
			live:      []string{tplA + "/" + bldX},
			wantDelta: []string{tplA + "/" + bldY, tplA + "/" + bldZ},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			liveSet := map[string]struct{}{}
			for _, k := range tc.live {
				liveSet[k] = struct{}{}
			}
			got := reconcileDecision(tc.onDisk, liveSet, snapshot)
			if len(got) != len(tc.wantDelta) {
				t.Fatalf("delete count = %d, want %d (got %+v)", len(got), len(tc.wantDelta), got)
			}
			for i, e := range got {
				want := tc.wantDelta[i]
				if e.TemplateID+"/"+e.BuildID != want {
					t.Errorf("delete[%d] = %s/%s, want %s", i, e.TemplateID, e.BuildID, want)
				}
			}
		})
	}
}

type fakeDeleter struct {
	calls  []string
	failOn map[string]bool
}

func (f *fakeDeleter) DeleteBuildArtifacts(_ context.Context, tplID, buildID string) error {
	key := tplID + "/" + buildID
	f.calls = append(f.calls, key)
	if f.failOn[key] {
		return errors.New("simulated")
	}
	return nil
}

func TestApplyDeletions(t *testing.T) {
	mkEntries := func(n int) []vmdclient.BuildArtifactEntry {
		out := make([]vmdclient.BuildArtifactEntry, n)
		for i := range out {
			out[i] = vmdclient.BuildArtifactEntry{
				TemplateID: "tpl",
				BuildID:    fmt.Sprintf("build-%03d", i),
			}
		}
		return out
	}
	log := zerolog.New(io.Discard)

	t.Run("caps at budget", func(t *testing.T) {
		f := &fakeDeleter{}
		attempted, deleted := applyDeletions(context.Background(), log, f, mkEntries(60), 50)
		if attempted != 50 || deleted != 50 || len(f.calls) != 50 {
			t.Errorf("attempted=%d deleted=%d calls=%d, want 50/50/50", attempted, deleted, len(f.calls))
		}
	})

	t.Run("under budget processes all", func(t *testing.T) {
		f := &fakeDeleter{}
		attempted, deleted := applyDeletions(context.Background(), log, f, mkEntries(7), 50)
		if attempted != 7 || deleted != 7 {
			t.Errorf("attempted=%d deleted=%d, want 7/7", attempted, deleted)
		}
	})

	t.Run("zero budget is unbounded", func(t *testing.T) {
		f := &fakeDeleter{}
		attempted, deleted := applyDeletions(context.Background(), log, f, mkEntries(120), 0)
		if attempted != 120 || deleted != 120 {
			t.Errorf("attempted=%d deleted=%d, want 120/120", attempted, deleted)
		}
	})

	t.Run("failures count against budget", func(t *testing.T) {
		f := &fakeDeleter{failOn: map[string]bool{
			"tpl/build-000": true,
			"tpl/build-001": true,
			"tpl/build-002": true,
		}}
		attempted, deleted := applyDeletions(context.Background(), log, f, mkEntries(60), 50)
		if attempted != 50 {
			t.Errorf("attempted=%d, want 50 (failures still consume budget)", attempted)
		}
		if deleted != 47 {
			t.Errorf("deleted=%d, want 47", deleted)
		}
	})
}

func TestBuildKeyFromPath(t *testing.T) {
	tests := []struct {
		path    string
		wantKey string
		wantOK  bool
	}{
		{"/var/lib/sandbox/rundir/templates/abc/build-xyz/base.ext4", "abc/build-xyz", true},
		{"/var/lib/sandbox/snapshots/templates/abc/build-xyz/rootfs.delta", "abc/build-xyz", true},
		// Legacy layout: no buildID segment → skip
		{"/var/lib/sandbox/rundir/templates/abc/rootfs.ext4", "", false},
		// Subdir without "build-" prefix → skip (not an overlay artifact dir)
		{"/var/lib/sandbox/rundir/templates/abc/legacy/base.ext4", "", false},
		{"", "", false},
		{"/", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			k, ok := buildKeyFromPath(tc.path)
			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v", ok, tc.wantOK)
			}
			if k != tc.wantKey {
				t.Errorf("key = %q, want %q", k, tc.wantKey)
			}
		})
	}
}
