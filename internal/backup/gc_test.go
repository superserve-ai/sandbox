package backup

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func objectNames(t *testing.T, store *memBlobs, prefix string) []string {
	t.Helper()
	objs, err := store.List(context.Background(), prefix)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(objs))
	for _, o := range objs {
		names = append(names, o.Name)
	}
	return names
}

// Purging a generation removes exactly that generation: its manifest and
// artifacts go, the sandbox's other generation and the shared base stay,
// and a second purge finds nothing to do.
func TestPurgeGenerationRemovesOnlyThatGeneration(t *testing.T) {
	store := newMemBlobs()
	dir := t.TempDir()
	baseData := bytes.Repeat([]byte{0x11}, 64<<10)
	basePath := filepath.Join(dir, "base.ext4")
	if err := os.WriteFile(basePath, baseData, 0o644); err != nil {
		t.Fatal(err)
	}
	overlay := writePauseFixture(t, dir, "pause A")
	overlay.Files[0].BasePath = basePath
	overlay.Files[0].BaseSHA256 = digestOf(baseData)
	overlay.Generation = GenerationKey(overlay.Files)
	uploadFixture(t, store, overlay)
	other := writePauseFixture(t, t.TempDir(), "pause B")
	other.SandboxID = overlay.SandboxID
	uploadFixture(t, store, other)

	prefix := "sandboxes/" + overlay.SandboxID + "/" + overlay.Generation + "/"
	before := objectNames(t, store, prefix)
	if len(before) != 3 {
		t.Fatalf("fixture generation has %d objects, want manifest, disk and vmstate: %v", len(before), before)
	}
	bases := objectNames(t, store, "bases/")
	if len(bases) != 1 {
		t.Fatalf("shared bases = %v, want one", bases)
	}

	deleted, err := PurgeGeneration(context.Background(), store, overlay.SandboxID, overlay.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 3 {
		t.Fatalf("deleted %d objects, want 3", deleted)
	}
	if left := objectNames(t, store, prefix); len(left) != 0 {
		t.Fatalf("generation objects left: %v", left)
	}
	if got := objectNames(t, store, "sandboxes/"+other.SandboxID+"/"+other.Generation+"/"); len(got) != 3 {
		t.Fatalf("other generation touched: %v", got)
	}
	if got := objectNames(t, store, "bases/"); len(got) != 1 {
		t.Fatalf("shared base touched: %v", got)
	}
	if _, err := fetchManifest(context.Background(), store, overlay.SandboxID, overlay.Generation, func(string, ...any) {}); err == nil {
		t.Fatal("a purged generation must not restore")
	}

	again, err := PurgeGeneration(context.Background(), store, overlay.SandboxID, overlay.Generation)
	if err != nil || again != 0 {
		t.Fatalf("second purge: deleted=%d err=%v", again, err)
	}
}

func TestSandboxGenerationsDescribesTheBucketFromOneListing(t *testing.T) {
	store := newMemBlobs()
	a := writePauseFixture(t, t.TempDir(), "pause A")
	uploadFixture(t, store, a)
	b := writePauseFixture(t, t.TempDir(), "pause B")
	b.SandboxID = "sb-other"
	uploadFixture(t, store, b)
	for _, name := range []string{"sandboxes/" + a.SandboxID + "/half-done/rootfs.ext4.p1", "sandboxes/stray", "sandboxes/../x/y/z", "bases/abc.p1"} {
		if _, err := store.Create(context.Background(), name, bytes.NewReader([]byte("x"))); err != nil {
			t.Fatal(err)
		}
	}
	got, err := SandboxGenerations(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || len(got[a.SandboxID]) != 2 || len(got[b.SandboxID]) != 1 {
		t.Fatalf("generations = %v", got)
	}
	if !got[a.SandboxID][a.Generation] || got[a.SandboxID]["half-done"] {
		t.Fatalf("completeness = %v; want the uploaded generation complete and the manifest-less one not", got[a.SandboxID])
	}
}
