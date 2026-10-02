package backup

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

type templateReconcileStore struct {
	object string
	data   string
}

func (s templateReconcileStore) List(context.Context, string) ([]ObjectInfo, error) {
	if s.object == "" {
		return nil, nil
	}
	return []ObjectInfo{{Name: s.object}}, nil
}

func (s templateReconcileStore) NewReader(context.Context, string) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(s.data)), nil
}

func TestFindTemplatePublication(t *testing.T) {
	const templateID = "template-id"
	const vmID = "build-attempt-id"
	paths := []string{"/runtime/rootfs.ext4", "/runtime/vmstate.snap", "/runtime/mem.bin", "/runtime/build.meta.json"}
	names := []string{"rootfs.ext4", "vmstate.snap", "mem.bin", "build.meta.json"}
	files := make([]ManifestFile, 0, len(paths))
	keyFiles := make([]TaskFile, 0, len(paths))
	for i, name := range names {
		hash := strings.Repeat(string(rune('a'+i)), 64)
		files = append(files, ManifestFile{Name: name, RuntimePath: paths[i], Object: name + ".pabc", SHA256: hash, Size: 10, AllocatedBytes: int64((i + 1) * 4096)})
		keyFiles = append(keyFiles, TaskFile{Name: name, SHA256: hash, Size: 10})
	}
	generation := GenerationKey(keyFiles)
	manifest := GenerationManifest{TemplateID: templateID, BuildID: vmID, Generation: generation, Files: files,
		TemplateRuntime: &TemplateRuntime{RootfsPath: paths[0], SnapshotPath: paths[1], MemPath: paths[2]}}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	object, err := TemplateObject(templateID, vmID, generation, ManifestObject)
	if err != nil {
		t.Fatal(err)
	}
	store := templateReconcileStore{object: object, data: string(data)}
	got, mapped, named, err := FindTemplatePublication(context.Background(), store, templateID, vmID)
	if err != nil || got == nil || named != object || len(mapped) != len(files) {
		t.Fatalf("publication = %v, %d files, %q, %v", got, len(mapped), named, err)
	}
	for i, file := range mapped {
		want, _ := TemplateObject(templateID, vmID, generation, files[i].Object)
		if file.Object != want || file.RuntimePath != paths[i] || file.AllocatedBytes != files[i].AllocatedBytes {
			t.Fatalf("mapped file %d = %+v, want object %q", i, file, want)
		}
	}
	manifest.BuildID = "another-execution"
	bad, _ := json.Marshal(manifest)
	store.data = string(bad)
	if _, _, _, err := FindTemplatePublication(context.Background(), store, templateID, vmID); err == nil {
		t.Fatal("accepted a manifest for another execution")
	}
	store.object = ""
	if got, _, _, err := FindTemplatePublication(context.Background(), store, templateID, vmID); err != nil || got != nil {
		t.Fatalf("missing manifest = %v, %v", got, err)
	}
}
