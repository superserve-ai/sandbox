package vm

import (
	"context"
	"encoding/json"
	bolt "go.etcd.io/bbolt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/retainedstorage"
)

func TestRetainedRecordPathsTrackFullAndLayeredGenerations(t *testing.T) {
	root := t.TempDir()
	rec := VMRecord{ID: uuid.NewString(), SourceSnapshotID: uuid.NewString(), Status: StatusPaused, DiskPath: filepath.Join(root, "overlay.ext4"), BasePath: filepath.Join(root, "base.ext4"), SnapshotPath: filepath.Join(root, "vmstate.snap"), MemFilePath: filepath.Join(root, "mem.diff"), BaseMemPath: filepath.Join(root, "base-mem.snap")}
	paths, err := retainedRecordPaths(rec, root)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(paths, []string{rec.DiskPath, rec.BasePath, rec.SnapshotPath, rec.MemFilePath, rec.BaseMemPath}) {
		t.Fatalf("layered dependencies: %v", paths)
	}
	old := rec.MemFilePath
	rec.MemFilePath = filepath.Join(root, "mem.snap")
	rec.BaseMemPath = ""
	rec.StrandedOverlays = []string{old}
	paths, err = retainedRecordPaths(rec, root)
	if err != nil {
		t.Fatal(err)
	}
	if paths[len(paths)-1] != old || paths[3] != rec.MemFilePath || paths[4] != "" {
		t.Fatalf("full transition dependencies: %v", paths)
	}
	rec.StrandedOverlays = nil
	rec.Status = StatusRunning
	paths, err = retainedRecordPaths(rec, root)
	if err != nil || paths[3] != rec.MemFilePath {
		t.Fatalf("running retained memory: %v %v", paths, err)
	}
	rec.Status = StatusPaused
	rec.MemFilePath = ""
	if _, err = retainedRecordPaths(rec, root); err == nil {
		t.Fatal("missing paused memory was treated as absent")
	}
}

func TestRetainedRecordPathsResolvePinnedTemplateAndLayeredSidecar(t *testing.T) {
	root := t.TempDir()
	mem := filepath.Join(root, "mem.diff")
	base := filepath.Join(root, "template", "mem.snap")
	if err := os.WriteFile(mem+".base", []byte(base+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := VMRecord{ID: uuid.NewString(), Status: StatusPaused,
		DiskPath: filepath.Join(root, "overlay.ext4"), BasePath: filepath.Join(root, "template", "base.ext4"), SnapshotPath: filepath.Join(root, "vmstate.snap"),
		MemFilePath: mem, DeltaDir: filepath.Join(root, "template"), RootfsPath: filepath.Join(root, "template", "rootfs.ext4")}
	paths, err := retainedRecordPaths(rec, root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{rec.DiskPath, rec.BasePath, rec.SnapshotPath, rec.MemFilePath, base, rec.RootfsPath, filepath.Join(rec.DeltaDir, "rootfs.delta")}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("retained dependencies = %v, want %v", paths, want)
	}
}

func TestRetainedRecordPathsAllowRevivedOverlayWithoutTemplateAnchor(t *testing.T) {
	root := t.TempDir()
	rec := VMRecord{
		ID:          uuid.NewString(),
		Status:      StatusRunning,
		RevivedDisk: filepath.Join(root, "salvaged.ext4"),
		DiskPath:    filepath.Join(root, "overlay.ext4"),
		BasePath:    filepath.Join(root, "template.ext4"),
	}
	paths, err := retainedRecordPaths(rec, root)
	if err != nil {
		t.Fatalf("revived overlay rejected without unrelated template delta: %v", err)
	}
	if !slices.Contains(paths, rec.DiskPath) || !slices.Contains(paths, rec.BasePath) {
		t.Fatalf("revived overlay dependencies omitted: %v", paths)
	}
}

func TestRetainedInventoryRejectsLifecycleOverlap(t *testing.T) {
	state, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	m := &Manager{state: state, cfg: ManagerConfig{SnapshotDir: t.TempDir()}}
	if _, err := m.RetainedStorageInventory(t.Context()); err != nil {
		t.Fatal(err)
	}
	unlock, err := m.lockVMOp(context.Background(), uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	epoch := m.storageEpoch.Load()
	if m.storageMutations.Load() != 1 {
		t.Fatal("operation not fenced")
	}
	if _, err := m.RetainedStorageInventory(context.Background()); err == nil {
		t.Fatal("sampled a changing generation")
	}
	unlock()
	if m.storageMutations.Load() != 0 || m.storageEpoch.Load() <= epoch {
		t.Fatal("operation release did not advance generation")
	}
}

func TestRetainedInventoryRejectsIncompleteSavedSnapshotManifest(t *testing.T) {
	root := t.TempDir()
	state, err := OpenStateStore(filepath.Join(root, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	snapshotID := uuid.NewString()
	snapshotDir := filepath.Join(root, SavedSnapshotsDirName, snapshotID)
	if err := os.MkdirAll(snapshotDir, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := []byte(`{"version":1,"snapshot_id":"` + snapshotID + `","kind":"mem+fs"}`)
	if err := os.WriteFile(filepath.Join(snapshotDir, savedSnapshotManifestName), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	m := &Manager{state: state, cfg: ManagerConfig{RunDir: root, SnapshotDir: root}}
	_, err = m.retainedStorageInventory(t.Context(), func(*os.File, int) ([]retainedstorage.Extent, string, error) {
		return []retainedstorage.Extent{}, "generation", nil
	})
	if err == nil {
		t.Fatal("incomplete saved snapshot manifest was accepted")
	}
}

func TestRetainedInventorySpoolPreservesIdentityAndVersion(t *testing.T) {
	dir := t.TempDir()
	incarnation := uuid.NewString()
	cache := newHeartbeatStorageCache(dir, zerolog.Nop(), incarnation)
	inv := &retainedstorage.Inventory{Version: retainedstorage.Version, Owners: []retainedstorage.Owner{{Kind: "sandbox", ID: uuid.NewString(), Generation: strings.Repeat("1", 64), Extents: []retainedstorage.Extent{}}}}
	if err := cache.store([]heartbeatStorageMeasurement{{Retained: inv}}); err != nil {
		t.Fatal(err)
	}
	pending := cache.pendingSnapshot()
	if len(pending) != 1 {
		t.Fatalf("pending reports: %d", len(pending))
	}
	restored := newHeartbeatStorageCache(dir, zerolog.Nop(), incarnation).pendingSnapshot()
	if !reflect.DeepEqual(pending, restored) {
		t.Fatal("restart changed retained report identity or explicit zero")
	}
}

func TestRetainedPausedUpgradeDependencies(t *testing.T) {
	root := t.TempDir()
	generation := filepath.Join(root, "snapshots", "templates", uuid.NewString(), uuid.NewString())
	if err := os.MkdirAll(generation, 0700); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(root, "bases", "base.ext4")
	delta := filepath.Join(generation, "rootfs.delta")
	memory := filepath.Join(generation, "mem.snap")
	meta := `{"base_path":` + strconv.Quote(base) + `,"delta_path":` + strconv.Quote(delta) + `}`
	if err := os.WriteFile(filepath.Join(generation, buildMetaFilename), []byte(meta), 0600); err != nil {
		t.Fatal(err)
	}
	rec := VMRecord{ID: uuid.NewString(), Status: StatusPaused, BasePath: base, DiskPath: filepath.Join(root, "overlay.ext4"), SnapshotPath: filepath.Join(root, "paused", "vmstate.snap"), MemFilePath: filepath.Join(root, "paused", "mem.diff"), BaseMemPath: memory, DeltaDir: generation}
	// These are the fields that survive a pre-upgrade daemon's record rewrite.
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	var oldFields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &oldFields); err != nil {
		t.Fatal(err)
	}
	delete(oldFields, "delta_dir")
	delete(oldFields, "rootfs_path")
	raw, err = json.Marshal(oldFields)
	if err != nil {
		t.Fatal(err)
	}
	var rewritten VMRecord
	if err := json.Unmarshal(raw, &rewritten); err != nil {
		t.Fatal(err)
	}
	paths, resolved, err := resolveRetainedRecordPaths(rewritten, root)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(paths, delta) || !slices.Contains(paths, memory) || !slices.Contains(paths, base) {
		t.Fatalf("lost pinned generation: %v", paths)
	}
	if resolved.DeltaDir != generation {
		t.Fatalf("resolved generation anchor = %q, want %q", resolved.DeltaDir, generation)
	}
	// A full pause can erase the last template-generation anchor in old
	// records. Neither a mutable latest build nor the sandbox image proves it.
	rewritten.MemFilePath = filepath.Join(root, "paused", "mem.snap")
	rewritten.BaseMemPath = ""
	if _, err := retainedRecordPaths(rewritten, root); err == nil {
		t.Fatal("unresolved paused overlay accepted")
	}
	rewritten.BasePath = ""
	if _, err := retainedRecordPaths(rewritten, root); err == nil {
		t.Fatal("unresolved full-copy template accepted")
	}
	// A durable legacy generation manifest resolves the full-copy rootfs.
	rootfs := filepath.Join(root, "templates", "legacy", "rootfs.ext4")
	if err := os.WriteFile(filepath.Join(generation, buildMetaFilename), []byte(`{"rootfs_path":`+strconv.Quote(rootfs)+`}`), 0600); err != nil {
		t.Fatal(err)
	}
	rewritten.SnapshotPath = filepath.Join(generation, "vmstate.snap")
	paths, err = retainedRecordPaths(rewritten, root)
	if err != nil || !slices.Contains(paths, rootfs) {
		t.Fatalf("legacy generation: %v %v", paths, err)
	}
}

func TestRetainedInventoryArtifactRacePreservesAcceptedQuantity(t *testing.T) {
	for _, remove := range []bool{false, true} {
		name := "replacement"
		if remove {
			name = "deletion"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			state, err := OpenStateStore(filepath.Join(root, "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer state.Close()
			disk := filepath.Join(root, "overlay.ext4")
			if err := os.WriteFile(disk, []byte("accepted generation"), 0600); err != nil {
				t.Fatal(err)
			}
			rec := VMRecord{ID: uuid.NewString(), SourceSnapshotID: uuid.NewString(), Status: StatusRunning, DiskPath: disk}
			if err := state.Put(rec); err != nil {
				t.Fatal(err)
			}
			m := &Manager{state: state, cfg: ManagerConfig{RunDir: root, SnapshotDir: filepath.Join(root, "snapshots")}}
			measure := func(*os.File, int) ([]retainedstorage.Extent, string, error) {
				return []retainedstorage.Extent{{Device: "fs", Start: 4096, Length: 4096}}, "accepted", nil
			}
			accepted, err := m.retainedStorageInventory(t.Context(), measure)
			if err != nil {
				t.Fatal(err)
			}
			cache := newHeartbeatStorageCache(t.TempDir(), zerolog.Nop(), uuid.NewString())
			if err := cache.store([]heartbeatStorageMeasurement{{Retained: accepted}}); err != nil {
				t.Fatal(err)
			}
			before := cache.pendingSnapshot()
			raced := false
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			runRetainedStorageSampler(ctx, HeartbeatConfig{LifecycleReady: func() bool { return true }, RetainedStorage: func(context.Context) (*retainedstorage.Inventory, error) {
				defer cancel()
				return m.retainedStorageInventory(t.Context(), func(f *os.File, budget int) ([]retainedstorage.Extent, string, error) {
					raced = true
					if remove {
						if err := os.Remove(disk); err != nil {
							t.Fatal(err)
						}
					} else {
						replacement := disk + ".replacement"
						if err := os.WriteFile(replacement, []byte("new generation"), 0600); err != nil {
							t.Fatal(err)
						}
						if err := os.Rename(replacement, disk); err != nil {
							t.Fatal(err)
						}
					}
					return measure(f, budget)
				})
			}}, cache, zerolog.Nop())
			if !raced {
				t.Fatal("inventory never reached artifact scan")
			}
			if !reflect.DeepEqual(before, cache.pendingSnapshot()) {
				t.Fatal("race replaced accepted report quantity")
			}
		})
	}
}

func TestRetainedDependencyUpdateRejectsNewLifecycleGeneration(t *testing.T) {
	for _, tracked := range []bool{false, true} {
		for _, transition := range []string{"pause", "resume", "recreate", "delete"} {
			t.Run(strconv.FormatBool(tracked)+"/"+transition, func(t *testing.T) {
				state, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
				if err != nil {
					t.Fatal(err)
				}
				defer state.Close()
				original := VMRecord{ID: uuid.NewString(), Status: StatusRunning, DiskPath: "/example/overlay.ext4", SnapshotPath: "/example/templates/old/vmstate.snap", MemFilePath: "/example/templates/old/mem.snap"}
				if transition == "resume" {
					original.Status = StatusPaused
				}
				if err := state.Put(original); err != nil {
					t.Fatal(err)
				}
				resolved := original
				resolved.RootfsPath = "/example/templates/old/rootfs.ext4"
				m := &Manager{state: state, vms: map[string]*VMInstance{}}
				if tracked {
					m.vms[original.ID] = toInstance(original)
				}
				unlock, err := m.lockVMOp(t.Context(), original.ID)
				if err != nil {
					t.Fatal(err)
				}
				// The sampler captured the old record before the operation began.
				if err := m.rememberRetainedDependencies(original, resolved); err == nil {
					t.Fatal("dependency update entered an active lifecycle operation")
				}
				newer := original
				switch transition {
				case "pause":
					newer.Status = StatusPaused
					newer.SnapshotPath = "/example/paused/vmstate.snap"
					newer.MemFilePath = "/example/paused/mem.snap"
					newer.ArtifactID = "new-pause"
				case "resume":
					newer.Status = StatusRunning
					newer.PID = 12345
					newer.DiskPath = "/example/resumed/rootfs.ext4"
				case "recreate":
					newer.CreatedAt = time.Now().UTC()
				case "delete":
					if err := state.Delete(original.ID); err != nil {
						t.Fatal(err)
					}
					delete(m.vms, original.ID)
				}
				if transition != "delete" {
					if err := state.Put(newer); err != nil {
						t.Fatal(err)
					}
					if tracked {
						m.vms[original.ID] = toInstance(newer)
					}
				}
				unlock()
				before, err := state.Get(original.ID)
				if err != nil {
					t.Fatal(err)
				}
				if err := m.rememberRetainedDependencies(original, resolved); err == nil {
					t.Fatal("stale dependency update accepted after lifecycle transition")
				}
				after, err := state.Get(original.ID)
				if err != nil || !reflect.DeepEqual(before, after) {
					t.Fatalf("stale update changed durable lifecycle state: before=%+v after=%+v err=%v", before, after, err)
				}
				if inst := m.vms[original.ID]; inst != nil && inst.Config.RootfsPath != "" {
					t.Fatal("stale dependency installed in memory")
				}
			})
		}
	}
}

func TestRetainedDependencyUpdatePreservesCurrentFields(t *testing.T) {
	for _, tracked := range []bool{false, true} {
		t.Run(strconv.FormatBool(tracked), func(t *testing.T) {
			state, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer state.Close()
			original := VMRecord{ID: uuid.NewString(), Status: StatusPaused, DiskPath: "/example/overlay.ext4", SnapshotPath: "/example/vmstate.snap", MemFilePath: "/example/mem.diff"}
			current := original
			current.Metadata = map[string]string{"label": "newer-value"}
			if err := state.Put(current); err != nil {
				t.Fatal(err)
			}
			// Fields from a newer daemon must survive a dependency-only patch.
			if err := state.db.Update(func(tx *bolt.Tx) error {
				b := tx.Bucket(bucketName)
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(b.Get([]byte(original.ID)), &fields); err != nil {
					return err
				}
				fields["future_field"] = json.RawMessage(`"keep"`)
				raw, err := json.Marshal(fields)
				if err != nil {
					return err
				}
				return b.Put([]byte(original.ID), raw)
			}); err != nil {
				t.Fatal(err)
			}
			m := &Manager{state: state, vms: map[string]*VMInstance{}}
			if tracked {
				m.vms[original.ID] = toInstance(current)
			}
			resolved := original
			resolved.BaseMemPath = "/example/templates/pinned/mem.snap"
			resolved.RootfsPath = "/example/templates/pinned/rootfs.ext4"
			resolved.DeltaDir = "/example/templates/pinned"
			if err := m.rememberRetainedDependencies(original, resolved); err != nil {
				t.Fatal(err)
			}
			current.BaseMemPath, current.RootfsPath, current.DeltaDir = resolved.BaseMemPath, resolved.RootfsPath, resolved.DeltaDir
			after, err := state.Get(original.ID)
			if err != nil || after == nil || !reflect.DeepEqual(*after, current) {
				t.Fatalf("dependency patch lost current fields: %+v %v", after, err)
			}
			if err := state.db.View(func(tx *bolt.Tx) error {
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(tx.Bucket(bucketName).Get([]byte(original.ID)), &fields); err != nil {
					return err
				}
				if string(fields["future_field"]) != `"keep"` {
					t.Fatal("dependency patch lost unknown field")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if tracked && !sameRetainedGeneration(current, toRecord(m.vms[original.ID])) {
				t.Fatal("durable and in-memory dependencies disagree")
			}
		})
	}
}

func TestRetainedRevivedFullCopySurvivesPauseAndRestart(t *testing.T) {
	for _, legacy := range []bool{true, false} {
		t.Run(strconv.FormatBool(legacy), func(t *testing.T) {
			root := t.TempDir()
			statePath := filepath.Join(root, "state.db")
			state, err := OpenStateStore(statePath)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { state.Close() })
			id := uuid.NewString()
			previous := VMRecord{ID: id, Status: StatusError}
			salvage := filepath.Join(root, "salvaged.ext4")
			if !legacy {
				previous.RootfsPath = filepath.Join(root, "pinned-rootfs.ext4")
			}
			// coldBootFromRootfs establishes this source before invoking the
			// revival seed; the writable copy is a separate retained file.
			inst := &VMInstance{ID: id, Status: StatusCreating, Config: VMConfig{RootfsPath: salvage}, RevivedDisk: salvage}
			seedRevivedRetainedDependencies(inst, &previous)
			wantRootfs := previous.RootfsPath
			if legacy {
				wantRootfs = salvage
			}
			if inst.Config.RootfsPath != wantRootfs {
				t.Fatalf("revival rootfs = %q, want %q", inst.Config.RootfsPath, wantRootfs)
			}
			inst.DiskPath = filepath.Join(root, "rootfs.ext4")
			inst.Status = StatusRunning
			if err := state.Put(toRecord(inst)); err != nil {
				t.Fatal(err)
			}
			// Persist the full-pause transition, which replaces memory anchors.
			inst.Status = StatusPaused
			inst.SnapshotPath = filepath.Join(root, "vmstate.snap")
			inst.MemFilePath = filepath.Join(root, "mem.snap")
			inst.BaseMemPath = ""
			for _, path := range []string{wantRootfs, inst.DiskPath, inst.SnapshotPath, inst.MemFilePath} {
				if err := os.WriteFile(path, []byte("retained"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := state.Put(toRecord(inst)); err != nil {
				t.Fatal(err)
			}
			if err := state.Close(); err != nil {
				t.Fatal(err)
			}
			state, err = OpenStateStore(statePath)
			if err != nil {
				t.Fatal(err)
			}
			rec, err := state.Get(id)
			if err != nil || rec == nil {
				t.Fatalf("restart lost record: %v", err)
			}
			m := &Manager{state: state, cfg: ManagerConfig{RunDir: root, SnapshotDir: filepath.Join(root, "snapshots")}, vms: map[string]*VMInstance{id: toInstance(*rec)}}
			seen := map[string]bool{}
			inv, err := m.retainedStorageInventory(t.Context(), func(f *os.File, _ int) ([]retainedstorage.Extent, string, error) {
				seen[f.Name()] = true
				return []retainedstorage.Extent{{Device: "fs", Start: int64(len(seen)) * 4096, Length: 4096}}, f.Name(), nil
			})
			if err != nil || inv == nil || len(inv.Owners) != 1 || len(seen) != 4 || !seen[wantRootfs] {
				t.Fatalf("revived inventory lost dependencies: paths=%v err=%v", seen, err)
			}
		})
	}
}

func TestRetainedDependencyUpdateFencesConcurrentDurableWrite(t *testing.T) {
	state, err := OpenStateStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	original := VMRecord{ID: uuid.NewString(), Status: StatusRunning, SnapshotPath: "/example/templates/pinned/vmstate.snap"}
	if err := state.Put(original); err != nil {
		t.Fatal(err)
	}
	resolved := original
	resolved.RootfsPath = "/example/templates/pinned/rootfs.ext4"
	// Hold the lifecycle writer transaction while the sampler attempts its
	// update. Its generation comparison must observe the committed pause.
	tx, err := state.db.Begin(true)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	newer := original
	newer.Status = StatusPaused
	newer.SnapshotPath = "/example/paused/vmstate.snap"
	newer.MemFilePath = "/example/paused/mem.snap"
	newer.ArtifactID = "new-pause"
	if _, err := putRecord(tx, newer, true); err != nil {
		t.Fatal(err)
	}
	started, done := make(chan struct{}), make(chan error, 1)
	go func() {
		close(started)
		done <- state.updateRetainedDependencies(original, resolved)
	}()
	<-started
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Fatal("sampler accepted the prior generation after concurrent pause")
	}
	after, err := state.Get(original.ID)
	if err != nil || after == nil || !reflect.DeepEqual(*after, newer) {
		t.Fatalf("concurrent pause was overwritten: %+v %v", after, err)
	}
}
