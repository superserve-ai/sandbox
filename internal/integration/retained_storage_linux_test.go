//go:build integration && linux

package integration

import (
	"bytes"
	"encoding/json"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/superserve-ai/sandbox/internal/retainedstorage"
	vm "github.com/superserve-ai/sandbox/internal/vm"
)

func TestRetainedStorageRealFilesystemReachesBillingConsumer(t *testing.T) {
	root := os.Getenv("RETAINED_STORAGE_TEST_DIR")
	if root == "" {
		t.Skip("RETAINED_STORAGE_TEST_DIR must name a qualified Linux reflink filesystem")
	}
	dir, err := os.MkdirTemp(root, "retained-billing-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	f := newStorageReportFixture(t, "paused", false)
	state, err := vm.OpenStateStore(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	paths := []string{
		filepath.Join(dir, "overlay.ext4"),
		filepath.Join(dir, "vmstate.snap"),
		filepath.Join(dir, "mem.snap"),
	}
	for i, path := range paths {
		data := bytes.Repeat([]byte{byte(i + 1)}, (i+1)*4096)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rec := vm.VMRecord{ID: f.sandboxID.String(), Status: vm.StatusPaused,
		DiskPath: paths[0], RootfsPath: paths[0], SnapshotPath: paths[1], MemFilePath: paths[2]}
	if err := state.Put(rec); err != nil {
		t.Fatal(err)
	}
	mgr, err := vm.NewManager(vm.ManagerConfig{RunDir: dir, SnapshotDir: filepath.Join(dir, "snapshots")}, nil, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	mgr.SetStateStore(state)
	inv, err := mgr.RetainedStorageInventory(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Owners) != 1 || len(inv.Owners[0].Extents) == 0 {
		t.Fatalf("real filesystem inventory = %#v", inv)
	}
	// The report is the actual FIEMAP-derived payload, not synthetic extents.
	reportID := uuid.New()
	body, err := json.Marshal(map[string]any{
		"incarnation_id": f.incarnation, "report_id": reportID,
		"measurements": []any{map[string]any{"sandbox_id": "", "allocated_bytes": 0, "retained": inv}},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := requestStorageReport(f.router, f.hostID, string(body))
	if response.Code != http.StatusCreated {
		t.Fatalf("real inventory report: %d %s", response.Code, response.Body.String())
	}
	ack := decodeStorageReportAck(t, response)
	waitStorageReportState(t, reportID, "processed")
	var got float64
	if err := testPool.QueryRow(t.Context(), `SELECT retained_storage_mib_seconds($1,$2,$3)::float8`, sandboxTeamID(t, f.sandboxID), ack.ReceivedAt, ack.ReceivedAt.Add(time.Minute)).Scan(&got); err != nil {
		t.Fatal(err)
	}
	extents := append([]retainedstorage.Extent(nil), inv.Owners[0].Extents...)
	sort.Slice(extents, func(i, j int) bool {
		if extents[i].Device != extents[j].Device {
			return extents[i].Device < extents[j].Device
		}
		return extents[i].Start < extents[j].Start
	})
	total := int64(0)
	var device string
	var end int64
	for _, e := range extents {
		if e.Device != device {
			device, end = e.Device, 0
		}
		start := e.Start
		if start < end {
			start = end
		}
		if e.Start+e.Length > start {
			total += e.Start + e.Length - start
		}
		if e.Start+e.Length > end {
			end = e.Start + e.Length
		}
	}
	want := float64(total) / (1 << 20) * 60
	if math.Abs(got-want) > 0.0001 {
		t.Fatalf("real inventory billing = %v, want %v MiB-seconds", got, want)
	}
}
