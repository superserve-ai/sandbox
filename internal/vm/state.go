package vm

import (
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// State provides durable local persistence for VM instance metadata.
// It is a cache — systemd is the ground truth for liveness, the control
// plane DB is the ground truth for intent. State allows VMD to reattach
// to running Firecracker processes after a restart without querying the
// control plane.

var bucketName = []byte("vms")

// VMRecord is the serializable subset of VMInstance persisted to BoltDB.
// It contains everything VMD needs to reconstruct its in-memory map on
// startup and reattach to a live Firecracker process.
type VMRecord struct {
	ID           string   `json:"id"`
	PID          int      `json:"pid"`
	SocketPath   string   `json:"socket_path"`
	VsockPath    string   `json:"vsock_path,omitempty"`
	IP           string   `json:"ip"`
	TAPDevice    string   `json:"tap_device"`
	MACAddress   string   `json:"mac_address"`
	Status       VMStatus `json:"status"`
	RunDirID     string   `json:"rundir_id"`
	Namespace    string   `json:"namespace"`
	DiskPath     string   `json:"disk_path"`
	SnapshotPath string   `json:"snapshot_path,omitempty"`
	MemFilePath  string   `json:"mem_file_path,omitempty"`
	// Persisted so a layered (diff-overlay) sandbox resumes correctly after a vmd
	// restart: non-empty means MemFilePath is an overlay to be served over this
	// base. Without it, resume would load the overlay standalone and read the
	// base's pages as zero holes.
	BaseMemPath string            `json:"base_mem_path,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	VCPU        uint32            `json:"vcpu"`
	MemoryMiB   uint32            `json:"memory_mib"`
	// Persisted so overlay-mode sandboxes can be resumed correctly after a
	// vmd restart (the start script needs basePath to wire up the
	// dual-symlink mount namespace). DeltaDir is intentionally NOT
	// persisted — it's only relevant at create-from-template; a resumed
	// sandbox reuses its existing overlay file in place.
	BasePath string `json:"base_path,omitempty"`
	// Persisted so usage attribution survives a vmd restart.
	TeamID  string `json:"team_id,omitempty"`
	OwnerID string `json:"owner_id,omitempty"`
}

// StateStore wraps a BoltDB database for VM state persistence.
type StateStore struct {
	db *bolt.DB
}

// OpenStateStore opens (or creates) the BoltDB file at path.
func OpenStateStore(path string) (*StateStore, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open state store %s: %w", path, err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketName)
		return err
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("create bucket: %w", err)
	}
	return &StateStore{db: db}, nil
}

// Close flushes and closes the database.
func (s *StateStore) Close() error {
	return s.db.Close()
}

// Put persists a VM record. Batched; the callback is idempotent so
// Batch's retry-on-failure semantics are safe.
func (s *StateStore) Put(rec VMRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal vm record: %w", err)
	}
	return s.db.Batch(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketName).Put([]byte(rec.ID), data)
	})
}

// Get retrieves a single VM record by ID. Returns nil if not found.
func (s *StateStore) Get(vmID string) (*VMRecord, error) {
	var rec VMRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketName).Get([]byte(vmID))
		if v == nil {
			return nil
		}
		return json.Unmarshal(v, &rec)
	})
	if err != nil {
		return nil, err
	}
	if rec.ID == "" {
		return nil, nil
	}
	return &rec, nil
}

// Delete removes a VM record.
func (s *StateStore) Delete(vmID string) error {
	return s.db.Batch(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketName).Delete([]byte(vmID))
	})
}

// PutIfPresent writes rec only if its key still exists, returning false if not.
// bbolt serializes writes, so the get-then-put is atomic against a concurrent
// Delete — a record deleted mid-startup can't be resurrected by a stale persist.
func (s *StateStore) PutIfPresent(rec VMRecord) (bool, error) {
	data, err := json.Marshal(rec)
	if err != nil {
		return false, fmt.Errorf("marshal vm record: %w", err)
	}
	wrote := false
	err = s.db.Batch(func(tx *bolt.Tx) error {
		// Batch may retry this closure (coalesced transactions), so recompute
		// wrote each run — the final successful run is authoritative.
		wrote = false
		b := tx.Bucket(bucketName)
		if b.Get([]byte(rec.ID)) == nil {
			return nil
		}
		wrote = true
		return b.Put([]byte(rec.ID), data)
	})
	return wrote, err
}

// Has reports whether a record for vmID exists.
func (s *StateStore) Has(vmID string) (bool, error) {
	exists := false
	err := s.db.View(func(tx *bolt.Tx) error {
		exists = tx.Bucket(bucketName).Get([]byte(vmID)) != nil
		return nil
	})
	return exists, err
}

// All returns every persisted VM record.
func (s *StateStore) All() ([]VMRecord, error) {
	var records []VMRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		return b.ForEach(func(_, v []byte) error {
			var rec VMRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return fmt.Errorf("unmarshal vm record: %w", err)
			}
			records = append(records, rec)
			return nil
		})
	})
	return records, err
}

// IDs returns the set of persisted VM IDs without unmarshaling records.
func (s *StateStore) IDs() (map[string]struct{}, error) {
	ids := make(map[string]struct{})
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		return b.ForEach(func(k, _ []byte) error {
			ids[string(k)] = struct{}{}
			return nil
		})
	})
	return ids, err
}

// toRecord converts a VMInstance to a persistable VMRecord.
func toRecord(inst *VMInstance) VMRecord {
	inst.mu.RLock()
	defer inst.mu.RUnlock()
	return VMRecord{
		ID:           inst.ID,
		PID:          inst.PID,
		SocketPath:   inst.SocketPath,
		VsockPath:    inst.VsockPath,
		IP:           inst.IP,
		TAPDevice:    inst.TAPDevice,
		MACAddress:   inst.MACAddress,
		Status:       inst.Status,
		RunDirID:     inst.RunDirID,
		Namespace:    inst.Namespace,
		DiskPath:     inst.DiskPath,
		SnapshotPath: inst.SnapshotPath,
		MemFilePath:  inst.MemFilePath,
		BaseMemPath:  inst.BaseMemPath,
		CreatedAt:    inst.CreatedAt,
		Metadata:     inst.Metadata,
		VCPU:         inst.Config.VCPU,
		MemoryMiB:    inst.Config.MemoryMiB,
		BasePath:     inst.Config.BasePath,
		TeamID:       inst.TeamID,
		OwnerID:      inst.OwnerID,
	}
}

// toInstance converts a VMRecord back to a VMInstance.
func toInstance(rec VMRecord) *VMInstance {
	return &VMInstance{
		ID:           rec.ID,
		PID:          rec.PID,
		SocketPath:   rec.SocketPath,
		VsockPath:    rec.VsockPath,
		IP:           rec.IP,
		TAPDevice:    rec.TAPDevice,
		MACAddress:   rec.MACAddress,
		Status:       rec.Status,
		RunDirID:     rec.RunDirID,
		Namespace:    rec.Namespace,
		DiskPath:     rec.DiskPath,
		SnapshotPath: rec.SnapshotPath,
		MemFilePath:  rec.MemFilePath,
		BaseMemPath:  rec.BaseMemPath,
		CreatedAt:    rec.CreatedAt,
		Metadata:     rec.Metadata,
		TeamID:       rec.TeamID,
		OwnerID:      rec.OwnerID,
		Config: VMConfig{
			VCPU:      rec.VCPU,
			MemoryMiB: rec.MemoryMiB,
			BasePath:  rec.BasePath,
		},
	}
}
