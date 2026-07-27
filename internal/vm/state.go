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

var (
	bucketName              = []byte("vms")
	previewPolicyBucketName = []byte("vm_preview_policies")
)

// persistedPreviewPolicy is stored separately from VMRecord so a rollback to
// a VMD binary that predates preview policy fields can keep writing lifecycle
// records without erasing the last policy enforced by newer binaries.
type persistedPreviewPolicy struct {
	Access        string
	Ports         map[int32]bool
	Revision      int64
	unknownFields map[string]json.RawMessage
}

func (p *persistedPreviewPolicy) UnmarshalJSON(data []byte) error {
	var known struct {
		Access   string         `json:"access,omitempty"`
		Ports    map[int32]bool `json:"ports,omitempty"`
		Revision int64          `json:"revision,omitempty"`
	}
	if err := json.Unmarshal(data, &known); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	delete(fields, "access")
	delete(fields, "ports")
	delete(fields, "revision")
	if len(fields) == 0 {
		fields = nil
	}
	*p = persistedPreviewPolicy{
		Access:        known.Access,
		Ports:         known.Ports,
		Revision:      known.Revision,
		unknownFields: fields,
	}
	return nil
}

func (p persistedPreviewPolicy) MarshalJSON() ([]byte, error) {
	fields := make(map[string]json.RawMessage, len(p.unknownFields)+3)
	for key, value := range p.unknownFields {
		fields[key] = value
	}
	if p.Access != "" {
		data, err := json.Marshal(p.Access)
		if err != nil {
			return nil, err
		}
		fields["access"] = data
	}
	if len(p.Ports) != 0 {
		data, err := json.Marshal(p.Ports)
		if err != nil {
			return nil, err
		}
		fields["ports"] = data
	}
	if p.Revision != 0 {
		data, err := json.Marshal(p.Revision)
		if err != nil {
			return nil, err
		}
		fields["revision"] = data
	}
	return json.Marshal(fields)
}

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
	// Preview publication policy must survive vmd restarts; old records decode
	// to empty/legacy behavior for backward compatibility.
	PreviewAccess         string         `json:"preview_access,omitempty"`
	PreviewPorts          map[int32]bool `json:"preview_ports,omitempty"`
	PreviewPolicyRevision int64          `json:"preview_policy_revision,omitempty"`
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
		records, err := tx.CreateBucketIfNotExists(bucketName)
		if err != nil {
			return err
		}
		policies, err := tx.CreateBucketIfNotExists(previewPolicyBucketName)
		if err != nil {
			return err
		}

		// An old VMD can delete the primary record without knowing about the
		// sidecar bucket. Remove those orphans before migrating so a later VM
		// reusing the same key cannot inherit deleted policy state.
		var orphanKeys [][]byte
		if err := policies.ForEach(func(k, _ []byte) error {
			if records.Get(k) == nil {
				orphanKeys = append(orphanKeys, append([]byte(nil), k...))
			}
			return nil
		}); err != nil {
			return err
		}
		for _, key := range orphanKeys {
			if err := policies.Delete(key); err != nil {
				return err
			}
		}

		// Seed the sidecar for records written by the immediately preceding
		// schema. Once present, the sidecar is authoritative and is never
		// replaced from the primary JSON during startup.
		return records.ForEach(func(k, v []byte) error {
			if policies.Get(k) != nil {
				return nil
			}
			var rec VMRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return fmt.Errorf("unmarshal vm record during preview policy migration: %w", err)
			}
			policy := previewPolicyFromRecord(rec)
			if !policy.isSet() {
				return nil
			}
			return putPreviewPolicy(policies, k, policy)
		})
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize state store: %w", err)
	}
	return &StateStore{db: db}, nil
}

// Close flushes and closes the database.
func (s *StateStore) Close() error {
	return s.db.Close()
}

// Put persists a VM record. Batched; the callback is idempotent so Batch's
// retry-on-failure semantics are safe. The lifecycle record and authoritative
// preview-policy sidecar are updated in the same transaction.
func (s *StateStore) Put(rec VMRecord) error {
	return s.db.Batch(func(tx *bolt.Tx) error {
		_, err := putRecord(tx, rec, false)
		return err
	})
}

// Get retrieves a single VM record by ID. Returns nil if not found.
func (s *StateStore) Get(vmID string) (*VMRecord, error) {
	var rec VMRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		key := []byte(vmID)
		v := tx.Bucket(bucketName).Get(key)
		if v == nil {
			return nil
		}
		if err := json.Unmarshal(v, &rec); err != nil {
			return err
		}
		return overlayPreviewPolicy(&rec, tx.Bucket(previewPolicyBucketName).Get(key))
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
		key := []byte(vmID)
		if err := tx.Bucket(bucketName).Delete(key); err != nil {
			return err
		}
		return tx.Bucket(previewPolicyBucketName).Delete(key)
	})
}

// PutIfPresent writes rec only if its key still exists, returning false if not.
// bbolt serializes writes, so the get-then-put is atomic against a concurrent
// Delete — a record deleted mid-startup can't be resurrected by a stale persist.
func (s *StateStore) PutIfPresent(rec VMRecord) (bool, error) {
	wrote := false
	err := s.db.Batch(func(tx *bolt.Tx) error {
		// Batch may retry this closure (coalesced transactions), so recompute
		// wrote each run — the final successful run is authoritative.
		wrote = false
		var err error
		wrote, err = putRecord(tx, rec, true)
		return err
	})
	return wrote, err
}

// putRecord writes both representations atomically and reports whether the
// primary lifecycle record was written. A sidecar without a primary record is
// an orphan left by an old-binary delete and must never influence a new VM.
func putRecord(tx *bolt.Tx, incoming VMRecord, onlyIfPresent bool) (bool, error) {
	records := tx.Bucket(bucketName)
	policies := tx.Bucket(previewPolicyBucketName)
	key := []byte(incoming.ID)
	primaryExists := records.Get(key) != nil
	if !primaryExists {
		if err := policies.Delete(key); err != nil {
			return false, err
		}
		if onlyIfPresent {
			return false, nil
		}
	}

	incomingPolicy := previewPolicyFromRecord(incoming)
	if primaryExists {
		persistedPolicy, ok, err := getPreviewPolicy(policies, key)
		if err != nil {
			return false, err
		}
		if ok {
			// Preserve fields introduced by later VMD versions even when this
			// binary legitimately advances the fields it understands.
			incomingPolicy.unknownFields = persistedPolicy.unknownFields
			// A policy revision identifies one immutable policy snapshot. Keeping
			// the sidecar on equality also protects an initial strict revision-zero
			// policy from an old lifecycle record with legacy zero values.
			if persistedPolicy.Revision >= incomingPolicy.Revision {
				persistedPolicy.applyTo(&incoming)
				incomingPolicy = persistedPolicy
			}
		}
	}

	data, err := json.Marshal(incoming)
	if err != nil {
		return false, fmt.Errorf("marshal vm record: %w", err)
	}
	if err := records.Put(key, data); err != nil {
		return false, err
	}
	if incomingPolicy.isSet() {
		if err := putPreviewPolicy(policies, key, incomingPolicy); err != nil {
			return false, err
		}
	} else if err := policies.Delete(key); err != nil {
		return false, err
	}
	return true, nil
}

func previewPolicyFromRecord(rec VMRecord) persistedPreviewPolicy {
	return persistedPreviewPolicy{
		Access:   rec.PreviewAccess,
		Ports:    rec.PreviewPorts,
		Revision: rec.PreviewPolicyRevision,
	}
}

func (p persistedPreviewPolicy) isSet() bool {
	return p.Access != "" || len(p.Ports) != 0 || p.Revision != 0 || len(p.unknownFields) != 0
}

func (p persistedPreviewPolicy) applyTo(rec *VMRecord) {
	rec.PreviewAccess = p.Access
	rec.PreviewPorts = p.Ports
	rec.PreviewPolicyRevision = p.Revision
}

func getPreviewPolicy(bucket *bolt.Bucket, key []byte) (persistedPreviewPolicy, bool, error) {
	data := bucket.Get(key)
	if data == nil {
		return persistedPreviewPolicy{}, false, nil
	}
	var policy persistedPreviewPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return persistedPreviewPolicy{}, false, fmt.Errorf("unmarshal persisted preview policy: %w", err)
	}
	return policy, true, nil
}

func putPreviewPolicy(bucket *bolt.Bucket, key []byte, policy persistedPreviewPolicy) error {
	data, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("marshal preview policy: %w", err)
	}
	return bucket.Put(key, data)
}

func overlayPreviewPolicy(rec *VMRecord, data []byte) error {
	if data == nil {
		return nil
	}
	var policy persistedPreviewPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return fmt.Errorf("unmarshal persisted preview policy: %w", err)
	}
	policy.applyTo(rec)
	return nil
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
		policies := tx.Bucket(previewPolicyBucketName)
		return b.ForEach(func(k, v []byte) error {
			var rec VMRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return fmt.Errorf("unmarshal vm record: %w", err)
			}
			if err := overlayPreviewPolicy(&rec, policies.Get(k)); err != nil {
				return err
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
	return toRecordLocked(inst)
}

// toRecordLocked snapshots an instance while its caller holds inst.mu. It is
// used when a state write must be serialized with the in-memory mutation.
func toRecordLocked(inst *VMInstance) VMRecord {
	return VMRecord{
		ID:                    inst.ID,
		PID:                   inst.PID,
		SocketPath:            inst.SocketPath,
		VsockPath:             inst.VsockPath,
		IP:                    inst.IP,
		TAPDevice:             inst.TAPDevice,
		MACAddress:            inst.MACAddress,
		Status:                inst.Status,
		RunDirID:              inst.RunDirID,
		Namespace:             inst.Namespace,
		DiskPath:              inst.DiskPath,
		SnapshotPath:          inst.SnapshotPath,
		MemFilePath:           inst.MemFilePath,
		BaseMemPath:           inst.BaseMemPath,
		CreatedAt:             inst.CreatedAt,
		Metadata:              inst.Metadata,
		VCPU:                  inst.Config.VCPU,
		MemoryMiB:             inst.Config.MemoryMiB,
		BasePath:              inst.Config.BasePath,
		TeamID:                inst.TeamID,
		OwnerID:               inst.OwnerID,
		PreviewAccess:         inst.PreviewAccess,
		PreviewPorts:          previewPortsToRecord(inst.PreviewPorts),
		PreviewPolicyRevision: inst.PreviewPolicyRevision,
	}
}

func previewPortsToRecord(in map[int32]struct{}) map[int32]bool {
	if len(in) == 0 {
		return nil
	}
	out := make(map[int32]bool, len(in))
	for port := range in {
		out[port] = true
	}
	return out
}

func previewPortsFromRecord(in map[int32]bool) map[int32]struct{} {
	if len(in) == 0 {
		return nil
	}
	out := make(map[int32]struct{}, len(in))
	for port, published := range in {
		if published {
			out[port] = struct{}{}
		}
	}
	return out
}

// toInstance converts a VMRecord back to a VMInstance.
func toInstance(rec VMRecord) *VMInstance {
	return &VMInstance{
		ID:                    rec.ID,
		PID:                   rec.PID,
		SocketPath:            rec.SocketPath,
		VsockPath:             rec.VsockPath,
		IP:                    rec.IP,
		TAPDevice:             rec.TAPDevice,
		MACAddress:            rec.MACAddress,
		Status:                rec.Status,
		RunDirID:              rec.RunDirID,
		Namespace:             rec.Namespace,
		DiskPath:              rec.DiskPath,
		SnapshotPath:          rec.SnapshotPath,
		MemFilePath:           rec.MemFilePath,
		BaseMemPath:           rec.BaseMemPath,
		CreatedAt:             rec.CreatedAt,
		Metadata:              rec.Metadata,
		TeamID:                rec.TeamID,
		OwnerID:               rec.OwnerID,
		PreviewAccess:         rec.PreviewAccess,
		PreviewPorts:          previewPortsFromRecord(rec.PreviewPorts),
		PreviewPolicyRevision: rec.PreviewPolicyRevision,
		Config: VMConfig{
			VCPU:      rec.VCPU,
			MemoryMiB: rec.MemoryMiB,
			BasePath:  rec.BasePath,
		},
	}
}
