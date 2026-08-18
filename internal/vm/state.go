package vm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	// pendingBackupBucketName records pauses whose backup enqueue has not
	// completed: the async retry goroutine is not a durable record, and a
	// crash or deploy during its window must not lose the pause's coverage.
	pendingBackupBucketName = []byte("pending_backups")
	// backfillMarkBucketName is the backup backfill ledger: vm ID → the
	// snapshot stat identity whose coverage a backfill pass already minted.
	// Without it every pass would re-hash the whole paused fleet to learn
	// that nothing changed, since generation keys only exist after hashing.
	backfillMarkBucketName = []byte("backup_backfill_marks")
)

// persistedPreviewPolicy is stored separately from VMRecord so a rollback to
// a VMD binary that predates preview policy fields can keep writing lifecycle
// records without erasing the last policy enforced by newer binaries.
type persistedPreviewPolicy struct {
	Access              string
	Ports               map[int32]bool
	PortAccess          map[int32]string
	TokenVersions       map[int32]int64
	Revision            int64
	TokenPolicyRevision int64
	unknownFields       map[string]json.RawMessage
}

func (p *persistedPreviewPolicy) UnmarshalJSON(data []byte) error {
	var known struct {
		Access              string           `json:"access,omitempty"`
		Ports               map[int32]bool   `json:"ports,omitempty"`
		PortAccess          map[int32]string `json:"port_access,omitempty"`
		TokenVersions       map[int32]int64  `json:"token_versions,omitempty"`
		Revision            int64            `json:"revision,omitempty"`
		TokenPolicyRevision int64            `json:"token_policy_revision,omitempty"`
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
	delete(fields, "port_access")
	delete(fields, "token_versions")
	delete(fields, "revision")
	delete(fields, "token_policy_revision")
	if len(fields) == 0 {
		fields = nil
	}
	*p = persistedPreviewPolicy{
		Access:              known.Access,
		Ports:               known.Ports,
		PortAccess:          known.PortAccess,
		TokenVersions:       known.TokenVersions,
		Revision:            known.Revision,
		TokenPolicyRevision: known.TokenPolicyRevision,
		unknownFields:       fields,
	}
	return nil
}

func (p persistedPreviewPolicy) MarshalJSON() ([]byte, error) {
	p = p.normalizedTokenState()
	fields := make(map[string]json.RawMessage, len(p.unknownFields)+6)
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
	if len(p.PortAccess) != 0 {
		data, err := json.Marshal(p.PortAccess)
		if err != nil {
			return nil, err
		}
		fields["port_access"] = data
	}
	if len(p.TokenVersions) != 0 {
		data, err := json.Marshal(p.TokenVersions)
		if err != nil {
			return nil, err
		}
		fields["token_versions"] = data
	}
	if p.Revision != 0 {
		data, err := json.Marshal(p.Revision)
		if err != nil {
			return nil, err
		}
		fields["revision"] = data
	}
	if p.TokenPolicyRevision != 0 {
		data, err := json.Marshal(p.TokenPolicyRevision)
		if err != nil {
			return nil, err
		}
		fields["token_policy_revision"] = data
	}
	return json.Marshal(fields)
}

// VMRecord is the serializable subset of VMInstance persisted to BoltDB.
// It contains everything VMD needs to reconstruct its in-memory map on
// startup and reattach to a live Firecracker process.
type VMRecord struct {
	ID         string   `json:"id"`
	PID        int      `json:"pid"`
	SocketPath string   `json:"socket_path"`
	VsockPath  string   `json:"vsock_path,omitempty"`
	IP         string   `json:"ip"`
	TAPDevice  string   `json:"tap_device"`
	MACAddress string   `json:"mac_address"`
	Status     VMStatus `json:"status"`
	// Unverified marks a Running record persisted before boxd readiness was
	// confirmed (the persist overlaps the wait). Absent/false — including on
	// every record from before the field — means verified; a background
	// persist clears it right after verification, so a durable true means a
	// crash before readiness was proven. Both restore and resume adoption
	// re-verify such records before adopting (clearing the marker on
	// success), a pause clears it (a snapshotted guest was provably live),
	// and a resume relaunch verifies readiness synchronously before
	// clearing it.
	Unverified bool `json:"unverified,omitempty"`
	// RevivalPending marks a record kept alive across a revival attempt:
	// it is the retry's anchor (revive refuses unknown sandboxes), so
	// startup stale cleanup must park it instead of deleting it.
	RevivalPending bool `json:"revival_pending,omitempty"`
	// RevivedDisk records the resolved salvage path a completed revival
	// booted from: the idempotency witness that lets a retry of the same
	// request (a lost RPC response, a failed post-commit injection)
	// recognize the live VM as its own completed work.
	RevivedDisk string `json:"revived_disk,omitempty"`
	// TeardownPending mirrors VMInstance.TeardownPending: a non-empty value
	// is an explicit, durable claim that this record's resources were
	// deliberately retained after a failed op and the reconciler owns the
	// residual teardown. Omitted when empty so rollback binaries read
	// records unchanged.
	TeardownPending string `json:"teardown_pending,omitempty"`
	RunDirID        string `json:"rundir_id"`
	Namespace       string `json:"namespace"`
	DiskPath        string `json:"disk_path"`
	SnapshotPath    string `json:"snapshot_path,omitempty"`
	MemFilePath     string `json:"mem_file_path,omitempty"`
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
	// PausedAt marks when a sandbox last entered the paused state. Zero on
	// records written before the field existed; callers needing an ordering
	// key fall back to CreatedAt.
	PausedAt time.Time `json:"paused_at,omitempty"`
	// Supervision dispatches liveness/stop/reattach for this VM's current
	// run. Empty (SupervisionUnit) is canonical for systemd-unit VMs so
	// records written by this binary stay readable-and-correct under a
	// rollback binary that predates the field; never write a non-empty
	// value for unit mode.
	Supervision Supervision `json:"supervision,omitempty"`
	// Preview publication policy must survive vmd restarts; old records decode
	// to empty/legacy behavior for backward compatibility.
	PreviewAccess            string           `json:"preview_access,omitempty"`
	PreviewPorts             map[int32]bool   `json:"preview_ports,omitempty"`
	PreviewPortAccess        map[int32]string `json:"preview_port_access,omitempty"`
	PreviewPortTokenVersions map[int32]int64  `json:"preview_port_token_versions,omitempty"`
	PreviewPolicyRevision    int64            `json:"preview_policy_revision,omitempty"`
	// PreviewTokenPolicyRevision is a sidecar-backed watermark. Token versions
	// are active only when it exactly matches PreviewPolicyRevision.
	PreviewTokenPolicyRevision int64 `json:"preview_token_policy_revision,omitempty"`
}

// Supervision is how a VM's current Firecracker run is supervised. A named
// type (like VMStatus) so the liveness/stop/reattach/reconcile paths switch on
// a checked value, not a bare string a typo could silently break.
type Supervision string

// Supervision values for VMInstance/VMRecord.
const (
	// SupervisionUnit: the VM runs as firecracker@<id>.service. Canonically
	// the empty string — legacy records predate the field.
	SupervisionUnit Supervision = ""
	// SupervisionCgroup: the VM was direct-spawned into a per-VM cgroup
	// under vmd's delegated subtree; no systemd unit exists for it.
	SupervisionCgroup Supervision = "cgroup"
)

// String renders the mode for logs — the empty canonical value reads as "unit"
// rather than blank.
func (s Supervision) String() string {
	if s == SupervisionUnit {
		return "unit"
	}
	return string(s)
}

// knownSupervision reports whether s is a mode this binary can dispatch.
// Anything else (store corruption, or a record written by a NEWER binary
// with a mode this one predates) is unmanageable: dispatchers must refuse
// or read inconclusive, never fall through to the unit path — its vacuous
// probes would release a live non-unit FC's record and network.
func knownSupervision(s Supervision) bool {
	return s == SupervisionUnit || s == SupervisionCgroup
}

// cgroupSupervised reports whether a supervision value means the VM has no
// systemd unit and lives in a per-VM cgroup.
func cgroupSupervised(s Supervision) bool { return s == SupervisionCgroup }

// StateBreadcrumbPath is the fixed, non-configurable location where vmd
// records its RESOLVED state-store path. The host-resident rollback guard
// reads it instead of re-deriving the path from env files, so the two can
// never disagree about grammar; ArmDirectSpawn requires the write before
// arming OR managing cgroup records, so "cgroup records exist without a
// current breadcrumb" is unrepresentable.
const StateBreadcrumbPath = "/var/lib/sandbox/vmd-state-path"

// WriteStateBreadcrumb records the resolved state path atomically
// (write+rename), so the guard never reads a torn value.
func WriteStateBreadcrumb(statePath string) error {
	return writeStateBreadcrumbTo(StateBreadcrumbPath, statePath)
}

func writeStateBreadcrumbTo(at, statePath string) error {
	if err := os.MkdirAll(filepath.Dir(at), 0o755); err != nil {
		return fmt.Errorf("state breadcrumb dir: %w", err)
	}
	tmp := at + ".tmp"
	if err := os.WriteFile(tmp, []byte(statePath+"\n"), 0o644); err != nil {
		return fmt.Errorf("write state breadcrumb: %w", err)
	}
	if err := os.Rename(tmp, at); err != nil {
		return fmt.Errorf("commit state breadcrumb: %w", err)
	}
	return nil
}

// StateStore wraps a BoltDB database for VM state persistence.
type StateStore struct {
	db        *bolt.DB
	openStats StateStoreOpenStats
}

// StateStoreOpenStats breaks OpenStateStore's cost into its sub-steps for
// startup timing. Observability only.
type StateStoreOpenStats struct {
	BoltOpen       time.Duration // bolt.Open: mmap + freelist load
	PolicyScan     time.Duration // sidecar orphan scan + deletes
	RecordScan     time.Duration // primary record scan + policy migration
	TxResidual     time.Duration // db.Update outside the scans: bucket creates + commit/fsync
	Records        int
	Policies       int
	OrphansDeleted int
}

// OpenStats returns the timing/count breakdown captured while the store opened.
func (s *StateStore) OpenStats() StateStoreOpenStats { return s.openStats }

// Path returns the resolved filesystem path of the open store.
func (s *StateStore) Path() string { return s.db.Path() }

// OpenStateStore opens (or creates) the BoltDB file at path.
func OpenStateStore(path string) (*StateStore, error) {
	var stats StateStoreOpenStats
	tOpen := time.Now()
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open state store %s: %w", path, err)
	}
	stats.BoltOpen = time.Since(tOpen)
	tTx := time.Now()
	if err := db.Update(func(tx *bolt.Tx) error {
		records, err := tx.CreateBucketIfNotExists(bucketName)
		if err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(pendingBackupBucketName); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(backfillMarkBucketName); err != nil {
			return err
		}
		policies, err := tx.CreateBucketIfNotExists(previewPolicyBucketName)
		if err != nil {
			return err
		}

		// An old VMD can delete the primary record without knowing about the
		// sidecar bucket. Remove those orphans before migrating so a later VM
		// reusing the same key cannot inherit deleted policy state.
		tPolicy := time.Now()
		var orphanKeys [][]byte
		if err := policies.ForEach(func(k, _ []byte) error {
			stats.Policies++
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
		stats.OrphansDeleted = len(orphanKeys)
		stats.PolicyScan = time.Since(tPolicy)

		// Seed the sidecar for records written by the immediately preceding
		// schema. Once present, the sidecar is authoritative and is never
		// replaced from the primary JSON during startup.
		tRecord := time.Now()
		err = records.ForEach(func(k, v []byte) error {
			stats.Records++
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
		stats.RecordScan = time.Since(tRecord)
		return err
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize state store: %w", err)
	}
	// db.Update time outside the two scans: bucket creation plus the Bolt
	// commit/fsync, which only happens after the callback returns.
	stats.TxResidual = time.Since(tTx) - stats.PolicyScan - stats.RecordScan
	return &StateStore{db: db, openStats: stats}, nil
}

// OpenStateStoreReadOnly opens the BoltDB file for reading only. Unlike
// OpenStateStore it neither creates the file nor writes a bucket, so a missing
// DB or a store still locked by a running vmd fails here rather than reporting
// an empty (falsely "drained") store — the drain guard depends on that
// fail-closed behavior.
func OpenStateStoreReadOnly(path string) (*StateStore, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true, Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open state store read-only %s: %w", path, err)
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
	// Keep the Phase 1-visible primary JSON restrictive too. A rolled-back VMD
	// does not know about the sidecar or its parallel access map; it must still
	// read a private top-level fallback for every mixed/private snapshot.
	incomingPolicy.applyTo(&incoming)

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
	ports := previewPortsFromRecord(rec.PreviewPorts, rec.PreviewPortAccess, rec.PreviewPortTokenVersions)
	return persistedPreviewPolicy{
		Access:              restrictivePreviewAccess(rec.PreviewAccess, ports),
		Ports:               previewPortsToRecord(ports),
		PortAccess:          previewPortAccessToRecord(ports),
		TokenVersions:       previewPortTokenVersionsToRecord(ports),
		Revision:            rec.PreviewPolicyRevision,
		TokenPolicyRevision: rec.PreviewTokenPolicyRevision,
	}.normalizedTokenState()
}

func (p persistedPreviewPolicy) isSet() bool {
	return p.Access != "" || len(p.Ports) != 0 || len(p.PortAccess) != 0 ||
		len(p.TokenVersions) != 0 || p.Revision != 0 || p.TokenPolicyRevision != 0 ||
		len(p.unknownFields) != 0
}

func (p persistedPreviewPolicy) applyTo(rec *VMRecord) {
	p = p.normalizedTokenState()
	ports := previewPortsFromRecord(p.Ports, p.PortAccess, p.TokenVersions)
	rec.PreviewAccess = restrictivePreviewAccess(p.Access, ports)
	rec.PreviewPorts = previewPortsToRecord(ports)
	rec.PreviewPortAccess = previewPortAccessToRecord(ports)
	rec.PreviewPortTokenVersions = previewPortTokenVersionsToRecord(ports)
	rec.PreviewPolicyRevision = p.Revision
	rec.PreviewTokenPolicyRevision = p.TokenPolicyRevision
}

// normalizedTokenState makes the token sidecar self-invalidating across a
// rollback. A writer which predates the active token carrier either clears its
// generation or advances Revision without a matching watermark. A newer VMD
// therefore clears every generation instead of reviving credentials from an
// older tokenized snapshot.
func (p persistedPreviewPolicy) normalizedTokenState() persistedPreviewPolicy {
	ports := previewPortsFromRecord(p.Ports, p.PortAccess, p.TokenVersions)
	ports, watermark := normalizePreviewTokenPolicy(ports, p.Revision, p.TokenPolicyRevision)
	p.Access = restrictivePreviewAccess(p.Access, ports)
	p.Ports = previewPortsToRecord(ports)
	p.PortAccess = previewPortAccessToRecord(ports)
	p.TokenVersions = previewPortTokenVersionsToRecord(ports)
	p.TokenPolicyRevision = watermark
	return p
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
		ID:                         inst.ID,
		PID:                        inst.PID,
		SocketPath:                 inst.SocketPath,
		VsockPath:                  inst.VsockPath,
		IP:                         inst.IP,
		TAPDevice:                  inst.TAPDevice,
		MACAddress:                 inst.MACAddress,
		Status:                     inst.Status,
		Unverified:                 inst.Unverified,
		RevivalPending:             inst.RevivalPending,
		RevivedDisk:                inst.RevivedDisk,
		TeardownPending:            inst.TeardownPending,
		RunDirID:                   inst.RunDirID,
		Namespace:                  inst.Namespace,
		DiskPath:                   inst.DiskPath,
		SnapshotPath:               inst.SnapshotPath,
		MemFilePath:                inst.MemFilePath,
		BaseMemPath:                inst.BaseMemPath,
		CreatedAt:                  inst.CreatedAt,
		Metadata:                   inst.Metadata,
		VCPU:                       inst.Config.VCPU,
		MemoryMiB:                  inst.Config.MemoryMiB,
		BasePath:                   inst.Config.BasePath,
		TeamID:                     inst.TeamID,
		OwnerID:                    inst.OwnerID,
		PausedAt:                   inst.PausedAt,
		Supervision:                inst.Supervision,
		PreviewAccess:              restrictivePreviewAccess(inst.PreviewAccess, inst.PreviewPorts),
		PreviewPorts:               previewPortsToRecord(inst.PreviewPorts),
		PreviewPortAccess:          previewPortAccessToRecord(inst.PreviewPorts),
		PreviewPortTokenVersions:   previewPortTokenVersionsToRecord(inst.PreviewPorts),
		PreviewPolicyRevision:      inst.PreviewPolicyRevision,
		PreviewTokenPolicyRevision: inst.PreviewTokenPolicyRevision,
	}
}

func previewPortsToRecord(in map[int32]PreviewPortPolicy) map[int32]bool {
	if len(in) == 0 {
		return nil
	}
	out := make(map[int32]bool, len(in))
	for port := range in {
		out[port] = true
	}
	return out
}

func previewPortAccessToRecord(in map[int32]PreviewPortPolicy) map[int32]string {
	out := make(map[int32]string, len(in))
	for port, policy := range in {
		if policy.Access != "" {
			out[port] = policy.Access
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func previewPortTokenVersionsToRecord(in map[int32]PreviewPortPolicy) map[int32]int64 {
	out := make(map[int32]int64, len(in))
	for port, policy := range in {
		if policy.TokenVersion > 0 {
			out[port] = policy.TokenVersion
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func previewPortsFromRecord(in map[int32]bool, access map[int32]string, tokenVersions map[int32]int64) map[int32]PreviewPortPolicy {
	if len(in) == 0 {
		return nil
	}
	out := make(map[int32]PreviewPortPolicy, len(in))
	for port, published := range in {
		if published {
			out[port] = PreviewPortPolicy{Access: access[port], TokenVersion: tokenVersions[port]}
		}
	}
	return out
}

// toInstance converts a VMRecord back to a VMInstance.
func toInstance(rec VMRecord) *VMInstance {
	ports := previewPortsFromRecord(rec.PreviewPorts, rec.PreviewPortAccess, rec.PreviewPortTokenVersions)
	ports, tokenPolicyRevision := normalizePreviewTokenPolicy(ports, rec.PreviewPolicyRevision, rec.PreviewTokenPolicyRevision)
	return &VMInstance{
		ID:                         rec.ID,
		PID:                        rec.PID,
		SocketPath:                 rec.SocketPath,
		VsockPath:                  rec.VsockPath,
		IP:                         rec.IP,
		TAPDevice:                  rec.TAPDevice,
		MACAddress:                 rec.MACAddress,
		Status:                     rec.Status,
		Unverified:                 rec.Unverified,
		RevivalPending:             rec.RevivalPending,
		RevivedDisk:                rec.RevivedDisk,
		TeardownPending:            rec.TeardownPending,
		RunDirID:                   rec.RunDirID,
		Namespace:                  rec.Namespace,
		DiskPath:                   rec.DiskPath,
		SnapshotPath:               rec.SnapshotPath,
		MemFilePath:                rec.MemFilePath,
		BaseMemPath:                rec.BaseMemPath,
		CreatedAt:                  rec.CreatedAt,
		Metadata:                   rec.Metadata,
		TeamID:                     rec.TeamID,
		OwnerID:                    rec.OwnerID,
		PausedAt:                   rec.PausedAt,
		Supervision:                rec.Supervision,
		PreviewAccess:              restrictivePreviewAccess(rec.PreviewAccess, ports),
		PreviewPorts:               ports,
		PreviewPolicyRevision:      rec.PreviewPolicyRevision,
		PreviewTokenPolicyRevision: tokenPolicyRevision,
		Config: VMConfig{
			VCPU:      rec.VCPU,
			MemoryMiB: rec.MemoryMiB,
			BasePath:  rec.BasePath,
		},
	}
}

// PendingBackup is a durable marker that a pause still owes its backup
// enqueue: the artifact paths to (re)hash and journal. Deleted once the
// journal write lands or the pause is superseded.
type PendingBackup struct {
	VMID         string `json:"vm_id"`
	SnapshotPath string `json:"snapshot_path"`
	DiskPath     string `json:"disk_path"`
	DiskBasePath string `json:"disk_base_path,omitempty"`
	// Token identifies which pause owns the record: rows are keyed by VM
	// ID, so a later pause's Put replaces an older one, and the older
	// pause's async worker must not delete the newer record.
	Token string `json:"token,omitempty"`
	// BaseIdentity is the overlay base's stat identity captured when the
	// marker was created: the rehash must prove it is hashing the
	// pause-time base, not a same-path replacement.
	BaseIdentity string `json:"base_identity,omitempty"`
	// OrigSnapshotPath and OrigDiskPath preserve the pause-time artifact
	// locations when staging repointed the primary paths at copies: if
	// the copies are ever lost (sweep after a very long outage), a
	// still-paused sandbox can fall back to the at-rest flow over the
	// originals instead of dropping coverage.
	OrigSnapshotPath string `json:"orig_snapshot_path,omitempty"`
	OrigDiskPath     string `json:"orig_disk_path,omitempty"`
	// StagedDir is the pending staging directory holding immutable
	// pause-time copies of the mutable artifacts. When set, the worker
	// hashes those copies and needs no at-rest proof for them: a resume
	// cannot mutate a snapshot, so an immediately-resumed pause still
	// gets its backup.
	StagedDir string `json:"staged_dir,omitempty"`
	// SnapshotIdentity is SnapshotPath's stat identity captured when the
	// marker was created. A VM's snapshot path is fixed across pauses, so
	// a resume-then-pause reuses the exact same pathname; only identity
	// distinguishes a genuine RPC retry (same bytes) from a distinct pause
	// that overwrote them, and the marker-reuse check is load-bearing on it.
	SnapshotIdentity string `json:"snapshot_identity,omitempty"`
	// BestEffort routes the eventual journal write to the lowest upload
	// priority. Set by the backfill sweep, whose thousands of historical
	// pauses must never delay a live pause's generation; absent (every
	// marker minted by a real pause) means pause priority.
	BestEffort bool `json:"best_effort,omitempty"`
}

// PutPendingBackup records (or refreshes) a pause's owed backup.
func (s *StateStore) PutPendingBackup(p PendingBackup) error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(pendingBackupBucketName).Put([]byte(p.VMID), data)
	})
}

// PutPendingBackupIfOwner writes the marker when the slot is empty,
// owned by the same token, or owned by an OLDER token (tokens are
// fixed-width creation-ordered): healing re-persists a record to repair
// a failed initial write, and the newest pause always wins the slot
// while a newer record is never overwritten by an older worker.
func (s *StateStore) PutPendingBackupIfOwner(p PendingBackup) error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(pendingBackupBucketName)
		if v := b.Get([]byte(p.VMID)); v != nil {
			var cur PendingBackup
			if json.Unmarshal(v, &cur) == nil && cur.Token > p.Token {
				return nil
			}
		}
		return b.Put([]byte(p.VMID), data)
	})
}

// PutPendingBackupIfAbsent writes the marker only when no marker exists
// for the VM, reporting whether it wrote. The backfill mints through
// this: a marker minted concurrently by a real pause owns the slot and
// must never be replaced by backfill's view of the same sandbox.
func (s *StateStore) PutPendingBackupIfAbsent(p PendingBackup) (bool, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return false, err
	}
	wrote := false
	err = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(pendingBackupBucketName)
		if b.Get([]byte(p.VMID)) != nil {
			return nil
		}
		wrote = true
		return b.Put([]byte(p.VMID), data)
	})
	return wrote, err
}

// DeletePendingBackupIf clears the marker only while the given token
// still owns it: an older pause's async worker finishing late must not
// erase the record a newer pause has since written over the same key.
func (s *StateStore) DeletePendingBackupIf(vmID, token string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(pendingBackupBucketName)
		v := b.Get([]byte(vmID))
		if v == nil {
			return nil
		}
		var cur PendingBackup
		if json.Unmarshal(v, &cur) == nil && cur.Token != token {
			return nil
		}
		return b.Delete([]byte(vmID))
	})
}

// GetPendingBackup returns a VM's pending-backup marker, if any.
func (s *StateStore) GetPendingBackup(vmID string) (PendingBackup, bool, error) {
	var p PendingBackup
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(pendingBackupBucketName).Get([]byte(vmID))
		if v == nil {
			return nil
		}
		if json.Unmarshal(v, &p) == nil && p.VMID != "" {
			found = true
		}
		return nil
	})
	return p, found, err
}

// PutBackfillMark records that a backfill pass minted coverage for this
// exact snapshot identity, so reruns and later boots skip it without
// re-hashing. Marks say "a marker was minted", never "the upload
// verified": once minted, the pending-backup machinery owns the outcome.
func (s *StateStore) PutBackfillMark(vmID, snapshotIdentity, generation string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(backfillMarkBucketName)
		if b == nil {
			return fmt.Errorf("backfill ledger bucket missing")
		}
		// Identity NUL generation: binding the mark to the exact
		// generation its mint enqueued lets the skip path probe the
		// journal with a point lookup, so no other generation's fate can
		// masquerade as this snapshot's coverage.
		return b.Put([]byte(vmID), []byte(snapshotIdentity+"\x00"+generation))
	})
}

// GetBackfillMark returns the snapshot identity a backfill pass last
// covered for this VM and the generation its mint enqueued, if any.
func (s *StateStore) GetBackfillMark(vmID string) (string, string, bool, error) {
	var id, gen string
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(backfillMarkBucketName)
		if b == nil {
			return nil
		}
		v := b.Get([]byte(vmID))
		if v == nil {
			return nil
		}
		id, found = string(v), true
		if i := strings.IndexByte(id, 0); i >= 0 {
			id, gen = id[:i], id[i+1:]
		}
		return nil
	})
	return id, gen, found, err
}

// PruneBackfillMarks drops ledger entries for VMs no longer in the
// record set, so the ledger tracks the fleet instead of growing forever.
func (s *StateStore) PruneBackfillMarks(keep map[string]struct{}) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(backfillMarkBucketName)
		if b == nil {
			return nil
		}
		var stale [][]byte
		if err := b.ForEach(func(k, _ []byte) error {
			if _, ok := keep[string(k)]; !ok {
				stale = append(stale, append([]byte(nil), k...))
			}
			return nil
		}); err != nil {
			return err
		}
		for _, k := range stale {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}

// ListPendingBackups returns every pause still owing its backup enqueue.
// Corrupt entries are skipped.
func (s *StateStore) ListPendingBackups() ([]PendingBackup, error) {
	var out []PendingBackup
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(pendingBackupBucketName).ForEach(func(k, v []byte) error {
			var p PendingBackup
			if json.Unmarshal(v, &p) == nil && p.VMID != "" {
				out = append(out, p)
			}
			return nil
		})
	})
	return out, err
}
