package vm

import (
	"context"
	"time"

	"github.com/superserve-ai/sandbox/internal/admission"
)

// admissionReadyPoll is how often the readiness transition re-checks
// whether the daemon has finished working out what it is carrying.
// Startup-only and bounded by reattach, so the cost is a handful of atomic
// loads across a window already dominated by reattaching VMs.
var admissionReadyPoll = 250 * time.Millisecond

// AdmissionGate exposes the gate for the RPC surface and for drain.
func (m *Manager) AdmissionGate() *admission.Gate { return m.admission }

// StartAdmission brings the gate into service once the daemon knows what
// this host is already running, and never before.
//
// Runs as a background transition rather than from a request, because the
// listening socket survives a restart: queued calls can arrive before
// reattach completes, and a gate that reconstructed lazily on the first one
// would either block that request behind fleet-sized work or admit it
// against an empty ledger. Both are worse than refusing briefly.
func (m *Manager) StartAdmission(ctx context.Context) {
	if !m.admission.Enabled() {
		return
	}
	go func() {
		ticker := time.NewTicker(admissionReadyPoll)
		defer ticker.Stop()
		for {
			// PressureReady is exactly this condition already: reattach
			// complete, the surviving-builder scan finished, and no
			// leftover build cgroup or unit still possibly alive. Reused
			// rather than duplicated — a second readiness rule would be
			// one more thing to keep in agreement with the first.
			if m.PressureReady() {
				m.reconstructAdmission()
				m.admission.Open()
				m.log.Info().Int("charged", m.admission.Charged()).
					Msg("host-local admission open")
				go m.auditAdmissionLoop(ctx)
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

// reconstructAdmission seeds the ledger from everything this host is
// holding capacity for.
//
// Persisted records, not live instances: a sandbox paused on this host owns
// its slot for its whole host-owned lifetime, and it has no live instance to
// enumerate. Reading the store is what makes a restarted daemon charge for
// the paused sandboxes it is still responsible for, rather than treating a
// restart as a way to forget them.
//
// A store read failure leaves the gate closed. That refuses creates until
// the next attempt, which is the safe direction: opening on a partial ledger
// would admit against a count known to be too low.
func (m *Manager) reconstructAdmission() {
	if !m.admission.Enabled() {
		return
	}
	var sandboxIDs []string
	if m.state != nil {
		records, err := m.state.All()
		if err != nil {
			m.log.Error().Err(err).
				Msg("admission reconstruction could not read persisted records; gate stays closed")
			return
		}
		for _, rec := range records {
			// Builds are counted from the live registry below. A
			// build-prefixed record is either that same build — which
			// would then be charged twice — or residue of one that has
			// already exited and holds nothing.
			if isBuildVM(rec.ID) {
				continue
			}
			sandboxIDs = append(sandboxIDs, rec.ID)
		}
	}
	m.admission.Reconstruct(sandboxIDs, m.liveBuildIDs())
}

// liveBuildIDs returns builds whose subprocess may still hold capacity.
//
// Terminal records are skipped: the registry retains them for status
// polling long after the worker exits, so charging them would leak a token
// per completed build until the daemon restarted.
func (m *Manager) liveBuildIDs() []string {
	m.buildsMu.Lock()
	defer m.buildsMu.Unlock()
	var ids []string
	for id, rec := range m.builds {
		if rec == nil || rec.Status.IsTerminal() {
			continue
		}
		ids = append(ids, id)
	}
	return ids
}

// deleteRecord removes a VM's persisted record and releases the capacity it
// was holding.
//
// The two belong together: the ledger is reconstructed from persisted
// records, so a record that disappears without its token being released
// leaves a charge no restart could explain and no audit could attribute.
// Every caller that retires a record routes through here for that reason —
// a release bolted onto each call site individually is one forgotten site
// away from a slow capacity leak.
//
// Release is unconditional on the delete succeeding. A record that survives
// a failed delete keeps its token, which is the fail-closed direction: the
// host may under-admit briefly, but it cannot over-admit against a sandbox
// still on disk.
func (m *Manager) deleteRecord(vmID string) error {
	if err := m.state.Delete(vmID); err != nil {
		return err
	}
	m.admission.Release(vmID)
	return nil
}

// admissionAuditInterval is how often the ledger is checked against
// observed load. Slow on purpose: an undercount is a bug, not an expected
// condition, and each pass walks the fleet. Frequent enough that a leak is
// caught in minutes rather than at the next restart.
var admissionAuditInterval = 2 * time.Minute

// auditAdmissionLoop re-checks the ledger for as long as the daemon runs.
// Its own goroutine because the check walks the fleet and must never sit on
// a request path, and because closing the gate mid-audit has to be able to
// happen without a caller waiting on it.
func (m *Manager) auditAdmissionLoop(ctx context.Context) {
	ticker := time.NewTicker(admissionAuditInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.AuditAdmission()
		}
	}
}

// AuditAdmission compares the gate's ledger against an independently
// observed sandbox count and closes the gate if the ledger is behind.
//
// One-directional, and that is the whole design. The observation is an
// eventually consistent sample: it can be taken before a just-admitted
// sandbox materializes, so seeing fewer than the ledger holds is ordinary
// and must never lower the count. Seeing more means something is running
// that nothing is charging for — a real correctness bug — and the answer is
// to stop admitting and rebuild, not to quietly adopt the sample.
func (m *Manager) AuditAdmission() {
	if !m.admission.Enabled() {
		return
	}
	p := m.CapacityPressure()
	observed := int(p.RunningSandboxes + p.ProvisioningSandboxes + p.PausedSandboxes)
	if !m.admission.AuditUndercount(observed) {
		return
	}
	m.log.Error().Int("observed", observed).Int("charged", m.admission.Charged()).
		Msg("admission ledger undercounts live sandboxes; closing gate to reconstruct")
	m.admission.Close()
	m.reconstructAdmission()
	m.admission.Open()
}
