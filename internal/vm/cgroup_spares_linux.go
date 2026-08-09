package vm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"

	"github.com/superserve-ai/sandbox/internal/sentrylog"
)

// Spare cgroup pool. Creating a memory cgroup allocates per-CPU and per-NUMA-
// node bookkeeping under globally-serialized kernel locks, so concurrent
// launches queue on it — the wider the burst and the bigger the host, the
// longer the line. The pool pays that cost in the background: it keeps a
// reserve of pre-created, empty "spare-<n>" groups in the delegated scope,
// and a launch claims one with a same-parent rename (cheap, no allocation)
// instead of a mkdir.
//
// The pool is strictly an optimization: every claim failure — empty pool,
// lost rename race, unwritable attribute — falls back to the inline
// createVMCgroup path, so correctness never depends on it. Spares are
// reserved names (isReservedCgroupName): no scan counts them as VMs, the
// drain report ignores them, and disarming reaps them.
type spareCgroupPool struct {
	tree   *cgroupTree
	log    zerolog.Logger
	target int
	free   chan string   // names of ready spares
	kick   chan struct{} // claims nudge the refiller; buffered 1
	ctr    atomic.Uint64 // next spare index; monotonic within a life
}

func newSpareCgroupPool(tree *cgroupTree, target int, log zerolog.Logger) *spareCgroupPool {
	return &spareCgroupPool{
		tree:   tree,
		log:    log,
		target: target,
		free:   make(chan string, target),
		kick:   make(chan struct{}, 1),
	}
}

// adoptExisting re-inventories spares left by a previous vmd life (the dirs
// persist across restarts). Parsable names up to the pool target are reused;
// excess (a lowered target) and unparsable ones are removed — an empty rmdir
// is free, and a spare must never outlive the pool's ability to account for
// it. Returns the number adopted.
func (p *spareCgroupPool) adoptExisting() int {
	entries, err := os.ReadDir(p.tree.vms)
	if err != nil {
		p.log.Warn().Err(err).Msg("spare cgroup pool: scope scan failed; starting empty")
		return 0
	}
	adopted := 0
	var maxIdx uint64
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() || !strings.HasPrefix(name, spareCgroupPrefix) {
			continue
		}
		idx, perr := strconv.ParseUint(strings.TrimPrefix(name, spareCgroupPrefix), 10, 64)
		ok := perr == nil
		if ok && idx > maxIdx {
			maxIdx = idx
		}
		if ok {
			select {
			case p.free <- name:
				adopted++
				continue
			default: // pool full — excess spare
			}
		}
		_ = os.Remove(filepath.Join(p.tree.vms, name))
	}
	p.ctr.Store(maxIdx + 1)
	return adopted
}

// run refills the pool to target and then tops it up on every claim kick (or
// a slow tick, catching kicks lost to the buffer). Serial on purpose: one
// creation at a time is what keeps the refill from competing with live
// launches for the same kernel locks; creation is slow enough that the loop
// needs no pacing of its own.
func (p *spareCgroupPool) run(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		for len(p.free) < p.target {
			if ctx.Err() != nil {
				return
			}
			name, err := p.createSpare()
			if err != nil {
				p.log.Warn().Err(err).Msg("spare cgroup pool: create failed; retrying after backoff")
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Second):
				}
				continue
			}
			select {
			case p.free <- name:
			default:
				// Target shrank underneath us (never at runtime today, but
				// cheap to tolerate): the spare is excess.
				_ = os.Remove(filepath.Join(p.tree.vms, name))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-p.kick:
		case <-tick.C:
		}
	}
}

// createSpare makes one spare group, paying the expensive kernel-side
// creation here so a claim doesn't. The oom.group write is best-effort at
// creation — claim re-writes it anyway (see claim).
func (p *spareCgroupPool) createSpare() (string, error) {
	name := spareCgroupPrefix + strconv.FormatUint(p.ctr.Add(1)-1, 10)
	dir := filepath.Join(p.tree.vms, name)
	if err := os.Mkdir(dir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir spare cgroup: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "memory.oom.group"), []byte("1"), 0o644); err != nil {
		_ = os.Remove(dir)
		return "", fmt.Errorf("set oom.group on spare: %w", err)
	}
	return name, nil
}

// claim hands the caller a pre-created group renamed to vmID, or (nil, false)
// when the pool can't — the caller then creates inline. The oom.group write
// is repeated after the rename: it is idempotent, costs one attribute write,
// and makes a half-initialized spare (crash mid-create in a prior life)
// impossible to hand out rather than something to validate.
func (p *spareCgroupPool) claim(vmID string) (*os.File, bool) {
	dst, derr := p.tree.safeVMCgroupDir(vmID)
	if derr != nil {
		return nil, false
	}
	for {
		var name string
		select {
		case name = <-p.free:
		default:
			p.log.Info().Str("vm_id", vmID).Msg("spare cgroup pool empty — creating inline")
			return nil, false
		}
		p.kickRefill()
		if err := os.Rename(filepath.Join(p.tree.vms, name), dst); err != nil {
			// Return the spare only if it still exists under its own name
			// (target collision — this vmID already has a dir, which the
			// inline fallback tolerates). A vanished spare (reaped underneath
			// us) must be dropped, or its dead name would poison a pool slot
			// forever: every future claim would pop it, fail, and re-queue it.
			if _, serr := os.Stat(filepath.Join(p.tree.vms, name)); serr == nil {
				select {
				case p.free <- name:
				default:
					_ = os.Remove(filepath.Join(p.tree.vms, name))
				}
			}
			return nil, false
		}
		if err := os.WriteFile(filepath.Join(dst, "memory.oom.group"), []byte("1"), 0o644); err != nil {
			// The claimed group is broken; give it back to the kernel and
			// fall back rather than launch without whole-VM OOM semantics.
			_ = os.Remove(dst)
			return nil, false
		}
		f, err := os.Open(dst)
		if err != nil {
			_ = os.Remove(dst)
			return nil, false
		}
		return f, true
	}
}

func (p *spareCgroupPool) kickRefill() {
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

// reapSpareCgroups removes every spare under the scope root — used when the
// pool is disabled or the host is disarming, so a drained tree holds nothing
// but VMs and the keeper. Spares are empty by construction, so rmdir either
// succeeds or the dir is not ours to touch (and the error is only logged).
func reapSpareCgroups(scopeRoot string, log zerolog.Logger) {
	entries, err := os.ReadDir(scopeRoot)
	if err != nil {
		return
	}
	reaped := 0
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), spareCgroupPrefix) {
			if rerr := os.Remove(filepath.Join(scopeRoot, e.Name())); rerr == nil {
				reaped++
			} else {
				log.Warn().Err(rerr).Str("name", e.Name()).Msg("spare cgroup reap failed")
			}
		}
	}
	if reaped > 0 {
		log.Info().Int("reaped", reaped).Msg("reaped spare cgroups")
	}
}

// DirectSpawnArmed reports whether new launches take the cgroup path.
func (m *Manager) DirectSpawnArmed() bool { return m.directSpawnArmed.Load() }

// StartSpareCgroupPool builds and starts the pool once direct spawn is armed.
// No-op unless armed with a positive target — the pool must never exist on a
// host whose launches wouldn't consume it.
func (m *Manager) StartSpareCgroupPool(ctx context.Context) {
	if m.cgroups == nil || !m.directSpawnArmed.Load() || m.cfg.SpareCgroupTarget <= 0 {
		return
	}
	p := newSpareCgroupPool(m.cgroups, m.cfg.SpareCgroupTarget, m.log)
	adopted := p.adoptExisting()
	m.spares = p
	go func() {
		defer sentrylog.Recover("spare-cgroup-pool")
		p.run(ctx)
	}()
	m.log.Info().Int("target", p.target).Int("adopted", adopted).
		Msg("spare cgroup pool started (filling in background)")
}

// claimSpareCgroup is the launch-path entry: a pooled claim when available,
// (nil, false) otherwise — the caller creates inline.
func (m *Manager) claimSpareCgroup(vmID string) (*os.File, bool) {
	if m.spares == nil {
		return nil, false
	}
	return m.spares.claim(vmID)
}

// ReapStrayLeftoverSpares removes spares a previously-armed life left behind
// on a host that is now disarmed (the pool never starts, so nothing else
// would). Resolves the scope read-only via systemd; absent scope means
// nothing to reap.
func (m *Manager) ReapStrayLeftoverSpares(ctx context.Context) {
	rel, err := unitControlGroup(ctx, vmsUnitName)
	if err != nil || rel == "" {
		return
	}
	reapSpareCgroups(filepath.Join(cgroupMount, rel), m.log)
}
