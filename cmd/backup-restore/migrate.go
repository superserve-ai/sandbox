package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/superserve-ai/sandbox/internal/backup"
	"github.com/superserve-ai/sandbox/proto/vmdpb"
)

// runMigrate moves paused sandboxes from one host to this one using the
// filesystems a host restore materialized: for each sandbox it re-pins the
// control-plane row here, cold-boots the restored disk through ReviveVM,
// and lets the control plane's timeout reaper take it back to paused
// through the ordinary pause path, so the sandbox ends up paused on this
// host with a fresh snapshot and backup generation.
//
// Each sandbox goes through three steps. The row is claimed first: it
// moves here as 'migrating', fenced on the snapshot whose digests were
// checked and on the timeout read with it. Resume claims only paused rows,
// so the owner cannot start a second copy beside the boot, and no request
// of theirs is served by it: the row is never active. The restored disk is
// then booted, and the row is armed with the fresh address and a short
// timeout as soon as the RPC returns; the reaper pauses migrating rows as
// it does active ones, so the sandbox goes straight from the operator's
// boot to paused here. A boot that fails hands the claim back to the
// source, paused as it was.
//
// Nothing on the host pauses an idle VM by itself: the reaper pauses
// active rows whose timeout has elapsed, and most rows carry no timeout.
// A short temporary timeout replaces whatever the row had on the flip
// (a long one would not elapse either) and the original value, timeout
// or none, is written back once the row is paused again; a row stays
// pending until that write-back succeeds. The original is journaled
// under the restore root before it is replaced, and a rerun finishes the
// write-back for rows an interrupted run left paused here. No active interval
// is opened for the boot: it is not the owner's usage and must not bill,
// and without one the reaper treats the row as long expired and pauses
// it on its next tick, which is the intent. The reaper's own retry after
// a failed pause attempt does reopen intervals; the tool does not touch
// billing tables, so any interval opened on a row during its migration is
// reported and written to the ledger for a credit.
//
// A restored copy is only booted when it is the sandbox's current pause:
// the digests the control plane recorded for the row's snapshot must all
// appear in the restored generation, and the flip is fenced on that same
// snapshot so a pause completed during the boot is never overwritten. A
// sandbox its owner resumed and paused again since the restore is skipped
// for a fresh one; one whose snapshot has no recorded digests is skipped
// as unverifiable.
//
// Egress rules are re-read from the row and applied at boot, as vmd does
// not persist them. Secret bindings are re-minted by the control plane on
// the owner's next resume (the guest's address changed, so the recorded
// injection no longer matches). Plain environment variables are held only
// in the guest's memory, which a cold boot does not carry over; that is
// the filesystem-only contract of a host restore.
//
// The scheduler's load ranking does not count migrating rows, so a
// destination that is already taking placements sees the wave's boots
// only once they are paused; keep -inflight modest there.
//
// Operator tool, run on the destination host next to vmd with the same
// database credentials vmd uses. Sandboxes that fail to boot are recorded
// so a rerun does not retry them. A row the control plane failed after
// the boot is left failed and reported: that transition already dropped
// the sandbox's secret bindings and auto-delete, so putting it back to
// paused would hide a loss.
func runMigrate(args []string) int {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	dbURL := fs.String("db-url", os.Getenv("DATABASE_URL"), "control-plane DB URL (default $DATABASE_URL)")
	fromHost := fs.String("from-host", "", "host id the paused rows point at now")
	toHost := fs.String("to-host", "", "this host's id (the host row with a live heartbeat)")
	root := fs.String("restore-root", "", "host-restore destination root; each sandbox at <root>/<id>")
	vmdAddr := fs.String("vmd", "127.0.0.1:50051", "vmd gRPC address")
	inflight := fs.Int("inflight", 100, "sandboxes booted here but not yet paused again, at most")
	concurrency := fs.Int("concurrency", 8, "parallel ReviveVM calls")
	limit := fs.Int("limit", 0, "stop after this many sandboxes (0 = all)")
	tmpTimeout := fs.Int("pause-timeout-seconds", 60, "temporary timeout_seconds for rows that have none")
	pauseWait := fs.Duration("pause-wait", 15*time.Minute, "how long a booted sandbox may stay active before it counts as stuck")
	dryRun := fs.Bool("dry-run", false, "list what would move and exit")
	_ = fs.Parse(args)
	if *fromHost == "" || *toHost == "" || *root == "" || *dbURL == "" {
		fmt.Fprintln(os.Stderr, "migrate: -from-host, -to-host, -restore-root and -db-url are required")
		return 2
	}
	if *fromHost == *toHost {
		fmt.Fprintln(os.Stderr, "migrate: -from-host and -to-host are the same host")
		return 2
	}
	if *inflight <= 0 || *concurrency <= 0 || *tmpTimeout <= 0 {
		fmt.Fprintln(os.Stderr, "migrate: -inflight, -concurrency and -pause-timeout-seconds must be positive")
		return 2
	}
	ctx := context.Background()
	// A pool, not a single connection: the per-row flips run from the boot
	// workers concurrently.
	conn, err := pgxpool.New(ctx, *dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate: connect: %v\n", err)
		return 1
	}
	defer conn.Close()

	// The destination must be the id vmd heartbeats under: a row that
	// exists but is silent (a retired slot name, a typo) would have every
	// boot killed as an orphan by the reconciler of the real host.
	var age float64
	var rowVMD string
	err = conn.QueryRow(ctx, `SELECT EXTRACT(EPOCH FROM now() - last_heartbeat_at), vmd_addr FROM host WHERE id = $1`, *toHost).Scan(&age, &rowVMD)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate: destination host %q: %v\n", *toHost, err)
		return 1
	}
	if age > 120 {
		fmt.Fprintf(os.Stderr, "migrate: destination host %q has no heartbeat for %.0fs; use the id vmd registers under\n", *toHost, age)
		return 1
	}
	// The daemon the boots go to must be the one that row describes: a
	// loopback endpoint has to be on the machine the row's address names,
	// any other endpoint has to be that address. Otherwise the guest would
	// run on one host while the row points at another, and both
	// reconcilers would undo it.
	if err := endpointIsHost(*vmdAddr, rowVMD); err != nil {
		fmt.Fprintf(os.Stderr, "migrate: -vmd %s is not host %q (%s): %v\n", *vmdAddr, *toHost, rowVMD, err)
		return 1
	}
	var srcStatus string
	if err := conn.QueryRow(ctx, `SELECT status FROM host WHERE id = $1`, *fromHost).Scan(&srcStatus); err != nil {
		fmt.Fprintf(os.Stderr, "migrate: source host %q: %v\n", *fromHost, err)
		return 1
	}
	// Resume is gated on the host advertising every capability a sandbox's
	// preview policy needs. The source served these sandboxes, so its
	// current capability set is what they may need; the destination must
	// advertise all of it or their resumes would be refused there.
	var missing []string
	mr, err := conn.Query(ctx, `SELECT src.capability FROM host_capability src
		JOIN host sh ON sh.id = src.host_id AND src.heartbeat_at = sh.last_heartbeat_at
		WHERE src.host_id = $1 AND NOT EXISTS (
			SELECT 1 FROM host_capability dst JOIN host dh ON dh.id = dst.host_id AND dst.heartbeat_at = dh.last_heartbeat_at
			WHERE dst.host_id = $2 AND dst.capability = src.capability)`, *fromHost, *toHost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate: host capabilities: %v\n", err)
		return 1
	}
	for mr.Next() {
		var c string
		if err := mr.Scan(&c); err != nil {
			mr.Close()
			fmt.Fprintf(os.Stderr, "migrate: host capabilities: %v\n", err)
			return 1
		}
		missing = append(missing, c)
	}
	mr.Close()
	if err := mr.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "migrate: host capabilities: %v\n", err)
		return 1
	}
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "migrate: destination %q does not advertise %v, which %q does; sandboxes needing them could not resume there\n", *toHost, missing, *fromHost)
		return 1
	}

	skip := loadSkipSet(filepath.Join(*root, "migrate-failed.txt"))
	// A dry run only reads the journal, and only if there is one; a real
	// run creates it and holds it: one run per restore root, since entries
	// are retired by sandbox id and two runs claiming the same rows could
	// retire each other's. The lock is released with the descriptor.
	journalPath := filepath.Join(*root, "migrate-timeouts.txt")
	flags := os.O_APPEND | os.O_CREATE | os.O_RDWR
	if *dryRun {
		flags = os.O_RDONLY
	}
	journal, err := os.OpenFile(journalPath, flags, 0o644)
	if err != nil && !(*dryRun && errors.Is(err, os.ErrNotExist)) {
		fmt.Fprintf(os.Stderr, "migrate: timeout journal: %v\n", err)
		return 1
	}
	pending := map[string]journaled{}
	if journal != nil {
		defer journal.Close()
		if !*dryRun {
			if err := unix.Flock(int(journal.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
				fmt.Fprintf(os.Stderr, "migrate: another run holds %s: %v\n", journalPath, err)
				return 1
			}
		}
		if pending, err = pendingJournal(journal); err != nil {
			fmt.Fprintf(os.Stderr, "migrate: timeout journal: %v\n", err)
			return 1
		}
	}
	// One inventory up front; the flip re-checks each row under its own
	// WHERE clause, so a sandbox the owner resumed meanwhile is skipped
	// rather than moved out from under them.
	rows, err := conn.Query(ctx, `SELECT id::text FROM sandbox WHERE host_id = $1 AND status = 'paused' AND destroyed_at IS NULL ORDER BY updated_at DESC`, *fromHost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate: inventory: %v\n", err)
		return 1
	}
	var queue []string
	notRestored := 0
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			fmt.Fprintf(os.Stderr, "migrate: inventory: %v\n", err)
			return 1
		}
		if skip[id] {
			continue
		}
		if _, err := restoredDisk(*root, id); err != nil {
			notRestored++
			continue
		}
		queue = append(queue, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		// A partial inventory would migrate a subset and report it whole.
		fmt.Fprintf(os.Stderr, "migrate: inventory: %v\n", err)
		return 1
	}
	if *limit > 0 && len(queue) > *limit {
		queue = queue[:*limit]
	}
	fmt.Printf("migrate: %d paused on %s (%s); %d restored here and queued, %d not restored, %d skipped from earlier failures, %d left mid-flight by an earlier run\n",
		len(queue)+notRestored+len(skip), *fromHost, srcStatus, len(queue), notRestored, len(skip), len(pending))
	if *dryRun || len(queue)+len(pending) == 0 {
		return 0
	}
	gconn, err := grpc.NewClient(*vmdAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate: dial vmd: %v\n", err)
		return 1
	}
	defer gconn.Close()
	vmd := vmdpb.NewVMDaemonClient(gconn)

	type live struct {
		since       time.Time
		origTimeout *int32 // written back after the pause; nil = none
		generation  int64  // the pause generation at the claim; a higher one means the migration pause completed
		restores    int    // write-back attempts so far
		reported    bool   // already reported as stuck; stays counted against -inflight
	}
	active := map[string]live{} // booted here, waiting for the reaper
	moved, failed, stuck, stale, unanchored, retried := 0, 0, 0, 0, 0, 0
	failFile, _ := os.OpenFile(filepath.Join(*root, "migrate-failed.txt"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if failFile != nil {
		defer failFile.Close()
	}
	// Rows an earlier run flipped here but never finished: ones still on
	// their way to paused join the live set and complete through the same
	// pause and write-back below; ones already paused with the temporary
	// timeout get the write-back now; anything else is retired.
	if len(pending) > 0 {
		ids := make([]string, 0, len(pending))
		for id := range pending {
			ids = append(ids, id)
		}
		for id, j := range pending {
			if j.fromHost != *fromHost || j.toHost != *toHost || j.tmp != int32(*tmpTimeout) {
				fmt.Fprintf(os.Stderr, "migrate: %s was left mid-flight by a run with -from-host %s -to-host %s -pause-timeout-seconds %d; rerun with those to finish it\n", id, j.fromHost, j.toHost, j.tmp)
				return 2
			}
		}
		pr, err := conn.Query(ctx, `SELECT id::text, status::text, host_id, timeout_seconds FROM sandbox WHERE id = ANY($1::uuid[]) AND destroyed_at IS NULL`, ids)
		if err != nil {
			fmt.Fprintf(os.Stderr, "migrate: journal recovery: %v\n", err)
			return 1
		}
		seen := map[string]bool{}
		for pr.Next() {
			var id, status, host string
			var timeout *int32
			if err := pr.Scan(&id, &status, &host, &timeout); err != nil {
				pr.Close()
				fmt.Fprintf(os.Stderr, "migrate: journal recovery: %v\n", err)
				return 1
			}
			seen[id] = true
			switch {
			case host == *toHost && (status == "active" || status == "pausing"):
				// Still on its way to paused, or paused and resumed by the
				// owner already: the poll tells the two apart by comparing
				// against the journaled pre-migration snapshot. The audit
				// window keeps the journaled claim time so nothing billed
				// meanwhile is missed.
				active[id] = live{since: pending[id].since, origTimeout: pending[id].orig, generation: pending[id].generation}
			case host == *toHost && status == "migrating" && timeout != nil && *timeout == int32(*tmpTimeout):
				// Booted and armed; the reaper will pause it. Adopt it.
				active[id] = live{since: pending[id].since, origTimeout: pending[id].orig, generation: pending[id].generation}
			case host == *toHost && status == "migrating":
				// Claimed but never armed. The earlier run may have got as
				// far as booting, so the guest is stopped here first; only
				// then is the row resumable on the source again.
				dctx, dcancel := context.WithTimeout(ctx, time.Minute)
				_, derr := vmd.DestroyVM(dctx, &vmdpb.DestroyVMRequest{VmId: id, Force: true})
				dcancel()
				if derr != nil {
					fmt.Fprintf(os.Stderr, "migrate: journal recovery: %s: stopping the booted guest: %v\n", id, derr)
					return 1
				}
				if _, err := conn.Exec(ctx, `UPDATE sandbox SET host_id = $1, status = 'paused',
						timeout_seconds = CASE WHEN timeout_seconds IS NULL THEN $4 ELSE timeout_seconds END, updated_at = now()
					WHERE id = $2 AND host_id = $3 AND status = 'migrating'`, *fromHost, id, *toHost, pending[id].orig); err != nil {
					fmt.Fprintf(os.Stderr, "migrate: journal recovery: %v\n", err)
					return 1
				}
				if err := journalDone(journal, id); err != nil {
					fmt.Fprintf(os.Stderr, "migrate: journal: %v\n", err)
					return 1
				}
			case host == *toHost && status == "paused" && timeout != nil && *timeout == int32(*tmpTimeout):
				active[id] = live{since: pending[id].since, origTimeout: pending[id].orig, generation: pending[id].generation, restores: 1}
			default:
				if err := journalDone(journal, id); err != nil {
					fmt.Fprintf(os.Stderr, "migrate: journal: %v\n", err)
					return 1
				}
			}
		}
		pr.Close()
		if err := pr.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "migrate: journal recovery: %v\n", err)
			return 1
		}
		for _, id := range ids {
			// Not returned: destroyed since, or gone. Nothing is owed.
			if !seen[id] {
				if err := journalDone(journal, id); err != nil {
					fmt.Fprintf(os.Stderr, "migrate: journal: %v\n", err)
					return 1
				}
			}
		}
		fmt.Printf("migrate: adopted %d rows left mid-flight by an earlier run\n", len(active))
	}
	recordFailure := func(id, why string) {
		failed++
		fmt.Printf("FAILED %s: %s\n", id, why)
		if failFile != nil {
			fmt.Fprintf(failFile, "%s %s\n", id, why)
		}
	}
	// A retryable miss (the row moved on, a transient database error) is
	// reported but not written to the skip file: a later run picks the
	// sandbox up again once it is paused with a current restore.
	recordRetry := func(id, why string) {
		retried++
		fmt.Printf("RETRY %s: %s\n", id, why)
	}
	type shape struct {
		vcpu, mem   int32
		team        string
		origTimeout *int32
		rules       egressRules
		recorded    map[string]string
		snapshotID  *string
		generation  int64 // the snapshot row is reused across pauses; its generation is what moves
	}
	type job struct {
		id         string
		s          shape
		disk, base string
		standalone bool
	}
	// Boots run on a fixed pool fed a little at a time, so the poll below
	// never waits on a whole batch: a sandbox the reaper has paused gets
	// its timeout back on the next tick whatever the other boots are doing.
	// mu guards active, booting, and the counters and ledger the workers
	// touch.
	var mu sync.Mutex
	booting := 0 // handed to a worker, not yet settled into active or failed
	jobs := make(chan job, *inflight)
	var run func(j job)
	var wg sync.WaitGroup
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				run(j)
				mu.Lock()
				booting--
				mu.Unlock()
			}
		}()
	}
	defer wg.Wait()
	defer close(jobs)

	run = func(j job) {
		id, s, disk, base, standalone := j.id, j.s, j.disk, j.base, j.standalone
		{
			{
				{
					// Claim first: the row moves to this host as 'migrating',
					// fenced on the snapshot whose digests were checked (id and
					// generation: a pause reuses the row and bumps the latter)
					// and on the timeout that was journaled. Resume takes only paused
					// rows, so from here the owner cannot start a second copy
					// next to the boot; their request waits for the flip.
					// The original timeout reaches the journal before the
					// claim so a run that dies afterwards can still put it
					// back.
					claimedAt := time.Now()
					mu.Lock()
					err := journalTimeout(journal, id, s.origTimeout, claimedAt, *fromHost, *toHost, int32(*tmpTimeout), s.generation)
					mu.Unlock()
					if err != nil {
						mu.Lock()
						recordFailure(id, err.Error())
						mu.Unlock()
						return
					}
					// The timeout is cleared with the claim: an elapsed one
					// would let the reaper pause the row while the boot is
					// still running. It is journaled, and set again on arming
					// or put back on hand-back.
					tag, err := conn.Exec(ctx, `UPDATE sandbox SET host_id = $1, status = 'migrating', timeout_seconds = NULL, updated_at = now()
						WHERE id = $2 AND host_id = $3 AND status = 'paused' AND destroyed_at IS NULL AND snapshot_id = $4
							AND timeout_seconds IS NOT DISTINCT FROM $5
							AND (SELECT sn.generation FROM snapshot sn WHERE sn.id = sandbox.snapshot_id) = $6`,
						*toHost, id, *fromHost, *s.snapshotID, s.origTimeout, s.generation)
					if err != nil {
						// The write's outcome is unknown (a lost reply may have
						// committed it): the journal entry stays, and a rerun's
						// recovery hands back whatever was claimed.
						mu.Lock()
						recordRetry(id, err.Error())
						mu.Unlock()
						return
					}
					if tag.RowsAffected() == 0 {
						// Nothing was claimed: the row moved on. A later run may
						// find it paused again.
						mu.Lock()
						recordRetry(id, "changed on "+*fromHost+" since it was read")
						if jerr := journalDone(journal, id); jerr != nil {
							fmt.Printf("WARN %s: journal not updated: %v\n", id, jerr)
						}
						mu.Unlock()
						return
					}
					// Boot, then activate with the fresh address so nothing
					// routes to the old slot. A failed boot hands the row back
					// to the source, still paused, exactly as it was.
					rctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
					resp, err := vmd.ReviveVM(rctx, &vmdpb.ReviveVMRequest{
						VmId: id, DiskPath: disk, BasePath: base, StandaloneDisk: standalone, AllowRecordless: true,
						TeamId: s.team, Vcpu: uint32(s.vcpu), MemMib: uint32(s.mem),
						AllowedCidrs: s.rules.allowedCIDRs, DeniedCidrs: s.rules.deniedCIDRs, AllowedDomains: s.rules.allowedDomains,
					})
					cancel()
					// vmd does not persist the preview policy; a recordless
					// boot starts private with no published ports, and it
					// stays that way here so nothing routes to a guest that
					// holds no environment. The owner's next resume applies
					// the stored policy as it always does.
					if err == nil {
						var ip netip.Addr
						if ip, err = netip.ParseAddr(resp.GetHostIp()); err == nil {
							// The row stays 'migrating': it is never exposed as
							// active, so no owner request reaches a guest that
							// holds no secrets. The short timeout arms the reaper,
							// which pauses migrating rows like active ones.
							// Fenced on the timeout still being cleared: a PATCH
							// the owner made during the boot is theirs to keep. The
							// secret-injection markers are cleared with it: the
							// cold boot holds no secrets, and a same address on
							// this host would otherwise let the next resume
							// believe the guest still does.
							tag, err = conn.Exec(ctx, `UPDATE sandbox SET timeout_seconds = $1, ip_address = $2,
									secret_env_fingerprint = NULL, secret_env_ip = NULL, secret_env_injected_at = NULL, secret_env_expires_at = NULL,
									updated_at = now()
								WHERE id = $3 AND host_id = $4 AND status = 'migrating' AND destroyed_at IS NULL
									AND timeout_seconds IS NULL`,
								int32(*tmpTimeout), ip, id, *toHost)
							if err != nil {
								// Outcome unknown: the row decides. The temporary
								// timeout is only ever set here, so seeing it means
								// the write landed and the boot stands.
								var armed bool
								if qerr := conn.QueryRow(ctx, `SELECT timeout_seconds = $3 FROM sandbox WHERE id = $1 AND host_id = $2 AND status IN ('migrating', 'pausing', 'paused')`,
									id, *toHost, int32(*tmpTimeout)).Scan(&armed); qerr == nil && armed {
									err = nil
								} else {
									err = errRetry{fmt.Errorf("arming the pause: %w", err)}
								}
							} else if tag.RowsAffected() == 0 {
								err = errRetry{fmt.Errorf("claim on %s changed before the boot finished", *toHost)}
							}
						}
					}
					if err != nil {
						// Not activated: take the VM back down before the row is
						// handed back. Unconditional, because a lost reply looks
						// like a failed RPC while the VM is up; destroying a VM
						// that never started is a no-op. If even that fails the
						// claim stays here, with its journal entry, so nothing
						// can resume beside a guest that may still be running;
						// a rerun retries the stop.
						dctx, dcancel := context.WithTimeout(ctx, time.Minute)
						_, derr := vmd.DestroyVM(dctx, &vmdpb.DestroyVMRequest{VmId: id, Force: true})
						dcancel()
						if derr != nil {
							mu.Lock()
							recordFailure(id, fmt.Sprintf("%v; and the booted VM could not be destroyed, claim kept: %v", err, derr))
							mu.Unlock()
							return
						}
					}
					if err != nil {
						// The guest is down; give the row back. Until that write
						// is confirmed the journal entry stays, so a rerun's
						// recovery finishes the hand-back.
						_, rerr := conn.Exec(ctx, `UPDATE sandbox SET host_id = $1, status = 'paused',
								timeout_seconds = CASE WHEN timeout_seconds IS NULL THEN $4 ELSE timeout_seconds END, updated_at = now()
							WHERE id = $2 AND host_id = $3 AND status = 'migrating'`, *fromHost, id, *toHost, s.origTimeout)
						mu.Lock()
						var retry errRetry
						switch {
						case rerr != nil:
							recordRetry(id, fmt.Sprintf("%v; and the claim could not be handed back yet: %v", err, rerr))
						case errors.As(err, &retry):
							recordRetry(id, err.Error())
						default:
							recordFailure(id, err.Error())
						}
						if rerr == nil {
							if jerr := journalDone(journal, id); jerr != nil {
								fmt.Printf("WARN %s: journal not updated: %v\n", id, jerr)
							}
						}
						mu.Unlock()
						return
					}
					mu.Lock()
					active[id] = live{since: claimedAt, origTimeout: s.origTimeout, generation: s.generation}
					mu.Unlock()
				}
			}
		}
	}

	started := time.Now()
	for {
		mu.Lock()
		more := len(queue) > 0 || len(active) > 0 || booting > 0
		mu.Unlock()
		if !more {
			break
		}
		// Settle what the reaper finished: paused rows are done (their
		// temporary timeout cleared); failed rows are left for a human, and
		// rows still in flight past the wait are reported but keep their
		// slot until they settle.
		mu.Lock()
		if len(active) > 0 {
			ids := make([]string, 0, len(active))
			for id := range active {
				ids = append(ids, id)
			}
			st, err := conn.Query(ctx, `SELECT s.id::text, s.status::text, COALESCE((SELECT sn.generation FROM snapshot sn WHERE sn.id = s.snapshot_id), 0)::bigint
				FROM sandbox s WHERE s.id = ANY($1::uuid[])`, ids)
			if err != nil {
				fmt.Fprintf(os.Stderr, "migrate: poll: %v\n", err)
				mu.Unlock()
				return 1
			}
			var paused, gone, deleted []string
			pausedSeen := time.Now()
			for st.Next() {
				var id, status string
				var gen int64
				if err := st.Scan(&id, &status, &gen); err != nil {
					st.Close()
					fmt.Fprintf(os.Stderr, "migrate: poll: %v\n", err)
					mu.Unlock()
					return 1
				}
				switch {
				case status == "failed":
					gone = append(gone, id)
				case status == "deleted":
					deleted = append(deleted, id)
				case status == "paused", gen > active[id].generation:
					// Paused here, or paused and already resumed by the
					// owner between polls: the migration pause completed
					// either way and the timeout goes back now.
					paused = append(paused, id)
				}
			}
			st.Close()
			if err := st.Err(); err != nil {
				fmt.Fprintf(os.Stderr, "migrate: poll: %v\n", err)
				mu.Unlock()
				return 1
			}
			// A paused row is moved only once its original timeout is back;
			// until then it stays pending and the write-back is retried.
			if len(paused) > 0 {
				origs := make([]*int32, len(paused))
				for i, id := range paused {
					origs[i] = active[id].origTimeout
				}
				// The write-back is keyed on the temporary value alone: a row
				// the owner resumed between the poll and this statement still
				// gets its timeout back. Rows the statement did not reach stay
				// pending and are polled again. Timeouts cannot be changed
				// while a row is migrating, so the value can only be the
				// tool's own, except for an owner who sets exactly this value
				// in the seconds between the pause and this poll and gets
				// their earlier one back instead.
				written := map[string]bool{}
				wr, err := conn.Query(ctx, `UPDATE sandbox s SET timeout_seconds = v.orig, updated_at = now()
					FROM unnest($1::uuid[], $2::int[]) AS v(id, orig)
					WHERE s.id = v.id AND s.host_id = $3 AND s.timeout_seconds = $4
					RETURNING s.id::text`, paused, origs, *toHost, int32(*tmpTimeout))
				if err == nil {
					for wr.Next() {
						var id string
						if err = wr.Scan(&id); err != nil {
							break
						}
						written[id] = true
					}
					wr.Close()
					if err == nil {
						err = wr.Err()
					}
				}
				for _, id := range paused {
					if err == nil && !written[id] {
						err = fmt.Errorf("row changed before the write-back reached it")
					}
					if err != nil {
						l := active[id]
						l.restores++
						active[id] = l
						if l.restores >= 5 {
							delete(active, id)
							recordFailure(id, fmt.Sprintf("paused here but its timeout could not be written back after %d attempts: %v", l.restores, err))
						}
						err = nil
						continue
					}
					if secs, ierr := billedDuring(ctx, conn, id, active[id].since, pausedSeen); ierr != nil {
						fmt.Printf("WARN %s: could not check for intervals opened during migration: %v\n", id, ierr)
					} else if secs > 0 {
						fmt.Printf("BILLED %s: %.0fs of intervals opened while migrating; credit the owner\n", id, secs)
						if failFile != nil {
							fmt.Fprintf(failFile, "%s billed %.0fs during migration\n", id, secs)
						}
					}
					if jerr := journalDone(journal, id); jerr != nil {
						fmt.Printf("WARN %s: journal not updated: %v\n", id, jerr)
					}
					delete(active, id)
					moved++
					fmt.Printf("MOVED %s\n", id)
				}

			}
			for _, id := range gone {
				delete(active, id)
				recordFailure(id, "row failed after boot and stays failed on "+*toHost+"; needs an operator")
			}
			for _, id := range deleted {
				// The owner deleted it meanwhile; nothing is owed.
				delete(active, id)
				fmt.Printf("DELETED %s: removed by its owner during the move\n", id)
				if jerr := journalDone(journal, id); jerr != nil {
					fmt.Printf("WARN %s: journal not updated: %v\n", id, jerr)
				}
			}
			for id, l := range active {
				if l.restores > 0 {
					continue // paused; only the write-back is outstanding
				}
				if !l.reported && time.Since(l.since) > *pauseWait {
					// Reported once, but it keeps its slot: the guest is still
					// running here, so it still counts against -inflight, and
					// it is settled like any other row if the reaper catches up.
					l.reported = true
					active[id] = l
					stuck++
					fmt.Printf("STUCK %s: not paused after %s; pause it by hand\n", id, pauseWait)
				}
			}
		}
		room := *inflight - len(active) - booting
		mu.Unlock()

		// Fill up to the in-flight bound: read each row's shape and egress
		// rules, then hand it to the pool, which boots and flips the row
		// the moment its VM is up.
		if n := room; n > 0 && len(queue) > 0 {
			if n > len(queue) {
				n = len(queue)
			}
			batch := queue[:n]
			queue = queue[n:]
			shapes := map[string]shape{}
			sq, err := conn.Query(ctx, `SELECT s.id::text, s.vcpu_count, s.memory_mib, s.team_id::text, s.timeout_seconds, s.network_config,
					COALESCE((SELECT json_object_agg(am.file_name, am.sha256) FROM artifact_manifest am WHERE am.snapshot_id = s.snapshot_id), '{}')::text,
					s.snapshot_id::text,
					COALESCE((SELECT sn.generation FROM snapshot sn WHERE sn.id = s.snapshot_id), 0)::bigint
				FROM sandbox s WHERE s.id = ANY($1::uuid[]) AND s.host_id = $2 AND s.status = 'paused' AND s.destroyed_at IS NULL`, batch, *fromHost)
			if err != nil {
				fmt.Fprintf(os.Stderr, "migrate: shapes: %v\n", err)
				return 1
			}
			for sq.Next() {
				var id, recorded string
				var s shape
				var raw []byte
				if err := sq.Scan(&id, &s.vcpu, &s.mem, &s.team, &s.origTimeout, &raw, &recorded, &s.snapshotID, &s.generation); err != nil {
					sq.Close()
					fmt.Fprintf(os.Stderr, "migrate: shapes: %v\n", err)
					return 1
				}
				if s.rules, err = parseEgressRules(raw); err != nil {
					recordFailure(id, "network_config: "+err.Error())
					continue
				}
				if err := json.Unmarshal([]byte(recorded), &s.recorded); err != nil {
					recordFailure(id, "recorded digests: "+err.Error())
					continue
				}
				shapes[id] = s
			}
			sq.Close()
			if err := sq.Err(); err != nil {
				fmt.Fprintf(os.Stderr, "migrate: shapes: %v\n", err)
				return 1
			}
			for _, id := range batch {
				if _, ok := shapes[id]; !ok && !skip[id] {
					fmt.Printf("SKIP %s: no longer paused on %s\n", id, *fromHost)
				}
			}

			handed := 0
			for id, s := range shapes {
				rd, err := restoredDisk(*root, id)
				if err == nil && (len(s.recorded) == 0 || s.snapshotID == nil) {
					mu.Lock()
					unanchored++
					fmt.Printf("SKIP %s: its current snapshot has no recorded digests, so no restored copy can be shown to match it\n", id)
					mu.Unlock()
					continue
				}
				if err == nil && !rd.current(s.recorded) {
					// Not a failure of the sandbox: the copy is behind its
					// owner's latest pause. Clear it so the next host restore
					// materializes the current one, and leave the id eligible.
					mu.Lock()
					stale++
					if rerr := os.RemoveAll(filepath.Join(*root, id)); rerr != nil {
						fmt.Printf("STALE %s: restored copy predates the current pause and could not be removed: %v\n", id, rerr)
					} else {
						fmt.Printf("STALE %s: restored copy predates the current pause; removed, restore it again\n", id)
					}
					mu.Unlock()
					continue
				}
				if err != nil {
					mu.Lock()
					recordFailure(id, err.Error())
					mu.Unlock()
					continue
				}
				mu.Lock()
				booting++
				mu.Unlock()
				handed++
				jobs <- job{id: id, s: s, disk: rd.disk, base: rd.base, standalone: rd.standalone}
			}
			mu.Lock()
			fmt.Printf("handed %d, booting %d, in flight %d, queued %d, moved %d, failed %d, %s elapsed\n",
				handed, booting, len(active), len(queue), moved, failed, time.Since(started).Round(time.Second))
			mu.Unlock()
		}
		mu.Lock()
		wait := len(active) > 0 || booting > 0
		mu.Unlock()
		if wait {
			time.Sleep(10 * time.Second)
		}
	}
	fmt.Printf("migrate complete: moved=%d failed=%d stuck=%d stale=%d unverifiable=%d retry=%d in %s\n", moved, failed, stuck, stale, unanchored, retried, time.Since(started).Round(time.Second))
	if failed+stuck+stale+unanchored+retried > 0 {
		return 1
	}
	return 0
}

// errRetry marks a failure a later run may not see again.
type errRetry struct{ error }

// journalTimeout records a row's timeout, the claim time, the run's hosts
// and temporary timeout, and the pause generation the row had, before the
// migration replaces any of it: `<id> <seconds>|none <unix> <from-host>
// <to-host> <tmp> <generation>`, fsynced, so a rerun can finish the row
// (and tell whether its pause already happened) and refuses to do so under
// different parameters.
func journalTimeout(journal *os.File, id string, orig *int32, at time.Time, fromHost, toHost string, tmp int32, generation int64) error {
	value := "none"
	if orig != nil {
		value = strconv.FormatInt(int64(*orig), 10)
	}
	line := fmt.Sprintf("%s %s %d %s %s %d %d\n", id, value, at.Unix(), fromHost, toHost, tmp, generation)
	if _, err := journal.WriteString(line); err != nil {
		return err
	}
	return journal.Sync()
}

// journalDone retires a journal entry once its write-back happened (or
// nothing is left to write back), so a rerun does not replay it.
func journalDone(journal *os.File, id string) error {
	if _, err := journal.WriteString(id + " done\n"); err != nil {
		return err
	}
	return journal.Sync()
}

// journaled is one un-retired journal entry: the timeout to put back and
// when the row was flipped.
type journaled struct {
	orig             *int32
	since            time.Time
	fromHost, toHost string
	tmp              int32
	generation       int64
}

// pendingJournal returns the rows whose journaled timeout has not been
// retired: a run that ended after flipping them owes them a write-back.
func pendingJournal(journal *os.File) (map[string]journaled, error) {
	if _, err := journal.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(journal)
	if err != nil {
		return nil, err
	}
	pending := map[string]journaled{}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[1] == "done" {
			delete(pending, f[0])
			continue
		}
		if len(f) != 7 {
			continue
		}
		at, err := strconv.ParseInt(f[2], 10, 64)
		if err != nil {
			continue
		}
		tmp, err := strconv.ParseInt(f[5], 10, 32)
		if err != nil {
			continue
		}
		gen, err := strconv.ParseInt(f[6], 10, 64)
		if err != nil {
			continue
		}
		entry := journaled{since: time.Unix(at, 0), fromHost: f[3], toHost: f[4], tmp: int32(tmp), generation: gen}
		if f[1] != "none" {
			n, err := strconv.ParseInt(f[1], 10, 32)
			if err != nil {
				continue
			}
			v := int32(n)
			entry.orig = &v
		}
		pending[f[0]] = entry
	}
	return pending, nil
}

// billedDuring sums the compute billing intervals that opened on a
// sandbox after it was claimed here and had closed by the time its pause
// was observed; nonzero means the reaper's retry path reopened billing on
// an operator-owned boot. An owner's own session after that pause is
// still open, or closed later, and is not counted.
func billedDuring(ctx context.Context, conn *pgxpool.Pool, id string, since, until time.Time) (float64, error) {
	var secs float64
	err := conn.QueryRow(ctx, `SELECT COALESCE(SUM(EXTRACT(EPOCH FROM ended_at - started_at)), 0)
		FROM sandbox_compute_billing_interval
		WHERE sandbox_id = $1 AND started_at >= $2 AND ended_at IS NOT NULL AND ended_at <= $3`, id, since, until).Scan(&secs)
	return secs, err
}

// endpointIsHost checks that a vmd endpoint is the host a row describes:
// a loopback or unspecified endpoint must be on a machine that holds the
// row's address, any other endpoint must be that address.
func endpointIsHost(endpoint, rowAddr string) error {
	rowHost, _, err := net.SplitHostPort(rowAddr)
	if err != nil {
		return fmt.Errorf("host row address: %w", err)
	}
	epHost, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return fmt.Errorf("endpoint: %w", err)
	}
	if ip := net.ParseIP(epHost); epHost == "" || epHost == "localhost" || (ip != nil && (ip.IsLoopback() || ip.IsUnspecified())) {
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			return err
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.String() == rowHost {
				return nil
			}
		}
		return fmt.Errorf("this machine does not hold %s", rowHost)
	}
	if epHost != rowHost {
		return fmt.Errorf("endpoint names %s", epHost)
	}
	return nil
}

// egressRules is the row's persisted network_config, in the shape vmd
// applies.
type egressRules struct {
	allowedCIDRs, deniedCIDRs, allowedDomains []string
}

func parseEgressRules(raw []byte) (egressRules, error) {
	var r egressRules
	if len(raw) == 0 {
		return r, nil
	}
	var cfg struct {
		Egress struct {
			AllowedCIDRs   []string `json:"allowed_cidrs"`
			DeniedCIDRs    []string `json:"denied_cidrs"`
			AllowedDomains []string `json:"allowed_domains"`
		} `json:"egress"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return r, err
	}
	r.allowedCIDRs, r.deniedCIDRs, r.allowedDomains = cfg.Egress.AllowedCIDRs, cfg.Egress.DeniedCIDRs, cfg.Egress.AllowedDomains
	return r, nil
}

// restoredDisk reads a host restore's completion marker for one sandbox
// and locates what ReviveVM needs: the rootfs, and either the base it was
// materialized against or the fact that it stands alone (a generation
// uploaded as a full image has no base dependency).
type restored struct {
	disk, base string
	standalone bool
	manifest   backup.GenerationManifest
}

func restoredDisk(root, id string) (restored, error) {
	var r restored
	dir := filepath.Join(root, id)
	marker := filepath.Join(dir, backup.ManifestObject)
	raw, err := os.ReadFile(marker)
	if err != nil {
		return r, fmt.Errorf("not restored")
	}
	if err := json.Unmarshal(raw, &r.manifest); err != nil {
		return r, fmt.Errorf("restore marker: %w", err)
	}
	for _, f := range r.manifest.Files {
		if f.Name != "rootfs.ext4" {
			continue
		}
		r.disk = filepath.Join(dir, f.Name)
		if _, err := os.Stat(r.disk); err != nil {
			return r, fmt.Errorf("restored without a rootfs")
		}
		if f.BaseSHA256 == "" {
			r.standalone = true
			return r, nil
		}
		r.base = filepath.Join(dir, backup.SharedBaseName(f.BaseSHA256))
		if _, err := os.Stat(r.base); err != nil {
			return r, fmt.Errorf("restored without its base %s", f.BaseSHA256)
		}
		return r, nil
	}
	return r, fmt.Errorf("restore marker lists no rootfs")
}

// current reports whether the restored generation is the sandbox's
// current pause: every digest the control plane recorded for the row's
// snapshot appears in it. A snapshot with no recorded digests cannot be
// matched to a generation at all (manifests carry no capture time, and
// the local marker's time says only when the copy landed), so such a
// sandbox is not booted. A stale copy is removed so the next host restore
// replaces it; the sandbox itself stays eligible.
func (r restored) current(recorded map[string]string) bool {
	if len(recorded) == 0 {
		return false
	}
	have := map[string]string{}
	for _, f := range r.manifest.Files {
		have[f.Name] = f.SHA256
	}
	for name, sha := range recorded {
		if have[name] != sha {
			return false
		}
	}
	return true
}

func loadSkipSet(path string) map[string]bool {
	skip := map[string]bool{}
	data, err := os.ReadFile(path)
	if err != nil {
		return skip
	}
	for _, line := range strings.Split(string(data), "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			skip[f[0]] = true
		}
	}
	return skip
}
