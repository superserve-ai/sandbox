package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/superserve-ai/sandbox/internal/backup"
	"github.com/superserve-ai/sandbox/internal/preview"
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
// so the owner cannot start a second copy beside the boot; a request of
// theirs waits for the flip. The restored disk is then booted, and the row
// is activated with the fresh address as soon as the RPC returns, inside
// the grace vmd's reconciler gives a running VM without an active row. A
// boot that fails hands the claim back to the source, paused as it was.
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
	err = conn.QueryRow(ctx, `SELECT EXTRACT(EPOCH FROM now() - last_heartbeat_at) FROM host WHERE id = $1`, *toHost).Scan(&age)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate: destination host %q: %v\n", *toHost, err)
		return 1
	}
	if age > 120 {
		fmt.Fprintf(os.Stderr, "migrate: destination host %q has no heartbeat for %.0fs; use the id vmd registers under\n", *toHost, age)
		return 1
	}
	var srcStatus string
	if err := conn.QueryRow(ctx, `SELECT status FROM host WHERE id = $1`, *fromHost).Scan(&srcStatus); err != nil {
		fmt.Fprintf(os.Stderr, "migrate: source host %q: %v\n", *fromHost, err)
		return 1
	}

	skip := loadSkipSet(filepath.Join(*root, "migrate-failed.txt"))
	journal, err := os.OpenFile(filepath.Join(*root, "migrate-timeouts.txt"), os.O_APPEND|os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate: timeout journal: %v\n", err)
		return 1
	}
	defer journal.Close()
	pending, err := pendingJournal(journal)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate: timeout journal: %v\n", err)
		return 1
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
		snapshotID  string // the pause the row had at the claim; a new one means the migration pause completed
		restores    int    // write-back attempts so far
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
		pr, err := conn.Query(ctx, `SELECT id::text, status::text, host_id, timeout_seconds FROM sandbox WHERE id = ANY($1::uuid[])`, ids)
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
				active[id] = live{since: pending[id].since, origTimeout: pending[id].orig, snapshotID: pending[id].snapshotID}
			case host == *toHost && status == "migrating":
				// Claimed but never activated. The earlier run may have got
				// as far as booting, so the guest is stopped here first; only
				// then is the row resumable on the source again.
				dctx, dcancel := context.WithTimeout(ctx, time.Minute)
				_, derr := vmd.DestroyVM(dctx, &vmdpb.DestroyVMRequest{VmId: id, Force: true})
				dcancel()
				if derr != nil {
					fmt.Fprintf(os.Stderr, "migrate: journal recovery: %s: stopping the booted guest: %v\n", id, derr)
					return 1
				}
				if _, err := conn.Exec(ctx, `UPDATE sandbox SET host_id = $1, status = 'paused', updated_at = now()
					WHERE id = $2 AND host_id = $3 AND status = 'migrating'`, *fromHost, id, *toHost); err != nil {
					fmt.Fprintf(os.Stderr, "migrate: journal recovery: %v\n", err)
					return 1
				}
				if err := journalDone(journal, id); err != nil {
					fmt.Fprintf(os.Stderr, "migrate: journal: %v\n", err)
					return 1
				}
			case host == *toHost && timeout != nil && *timeout == int32(*tmpTimeout):
				active[id] = live{since: pending[id].since, origTimeout: pending[id].orig, snapshotID: pending[id].snapshotID, restores: 1}
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
	started := time.Now()
	for len(queue) > 0 || len(active) > 0 {
		// Settle what the reaper finished: paused rows are done (their
		// temporary timeout cleared); failed rows and rows active past the
		// wait are reported and left for a human.
		if len(active) > 0 {
			ids := make([]string, 0, len(active))
			for id := range active {
				ids = append(ids, id)
			}
			st, err := conn.Query(ctx, `SELECT id::text, status::text, COALESCE(snapshot_id::text, '') FROM sandbox WHERE id = ANY($1::uuid[])`, ids)
			if err != nil {
				fmt.Fprintf(os.Stderr, "migrate: poll: %v\n", err)
				return 1
			}
			var paused, gone []string
			for st.Next() {
				var id, status, snap string
				if err := st.Scan(&id, &status, &snap); err != nil {
					st.Close()
					fmt.Fprintf(os.Stderr, "migrate: poll: %v\n", err)
					return 1
				}
				switch {
				case status == "failed":
					gone = append(gone, id)
				case status == "paused", snap != "" && snap != active[id].snapshotID:
					// Paused here, or paused and already resumed by the
					// owner between polls: the migration pause completed
					// either way and the timeout goes back now.
					paused = append(paused, id)
				}
			}
			st.Close()
			if err := st.Err(); err != nil {
				fmt.Fprintf(os.Stderr, "migrate: poll: %v\n", err)
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
				// pending and are polled again.
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
					if secs, ierr := billedDuring(ctx, conn, id, active[id].since); ierr != nil {
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
			for id, l := range active {
				if l.restores > 0 {
					continue // paused; only the write-back is outstanding
				}
				if time.Since(l.since) > *pauseWait {
					delete(active, id)
					stuck++
					fmt.Printf("STUCK %s: still active after %s; pause it by hand\n", id, pauseWait)
				}
			}
		}

		// Fill up to the in-flight bound: read each row's shape and egress
		// rules, boot, and flip the row the moment its VM is up.
		if n := *inflight - len(active); n > 0 && len(queue) > 0 {
			if n > len(queue) {
				n = len(queue)
			}
			batch := queue[:n]
			queue = queue[n:]
			type shape struct {
				vcpu, mem   int32
				team        string
				origTimeout *int32
				rules       egressRules
				recorded    map[string]string
				snapshotID  *string
			}
			shapes := map[string]shape{}
			sq, err := conn.Query(ctx, `SELECT s.id::text, s.vcpu_count, s.memory_mib, s.team_id::text, s.timeout_seconds, s.network_config,
					COALESCE((SELECT json_object_agg(am.file_name, am.sha256) FROM artifact_manifest am WHERE am.snapshot_id = s.snapshot_id), '{}')::text,
					s.snapshot_id::text
				FROM sandbox s WHERE s.id = ANY($1::uuid[]) AND s.host_id = $2 AND s.status = 'paused' AND s.destroyed_at IS NULL`, batch, *fromHost)
			if err != nil {
				fmt.Fprintf(os.Stderr, "migrate: shapes: %v\n", err)
				return 1
			}
			for sq.Next() {
				var id, recorded string
				var s shape
				var raw []byte
				if err := sq.Scan(&id, &s.vcpu, &s.mem, &s.team, &s.origTimeout, &raw, &recorded, &s.snapshotID); err != nil {
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

			var mu sync.Mutex
			var wg sync.WaitGroup
			sem := make(chan struct{}, *concurrency)
			booted := 0
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
				disk, base, standalone := rd.disk, rd.base, rd.standalone
				wg.Add(1)
				sem <- struct{}{}
				go func(id string, s shape) {
					defer wg.Done()
					defer func() { <-sem }()
					// Claim first: the row moves to this host as 'migrating',
					// fenced on the snapshot whose digests were checked and on
					// the timeout that was journaled. Resume takes only paused
					// rows, so from here the owner cannot start a second copy
					// next to the boot; their request waits for the flip.
					// The original timeout reaches the journal before the
					// claim so a run that dies afterwards can still put it
					// back.
					claimedAt := time.Now()
					mu.Lock()
					err := journalTimeout(journal, id, s.origTimeout, claimedAt, *fromHost, *toHost, int32(*tmpTimeout), *s.snapshotID)
					mu.Unlock()
					if err != nil {
						mu.Lock()
						recordFailure(id, err.Error())
						mu.Unlock()
						return
					}
					tag, err := conn.Exec(ctx, `UPDATE sandbox SET host_id = $1, status = 'migrating', updated_at = now()
						WHERE id = $2 AND host_id = $3 AND status = 'paused' AND destroyed_at IS NULL AND snapshot_id = $4
							AND timeout_seconds IS NOT DISTINCT FROM $5`,
						*toHost, id, *fromHost, *s.snapshotID, s.origTimeout)
					if err == nil && tag.RowsAffected() == 0 {
						err = fmt.Errorf("changed on %s since it was read", *fromHost)
					}
					if err != nil {
						// Nothing was claimed: the row moved on or the database
						// hiccuped. Either way a later run may succeed, so this
						// is not written to the skip file.
						mu.Lock()
						recordRetry(id, err.Error())
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
					if err == nil {
						// vmd does not persist the preview policy either; a
						// recordless boot starts private with no published
						// ports. The policy is read again now, after the record
						// exists, so an owner's change during the boot (whose
						// push found no record here) is what gets installed;
						// then it is pushed before the row is exposed, exactly
						// as a resume does.
						var policy previewPolicy
						if policy, err = loadPreviewPolicy(ctx, conn, id); err == nil {
							pctx, pcancel := context.WithTimeout(ctx, time.Minute)
							_, err = vmd.UpdateSandboxPreviewPolicy(pctx, policy.request(id))
							pcancel()
						}
						if err != nil {
							err = fmt.Errorf("apply preview policy: %w", err)
						}
					}
					if err == nil {
						var ip netip.Addr
						if ip, err = netip.ParseAddr(resp.GetHostIp()); err == nil {
							// Fenced on the journaled timeout as well: a PATCH
							// the owner made during the boot is theirs to keep.
							// The secret-injection markers are cleared with it:
							// the cold boot holds no secrets, and a same address
							// on this host would otherwise let the next resume
							// believe the guest still does.
							tag, err = conn.Exec(ctx, `UPDATE sandbox SET status = 'active', timeout_seconds = $1, ip_address = $2,
									secret_env_fingerprint = NULL, secret_env_ip = NULL, secret_env_injected_at = NULL, secret_env_expires_at = NULL,
									updated_at = now()
								WHERE id = $3 AND host_id = $4 AND status = 'migrating' AND destroyed_at IS NULL
									AND timeout_seconds IS NOT DISTINCT FROM $5`,
								int32(*tmpTimeout), ip, id, *toHost, s.origTimeout)
							if err == nil && tag.RowsAffected() == 0 {
								err = errRetry{fmt.Errorf("claim on %s changed before activation", *toHost)}
							}
						}
					}
					if err != nil {
						// Not activated: take the VM back down before the row is
						// handed back. Unconditional, because a lost reply looks
						// like a failed RPC while the VM is up; destroying a VM
						// that never started is a no-op.
						dctx, dcancel := context.WithTimeout(ctx, time.Minute)
						if _, derr := vmd.DestroyVM(dctx, &vmdpb.DestroyVMRequest{VmId: id, Force: true}); derr != nil {
							err = fmt.Errorf("%v; and the booted VM could not be destroyed: %v", err, derr)
						}
						dcancel()
					}
					if err != nil {
						if _, rerr := conn.Exec(ctx, `UPDATE sandbox SET host_id = $1, status = 'paused', updated_at = now()
							WHERE id = $2 AND host_id = $3 AND status = 'migrating'`, *fromHost, id, *toHost); rerr != nil {
							err = fmt.Errorf("%v; and the claim could not be handed back: %v", err, rerr)
						}
						mu.Lock()
						var retry errRetry
						if errors.As(err, &retry) {
							recordRetry(id, err.Error())
						} else {
							recordFailure(id, err.Error())
						}
						if jerr := journalDone(journal, id); jerr != nil {
							fmt.Printf("WARN %s: journal not updated: %v\n", id, jerr)
						}
						mu.Unlock()
						return
					}
					mu.Lock()
					booted++
					active[id] = live{since: claimedAt, origTimeout: s.origTimeout, snapshotID: *s.snapshotID}
					mu.Unlock()
				}(id, s)
			}
			wg.Wait()
			fmt.Printf("booted %d, in flight %d, queued %d, moved %d, failed %d, %s elapsed\n",
				booted, len(active), len(queue), moved, failed, time.Since(started).Round(time.Second))
		}
		if len(active) > 0 {
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
// and temporary timeout, and the snapshot the row had, before the
// migration replaces any of it: `<id> <seconds>|none <unix> <from-host>
// <to-host> <tmp> <snapshot>`, fsynced, so a rerun can finish the row (and
// tell whether its pause already happened) and refuses to do so under
// different parameters.
func journalTimeout(journal *os.File, id string, orig *int32, at time.Time, fromHost, toHost string, tmp int32, snapshotID string) error {
	value := "none"
	if orig != nil {
		value = strconv.FormatInt(int64(*orig), 10)
	}
	line := fmt.Sprintf("%s %s %d %s %s %d %s\n", id, value, at.Unix(), fromHost, toHost, tmp, snapshotID)
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
	snapshotID       string
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
		entry := journaled{since: time.Unix(at, 0), fromHost: f[3], toHost: f[4], tmp: int32(tmp), snapshotID: f[6]}
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

// billedDuring sums the compute billing intervals opened on a sandbox
// since it was flipped here; nonzero means the reaper's retry path
// reopened billing on an operator-owned boot.
func billedDuring(ctx context.Context, conn *pgxpool.Pool, id string, since time.Time) (float64, error) {
	var secs float64
	err := conn.QueryRow(ctx, `SELECT COALESCE(SUM(EXTRACT(EPOCH FROM COALESCE(ended_at, now()) - started_at)), 0)
		FROM sandbox_compute_billing_interval WHERE sandbox_id = $1 AND started_at >= $2`, id, since).Scan(&secs)
	return secs, err
}

// previewPolicy is the row's stored preview access and published ports in
// the shape vmd applies: private ports go on the wire as the browser mode,
// and only tokenized modes carry a generation.
type previewPolicy struct {
	access   string
	revision int64
	ports    []struct {
		Port         int32  `json:"port"`
		Access       string `json:"access"`
		TokenVersion int64  `json:"token_version"`
	}
}

// loadPreviewPolicy reads the row's current preview policy: the stored
// access and revision (absent side-table row = the pre-publication
// default) and the published ports that carry a positive generation.
func loadPreviewPolicy(ctx context.Context, conn *pgxpool.Pool, id string) (previewPolicy, error) {
	var p previewPolicy
	var ports string
	err := conn.QueryRow(ctx, `SELECT COALESCE(p.access, 'legacy_public')::text, COALESCE(p.revision, 0)::bigint,
			COALESCE((SELECT json_agg(json_build_object('port', pp.port, 'access', pp.access, 'token_version', g.token_version))
				FROM sandbox_published_port pp
				JOIN sandbox_preview_port_token_generation g ON g.sandbox_id = pp.sandbox_id AND g.port = pp.port
				WHERE pp.sandbox_id = s.id AND g.token_version > 0), '[]')::text
		FROM sandbox s LEFT JOIN sandbox_preview_policy p ON p.sandbox_id = s.id WHERE s.id = $1`, id).Scan(&p.access, &p.revision, &ports)
	if err != nil {
		return p, err
	}
	return p, json.Unmarshal([]byte(ports), &p.ports)
}

func (p previewPolicy) request(id string) *vmdpb.UpdateSandboxPreviewPolicyRequest {
	req := &vmdpb.UpdateSandboxPreviewPolicyRequest{VmId: id, PreviewAccess: p.access, PolicyRevision: p.revision}
	for _, port := range p.ports {
		access := port.Access
		if access == preview.AccessPrivate {
			access = preview.AccessPrivateBrowserV1
		}
		version := port.TokenVersion
		if !preview.IsTokenizedAccess(access) {
			version = 0
		}
		req.PreviewPorts = append(req.PreviewPorts, &vmdpb.PreviewPort{Port: port.Port, Access: access, TokenVersion: version})
	}
	return req
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
