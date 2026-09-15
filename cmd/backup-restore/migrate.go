package main

import (
	"context"
	"encoding/json"
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

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
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
// The ordering follows the ReviveVM contract and vmd's reconciler: a row
// becomes active here only once its VM is running, and it does so right
// after the RPC returns, because the reconciler stops a running VM whose
// row does not point at this host after a short grace. The row is re-read
// under the flip's own WHERE clause, so a sandbox its owner resumed in the
// meantime is not moved; the VM booted for it is destroyed again.
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
		restores    int    // write-back attempts so far
	}
	active := map[string]live{} // booted here, waiting for the reaper
	moved, failed, stuck, stale, unanchored := 0, 0, 0, 0, 0
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
				// Still on its way to paused; the audit window keeps the
				// journaled flip time so nothing billed meanwhile is missed.
				active[id] = live{since: pending[id].since, origTimeout: pending[id].orig}
			case host == *toHost && timeout != nil && *timeout == int32(*tmpTimeout):
				active[id] = live{since: pending[id].since, origTimeout: pending[id].orig, restores: 1}
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
			st, err := conn.Query(ctx, `SELECT id::text, status::text FROM sandbox WHERE id = ANY($1::uuid[])`, ids)
			if err != nil {
				fmt.Fprintf(os.Stderr, "migrate: poll: %v\n", err)
				return 1
			}
			var paused, gone []string
			for st.Next() {
				var id, status string
				if err := st.Scan(&id, &status); err != nil {
					st.Close()
					fmt.Fprintf(os.Stderr, "migrate: poll: %v\n", err)
					return 1
				}
				switch status {
				case "paused":
					paused = append(paused, id)
				case "failed":
					gone = append(gone, id)
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
					rctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
					resp, err := vmd.ReviveVM(rctx, &vmdpb.ReviveVMRequest{
						VmId: id, DiskPath: disk, BasePath: base, StandaloneDisk: standalone, AllowRecordless: true,
						TeamId: s.team, Vcpu: uint32(s.vcpu), MemMib: uint32(s.mem),
						AllowedCidrs: s.rules.allowedCIDRs, DeniedCidrs: s.rules.deniedCIDRs, AllowedDomains: s.rules.allowedDomains,
					})
					cancel()
					if err != nil {
						mu.Lock()
						recordFailure(id, err.Error())
						mu.Unlock()
						return
					}
					// The VM is up; pin the row here before the reconciler's
					// grace on an unclaimed VM runs out. A row that is no
					// longer paused on the source was resumed by its owner
					// meanwhile: leave it, and take the boot back down. The
					// original timeout reaches the journal first, so a run
					// that dies after the flip can still put it back.
					flippedAt := time.Now()
					mu.Lock()
					err = journalTimeout(journal, id, s.origTimeout, flippedAt)
					mu.Unlock()
					var tag pgconn.CommandTag
					if err == nil {
						ip, perr := netip.ParseAddr(resp.GetHostIp())
						if perr != nil {
							err = fmt.Errorf("revive returned address %q: %w", resp.GetHostIp(), perr)
						} else {
							// Fenced on the snapshot whose digests were checked
							// and on the timeout that was journaled: a pause the
							// owner completed or a timeout they set during the
							// boot must not be replaced. The fresh address lands
							// with the flip so nothing routes to the old slot.
							tag, err = conn.Exec(ctx, `UPDATE sandbox SET host_id = $1, status = 'active',
									timeout_seconds = $2, ip_address = $7, updated_at = now()
								WHERE id = $3 AND host_id = $4 AND status = 'paused' AND destroyed_at IS NULL AND snapshot_id = $5
									AND timeout_seconds IS NOT DISTINCT FROM $6`,
								*toHost, int32(*tmpTimeout), id, *fromHost, *s.snapshotID, s.origTimeout, ip)
						}
					}
					if err == nil && tag.RowsAffected() == 0 {
						err = fmt.Errorf("changed on %s since it was read", *fromHost)
					}
					if err != nil {
						// Take the boot back down without holding the batch
						// lock: other workers are waiting to flip rows whose
						// VMs are already running.
						dctx, dcancel := context.WithTimeout(ctx, time.Minute)
						_, derr := vmd.DestroyVM(dctx, &vmdpb.DestroyVMRequest{VmId: id, Force: true})
						dcancel()
						if derr != nil {
							err = fmt.Errorf("%v; and the booted VM could not be destroyed: %v", err, derr)
						}
						mu.Lock()
						recordFailure(id, err.Error())
						if jerr := journalDone(journal, id); jerr != nil {
							fmt.Printf("WARN %s: journal not updated: %v\n", id, jerr)
						}
						mu.Unlock()
						return
					}
					mu.Lock()
					booted++
					active[id] = live{since: flippedAt, origTimeout: s.origTimeout}
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
	fmt.Printf("migrate complete: moved=%d failed=%d stuck=%d stale=%d unverifiable=%d in %s\n", moved, failed, stuck, stale, unanchored, time.Since(started).Round(time.Second))
	if failed+stuck+stale+unanchored > 0 {
		return 1
	}
	return 0
}

// journalTimeout records a row's timeout and the flip time before the
// migration replaces it: `<id> <seconds>|none <unix>`, fsynced, so both
// survive the process.
func journalTimeout(journal *os.File, id string, orig *int32, at time.Time) error {
	line := fmt.Sprintf("%s none %d\n", id, at.Unix())
	if orig != nil {
		line = fmt.Sprintf("%s %d %d\n", id, *orig, at.Unix())
	}
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
	orig  *int32
	since time.Time
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
		if len(f) != 3 {
			continue
		}
		at, err := strconv.ParseInt(f[2], 10, 64)
		if err != nil {
			continue
		}
		entry := journaled{since: time.Unix(at, 0)}
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
