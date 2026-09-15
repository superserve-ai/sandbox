package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

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
// pending until that write-back succeeds. No active interval
// is opened for the boot: it is not the owner's usage and must not bill,
// and without one the reaper treats the row as long expired and pauses
// it on its next tick, which is the intent.
//
// A restored copy is only booted when it is the sandbox's current pause:
// the digests the control plane recorded for the row's snapshot must all
// appear in the restored generation (or, for a snapshot with no recorded
// digests, the snapshot must predate the restore). A sandbox its owner
// resumed and paused again since the restore is skipped for a fresh one.
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
	fmt.Printf("migrate: %d paused on %s (%s); %d restored here and queued, %d not restored, %d skipped from earlier failures\n",
		len(queue)+notRestored+len(skip), *fromHost, srcStatus, len(queue), notRestored, len(skip))
	if *dryRun || len(queue) == 0 {
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
	moved, failed, stuck, stale := 0, 0, 0, 0
	failFile, _ := os.OpenFile(filepath.Join(*root, "migrate-failed.txt"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if failFile != nil {
		defer failFile.Close()
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
				_, err := conn.Exec(ctx, `UPDATE sandbox s SET timeout_seconds = v.orig, updated_at = now()
					FROM unnest($1::uuid[], $2::int[]) AS v(id, orig)
					WHERE s.id = v.id AND s.status = 'paused' AND s.timeout_seconds = $3`, paused, origs, int32(*tmpTimeout))
				for _, id := range paused {
					if err != nil {
						l := active[id]
						l.restores++
						active[id] = l
						if l.restores >= 5 {
							delete(active, id)
							recordFailure(id, fmt.Sprintf("paused here but its timeout could not be written back after %d attempts: %v", l.restores, err))
						}
						continue
					}
					delete(active, id)
					moved++
					fmt.Printf("MOVED %s\n", id)
				}
				if err != nil {
					fmt.Printf("WARN writing back the timeout on %d rows failed, retrying: %v\n", len(paused), err)
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
				snapshotAt  time.Time
			}
			shapes := map[string]shape{}
			sq, err := conn.Query(ctx, `SELECT s.id::text, s.vcpu_count, s.memory_mib, s.team_id::text, s.timeout_seconds, s.network_config,
					COALESCE((SELECT json_object_agg(am.file_name, am.sha256) FROM artifact_manifest am WHERE am.snapshot_id = s.snapshot_id), '{}')::text,
					(SELECT sn.created_at FROM snapshot sn WHERE sn.id = s.snapshot_id)
				FROM sandbox s WHERE s.id = ANY($1::uuid[]) AND s.host_id = $2 AND s.status = 'paused' AND s.destroyed_at IS NULL`, batch, *fromHost)
			if err != nil {
				fmt.Fprintf(os.Stderr, "migrate: shapes: %v\n", err)
				return 1
			}
			for sq.Next() {
				var id, recorded string
				var s shape
				var raw []byte
				var snapshotAt *time.Time
				if err := sq.Scan(&id, &s.vcpu, &s.mem, &s.team, &s.origTimeout, &raw, &recorded, &snapshotAt); err != nil {
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
				if snapshotAt != nil {
					s.snapshotAt = *snapshotAt
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
				if err == nil && !rd.current(s.recorded, s.snapshotAt) {
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
					_, err := vmd.ReviveVM(rctx, &vmdpb.ReviveVMRequest{
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
					// meanwhile: leave it, and take the boot back down.
					tag, err := conn.Exec(ctx, `UPDATE sandbox SET host_id = $1, status = 'active',
							timeout_seconds = $2, updated_at = now()
						WHERE id = $3 AND host_id = $4 AND status = 'paused' AND destroyed_at IS NULL`,
						*toHost, int32(*tmpTimeout), id, *fromHost)
					mu.Lock()
					defer mu.Unlock()
					if err == nil && tag.RowsAffected() == 0 {
						err = fmt.Errorf("no longer paused on %s", *fromHost)
					}
					if err != nil {
						dctx, dcancel := context.WithTimeout(ctx, time.Minute)
						_, derr := vmd.DestroyVM(dctx, &vmdpb.DestroyVMRequest{VmId: id, Force: true})
						dcancel()
						if derr != nil {
							err = fmt.Errorf("%v; and the booted VM could not be destroyed: %v", err, derr)
						}
						recordFailure(id, err.Error())
						return
					}
					booted++
					active[id] = live{since: time.Now(), origTimeout: s.origTimeout}
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
	fmt.Printf("migrate complete: moved=%d failed=%d stuck=%d stale=%d in %s\n", moved, failed, stuck, stale, time.Since(started).Round(time.Second))
	if failed+stuck+stale > 0 {
		return 1
	}
	return 0
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
	restoredAt time.Time // the completion marker's write time
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
	if fi, err := os.Stat(marker); err == nil {
		r.restoredAt = fi.ModTime()
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
// snapshot appears in it, or, when nothing was recorded, the snapshot was
// taken before the restore completed. A stale copy is removed so the
// next host restore replaces it; the sandbox itself stays eligible.
func (r restored) current(recorded map[string]string, snapshotAt time.Time) bool {
	if len(recorded) == 0 {
		return !snapshotAt.IsZero() && snapshotAt.Before(r.restoredAt)
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
