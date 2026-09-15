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
// A short temporary timeout is set on the flip and cleared once the row
// is paused again; rows that already had one keep it. No active interval
// is opened for the boot: it is not the owner's usage and must not bill,
// and without one the reaper treats the row as long expired and pauses
// it on its next tick, which is the intent.
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
// so a rerun does not retry them; rows the reconciler failed after a boot
// are reverted to the source host.
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
		if _, _, err := restoredDisk(*root, id); err != nil {
			notRestored++
			continue
		}
		queue = append(queue, id)
	}
	rows.Close()
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
		since      time.Time
		hadTimeout bool
	}
	active := map[string]live{} // booted here, waiting for the reaper
	moved, failed, stuck := 0, 0, 0
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
	// Rows flipped here whose VM the reconciler then failed go back where
	// they were, including the timeout they had (none, for most).
	revert := func(ids, hadNoTimeout []string) {
		if len(ids) == 0 {
			return
		}
		if _, err := conn.Exec(ctx, `UPDATE sandbox SET host_id = $1, status = 'paused',
				timeout_seconds = CASE WHEN id = ANY($4::uuid[]) THEN NULL ELSE timeout_seconds END, updated_at = now()
			WHERE id = ANY($2::uuid[]) AND host_id = $3 AND status IN ('active', 'failed')`, *fromHost, ids, *toHost, hadNoTimeout); err != nil {
			fmt.Printf("WARN revert of %d rows failed: %v; they are pinned to %s\n", len(ids), err, *toHost)
		}
	}

	started := time.Now()
	for len(queue) > 0 || len(active) > 0 {
		// Settle what the reaper finished: paused rows are done (their
		// temporary timeout cleared), failed rows are reverted, and a row
		// active past the wait is reported and left alone for a human.
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
			var clear []string
			for _, id := range paused {
				if !active[id].hadTimeout {
					clear = append(clear, id)
				}
				delete(active, id)
				moved++
				fmt.Printf("MOVED %s\n", id)
			}
			if len(clear) > 0 {
				if _, err := conn.Exec(ctx, `UPDATE sandbox SET timeout_seconds = NULL, updated_at = now()
					WHERE id = ANY($1::uuid[]) AND status = 'paused' AND timeout_seconds = $2`, clear, int32(*tmpTimeout)); err != nil {
					fmt.Printf("WARN clearing the temporary timeout on %d rows failed: %v\n", len(clear), err)
				}
			}
			var goneNoTimeout []string
			for _, id := range gone {
				if !active[id].hadTimeout {
					goneNoTimeout = append(goneNoTimeout, id)
				}
				delete(active, id)
				recordFailure(id, "row failed after boot; reverted to the source host")
			}
			revert(gone, goneNoTimeout)
			for id, l := range active {
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
				vcpu, mem  int32
				team       string
				hadTimeout bool
				rules      egressRules
			}
			shapes := map[string]shape{}
			sq, err := conn.Query(ctx, `SELECT id::text, vcpu_count, memory_mib, team_id::text, timeout_seconds IS NOT NULL, network_config
				FROM sandbox WHERE id = ANY($1::uuid[]) AND host_id = $2 AND status = 'paused' AND destroyed_at IS NULL`, batch, *fromHost)
			if err != nil {
				fmt.Fprintf(os.Stderr, "migrate: shapes: %v\n", err)
				return 1
			}
			for sq.Next() {
				var id string
				var s shape
				var raw []byte
				if err := sq.Scan(&id, &s.vcpu, &s.mem, &s.team, &s.hadTimeout, &raw); err != nil {
					sq.Close()
					fmt.Fprintf(os.Stderr, "migrate: shapes: %v\n", err)
					return 1
				}
				if s.rules, err = parseEgressRules(raw); err != nil {
					recordFailure(id, "network_config: "+err.Error())
					continue
				}
				shapes[id] = s
			}
			sq.Close()
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
				disk, base, err := restoredDisk(*root, id)
				if err != nil {
					mu.Lock()
					recordFailure(id, err.Error())
					mu.Unlock()
					continue
				}
				wg.Add(1)
				sem <- struct{}{}
				go func(id string, s shape) {
					defer wg.Done()
					defer func() { <-sem }()
					rctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
					_, err := vmd.ReviveVM(rctx, &vmdpb.ReviveVMRequest{
						VmId: id, DiskPath: disk, BasePath: base, AllowRecordless: true,
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
							timeout_seconds = COALESCE(timeout_seconds, $2), updated_at = now()
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
					active[id] = live{since: time.Now(), hadTimeout: s.hadTimeout}
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
	fmt.Printf("migrate complete: moved=%d failed=%d stuck=%d in %s\n", moved, failed, stuck, time.Since(started).Round(time.Second))
	if failed+stuck > 0 {
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

// restoredDisk locates a host restore's output for one sandbox: the
// overlay and the base it was materialized against. Both must be present;
// an overlay without its base boots a filesystem full of holes.
func restoredDisk(root, id string) (disk, base string, err error) {
	dir := filepath.Join(root, id)
	if _, err := os.Stat(filepath.Join(dir, "manifest.json")); err != nil {
		return "", "", fmt.Errorf("not restored")
	}
	disk = filepath.Join(dir, "rootfs.ext4")
	if _, err := os.Stat(disk); err != nil {
		return "", "", fmt.Errorf("restored without a rootfs")
	}
	bases, _ := filepath.Glob(filepath.Join(dir, "base-*.ext4"))
	if len(bases) != 1 {
		return "", "", fmt.Errorf("expected one base image, found %d", len(bases))
	}
	return disk, bases[0], nil
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
