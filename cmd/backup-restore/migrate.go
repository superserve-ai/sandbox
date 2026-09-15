package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
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
// The ordering is dictated by vmd's reconciler, which stops a running VM
// whose row does not point at this host and fails an active row whose VM
// is absent, each after a short grace. The row therefore flips first and
// the boot follows within seconds, and the number of sandboxes in flight
// stays bounded so every boot lands inside the grace.
//
// Nothing on the host pauses an idle VM by itself: the reaper pauses
// active rows whose timeout has elapsed, and most rows carry no timeout.
// A short temporary timeout is set on the flip and cleared once the row
// is paused again; rows that already had one keep it.
//
// Operator tool, run on the destination host next to vmd with the same
// database credentials vmd uses. Sandboxes that fail to boot are reverted
// to the source host and recorded so a rerun does not retry them.
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
	conn, err := pgx.Connect(ctx, *dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate: connect: %v\n", err)
		return 1
	}
	defer conn.Close(ctx)

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
	// Rows we flipped but could not boot go back where they were; the
	// reconciler may already have failed them, so both states revert.
	revert := func(ids []string) {
		if len(ids) == 0 {
			return
		}
		if _, err := conn.Exec(ctx, `UPDATE sandbox SET host_id = $1, status = 'paused', updated_at = now()
			WHERE id = ANY($2::uuid[]) AND host_id = $3 AND status IN ('active', 'failed')`, *fromHost, ids, *toHost); err != nil {
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
			for _, id := range gone {
				delete(active, id)
				recordFailure(id, "row failed after boot; reverted to the source host")
			}
			revert(gone)
			for id, l := range active {
				if time.Since(l.since) > *pauseWait {
					delete(active, id)
					stuck++
					fmt.Printf("STUCK %s: still active after %s; pause it by hand\n", id, pauseWait)
				}
			}
		}

		// Fill up to the in-flight bound: flip the rows in one statement,
		// then boot exactly what the statement returned.
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
			}
			shapes := map[string]shape{}
			fl, err := conn.Query(ctx, `WITH before AS (
					SELECT id, timeout_seconds IS NOT NULL AS had_timeout FROM sandbox
					WHERE id = ANY($3::uuid[]) AND host_id = $4 AND status = 'paused' AND destroyed_at IS NULL
					FOR UPDATE)
				UPDATE sandbox s SET host_id = $1, status = 'active',
					timeout_seconds = COALESCE(s.timeout_seconds, $2), updated_at = now()
				FROM before WHERE s.id = before.id
				RETURNING s.id::text, s.vcpu_count, s.memory_mib, s.team_id::text, before.had_timeout`,
				*toHost, int32(*tmpTimeout), batch, *fromHost)
			if err != nil {
				fmt.Fprintf(os.Stderr, "migrate: flip: %v\n", err)
				return 1
			}
			for fl.Next() {
				var id string
				var s shape
				if err := fl.Scan(&id, &s.vcpu, &s.mem, &s.team, &s.hadTimeout); err != nil {
					fl.Close()
					fmt.Fprintf(os.Stderr, "migrate: flip: %v\n", err)
					return 1
				}
				shapes[id] = s
			}
			fl.Close()
			for _, id := range batch {
				if _, ok := shapes[id]; !ok {
					fmt.Printf("SKIP %s: no longer paused on %s\n", id, *fromHost)
				}
			}

			var mu sync.Mutex
			var wg sync.WaitGroup
			sem := make(chan struct{}, *concurrency)
			var bad []string
			for id, s := range shapes {
				disk, base, err := restoredDisk(*root, id)
				if err != nil {
					bad = append(bad, id)
					recordFailure(id, err.Error())
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
					})
					cancel()
					mu.Lock()
					defer mu.Unlock()
					if err != nil {
						bad = append(bad, id)
						recordFailure(id, err.Error())
						return
					}
					active[id] = live{since: time.Now(), hadTimeout: s.hadTimeout}
				}(id, s)
			}
			wg.Wait()
			revert(bad)
			fmt.Printf("booted %d, in flight %d, queued %d, moved %d, failed %d, %s elapsed\n",
				len(shapes)-len(bad), len(active), len(queue), moved, failed, time.Since(started).Round(time.Second))
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
