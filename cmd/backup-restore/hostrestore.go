package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/superserve-ai/sandbox/internal/backup"
)

// runHostRestore is the bulk DR entry point: enumerate every sandbox the
// control plane says lived on a host, then restore each one's newest
// completed generation with bounded concurrency. Default is a dry run
// that produces the coverage ledger (restorable vs uncovered) without
// touching disk; -execute materializes.
//
// Enumeration comes from the DB when -db-url (or DATABASE_URL) is set,
// or from -sandboxes-file (one id per line) when the DB is unreachable,
// which in a real DR may be exactly the situation.
func runHostRestore(ctx context.Context, reader backup.BlobReader, lister backup.BlobLister,
	hostID, dbURL, itemsFile, destRoot string, concurrency int, execute bool) int {
	var ids []string
	wantSHAs := map[string][]string{}
	var err error
	switch {
	case itemsFile != "":
		ids, wantSHAs, err = sandboxIDsFromFile(itemsFile)
	case dbURL != "":
		ids, wantSHAs, err = sandboxIDsFromDB(ctx, dbURL, hostID)
	default:
		fmt.Fprintln(os.Stderr, "host restore needs -db-url (or DATABASE_URL) or -sandboxes-file")
		return 2
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "enumerate sandboxes: %v\n", err)
		return 1
	}
	if len(ids) == 0 {
		fmt.Println("nothing to restore: no live sandboxes recorded for this host")
		return 0
	}

	if err := os.MkdirAll(destRoot, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "create dest root: %v\n", err)
		return 1
	}
	items := make([]backup.HostRestoreItem, 0, len(ids))
	for _, id := range ids {
		items = append(items, backup.HostRestoreItem{
			SandboxID:       id,
			Dest:            filepath.Join(destRoot, id),
			WantVMStateSHAs: wantSHAs[id],
		})
	}
	mode := "dry-run"
	if execute {
		mode = "execute"
	}
	fmt.Printf("host restore (%s): %d sandboxes from host %s, concurrency %d\n", mode, len(items), hostID, concurrency)

	// Shared template bases spool to a local cache once instead of
	// streaming per sandbox.
	cache := &backup.CachingBaseReader{Inner: reader, Dir: filepath.Join(destRoot, ".base-cache")}
	restorer := &backup.HostRestorer{
		Reader:      cache,
		Lister:      lister,
		Concurrency: concurrency,
		DryRun:      !execute,
		Progress: func(r backup.HostRestoreResult) {
			switch r.Outcome {
			case backup.HostRestoreRestored:
				fmt.Printf("  restored  %s gen %.12s in %s\n", r.SandboxID, r.Generation, r.Duration.Round(time.Millisecond))
			case backup.HostRestoreCoverable:
				fmt.Printf("  coverable %s gen %.12s\n", r.SandboxID, r.Generation)
			case backup.HostRestoreUncovered:
				fmt.Printf("  UNCOVERED %s (%s)\n", r.SandboxID, r.Reason)
			default:
				fmt.Printf("  FAILED    %s: %s\n", r.SandboxID, r.Reason)
			}
		},
	}
	report := restorer.Run(ctx, items)

	fmt.Printf("\nrestored %d, coverable %d, uncovered %d, failed %d in %s\n",
		report.Restored, report.Coverable, report.Uncovered, report.Failed, report.Elapsed.Round(time.Second))
	// The machine-readable ledger is the artifact the runbook's
	// partial-failure playbook consumes: uncovered owners are the
	// customers to notify, failed ones are the retries.
	ledger, err := json.MarshalIndent(report, "", "  ")
	if err == nil {
		path := filepath.Join(destRoot, fmt.Sprintf("host-restore-report-%s.json", time.Now().UTC().Format("20060102T150405Z")))
		if werr := os.WriteFile(path, ledger, 0o600); werr == nil {
			fmt.Printf("ledger: %s\n", path)
		} else {
			fmt.Fprintf(os.Stderr, "ledger write failed (%v); printing instead:\n%s\n", werr, ledger)
		}
	}
	if report.Failed > 0 {
		return 1
	}
	return 0
}

// sandboxIDsFromDB enumerates live sandboxes the control plane pins to
// the host. Destroyed sandboxes are excluded (their backups follow the
// retention policy, not DR), as is anything never assigned here.
func sandboxIDsFromDB(ctx context.Context, dbURL, hostID string) ([]string, map[string][]string, error) {
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		return nil, nil, fmt.Errorf("connect: %w", err)
	}
	defer conn.Close(ctx)
	// Pause vmstate digests in capture order (newest first) anchor
	// generation selection to capture order rather than
	// upload-completion order, as deep as the control plane's snapshot
	// history goes.
	rows, err := conn.Query(ctx, `
		SELECT sb.id,
		       COALESCE(ARRAY(SELECT am.sha256 FROM artifact_manifest am
		         JOIN snapshot s ON s.id = am.snapshot_id
		         WHERE s.sandbox_id = sb.id AND am.file_name = 'vmstate.snap'
		         ORDER BY s.generation DESC), '{}')
		FROM sandbox sb WHERE sb.host_id = $1 AND sb.destroyed_at IS NULL ORDER BY sb.id`, hostID)
	if err != nil {
		return nil, nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()
	var ids []string
	shas := map[string][]string{}
	for rows.Next() {
		var id string
		var list []string
		if err := rows.Scan(&id, &list); err != nil {
			return nil, nil, err
		}
		ids = append(ids, id)
		if len(list) > 0 {
			shas[id] = list
		}
	}
	return ids, shas, rows.Err()
}

// sandboxIDsFromFile reads one sandbox per line: the id, optionally
// followed by whitespace and the latest pause's vmstate sha256 so
// file-based recovery keeps the capture-order anchor (export both
// columns from a DB replica when the primary is down). Without the
// digest, selection degrades to newest-completed, exactly as recorded
// in the ledger.
func sandboxIDsFromFile(path string) ([]string, map[string][]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	var ids []string
	shas := map[string][]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		ids = append(ids, fields[0])
		if len(fields) > 1 {
			shas[fields[0]] = fields[1:]
		}
	}
	return ids, shas, sc.Err()
}
