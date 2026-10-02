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
	anchors := map[string][]backup.CaptureAnchor{}
	var err error
	switch {
	case itemsFile != "":
		ids, anchors, err = sandboxIDsFromFile(itemsFile)
	case dbURL != "":
		ids, anchors, err = sandboxIDsFromDB(ctx, dbURL, hostID)
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
			SandboxID: id,
			Dest:      filepath.Join(destRoot, id),
			Anchors:   anchors[id],
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
func sandboxIDsFromDB(ctx context.Context, dbURL, hostID string) ([]string, map[string][]backup.CaptureAnchor, error) {
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		return nil, nil, fmt.Errorf("connect: %w", err)
	}
	defer conn.Close(ctx)
	// Each pause's recorded digest set, in capture order (newest
	// first), anchors generation selection to capture order rather than
	// upload-completion order, as deep as the control plane's snapshot
	// history goes. Today pause-time manifests record vmstate only
	// (hashing left the pause path), so these anchors are single-digest
	// until the async worker's manifest write-back populates the full
	// set; the grouping is per snapshot generation so richer rows bind
	// automatically as they appear, and the residual vmstate-collision
	// ambiguity until then is a recovery-point nuance the ledger's
	// generation column makes auditable.
	// A mistyped or foreign-cell host id must not read as a clean empty
	// restore: verify the host row exists before enumerating, so "host
	// unknown" and "host has no sandboxes" stay distinguishable.
	var hostStatus string
	err = conn.QueryRow(ctx, `SELECT status FROM host WHERE id = $1`, hostID).Scan(&hostStatus)
	if err == pgx.ErrNoRows {
		return nil, nil, fmt.Errorf("host %q is not in this cell's host table; check the id and the cell", hostID)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("verify host: %w", err)
	}
	// An active host is still taking placements, so the one-time
	// inventory below would silently miss sandboxes assigned after the
	// query and report an incomplete ledger as complete. The runbook's
	// freeze comes first; enumeration refuses to proceed without it.
	if hostStatus == "active" {
		return nil, nil, fmt.Errorf("host %q is still active and taking placements; freeze it (unhealthy or draining) before enumerating", hostID)
	}
	rows, err := conn.Query(ctx, `
		SELECT sb.id, COALESCE((
		  SELECT json_agg(sd.digests ORDER BY sd.gen DESC)
		  FROM (
		    SELECT s.generation AS gen, json_object_agg(am.file_name, am.sha256) AS digests
		    FROM snapshot s JOIN artifact_manifest am ON am.snapshot_id = s.id
		    WHERE s.sandbox_id = sb.id
		    GROUP BY s.generation
		  ) sd), '[]')::text
		FROM sandbox sb WHERE sb.host_id = $1 AND sb.destroyed_at IS NULL ORDER BY sb.id`, hostID)
	if err != nil {
		return nil, nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()
	var ids []string
	anchors := map[string][]backup.CaptureAnchor{}
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			return nil, nil, err
		}
		ids = append(ids, id)
		var list []backup.CaptureAnchor
		if err := json.Unmarshal([]byte(raw), &list); err != nil {
			return nil, nil, fmt.Errorf("parse anchors for %s: %w", id, err)
		}
		if len(list) > 0 {
			anchors[id] = list
		}
	}
	return ids, anchors, rows.Err()
}

// sandboxIDsFromFile reads one sandbox per line: the id, optionally
// followed by whitespace and the latest pause's vmstate sha256 so
// file-based recovery keeps the capture-order anchor (export both
// columns from a DB replica when the primary is down). Without the
// digest, selection degrades to newest-completed, exactly as recorded
// in the ledger.
func sandboxIDsFromFile(path string) ([]string, map[string][]backup.CaptureAnchor, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	var ids []string
	anchors := map[string][]backup.CaptureAnchor{}
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		// Duplicates fail the whole file up front: two entries for one
		// sandbox (a concatenated pair of replica exports) would race
		// two restores at one destination under concurrency.
		if seen[fields[0]] {
			return nil, nil, fmt.Errorf("duplicate sandbox id %s in %s; deduplicate the export", fields[0], path)
		}
		seen[fields[0]] = true
		ids = append(ids, fields[0])
		// Anchors separate by commas, one per pause (newest first);
		// within an anchor, name=sha tokens bind multiple files of the
		// SAME pause into one digest set, and a bare digest means
		// vmstate (the exportable shape). Splitting same-pause tokens
		// into separate anchors would misrank a vmstate-only match of a
		// newer pause above the richer set it belongs to.
		for _, tok := range fields[1:] {
			a := backup.CaptureAnchor{}
			for _, part := range strings.Split(tok, ",") {
				name, sha, ok := strings.Cut(part, "=")
				if !ok {
					name, sha = "vmstate.snap", part
				}
				if sha == "" {
					// A provided-but-empty digest (a nullable replica
					// column leaking through) must not silently drop the
					// anchor and degrade selection to completion order.
					return nil, nil, fmt.Errorf("sandbox %s: empty digest in anchor token %q", fields[0], tok)
				}
				// A malformed digest can never match a manifest, and an
				// unmatchable anchor silently degrades selection to
				// newest-completed: fail the file instead, since a
				// truncated sha or a stray export prefix is operator
				// input worth stopping on.
				if !isHexDigest(sha) {
					return nil, nil, fmt.Errorf("sandbox %s: %q is not a 64-hex sha256 digest", fields[0], sha)
				}
				// Manifest entries are leaf filenames; an empty or
				// path-shaped name can never match one and would silently
				// unanchor the sandbox.
				if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\") {
					return nil, nil, fmt.Errorf("sandbox %s: %q is not a valid artifact name in anchor token %q", fields[0], name, tok)
				}
				// The completion marker is reserved: no valid manifest
				// lists it, so an anchor naming it can never match and
				// would silently unanchor the sandbox.
				if name == backup.ManifestObject {
					return nil, nil, fmt.Errorf("sandbox %s: %q is a reserved name, not an artifact, in anchor token %q", fields[0], name, tok)
				}
				// A repeated name silently keeps only the last digest,
				// and a malformed export that pastes two pauses into one
				// anchor could then match the wrong generation.
				if _, dup := a[name]; dup {
					return nil, nil, fmt.Errorf("sandbox %s: duplicate artifact %q within one anchor", fields[0], name)
				}
				a[name] = sha
			}
			if len(a) > 0 {
				anchors[fields[0]] = append(anchors[fields[0]], a)
			}
		}
	}
	return ids, anchors, sc.Err()
}

// isHexDigest reports whether s is a 64-character lowercase hex sha256.
func isHexDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
