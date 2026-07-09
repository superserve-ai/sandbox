package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Content validation: count parity alone cannot see a source row that
// changed after a copy (background writers — billing rollups, interval
// closers — keep running through the freeze). Every migrated table is
// therefore also compared as a multiset of per-row checksums, with the copy
// transforms applied to the source side so a legitimate rewrite (host id,
// home region, role id) doesn't read as drift. Multisets, not per-PK pairs,
// so tables without a usable key compare the same way as everything else.

// checksumExclusions lists columns that legitimately differ between cells
// and carry no migration-correctness signal. updated_at is excluded
// globally below; per-table entries go here.
var checksumExclusions = map[string]map[string]bool{
	// The dest quota trigger recounts as rows land; with every sandbox
	// paused by precondition the counter is 0 on both sides, but the
	// source's value is not part of what the copy promises to preserve.
	"team": {"active_sandbox_count": true},
}

// rowChecksums returns hash → occurrence count for the team's rows of one
// table. Rows decode with UseNumber so numerics hash by their exact text,
// then re-marshal (Go sorts map keys) into a canonical form shared by both
// sides of the comparison.
func rowChecksums(
	ctx context.Context,
	pool *pgxpool.Pool,
	t tableSpec,
	teamID uuid.UUID,
	transform rowTransform,
) (map[string]int, error) {
	rows, err := pool.Query(ctx,
		fmt.Sprintf(`SELECT to_jsonb(t) FROM %s t WHERE %s`, t.name, t.effectiveCopyScope()), teamID)
	if err != nil {
		return nil, fmt.Errorf("checksum select %s: %w", t.name, err)
	}
	defer rows.Close()

	sums := map[string]int{}
	for rows.Next() {
		var raw json.RawMessage
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		h, err := checksumRow(t.name, raw, transform)
		if err != nil {
			return nil, fmt.Errorf("checksum %s: %w", t.name, err)
		}
		sums[h]++
	}
	return sums, rows.Err()
}

func checksumRow(table string, raw json.RawMessage, transform rowTransform) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var row map[string]any
	if err := dec.Decode(&row); err != nil {
		return "", err
	}
	if transform != nil {
		if err := transform(row); err != nil {
			return "", err
		}
	}
	delete(row, "updated_at")
	for col := range checksumExclusions[table] {
		delete(row, col)
	}
	canon, err := json.Marshal(row)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:]), nil
}

// diffChecksums reports how many rows on each side have no content-equal
// counterpart on the other.
func diffChecksums(src, dst map[string]int) (srcOnly, dstOnly int) {
	for h, n := range src {
		if d := n - dst[h]; d > 0 {
			srcOnly += d
		}
	}
	for h, n := range dst {
		if d := n - src[h]; d > 0 {
			dstOnly += d
		}
	}
	return srcOnly, dstOnly
}

// contentDriftUnderLock re-compares the mutation-prone tables — sandbox
// rows and secret bindings — between the locked source transaction and the
// dest, transform-aware, so purge's deletes act on exactly the rows
// validation approved. Runs on the transaction (not the pool): the FOR
// UPDATE row locks and per-sandbox advisory locks it holds are the point.
// Returns the first drifted table's name, or "".
func contentDriftUnderLock(ctx context.Context, tx pgx.Tx, dst *pgxpool.Pool, cfg config) (string, error) {
	transforms, err := buildTransforms(ctx, tx, dst, cfg)
	if err != nil {
		return "", err
	}
	copyTf := transforms["sandbox"]
	sandboxTf := func(row map[string]any) error {
		keep := row["snapshot_id"]
		if err := copyTf(row); err != nil {
			return err
		}
		row["snapshot_id"] = keep
		return nil
	}

	checks := []struct {
		spec tableSpec
		tf   rowTransform
	}{
		{tableSpec{name: "sandbox", scope: "team_id = $1"}, sandboxTf},
		{tableSpec{name: "sandbox_secret", scope: sandboxScope}, nil},
		{tableSpec{name: "secret", scope: "team_id = $1"}, nil},
	}
	for _, chk := range checks {
		srcSums := map[string]int{}
		rows, err := tx.Query(ctx,
			fmt.Sprintf(`SELECT to_jsonb(t) FROM %s t WHERE %s`, chk.spec.name, chk.spec.effectiveCopyScope()), cfg.teamID)
		if err != nil {
			return "", fmt.Errorf("locked %s read: %w", chk.spec.name, err)
		}
		for rows.Next() {
			var raw json.RawMessage
			if err := rows.Scan(&raw); err != nil {
				rows.Close()
				return "", err
			}
			h, err := checksumRow(chk.spec.name, raw, chk.tf)
			if err != nil {
				rows.Close()
				return "", err
			}
			srcSums[h]++
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return "", err
		}
		rows.Close()

		dstSums, err := rowChecksums(ctx, dst, chk.spec, cfg.teamID, nil)
		if err != nil {
			return "", err
		}
		if srcOnly, dstOnly := diffChecksums(srcSums, dstSums); srcOnly+dstOnly > 0 {
			return chk.spec.name, nil
		}
	}
	return "", nil
}
