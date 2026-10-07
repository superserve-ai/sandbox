//go:build integration

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestQMKeyUsage(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Fatal("DATABASE_URL must name a disposable test database")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	// The one-connection pool keeps the production query on this temporary table.
	_, err = pool.Exec(t.Context(), `CREATE TEMP TABLE api_key(id uuid PRIMARY KEY,team_id uuid,created_by uuid,name text,key_hash text UNIQUE,revoked_at timestamptz,expires_at timestamptz,last_used_at timestamptz)`)
	if err != nil {
		t.Fatal(err)
	}
	authority := qmAuthority{&Handlers{Pool: pool}}
	for _, kind := range []string{"unused", "stale", "recent", "revoked", "expired"} {
		t.Run(kind, func(t *testing.T) {
			id, team, owner := uuid.New(), uuid.New(), uuid.New()
			key := "test-" + kind
			sum := sha256.Sum256([]byte(key))
			var used, revoked, expired *time.Time
			old := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
			recent := time.Now().UTC().Add(-time.Second).Truncate(time.Microsecond)
			if kind != "unused" {
				used = &old
			}
			if kind == "recent" {
				used = &recent
			}
			if kind == "revoked" {
				revoked = &old
			}
			if kind == "expired" {
				expired = &old
			}
			_, err = pool.Exec(t.Context(), `INSERT INTO api_key VALUES($1,$2,$3,'example',$4,$5,$6,$7)`, id, team, owner, hex.EncodeToString(sum[:]), revoked, expired, used)
			if err != nil {
				t.Fatal(err)
			}
			identity, resolveErr := authority.Resolve(t.Context(), key)
			var after *time.Time
			if err = pool.QueryRow(t.Context(), `SELECT last_used_at FROM api_key WHERE id=$1`, id).Scan(&after); err != nil {
				t.Fatal(err)
			}
			if kind == "revoked" || kind == "expired" {
				if !errors.Is(resolveErr, pgx.ErrNoRows) || after == nil || !after.Equal(old) {
					t.Fatal("invalid key touched audit timestamp", resolveErr, after)
				}
				return
			}
			if resolveErr != nil || identity.KeyID != id || identity.TeamID != team || identity.OwnerID != owner || after == nil {
				t.Fatal(identity, resolveErr, after)
			}
			if kind == "recent" {
				if !after.Equal(recent) {
					t.Fatal("recent usage was rewritten")
				}
			} else if !after.After(old) {
				t.Fatal("successful key use not recorded")
			}
			if _, err = authority.Resolve(t.Context(), key); err != nil {
				t.Fatal(err)
			}
			var repeated time.Time
			if err = pool.QueryRow(t.Context(), `SELECT last_used_at FROM api_key WHERE id=$1`, id).Scan(&repeated); err != nil {
				t.Fatal(err)
			}
			if !repeated.Equal(*after) {
				t.Fatal("repeat request bypassed write throttle")
			}
		})
	}
	if _, err = authority.Resolve(t.Context(), "unknown-key"); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal(err)
	}
}
