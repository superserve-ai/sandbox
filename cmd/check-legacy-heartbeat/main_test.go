package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestProcessConfigRequiresExplicitLegacyIdentity(t *testing.T) {
	for _, host := range []string{"", "named-host", "default"} {
		for _, database := range []string{"", "postgres://example.test/db"} {
			gotHost, gotDatabase, err := processConfig([]byte("HOST_ID=" + host + "\x00DATABASE_URL=" + database + "\x00"))
			if err == nil && (gotHost != host || gotDatabase != database) {
				t.Fatalf("configuration changed: host=%q database=%q", gotHost, gotDatabase)
			}
			if (err == nil) != (host != "" && database != "") {
				t.Fatalf("host=%q database present=%t: %v", host, database != "", err)
			}
		}
	}
}

func TestHeartbeatQueryRejectsStaleWrongAndBoundRows(t *testing.T) {
	database := os.Getenv("PEER_ROUTING_TEST_DATABASE_URL")
	if database == "" {
		t.Skip("set PEER_ROUTING_TEST_DATABASE_URL for PostgreSQL test")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	_, err = conn.Exec(ctx, `CREATE TEMP TABLE host (id text, identity_bound boolean, vmd_addr text, last_heartbeat_at timestamptz)`)
	if err != nil {
		t.Fatal(err)
	}
	var now time.Time
	if err = conn.QueryRow(ctx, "SELECT now()").Scan(&now); err != nil {
		t.Fatal(err)
	}
	for _, hostID := range []string{"default", "named-host", "example-east-2"} {
		for _, tc := range []struct {
			name, id, addr string
			bound          bool
			beat           time.Time
			want           bool
		}{
			{"fresh", hostID, "192.0.2.1:50051", false, now.Add(-time.Second), true},
			{"before restart", hostID, "192.0.2.1:50051", false, now.Add(-20 * time.Second), false},
			{"stale", hostID, "192.0.2.1:50051", false, now.Add(-2 * time.Minute), false},
			{"future", hostID, "192.0.2.1:50051", false, now.Add(time.Minute), false},
			{"wrong address", hostID, "192.0.2.2:50051", false, now.Add(-time.Second), false},
			{"bound", hostID, "192.0.2.1:50051", true, now.Add(-time.Second), false},
			{"wrong host", hostID + "-other", "192.0.2.1:50051", false, now.Add(-time.Second), false},
		} {
			t.Run(hostID+"/"+tc.name, func(t *testing.T) {
				_, err = conn.Exec(ctx, "TRUNCATE host")
				if err != nil {
					t.Fatal(err)
				}
				_, err = conn.Exec(ctx, "INSERT INTO host VALUES ($1,$2,$3,$4)", tc.id, tc.bound, tc.addr, tc.beat)
				if err != nil {
					t.Fatal(err)
				}
				tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(ctx)
				var accepted bool
				err = tx.QueryRow(ctx, heartbeatQuery, "192.0.2.1:50051", now.Add(-10*time.Second).Unix(), hostID).Scan(&accepted)
				if err != nil && err != pgx.ErrNoRows {
					t.Fatal(err)
				}
				if accepted != tc.want {
					t.Fatalf("accepted=%t want=%t", accepted, tc.want)
				}
			})
		}
	}
}
