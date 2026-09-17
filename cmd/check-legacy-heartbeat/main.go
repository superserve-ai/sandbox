// check-legacy-heartbeat verifies a real legacy VMD heartbeat without publishing one.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

func processConfig(data []byte) (string, string, error) {
	env := map[string]string{}
	for _, entry := range strings.Split(string(data), "\x00") {
		if k, v, ok := strings.Cut(entry, "="); ok {
			env[k] = v
		}
	}
	if env["HOST_ID"] == "" {
		return "", "", fmt.Errorf("legacy check requires explicit running HOST_ID")
	}
	if env["DATABASE_URL"] == "" {
		return "", "", fmt.Errorf("running VMD has no DATABASE_URL")
	}
	return env["HOST_ID"], env["DATABASE_URL"], nil
}

const heartbeatQuery = `SELECT COALESCE(
 NOT identity_bound AND vmd_addr = $1
 AND last_heartbeat_at > to_timestamp($2)
 AND last_heartbeat_at > now() - interval '60 seconds'
 AND last_heartbeat_at <= now(), false)
 FROM host WHERE id = $3`

func check(pid int, started int64, addr string) error {
	if pid <= 0 || started <= 0 || addr == "" {
		return fmt.Errorf("missing current VMD process, start time or address")
	}
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/environ")
	if err != nil {
		return fmt.Errorf("cannot read running VMD configuration")
	}
	hostID, database, err := processConfig(data)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, database)
	if err != nil {
		return fmt.Errorf("legacy heartbeat database unavailable")
	}
	defer conn.Close(ctx)
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return fmt.Errorf("cannot start read-only heartbeat check")
	}
	defer tx.Rollback(ctx)
	var accepted bool
	if err := tx.QueryRow(ctx, heartbeatQuery, addr, started, hostID).Scan(&accepted); err != nil || !accepted {
		return fmt.Errorf("no fresh unbound heartbeat for running HOST_ID %q at this VMD start/address", hostID)
	}
	return nil
}

func main() {
	pid := flag.Int("pid", 0, "current VMD PID")
	started := flag.Int64("started", 0, "VMD start time, Unix seconds (rounded up)")
	addr := flag.String("address", "", "expected registered VMD address")
	flag.Parse()
	if err := check(*pid, *started, *addr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("fresh legacy control-plane heartbeat verified")
}
