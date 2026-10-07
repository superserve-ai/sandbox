package telemetry

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	conntrackSysctlDir = "/proc/sys/net/netfilter"
	conntrackStatPath  = "/proc/net/stat/nf_conntrack"
)

// HostConntrack is one sample of the host's connection-tracking table: how
// full it is against its ceiling, and the expiry settings that drain it.
type HostConntrack struct {
	HostID                string
	Entries               int64
	Max                   int64
	Buckets               int64
	TCPSynSentTimeoutSecs int64
	UDPTimeoutSecs        int64
	// Drops and EarlyDrops are the kernel's cumulative counts of packets
	// refused and entries evicted because the table was full: a burst that
	// fills and drains between two samples still moves them.
	Drops      int64
	EarlyDrops int64
}

// StartHostConntrackSampler exports the conntrack table's fill and settings
// every interval. A full table drops packets for every sandbox on the host:
// the fill ratio warns ahead of it, the drop counters record it even when a
// burst fits between samples, and the settings catch a host that came up
// without the fleet's sizing.
func StartHostConntrackSampler(ctx context.Context, recorder Recorder, hostID string, interval time.Duration) {
	if recorder == nil || interval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			c, err := readHostConntrack(conntrackSysctlDir)
			if err == nil {
				c.Drops, c.EarlyDrops, err = readConntrackDrops(conntrackStatPath)
			}
			if err != nil {
				log.Warn().Err(err).Msg("conntrack sample skipped")
			} else {
				c.HostID = hostID
				recorder.RecordHostConntrack(ctx, c)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func readHostConntrack(dir string) (HostConntrack, error) {
	var c HostConntrack
	for _, f := range []struct {
		name string
		dst  *int64
	}{
		{"nf_conntrack_count", &c.Entries},
		{"nf_conntrack_max", &c.Max},
		{"nf_conntrack_buckets", &c.Buckets},
		{"nf_conntrack_tcp_timeout_syn_sent", &c.TCPSynSentTimeoutSecs},
		{"nf_conntrack_udp_timeout", &c.UDPTimeoutSecs},
	} {
		raw, err := os.ReadFile(filepath.Join(dir, f.name))
		if err != nil {
			return HostConntrack{}, err
		}
		v, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
		if err != nil {
			return HostConntrack{}, err
		}
		*f.dst = v
	}
	return c, nil
}

// readConntrackDrops sums the per-CPU drop and early_drop columns of
// /proc/net/stat/nf_conntrack: a header of column names, then one row of
// hex counters per CPU.
func readConntrackDrops(path string) (drops, early int64, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) < 2 {
		return 0, 0, errors.New("conntrack stat: no rows")
	}
	cols := strings.Fields(lines[0])
	dropCol, earlyCol := -1, -1
	for i, c := range cols {
		switch c {
		case "drop":
			dropCol = i
		case "early_drop":
			earlyCol = i
		}
	}
	if dropCol < 0 || earlyCol < 0 {
		return 0, 0, errors.New("conntrack stat: drop columns missing")
	}
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) <= dropCol || len(f) <= earlyCol {
			return 0, 0, errors.New("conntrack stat: short row")
		}
		d, err := strconv.ParseInt(f[dropCol], 16, 64)
		if err != nil {
			return 0, 0, err
		}
		e, err := strconv.ParseInt(f[earlyCol], 16, 64)
		if err != nil {
			return 0, 0, err
		}
		drops += d
		early += e
	}
	return drops, early, nil
}
