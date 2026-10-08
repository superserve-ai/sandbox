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
	HostID  string
	Entries int64
	// EntriesPeak is the highest Entries seen over the last peak window, so a
	// burst that fills and drains between two metric exports still shows in
	// the exported value; last-value gauges would otherwise lose it.
	EntriesPeak           int64
	Max                   int64
	Buckets               int64
	TCPSynSentTimeoutSecs int64
	UDPTimeoutSecs        int64
	// Drops and EarlyDrops are the kernel's cumulative counts of packets
	// refused and entries evicted because the table was full: a burst that
	// fills and drains between two samples still moves them. Exported only
	// when DropsKnown: kernels without conntrack procfs stats have no source.
	Drops      int64
	EarlyDrops int64
	DropsKnown bool
}

// StartHostConntrackSampler exports the conntrack table's fill and settings
// every interval. A full table drops packets for every sandbox on the host:
// the fill ratio warns ahead of it, the drop counters record it even when a
// burst fits between samples, and the settings catch a host that came up
// without the fleet's sizing.
// peakWindow should cover at least one metric export interval.
func StartHostConntrackSampler(ctx context.Context, recorder Recorder, hostID string, interval, peakWindow time.Duration) {
	if _, noop := recorder.(noopRecorder); recorder == nil || noop || interval <= 0 {
		return
	}
	if peakWindow < interval {
		peakWindow = interval
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		warnedSample, warnedDrops := false, false
		var recent []entrySample
		for {
			c, err := readHostConntrack(conntrackSysctlDir)
			if err != nil {
				if !warnedSample {
					warnedSample = true
					log.Warn().Err(err).Msg("conntrack unavailable; samples skipped until it is")
				}
			} else {
				warnedSample = false
				c.HostID = hostID
				recent, c.EntriesPeak = peakEntries(append(recent, entrySample{time.Now(), c.Entries}), time.Now(), peakWindow)
				c.Drops, c.EarlyDrops, err = readConntrackDrops(conntrackStatPath)
				c.DropsKnown = err == nil
				if err != nil && !warnedDrops {
					warnedDrops = true
					log.Warn().Err(err).Msg("conntrack drop counters unavailable; exporting fill and settings only")
				}
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

type entrySample struct {
	at time.Time
	v  int64
}

// peakEntries drops samples older than window and returns the rest with the
// highest value among them.
func peakEntries(samples []entrySample, now time.Time, window time.Duration) ([]entrySample, int64) {
	kept := samples[:0]
	var peak int64
	for _, s := range samples {
		if now.Sub(s.at) > window {
			continue
		}
		kept = append(kept, s)
		if s.v > peak {
			peak = s.v
		}
	}
	return kept, peak
}
