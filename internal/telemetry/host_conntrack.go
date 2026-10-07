package telemetry

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

const conntrackSysctlDir = "/proc/sys/net/netfilter"

// HostConntrack is one sample of the host's connection-tracking table: how
// full it is against its ceiling, and the expiry settings that drain it.
type HostConntrack struct {
	HostID                string
	Entries               int64
	Max                   int64
	Buckets               int64
	TCPSynSentTimeoutSecs int64
	UDPTimeoutSecs        int64
}

// StartHostConntrackSampler exports the conntrack table's fill and settings
// every interval. A full table drops packets for every sandbox on the host,
// so the fill ratio is the alertable signal; the settings catch a host that
// came up without the fleet's sizing.
func StartHostConntrackSampler(ctx context.Context, recorder Recorder, hostID string, interval time.Duration) {
	if recorder == nil || interval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			c, err := readHostConntrack(conntrackSysctlDir)
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
