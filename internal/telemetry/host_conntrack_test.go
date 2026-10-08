package telemetry

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReadHostConntrack(t *testing.T) {
	dir := t.TempDir()
	for name, v := range map[string]string{
		"nf_conntrack_count":                "4200\n",
		"nf_conntrack_max":                  "4194304\n",
		"nf_conntrack_buckets":              "1048576\n",
		"nf_conntrack_tcp_timeout_syn_sent": "30\n",
		"nf_conntrack_udp_timeout":          "15\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	c, err := readHostConntrack(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := HostConntrack{Entries: 4200, Max: 4194304, Buckets: 1048576, TCPSynSentTimeoutSecs: 30, UDPTimeoutSecs: 15}
	if c != want {
		t.Fatalf("got %+v, want %+v", c, want)
	}

	// The module not being loaded leaves the keys absent: the sample is skipped, not zeroed.
	if _, err := readHostConntrack(t.TempDir()); err == nil {
		t.Fatal("missing sysctl keys must fail the sample")
	}
}

func TestReadConntrackDrops(t *testing.T) {
	// Two CPUs; counters are hex. drop is column 10, early_drop column 11.
	stat := filepath.Join(t.TempDir(), "nf_conntrack")
	if err := os.WriteFile(stat, []byte(
		"entries clashres found new invalid ignore delete chainlength insert insert_failed drop early_drop icmp_error expect_new expect_create expect_delete search_restart\n"+
			"00001068 00000000 0003f2a1 00000000 00000012 00000000 00000000 00000000 00000000 00000003 0000000a 00000001 00000000 00000000 00000000 00000000 00000000\n"+
			"00001068 00000000 0001c3b0 00000000 00000007 00000000 00000000 00000000 00000000 00000000 00000010 00000000 00000000 00000000 00000000 00000000 00000000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	drops, early, err := readConntrackDrops(stat)
	if err != nil || drops != 0x1a || early != 1 {
		t.Fatalf("drops=%d early=%d err=%v; want 26, 1, nil", drops, early, err)
	}
}

func TestPeakEntriesKeepsTheWindowHigh(t *testing.T) {
	now := time.Unix(1000, 0)
	samples := []entrySample{
		{now.Add(-20 * time.Second), 900000}, // outside the window: forgotten
		{now.Add(-10 * time.Second), 250000}, // the burst
		{now.Add(-5 * time.Second), 3000},
		{now, 2800},
	}
	kept, peak := peakEntries(samples, now, 15*time.Second)
	if peak != 250000 || len(kept) != 3 {
		t.Fatalf("peak=%d kept=%d; want 250000, 3", peak, len(kept))
	}
}
