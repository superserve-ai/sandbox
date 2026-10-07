package telemetry

import (
	"os"
	"path/filepath"
	"testing"
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
