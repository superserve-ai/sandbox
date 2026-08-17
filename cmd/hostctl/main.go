// hostctl is the operator CLI for host lifecycle: list hosts in a cell,
// activate a provisioning host, drain a host out of placement. It talks to
// the control plane's internal API — never to the database.
//
//	CONTROL_PLANE_URL=https://... OPERATOR_API_TOKEN=... hostctl list
//	hostctl activate <host-id>
//	hostctl drain <host-id>
//
// The operator token is distinct from the vmd-held internal token: hosts
// must not hold the credential that approves them.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

func main() {
	url := flag.String("url", os.Getenv("CONTROL_PLANE_URL"), "control plane base URL (env CONTROL_PLANE_URL)")
	token := flag.String("token", os.Getenv("OPERATOR_API_TOKEN"), "operator API token (env OPERATOR_API_TOKEN)")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: hostctl [flags] <list|activate|drain> [host-id]\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *url == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "hostctl: CONTROL_PLANE_URL and OPERATOR_API_TOKEN are required")
		os.Exit(2)
	}
	cli := client{base: strings.TrimRight(*url, "/"), token: *token}

	var err error
	switch cmd, arg := flag.Arg(0), flag.Arg(1); {
	case cmd == "list" && arg == "":
		err = cli.list()
	case cmd == "activate" && arg != "":
		err = cli.setStatus(arg, "active")
	case cmd == "drain" && arg != "":
		err = cli.setStatus(arg, "draining")
	default:
		flag.Usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "hostctl:", err)
		os.Exit(1)
	}
}

type client struct {
	base  string
	token string
}

func (c client) do(method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(msg)))
	}
	return resp, nil
}

func (c client) list() error {
	resp, err := c.do(http.MethodGet, "/internal/hosts", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var out struct {
		Hosts []struct {
			ID              string  `json:"id"`
			Status          string  `json:"status"`
			Region          string  `json:"region"`
			VMDAddr         string  `json:"vmd_addr"`
			LastHeartbeatAt   *string `json:"last_heartbeat_at"`
			RunningCount      int     `json:"running_count"`
			TransitionalCount int     `json:"transitional_count"`
			PausedCount       int     `json:"paused_count"`
			BuildingCount     int     `json:"building_count"`
		} `json:"hosts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	// BUSY counts pausing/resuming sandboxes and BUILDS counts in-flight
	// template builds — both mean a lifecycle RPC or build VM is still using
	// the host. RUNNING+BUSY+BUILDS at zero means DRAINED: no new work will
	// land. It does NOT mean safe to retire: PAUSED sandboxes' snapshots
	// live on the host's local disk and resume is pinned to it, so retiring
	// the machine strands every one of them. Until cross-host restore
	// exists, retirement additionally requires PAUSED = 0.
	fmt.Fprintln(w, "ID\tSTATUS\tREGION\tVMD_ADDR\tHEARTBEAT\tRUNNING\tBUSY\tBUILDS\tPAUSED")
	for _, h := range out.Hosts {
		beat := "never"
		if h.LastHeartbeatAt != nil {
			if t, err := time.Parse(time.RFC3339, *h.LastHeartbeatAt); err == nil {
				beat = fmt.Sprintf("%ds ago", int(time.Since(t).Seconds()))
			}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\n",
			h.ID, h.Status, h.Region, h.VMDAddr, beat, h.RunningCount, h.TransitionalCount, h.BuildingCount, h.PausedCount)
	}
	return w.Flush()
}

func (c client) setStatus(hostID, status string) error {
	body := strings.NewReader(fmt.Sprintf(`{"status":%q}`, status))
	resp, err := c.do(http.MethodPost, "/internal/hosts/"+hostID+"/status", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	fmt.Printf("%s -> %s\n", hostID, status)
	return nil
}
