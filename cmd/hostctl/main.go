// hostctl is the operator CLI for host lifecycle: list hosts in a cell,
// activate a provisioning host, drain a host out of placement. It talks to
// the control plane's internal API — never to the database.
//
//	CONTROL_PLANE_URL=https://... OPERATOR_API_TOKEN=... hostctl list
//	hostctl activate <host-id>
//	hostctl drain <host-id>
//
// The operator token is distinct from the vmd-held internal token: hosts
// must not hold the credential that approves them. The token's secret must
// be provisioned into the control plane's deployment before these commands
// work; until then the operator endpoints reject everything by design.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

func main() {
	url := flag.String("url", os.Getenv("CONTROL_PLANE_URL"), "control plane base URL (env CONTROL_PLANE_URL)")
	token := flag.String("token", os.Getenv("OPERATOR_API_TOKEN"), "operator API token (env OPERATOR_API_TOKEN)")
	wait := flag.Bool("wait", false, "drain only: block until placement has converged and counts read stably zero")
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
		if err = cli.setStatus(arg, "draining"); err == nil {
			if *wait {
				err = cli.waitDrained(arg)
			} else {
				fmt.Printf("note: other control-plane replicas may still place work for up to %s\n"+
					"(scheduler cache TTL + stale grace); do not trust zero counts before that.\n"+
					"Re-run with --wait, or poll `hostctl list` until counts read stably zero.\n",
					drainConvergence)
			}
		}
	default:
		flag.Usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "hostctl:", err)
		os.Exit(1)
	}
}

// Placement fencing is cache-based until the reservation work lands, and
// the counts read the sandbox TABLE — but a create admitted just before the
// convergence cutoff boots its VM BEFORE inserting the row (boot runs under
// a 2×30s context including one retry), so the host can carry invisible
// work well after placement stopped. The quiet window therefore must cover
// the longest admitted-but-uninserted create plus its failure cleanup, not
// merely a few polls:
//
//	drainConvergence — when the last stale replica can still ADMIT a
//	  create: scheduler cache TTL + stale grace (30s+30s), PLUS the fill
//	  bound (5s — a fill that reads the host set before the drain commits
//	  and finishes after it stamps a pre-drain view as fresh at its END),
//	  plus a 10s post-admission margin: the admitted create still runs the
//	  capability lookup (5s bound, api.hostCapQueryTimeout) and a cold
//	  registry resolve (2s bound) BEFORE its bounded boot begins.
//	drainQuietWindow — continuous zeros required AFTER that: 2×30s boot
//	  (incl. retry) + insert/cleanup visibility margin.
const (
	drainConvergence = 75 * time.Second
	drainQuietWindow = 90 * time.Second
	drainPollEvery   = 5 * time.Second
	drainWaitCeiling = 15 * time.Minute
)

// waitDrained blocks through the convergence window, then polls until
// RUNNING, BUSY, and BUILDS read zero continuously for drainQuietWindow.
// It aborts if the host leaves 'draining' (a concurrent activation would
// otherwise let it report "drained" while placement is enabled again), and
// is explicit that drained is not safe-to-retire while PAUSED is nonzero.
func (c client) waitDrained(hostID string) error {
	fmt.Printf("%s -> draining; waiting %s for placement convergence across replicas...\n",
		hostID, drainConvergence)
	time.Sleep(drainConvergence)

	deadline := time.Now().Add(drainWaitCeiling)
	var quietSince time.Time
	for {
		h, err := c.hostRow(hostID)
		if err != nil {
			return err
		}
		if h.Status != "draining" {
			return fmt.Errorf("host %s status changed to %q while waiting; placement may be enabled again — aborting", hostID, h.Status)
		}
		busy := h.RunningCount + h.TransitionalCount + h.BuildingCount
		switch {
		case busy != 0:
			quietSince = time.Time{}
			fmt.Printf("still busy: running=%d busy=%d builds=%d\n",
				h.RunningCount, h.TransitionalCount, h.BuildingCount)
		case quietSince.IsZero():
			quietSince = time.Now()
		}
		if !quietSince.IsZero() && time.Since(quietSince) >= drainQuietWindow {
			fmt.Printf("%s drained: counts zero continuously for %s.\n", hostID, drainQuietWindow)
			if h.PausedCount > 0 {
				fmt.Printf("NOT safe to retire: %d paused sandboxes have their snapshots on this host's local disk (%d without a durable backup — irrecoverable if the disk is lost).\n",
					h.PausedCount, h.PausedUnbacked)
			}
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("host %s not drained after %s; see `hostctl list`", hostID, drainWaitCeiling)
		}
		time.Sleep(drainPollEvery)
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

type hostView struct {
	ID                string  `json:"id"`
	Status            string  `json:"status"`
	Region            string  `json:"region"`
	VMDAddr           string  `json:"vmd_addr"`
	LastHeartbeatAt   *string `json:"last_heartbeat_at"`
	RunningCount      int     `json:"running_count"`
	TransitionalCount int     `json:"transitional_count"`
	PausedCount       int     `json:"paused_count"`
	BuildingCount     int     `json:"building_count"`
	PausedUnbacked    int     `json:"paused_unbacked_count"`
}

func (c client) hostsPath(path string) ([]hostView, error) {
	resp, err := c.do(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out struct {
		Hosts []hostView `json:"hosts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Hosts, nil
}

func (c client) hosts() ([]hostView, error) {
	return c.hostsPath("/internal/hosts")
}

// hostRow fetches ONE host's row. Scoped server-side because drain polls it
// every few seconds — the unscoped list recomputes sandbox and
// backup-coverage counts for the whole fleet.
func (c client) hostRow(hostID string) (hostView, error) {
	hosts, err := c.hostsPath("/internal/hosts?id=" + url.QueryEscape(hostID))
	if err != nil {
		return hostView{}, err
	}
	if len(hosts) == 0 {
		return hostView{}, fmt.Errorf("host %q not found", hostID)
	}
	return hosts[0], nil
}

func (c client) list() error {
	hosts, err := c.hosts()
	if err != nil {
		return err
	}
	out := struct{ Hosts []hostView }{hosts}

	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	// BUSY counts pausing/resuming sandboxes and BUILDS counts in-flight
	// template builds — both mean a lifecycle RPC or build VM is still using
	// the host. RUNNING+BUSY+BUILDS at zero means DRAINED: no new work will
	// land. It does NOT mean safe to retire: PAUSED sandboxes' snapshots
	// live on the host's local disk and resume is pinned to it, so retiring
	// the machine strands every one of them. Until cross-host restore
	// exists, retirement additionally requires PAUSED = 0. UNBACKED is the
	// irrecoverable subset — paused sandboxes with no durable backup copy
	// anywhere; retiring the machine destroys those outright, so that
	// number must read zero before retirement is even discussable.
	fmt.Fprintln(w, "ID\tSTATUS\tREGION\tVMD_ADDR\tHEARTBEAT\tRUNNING\tBUSY\tBUILDS\tPAUSED\tUNBACKED")
	for _, h := range out.Hosts {
		beat := "never"
		if h.LastHeartbeatAt != nil {
			if t, err := time.Parse(time.RFC3339, *h.LastHeartbeatAt); err == nil {
				beat = fmt.Sprintf("%ds ago", int(time.Since(t).Seconds()))
			}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\n",
			h.ID, h.Status, h.Region, h.VMDAddr, beat, h.RunningCount, h.TransitionalCount, h.BuildingCount, h.PausedCount, h.PausedUnbacked)
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
