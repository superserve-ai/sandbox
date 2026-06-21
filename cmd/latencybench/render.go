package main

import (
	"fmt"
	"io"
	"text/tabwriter"
	"time"
)

// renderTable writes the results table from VALIDATION-latency.md §6:
//
//	tier | mem | ws | cache | contention | T_wake p50/p90/p99 | T_control |
//	T_fetch | T_attach | T_load | T_resume | T_net | T_guest | gate
//
// One row per matrix cell. Phase columns that don't apply to a tier render "-".
// Cells whose provider errored render the error in place of the numbers, so the
// table makes clear that nothing was measured (e.g. the vmd provider).
func renderTable(out io.Writer, results []CellResult, providerLabel string) {
	fmt.Fprintf(out, "# latencybench results — provider: %s\n", providerLabel)
	fmt.Fprintf(out, "# T_wake is p50/p90/p99 of (wake trigger -> first meaningful op done). Phase columns are p50 medians.\n\n")

	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	header := []string{
		"tier", "mem", "ws", "cache", "cont",
		"T_wake p50/p90/p99",
		"T_control", "T_fetch", "T_attach", "T_load", "T_resume", "T_net", "T_guest",
		"gate",
	}
	fmt.Fprintln(w, joinTabs(header))

	for _, r := range results {
		c := r.Cell
		prefix := []string{
			c.Tier.String(),
			fmt.Sprintf("%dM", c.MemMiB),
			fmt.Sprintf("%dM", c.WorkingMiB),
			string(c.Cache),
			fmt.Sprintf("%d/core", c.Contention),
		}

		if r.Err != nil {
			row := append(prefix, "ERR: "+r.Err.Error())
			fmt.Fprintln(w, joinTabs(row))
			continue
		}

		wake := fmt.Sprintf("%s / %s / %s", fmtDur(r.Wake.P50), fmtDur(r.Wake.P90), fmtDur(r.Wake.P99))
		row := append(prefix,
			wake,
			fmtPhase(r.Phases.Control, true),
			fmtPhase(r.Phases.Fetch, c.Tier == Tier3),
			fmtPhase(r.Phases.Attach, c.Tier == Tier3),
			fmtPhase(r.Phases.Load, c.Tier == Tier2 || c.Tier == Tier3),
			fmtPhase(r.Phases.Resume, true),
			fmtPhase(r.Phases.Net, true),
			fmtPhase(r.Phases.Guest, true),
			r.Gate.String(),
		)
		fmt.Fprintln(w, joinTabs(row))
	}
	w.Flush()
}

// fmtPhase renders a phase duration, or "-" when the phase does not apply to the
// tier (matching the §6 template, which dashes out inapplicable phases).
func fmtPhase(d time.Duration, applies bool) string {
	if !applies {
		return "-"
	}
	return fmtDur(d)
}

// fmtDur formats a duration with a stable, compact unit for table readability:
// sub-millisecond in microseconds, otherwise milliseconds (sub-second wakes) or
// seconds. Two significant decimals.
func fmtDur(d time.Duration) string {
	switch {
	case d == 0:
		return "0"
	case d < time.Microsecond:
		return fmt.Sprintf("%dns", d.Nanoseconds())
	case d < time.Millisecond:
		return fmt.Sprintf("%.2fus", float64(d)/float64(time.Microsecond))
	case d < time.Second:
		return fmt.Sprintf("%.2fms", float64(d)/float64(time.Millisecond))
	default:
		return fmt.Sprintf("%.3fs", d.Seconds())
	}
}

func joinTabs(cols []string) string {
	out := ""
	for i, c := range cols {
		if i > 0 {
			out += "\t"
		}
		out += c
	}
	return out
}
