// Command probe-guest is a tiny, dependency-free guest probe that runs *inside*
// the microVM and is captured in the Firecracker snapshot. It exists to make the
// latency benchmark honest: it forces a realistic hot working set to be resident
// in guest RAM, then on a wake trigger it re-touches that working set (faulting in
// pages on Tier 2/3), exercises the durable /state filesystem, and reports the
// time from trigger receipt to first-meaningful-op completion.
//
// See .context/VALIDATION-latency.md §2.1 for the methodology this implements.
//
// Why this matters: Firecracker's resume/load API returns in ~1ms while the guest
// has faulted in *none* of its working set. The only honest wake metric is
// "trigger -> first meaningful operation done", which is exactly what FIRST_OP_DONE
// measures here. Because the probe is captured *in the snapshot*, it answers
// immediately on thaw; if the harness had to re-exec, the first op would show up as
// a multi-second outlier (SPEC §4.5 hard-requirement #1).
//
// The binary is intentionally stdlib-only and portable: it cross-builds for
// linux/amd64 (the real target) but also compiles and runs on the dev host so the
// host driver can smoke-test the trigger protocol without a VM.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const pageSize = 4096

func main() {
	var (
		workingSetMiB = flag.Int("working-set-mib", 512, "working-set size in MiB to allocate and touch (simulates a loaded harness held in RAM)")
		stateDir      = flag.String("state-dir", "/state", "durable state directory exercised on the wake path")
		addr          = flag.String("addr", "", "if set, serve the wake trigger over HTTP GET on this addr (e.g. :7070); otherwise read a byte from stdin per trigger")
		touchStride   = flag.Int("touch-stride", 1, "touch every Nth page when re-faulting the working set on wake (1 = every page)")
		oneShot       = flag.Bool("one-shot", false, "stdin mode only: handle a single trigger then exit")
	)
	flag.Parse()

	ws, err := newWorkingSet(*workingSetMiB)
	if err != nil {
		fmt.Fprintf(os.Stderr, "probe-guest: allocate working set: %v\n", err)
		os.Exit(1)
	}

	// Force residency at startup so the working set is real RAM captured in the
	// snapshot, not lazily-zeroed pages the kernel hasn't backed yet.
	ws.touchAll()

	if err := os.MkdirAll(*stateDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "probe-guest: create state dir %q: %v\n", *stateDir, err)
		os.Exit(1)
	}

	fmt.Printf("READY working_set_mib=%d pages=%d state_dir=%s\n", *workingSetMiB, len(ws.buf)/pageSize, *stateDir)

	p := &prober{ws: ws, stateDir: *stateDir, stride: *touchStride}

	if *addr != "" {
		serveHTTP(p, *addr)
		return
	}
	serveStdin(p, *oneShot)
}

// workingSet is a byte buffer sized to a multiple of the page size. Touching it
// writes one byte per page, forcing the guest to fault each page in.
type workingSet struct {
	buf []byte
}

func newWorkingSet(mib int) (*workingSet, error) {
	if mib < 0 {
		return nil, fmt.Errorf("working-set-mib must be >= 0, got %d", mib)
	}
	n := mib * 1024 * 1024
	// Round up to a whole number of pages.
	if rem := n % pageSize; rem != 0 {
		n += pageSize - rem
	}
	return &workingSet{buf: make([]byte, n)}, nil
}

// touchAll writes one byte to every page, forcing residency / page-in.
func (w *workingSet) touchAll() {
	w.touchStride(1)
}

// touchStride writes one byte to every stride-th page and returns how many pages
// were touched. A stride of 1 touches the whole working set.
func (w *workingSet) touchStride(stride int) int {
	if stride < 1 {
		stride = 1
	}
	touched := 0
	step := pageSize * stride
	for i := 0; i < len(w.buf); i += step {
		// XOR-in a changing value so the compiler can't elide the store and the
		// page is genuinely dirtied (forces a real write fault, not just a read).
		w.buf[i] ^= byte(i>>12) + 1
		touched++
	}
	return touched
}

type prober struct {
	ws       *workingSet
	stateDir string
	stride   int
}

// firstOp executes one "meaningful operation": re-touch the working set (page-in
// after thaw), then do a read+write against the durable /state filesystem. It
// returns the nanoseconds elapsed and the number of pages touched.
//
// The caller starts the clock at trigger receipt and stops it here, so the
// returned duration is exactly "wake trigger -> first meaningful op done".
func (p *prober) firstOp(start time.Time) (elapsedNanos int64, pagesTouched int, err error) {
	pagesTouched = p.ws.touchStride(p.stride)

	// Exercise the durable FS on the wake path: write a token then read it back.
	statePath := filepath.Join(p.stateDir, "probe-firstop.bin")
	token := []byte(fmt.Sprintf("op-%d\n", start.UnixNano()))
	if err := os.WriteFile(statePath, token, 0o644); err != nil {
		return 0, pagesTouched, fmt.Errorf("write state file: %w", err)
	}
	got, err := os.ReadFile(statePath)
	if err != nil {
		return 0, pagesTouched, fmt.Errorf("read state file: %w", err)
	}
	if string(got) != string(token) {
		return 0, pagesTouched, fmt.Errorf("state file mismatch: wrote %q read %q", token, got)
	}

	return time.Since(start).Nanoseconds(), pagesTouched, nil
}

// serveStdin treats each byte read from stdin as a wake trigger. The clock starts
// the instant the byte is read. This is the simplest transport and avoids any
// network reattach on the measurement path.
func serveStdin(p *prober, oneShot bool) {
	r := bufio.NewReader(os.Stdin)
	for {
		if _, err := r.ReadByte(); err != nil {
			// EOF / closed stdin: nothing more to do.
			return
		}
		start := time.Now()
		nanos, pages, err := p.firstOp(start)
		if err != nil {
			fmt.Fprintf(os.Stderr, "probe-guest: first op failed: %v\n", err)
			fmt.Printf("FIRST_OP_ERR %v\n", err)
		} else {
			// Single, parseable line: the host driver scrapes this.
			fmt.Printf("FIRST_OP_DONE %d pages=%d\n", nanos, pages)
		}
		os.Stdout.Sync()
		if oneShot {
			return
		}
	}
}

// serveHTTP treats each GET as a wake trigger. The clock starts when the handler
// fires. Note: if network reattach happens on resume, that cost lands *outside*
// this measurement (in the host driver's T_net) — see VALIDATION-latency.md §4.
func serveHTTP(p *prober, addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/probe", func(w http.ResponseWriter, _ *http.Request) {
		start := time.Now()
		nanos, pages, err := p.firstOp(start)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "FIRST_OP_ERR %v\n", err)
			fmt.Fprintf(os.Stderr, "probe-guest: first op failed: %v\n", err)
			return
		}
		line := fmt.Sprintf("FIRST_OP_DONE %d pages=%d\n", nanos, pages)
		fmt.Fprint(w, line)
		fmt.Print(line)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	server := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	fmt.Printf("SERVING addr=%s\n", addr)
	if err := server.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "probe-guest: http server: %v\n", err)
		os.Exit(1)
	}
}
