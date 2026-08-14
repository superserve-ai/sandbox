package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/superserve-ai/sandbox/proto/vmdpb"
)

// runRevive drives ReviveVM for a manifest of dead sandboxes, one per
// line: `<sandbox-id> <disk-path> [vcpu] [mem-mib]`. Operator tool, run
// on the host next to vmd: the disk paths name salvaged copies staged
// on the local array, and every line is attempted so the ledger reports
// the full outcome rather than stopping at the first failure. The
// control-plane status flip happens after this, per the runbook: vmd is
// the authority on whether a VM is actually running again.
func runRevive(args []string) int {
	fs := flag.NewFlagSet("revive", flag.ExitOnError)
	vmdAddr := fs.String("vmd", "127.0.0.1:50051", "vmd gRPC address")
	manifest := fs.String("manifest", "", "file of `sandbox-id disk-path [vcpu] [mem-mib]` lines")
	timeout := fs.Duration("timeout", 2*time.Minute, "per-VM revive timeout")
	_ = fs.Parse(args)
	if *manifest == "" {
		fmt.Fprintln(os.Stderr, "revive: -manifest is required")
		return 2
	}
	f, err := os.Open(*manifest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "revive: %v\n", err)
		return 1
	}
	defer f.Close()

	conn, err := grpc.NewClient(*vmdAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "revive: dial vmd: %v\n", err)
		return 1
	}
	defer conn.Close()
	client := vmdpb.NewVMDaemonClient(conn)

	revived, failed := 0, 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			fmt.Printf("SKIP %s (need id and disk path)\n", line)
			failed++
			continue
		}
		req := &vmdpb.ReviveVMRequest{VmId: fields[0], DiskPath: fields[1]}
		// Optional named tokens anywhere after the disk: base=<path> for
		// overlay salvages (defaults to the sandbox's recorded base).
		rest := fields[2:]
		fields = fields[:2]
		for _, tok := range rest {
			if p, ok := strings.CutPrefix(tok, "base="); ok {
				req.BasePath = p
			} else {
				fields = append(fields, tok)
			}
		}
		// Malformed resource fields reject the line rather than silently
		// booting at defaults: a typo must not revive a 32 GiB workload
		// into a 1 GiB VM.
		badField := false
		if len(fields) > 2 {
			v, err := strconv.ParseUint(fields[2], 10, 32)
			if err != nil {
				fmt.Printf("FAILED %s: malformed vcpu %q\n", req.VmId, fields[2])
				badField = true
			} else {
				req.Vcpu = uint32(v)
			}
		}
		if !badField && len(fields) > 3 {
			v, err := strconv.ParseUint(fields[3], 10, 32)
			if err != nil {
				fmt.Printf("FAILED %s: malformed mem-mib %q\n", req.VmId, fields[3])
				badField = true
			} else {
				req.MemMib = uint32(v)
			}
		}
		if badField {
			failed++
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		resp, err := client.ReviveVM(ctx, req)
		cancel()
		if err != nil {
			fmt.Printf("FAILED %s: %v\n", req.VmId, err)
			failed++
			continue
		}
		fmt.Printf("REVIVED %s ip=%s disk=%s\n", req.VmId, resp.GetHostIp(), resp.GetDiskPath())
		revived++
	}
	if err := sc.Err(); err != nil {
		// A truncated manifest read must not masquerade as a clean run:
		// every unread line is a sandbox nobody attempted.
		fmt.Fprintf(os.Stderr, "revive: manifest read failed mid-scan: %v\n", err)
		failed++
	}
	fmt.Printf("revive complete: revived=%d failed=%d\n", revived, failed)
	if failed > 0 {
		return 1
	}
	return 0
}
