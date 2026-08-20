// Command backup-restore materializes a sandbox backup generation from the
// cell's backup bucket onto local disk: it fetches the generation manifest,
// rebuilds each sparse artifact from its packed object, and verifies every
// file's full apparent content against the manifest digest. It is the
// operator entry point for the read path that lost-host recovery and
// single-sandbox restore build on.
//
// A successful restore ends with a fsynced manifest.json completion marker
// in the destination; a destination without the marker is a crashed or
// interrupted restore and must not be consumed.
//
// Credentials come from application default credentials; run it under the
// restore identity (object read access to the backup bucket).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cloud.google.com/go/storage"

	"github.com/superserve-ai/sandbox/internal/backup"
)

func main() {
	// Subcommand dispatch ahead of flag parsing: `revive` and
	// `discrepancy` own their flag sets.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "revive":
			os.Exit(runRevive(os.Args[2:]))
		case "discrepancy":
			os.Exit(runDiscrepancy(os.Args[2:]))
		}
	}
	bucket := flag.String("bucket", "", "backup bucket name")
	sandbox := flag.String("sandbox", "", "sandbox id")
	generation := flag.String("generation", "", "generation to restore; omit to list the sandbox's restorable generations")
	dest := flag.String("dest", "", "destination directory for restored artifacts")
	hostRestore := flag.String("host-restore", "", "bulk DR mode: restore every live sandbox the DB pins to this host id")
	dbURL := flag.String("db-url", os.Getenv("DATABASE_URL"), "control-plane DB URL for host enumeration (default $DATABASE_URL)")
	sandboxesFile := flag.String("sandboxes-file", "", "host enumeration from a file (one sandbox id per line) when the DB is unreachable")
	destRoot := flag.String("dest-root", "", "bulk mode: root directory; each sandbox restores into <dest-root>/<sandbox-id>")
	concurrency := flag.Int("concurrency", 4, "bulk mode: parallel restores")
	execute := flag.Bool("execute", false, "bulk mode: actually materialize (default is a dry-run coverage ledger)")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: backup-restore -bucket <bucket> -sandbox <id> -generation <gen> -dest <dir>")
		fmt.Fprintln(os.Stderr, "       backup-restore -bucket <bucket> -sandbox <id>   (list restorable generations, newest first)")
		fmt.Fprintln(os.Stderr, "       backup-restore revive -manifest <file>          (cold-boot dead sandboxes from salvaged disks, on-host)")
		fmt.Fprintln(os.Stderr, "       backup-restore discrepancy -bucket <bucket>     (classify paused sandboxes lacking a verified backup; read-only)")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *hostRestore != "" {
		if *bucket == "" || *destRoot == "" {
			fmt.Fprintln(os.Stderr, "-host-restore requires -bucket and -dest-root")
			os.Exit(2)
		}
	} else if *bucket == "" || *sandbox == "" {
		flag.Usage()
		os.Exit(2)
	}
	if *generation != "" && *dest == "" {
		fmt.Fprintln(os.Stderr, "-dest is required with -generation")
		os.Exit(2)
	}
	if *generation == "" && *dest != "" {
		fmt.Fprintln(os.Stderr, "-dest without -generation: refusing to guess; pass -generation to restore, or drop -dest to list")
		os.Exit(2)
	}

	// A canceled context is how RestoreGeneration's all-or-nothing cleanup
	// runs on SIGINT/SIGTERM: default signal handling would kill the process
	// mid-write and leave a partial destination behind. After the first
	// signal, stop() restores default handling so a second ^C force-kills
	// instead of being swallowed by a cleanup that is itself stuck.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		stop()
	}()
	client, err := storage.NewClient(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "storage client: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()
	reader := backup.NewGCSReader(client, *bucket)

	if *hostRestore != "" {
		os.Exit(runHostRestore(ctx, reader, reader, *hostRestore, *dbURL, *sandboxesFile, *destRoot, *concurrency, *execute))
	}

	if *generation == "" {
		generations, err := backup.ListGenerations(ctx, reader, *sandbox)
		if err != nil {
			fmt.Fprintf(os.Stderr, "list generations: %v\n", err)
			os.Exit(1)
		}
		if len(generations) == 0 {
			fmt.Fprintf(os.Stderr, "no restorable generations for sandbox %s\n", *sandbox)
			os.Exit(1)
		}
		for _, g := range generations {
			fmt.Printf("%s  %s\n", g.Created.UTC().Format(time.RFC3339), g.Generation)
		}
		return
	}

	progress := func(format string, args ...any) {
		fmt.Printf(format+"\n", args...)
	}
	manifest, err := backup.RestoreGeneration(ctx, reader, *sandbox, *generation, *dest, progress)
	if err != nil {
		if errors.Is(err, backup.ErrGenerationIncomplete) {
			fmt.Fprintf(os.Stderr, "restore failed: %v\nthis generation was never completed and must not be restored from; pick another (omit -generation to list them)\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "restore failed: %v\n", err)
		}
		os.Exit(1)
	}
	var apparent, packed int64
	for _, f := range manifest.Files {
		apparent += f.Size
		packed += f.PackedSize
	}
	fmt.Printf("restored sandbox %s generation %s: %d files, %d bytes apparent (%d packed) into %s\n",
		manifest.SandboxID, manifest.Generation, len(manifest.Files), apparent, packed, *dest)
}
