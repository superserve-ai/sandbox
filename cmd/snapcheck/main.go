// Command snapcheck compares two Firecracker guest-memory snapshot files page
// by page and reports any pages that differ. It is the correctness gate for
// incremental snapshots: a written page the change set misses makes the restored
// VM's memory differ from the original — silent corruption this catches.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	pageSize := flag.Int("page-size", 4096, "page size in bytes")
	maxReport := flag.Int("max-report", 20, "max differing page offsets to print")
	presence := flag.Bool("presence", false,
		"compare as layered overlay/side-car pairs (<mem>.presence required next to each input): "+
			"presence bits page by page, bytes only where both sides provide the page. "+
			"Raw byte comparison is blind to presence — two byte-identical overlays can restore differently.")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: snapcheck [flags] <mem-a> <mem-b>")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(2)
	}
	if *pageSize <= 0 {
		fmt.Fprintln(os.Stderr, "page-size must be positive")
		os.Exit(2)
	}

	if *presence {
		res, err := comparePresenceAware(flag.Arg(0), flag.Arg(1), *pageSize)
		if err != nil {
			fmt.Fprintf(os.Stderr, "snapcheck: %v\n", err)
			os.Exit(2)
		}
		fmt.Printf("pages: %d  presence-differing: %d  content-differing: %d\n",
			res.totalPages, len(res.presenceDiff), len(res.contentDiff))
		reportPages("presence ", res.presenceDiff, *pageSize, *maxReport)
		reportPages("content ", res.contentDiff, *pageSize, *maxReport)
		if len(res.presenceDiff) > 0 || len(res.contentDiff) > 0 {
			os.Exit(1)
		}
		fmt.Println("identical")
		return
	}

	res, err := compareFiles(flag.Arg(0), flag.Arg(1), *pageSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "snapcheck: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf("pages: %d  differing: %d\n", res.totalPages, len(res.diffPages))
	reportPages("", res.diffPages, *pageSize, *maxReport)
	if len(res.diffPages) > 0 {
		os.Exit(1)
	}
	fmt.Println("identical")
}

// reportPages prints up to maxReport page indices with their byte offsets.
// prefix distinguishes the diff kind in presence mode ("presence ", "content ")
// and is empty for the raw byte compare.
func reportPages(prefix string, pages []int, pageSize, maxReport int) {
	for i, p := range pages {
		if i >= maxReport {
			fmt.Printf("  ... %d more\n", len(pages)-maxReport)
			break
		}
		fmt.Printf("  %spage %d  offset 0x%x\n", prefix, p, int64(p)*int64(pageSize))
	}
}

type compareResult struct {
	totalPages int
	diffPages  []int // page indices that differ
}

// compareFiles compares a and b page by page, erroring if they differ in length
// (a mem file's size is fixed, so a mismatch means they aren't comparable).
func compareFiles(pathA, pathB string, pageSize int) (compareResult, error) {
	fa, err := os.Open(pathA)
	if err != nil {
		return compareResult{}, err
	}
	defer fa.Close()
	fb, err := os.Open(pathB)
	if err != nil {
		return compareResult{}, err
	}
	defer fb.Close()

	return comparePages(fa, fb, pageSize)
}

// comparePages reads a and b in lockstep, one page at a time, recording the
// index of every page whose bytes differ.
func comparePages(a, b io.Reader, pageSize int) (compareResult, error) {
	bufA := make([]byte, pageSize)
	bufB := make([]byte, pageSize)
	var res compareResult

	for page := 0; ; page++ {
		nA, errA := io.ReadFull(a, bufA)
		nB, errB := io.ReadFull(b, bufB)

		endA := errors.Is(errA, io.EOF)
		endB := errors.Is(errB, io.EOF)
		if endA && endB {
			return res, nil // both ended cleanly on a page boundary
		}
		// Surface a real read error (e.g. EIO) before inferring a length mismatch.
		// EOF/ErrUnexpectedEOF aren't real errors: EOF is handled above and as a
		// length mismatch below; a short final page (ErrUnexpectedEOF) is fine.
		if errA != nil && !endA && !errors.Is(errA, io.ErrUnexpectedEOF) {
			return res, fmt.Errorf("read a: %w", errA)
		}
		if errB != nil && !endB && !errors.Is(errB, io.ErrUnexpectedEOF) {
			return res, fmt.Errorf("read b: %w", errB)
		}
		if endA != endB || nA != nB {
			return res, fmt.Errorf("mem files differ in length (page %d: %d vs %d bytes)", page, nA, nB)
		}

		res.totalPages++
		if !bytes.Equal(bufA[:nA], bufB[:nB]) {
			res.diffPages = append(res.diffPages, page)
		}

		if errors.Is(errA, io.ErrUnexpectedEOF) {
			return res, nil // last (partial) page consumed
		}
	}
}
