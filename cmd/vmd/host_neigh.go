package main

import (
	"os"
	"strconv"
	"strings"
)

const neighTableCapPath = "/proc/sys/net/ipv4/neigh/default/gc_thresh3"

// The cap must cover a neighbour entry per namespace on disk and never sit
// near the kernel default a rebuilt host boots with, or guests drop off the
// host under bursts.
const neighTableFloor = 4096

func neighTableShortfall(cap, netns int) int {
	need := max(netns, neighTableFloor)
	if cap >= need {
		return 0
	}
	return need - cap
}

func readNeighTableCap() (int, error) {
	b, err := os.ReadFile(neighTableCapPath)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}
