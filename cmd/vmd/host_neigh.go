package main

import (
	"os"
	"strconv"
	"strings"
)

const neighTableCapPath = "/proc/sys/net/ipv4/neigh/default/gc_thresh3"

// Every slot is a host-side veth with its own neighbour entry, so the kernel
// cap must cover the live namespaces plus the warm pool or guests drop off
// the host under bursts.
func neighTableShortfall(cap, slots int) int {
	if cap >= slots {
		return 0
	}
	return slots - cap
}

func readNeighTableCap() (int, error) {
	b, err := os.ReadFile(neighTableCapPath)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}
