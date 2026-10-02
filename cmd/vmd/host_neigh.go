package main

import (
	"os"
	"strconv"
	"strings"
)

const neighTableCapPath = "/proc/sys/net/ipv4/neigh/default/gc_thresh3"

// A host still at the kernel default was not provisioned; every slot is a
// host-side veth with its own neighbour entry and bursts overflow 1024.
const kernelDefaultNeighTableCap = 1024

func readNeighTableCap() (int, error) {
	b, err := os.ReadFile(neighTableCapPath)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}
