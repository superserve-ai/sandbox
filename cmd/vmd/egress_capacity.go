package main

import (
	"fmt"
	"strconv"

	"github.com/superserve-ai/sandbox/internal/network"
)

func egressCapacityConfig(getenv func(string) string) (network.EgressCapacity, error) {
	c := network.EgressCapacity{MaxConnections: network.DefaultEgressMaxConnections}
	if value := getenv("VMD_EGRESS_MAX_CONNECTIONS"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil {
			return c, fmt.Errorf("VMD_EGRESS_MAX_CONNECTIONS must be a positive integer")
		}
		c.MaxConnections = n
	}
	if value := getenv("VMD_EGRESS_ENFORCE"); value != "" {
		if value != "true" && value != "false" {
			return c, fmt.Errorf("VMD_EGRESS_ENFORCE must be true or false")
		}
		c.Enforce = value == "true"
	}
	return c, c.Validate()
}

// Reserve descriptors for VMD/control work and allow four per admitted flow
// for client, upstream and transient resolver/parallel-dial sockets. This is
// a startup guard, not a substitute for measured production headroom.
func validateEgressFDHeadroom(c network.EgressCapacity, softLimit uint64) error {
	const reserve = 4096
	if c.Enforce && (softLimit <= reserve || uint64(c.MaxConnections) > (softLimit-reserve)/4) {
		return fmt.Errorf("egress limit leaves insufficient FD headroom under soft limit %d", softLimit)
	}
	return nil
}
