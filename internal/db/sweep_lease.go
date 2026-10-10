package db

import (
	"fmt"
	"math/rand/v2"
	"os"
	"sync"
)

// SweepHolderID names this process in a sweep lease row, stable for its
// lifetime so the holder's own renewal is recognised as a renewal. The pid
// separates replicas sharing a hostname; the random suffix separates
// processes within a test binary.
var SweepHolderID = sync.OnceValue(func() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown-host"
	}
	return fmt.Sprintf("%s-%d-%08x", host, os.Getpid(), rand.Uint32())
})
