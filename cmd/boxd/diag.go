package main

import (
	"fmt"
	"log"
	"sync"
)

// Lifecycle diagnostics go through one background writer, so no request
// waits on stderr. When the writer is backed up, lines are dropped rather
// than queued without bound.
var (
	diagOnce sync.Once
	diagCh   = make(chan string, 64)
)

func diagf(format string, args ...any) {
	diagOnce.Do(func() {
		go func() {
			for line := range diagCh {
				log.Print(line)
			}
		}()
	})
	select {
	case diagCh <- fmt.Sprintf(format, args...):
	default:
	}
}
