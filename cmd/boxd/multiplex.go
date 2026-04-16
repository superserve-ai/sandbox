package main

import (
	"sync"
	"sync/atomic"
)

// MultiplexedChannel fans an event stream out to one or more consumers.
// Producers push events to Source; a background goroutine drains Source
// and forwards a copy to each consumer channel registered via Fork.
//
// Purpose: connect-go's ServerStream.Send is not safe for concurrent
// use. When two goroutines (e.g., stdout and stderr readers) both call
// Send, their writes race the underlying HTTP/1.1 chunked body writer
// and produce malformed frames on the wire. Routing all events through
// a single consumer goroutine avoids that. Multi-consumer support lets
// future subscribers (persistent log buffer, audit sink, live tail) be
// added with a Fork call instead of restructuring the producer path.
//
// The pattern mirrors e2b-infra's envd MultiplexedChannel.
type MultiplexedChannel[T any] struct {
	Source chan T

	mu       sync.RWMutex
	channels []chan T
	exited   atomic.Bool
}

// NewMultiplexedChannel starts a drain goroutine and returns a new
// multiplexer. Closing Source stops the drain, then closes every
// registered consumer channel so range loops exit cleanly.
func NewMultiplexedChannel[T any](buffer int) *MultiplexedChannel[T] {
	m := &MultiplexedChannel[T]{
		Source: make(chan T, buffer),
	}

	go func() {
		for v := range m.Source {
			m.mu.RLock()
			for _, cons := range m.channels {
				cons <- v
			}
			m.mu.RUnlock()
		}

		m.exited.Store(true)
		m.mu.Lock()
		for _, cons := range m.channels {
			close(cons)
		}
		m.mu.Unlock()
	}()

	return m
}

// Fork registers a new consumer. The caller must drain the returned
// channel; unbuffered sends from the drain goroutine will otherwise
// block all consumers. Call the returned cancel func to unregister
// before Source is closed.
func (m *MultiplexedChannel[T]) Fork() (<-chan T, func()) {
	if m.exited.Load() {
		ch := make(chan T)
		close(ch)
		return ch, func() {}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	consumer := make(chan T, 1)
	m.channels = append(m.channels, consumer)

	return consumer, func() { m.remove(consumer) }
}

func (m *MultiplexedChannel[T]) remove(consumer chan T) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, ch := range m.channels {
		if ch == consumer {
			m.channels = append(m.channels[:i], m.channels[i+1:]...)
			return
		}
	}
}
