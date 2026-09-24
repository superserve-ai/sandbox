package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

const DefaultDrainGrace = 30 * time.Second

// Connections remain owned after Hijack; net/http no longer closes them then.
// Observing Close on the actual connection also covers reverse-proxy upgrades.
type DrainConnections struct {
	mu      sync.Mutex
	conns   map[*drainConn]bool
	changed chan struct{}
}

type drainConn struct {
	net.Conn
	owner *DrainConnections
	once  sync.Once
}

func (c *drainConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		c.owner.mu.Lock()
		delete(c.owner.conns, c)
		close(c.owner.changed)
		c.owner.changed = make(chan struct{})
		c.owner.mu.Unlock()
	})
	return err
}

func (c *drainConn) CloseWrite() error {
	if writer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return writer.CloseWrite()
	}
	return nil
}

type drainListener struct {
	net.Listener
	owner *DrainConnections
}

func (l drainListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	wrapped := &drainConn{Conn: c, owner: l.owner}
	l.owner.mu.Lock()
	l.owner.conns[wrapped] = false
	l.owner.mu.Unlock()
	return wrapped, nil
}

func NewDrainConnections() *DrainConnections {
	return &DrainConnections{conns: make(map[*drainConn]bool), changed: make(chan struct{})}
}
func (d *DrainConnections) Listener(l net.Listener) net.Listener { return drainListener{l, d} }
func (d *DrainConnections) ConnState(c net.Conn, state http.ConnState) {
	if state != http.StateHijacked {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if c, ok := c.(*drainConn); ok {
		if _, exists := d.conns[c]; exists {
			d.conns[c] = true
		}
	}
}

// Shutdown shares one absolute deadline between HTTP and upgraded connections.
// Closing connections at the cap does not wait for a stuck handler to return.
func (d *DrainConnections) Shutdown(ctx context.Context, srv *http.Server, log zerolog.Logger) error {
	httpDone := make(chan error, 1)
	go func() { httpDone <- srv.Shutdown(ctx) }()
	err := <-httpDone
	for {
		d.mu.Lock()
		if len(d.conns) == 0 {
			d.mu.Unlock()
			return err
		}
		changed := d.changed
		if ctx.Err() != nil {
			conns := make([]*drainConn, 0, len(d.conns))
			upgraded := 0
			for c, hijacked := range d.conns {
				conns = append(conns, c)
				if hijacked {
					upgraded++
				}
			}
			d.mu.Unlock()
			for _, c := range conns {
				_ = c.Close()
			}
			_ = srv.Close()
			log.Warn().Int("forced_http", len(conns)-upgraded).Int("forced_upgraded", upgraded).Msg("proxy drain deadline reached")
			return ctx.Err()
		}
		d.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
		}
	}
}

func ListenAndServeWithDrain(ctx context.Context, addr string, handler http.Handler, grace time.Duration, log zerolog.Logger) error {
	return ServeWithDrain(ctx, nil, addr, handler, grace, log)
}

// ServeWithDrain tracks connections accepted from either an inherited listener
// or a generation-specific listener bound here.
func ServeWithDrain(ctx context.Context, listener net.Listener, addr string, handler http.Handler, grace time.Duration, log zerolog.Logger) error {
	var err error
	if listener == nil {
		listener, err = net.Listen("tcp", addr)
		if err != nil {
			return err
		}
	}
	srv := NewServer(addr, handler)
	connections := NewDrainConnections()
	srv.ConnState = connections.ConnState
	done := make(chan error, 1)
	go func() { done <- srv.Serve(connections.Listener(listener)) }()
	log.Info().Str("addr", addr).Msg("proxy listening")
	select {
	case err = <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		deadline, cancel := context.WithTimeout(context.Background(), grace)
		defer cancel()
		log.Info().Dur("grace", grace).Msg("proxy drain started")
		err = connections.Shutdown(deadline, srv, log)
		<-done
		log.Info().Bool("forced", err != nil).Msg("proxy drain completed")
		if errors.Is(err, context.DeadlineExceeded) {
			return nil
		}
		return err
	}
}
