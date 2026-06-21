package step

import (
	"bufio"
	"encoding/json"
	"errors"
	"net"
	"os"
	"sync"
)

// Server serves the durable-step protocol over a unix socket, backed by a Log.
// The platform runs one per live Actor and exports its address as $ACTOR_STEP so
// the in-guest harness can record/recall steps that survive a crash.
type Server struct {
	log *Log
	ln  net.Listener

	mu    sync.Mutex
	conns map[net.Conn]struct{}
	done  bool
}

// Listen starts a step Server on a unix socket at addr, backed by log. Call
// Serve (typically in a goroutine) to accept connections, and Close to stop.
func Listen(addr string, log *Log) (*Server, error) {
	// Remove a stale socket from a previous (crashed) run so bind succeeds.
	if err := os.Remove(addr); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	ln, err := net.Listen("unix", addr)
	if err != nil {
		return nil, err
	}
	return &Server{log: log, ln: ln, conns: map[net.Conn]struct{}{}}, nil
}

// Addr returns the socket address the server is listening on.
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Serve accepts and handles connections until Close. It returns nil on a clean
// Close.
func (s *Server) Serve() error {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			s.mu.Lock()
			done := s.done
			s.mu.Unlock()
			if done || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		s.track(conn, true)
		go s.handle(conn)
	}
}

func (s *Server) track(c net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.conns[c] = struct{}{}
	} else {
		delete(s.conns, c)
	}
}

// handle services one connection: a stream of newline-delimited Requests, each
// answered with a Response. The harness may pipeline many steps on one conn.
func (s *Server) handle(conn net.Conn) {
	defer func() { conn.Close(); s.track(conn, false) }()
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	enc := json.NewEncoder(conn)
	for sc.Scan() {
		var req Request
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			_ = enc.Encode(Response{Error: "bad request: " + err.Error()})
			continue
		}
		_ = enc.Encode(s.serve(req))
	}
}

func (s *Server) serve(req Request) Response {
	switch req.Op {
	case OpRecall:
		v, found := s.log.Recall(req.Step)
		return Response{Found: found, Value: v}
	case OpRecord:
		v, err := s.log.Record(req.Step, req.Value)
		if err != nil {
			return Response{Error: err.Error()}
		}
		return Response{Found: true, Value: v}
	default:
		return Response{Error: "unknown op: " + string(req.Op)}
	}
}

// Close stops accepting, closes open connections, and removes the socket file.
func (s *Server) Close() error {
	s.mu.Lock()
	s.done = true
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	err := s.ln.Close()
	_ = os.Remove(s.Addr())
	return err
}
