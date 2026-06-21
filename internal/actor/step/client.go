package step

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
)

// Client is the harness side of the durable-step protocol. It dials the step
// server (the $ACTOR_STEP unix socket) and records/recalls steps over one
// connection. Safe for sequential use within an agent's turn; guard with a
// mutex for concurrent steps.
type Client struct {
	mu   sync.Mutex
	conn net.Conn
	enc  *json.Encoder
	sc   *bufio.Scanner
}

// Dial connects to the step server at addr.
func Dial(addr string) (*Client, error) {
	conn, err := net.Dial("unix", addr)
	if err != nil {
		return nil, fmt.Errorf("step: dial %s: %w", addr, err)
	}
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	return &Client{conn: conn, enc: json.NewEncoder(conn), sc: sc}, nil
}

// DialFromEnv connects using the $ACTOR_STEP address. Returns an error if the
// variable is unset (i.e. the platform did not provision Level-2 durability).
func DialFromEnv() (*Client, error) {
	addr := os.Getenv(EnvVar)
	if addr == "" {
		return nil, fmt.Errorf("step: $%s not set (Level-2 durability unavailable)", EnvVar)
	}
	return Dial(addr)
}

func (c *Client) roundtrip(req Request) (Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.enc.Encode(req); err != nil {
		return Response{}, err
	}
	if !c.sc.Scan() {
		if err := c.sc.Err(); err != nil {
			return Response{}, err
		}
		return Response{}, fmt.Errorf("step: server closed the connection")
	}
	var resp Response
	if err := json.Unmarshal(c.sc.Bytes(), &resp); err != nil {
		return Response{}, err
	}
	if resp.Error != "" {
		return resp, fmt.Errorf("step: server error: %s", resp.Error)
	}
	return resp, nil
}

// Recall returns the memoized raw value for name and whether it exists.
func (c *Client) Recall(name string) (json.RawMessage, bool, error) {
	resp, err := c.roundtrip(Request{Op: OpRecall, Step: name})
	if err != nil {
		return nil, false, err
	}
	return resp.Value, resp.Found, nil
}

// Record durably memoizes value under name (idempotent). Returns the committed
// value (the pre-existing one if the step was already recorded).
func (c *Client) Record(name string, value json.RawMessage) (json.RawMessage, error) {
	resp, err := c.roundtrip(Request{Op: OpRecord, Step: name, Value: value})
	if err != nil {
		return nil, err
	}
	return resp.Value, nil
}

// Close closes the connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

// Step is the fiber primitive: it runs fn exactly once across replays. On first
// execution it runs fn and durably records the JSON-encoded result; on replay
// (a fresh process after a crash) it returns the recorded result without running
// fn — so already-performed work and its side effects are not repeated and the
// harness fast-forwards to the interruption point.
//
// fn should be the unit of work whose result must be stable across replays (an
// LLM call, a tool invocation, a non-idempotent side effect). It is a free
// function (not a method) so it can be generic over the result type.
func Step[T any](c *Client, name string, fn func() (T, error)) (T, error) {
	var zero T
	if raw, found, err := c.Recall(name); err != nil {
		return zero, err
	} else if found {
		var v T
		if err := json.Unmarshal(raw, &v); err != nil {
			return zero, fmt.Errorf("step %q: decode memoized value: %w", name, err)
		}
		return v, nil
	}
	v, err := fn()
	if err != nil {
		// Not recorded: an errored step is retried on replay (no memoization of
		// failures), which is the desired at-least-once-until-success semantic.
		return zero, err
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return zero, fmt.Errorf("step %q: encode result: %w", name, err)
	}
	if _, err := c.Record(name, raw); err != nil {
		return zero, err
	}
	return v, nil
}
