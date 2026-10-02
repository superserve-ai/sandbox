package proxy

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestDrainHijackedConnection(t *testing.T) {
	for _, finish := range []bool{true, false} {
		t.Run(map[bool]string{true: "early completion", false: "force at cap"}[finish], func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			tracker := NewDrainConnections()
			hijacked := make(chan net.Conn, 1)
			srv := NewServer("", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				hijacked <- c
			}))
			srv.ConnState = tracker.ConnState
			go srv.Serve(tracker.Listener(listener))
			defer srv.Close()
			client, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
			var server net.Conn
			select {
			case server = <-hijacked:
			case <-time.After(time.Second):
				t.Fatal("no hijack")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- tracker.Shutdown(ctx, srv, zerolog.Nop()) }()
			select {
			case <-done:
				t.Fatal("hijacked work was not retained")
			case <-time.After(20 * time.Millisecond):
			}
			if finish {
				_ = server.Close()
			}
			select {
			case err := <-done:
				if finish && err != nil {
					t.Fatal(err)
				}
				if !finish && err != context.DeadlineExceeded {
					t.Fatalf("got %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("drain exceeded cap")
			}
			_ = client.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := bufio.NewReader(client).ReadByte(); err == nil {
				t.Fatal("connection still open")
			}
		})
	}
}

func TestDrainStuckHTTP(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tracker := NewDrainConnections()
	started, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	srv := NewServer("", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-release }))
	srv.ConnState = tracker.ConnState
	go srv.Serve(tracker.Listener(l))
	defer srv.Close()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := tracker.Shutdown(ctx, srv, zerolog.Nop()); err != context.DeadlineExceeded {
		t.Fatalf("got %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("stuck HTTP connection still open")
	}
}
