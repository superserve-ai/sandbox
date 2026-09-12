package api

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestTrialWarningPreTransmissionFailuresAreRetryable(t *testing.T) {
	for _, failure := range []struct {
		name string
		err  error
	}{
		{"dns", &net.DNSError{Err: "temporary lookup failure", Name: "example.com", IsTemporary: true}},
		{"tcp", &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}},
	} {
		t.Run(failure.name, func(t *testing.T) {
			transport := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
				return nil, failure.err
			}}
			defer transport.CloseIdleConnections()
			sender := &ResendTrialCreditWarningSender{endpoint: "https://example.com/emails", client: &http.Client{Transport: transport, Timeout: time.Second}}
			err := sender.sendEmail(context.Background(), []byte(`{}`))
			if !errors.Is(err, failure.err) {
				t.Fatalf("error = %v, want %v", err, failure.err)
			}
			assertTrialWarningTransportOutcome(t, err, false)
		})
	}
	t.Run("tls", func(t *testing.T) {
		var requests atomic.Int32
		server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			requests.Add(1)
		}))
		defer server.Close()
		// The test server's certificate is deliberately not trusted.
		transport := &http.Transport{}
		defer transport.CloseIdleConnections()
		sender := &ResendTrialCreditWarningSender{endpoint: server.URL, client: &http.Client{Transport: transport, Timeout: time.Second}}
		assertTrialWarningTransportOutcome(t, sender.sendEmail(context.Background(), []byte(`{}`)), false)
		if requests.Load() != 0 {
			t.Fatal("TLS failure reached the request handler")
		}
	})
}

func TestTrialWarningAmbiguousTransportFailuresRemainUnknown(t *testing.T) {
	t.Run("response lost after submission", func(t *testing.T) {
		var requests atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			requests.Add(1)
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = conn.Close()
		}))
		defer server.Close()
		sender := &ResendTrialCreditWarningSender{endpoint: server.URL, client: server.Client()}
		assertTrialWarningTransportOutcome(t, sender.sendEmail(context.Background(), []byte(`{}`)), true)
		if requests.Load() != 1 {
			t.Fatalf("provider requests = %d, want 1", requests.Load())
		}
	})
	t.Run("partial write", func(t *testing.T) {
		clientConn, peer := net.Pipe()
		defer peer.Close()
		conn := &trialWarningPartialWriteConn{Conn: clientConn}
		transport := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
			return conn, nil
		}}
		defer transport.CloseIdleConnections()
		sender := &ResendTrialCreditWarningSender{endpoint: "http://example.com/emails", client: &http.Client{Transport: transport, Timeout: time.Second}}
		assertTrialWarningTransportOutcome(t, sender.sendEmail(context.Background(), []byte(`{}`)), true)
		if !conn.wrote.Load() {
			t.Fatal("request never attempted a write")
		}
	})
	t.Run("untraced transport", func(t *testing.T) {
		sender := &ResendTrialCreditWarningSender{endpoint: "https://example.com/emails", client: &http.Client{Transport: trialWarningUntracedTransport{}}}
		assertTrialWarningTransportOutcome(t, sender.sendEmail(context.Background(), []byte(`{}`)), true)
	})
}

func assertTrialWarningTransportOutcome(t *testing.T, err error, wantUnknown bool) {
	t.Helper()
	if err == nil {
		t.Fatal("transport failure returned success")
	}
	var unknown UnknownTrialCreditWarningOutcome
	if got := errors.As(err, &unknown) && unknown.UnknownTrialCreditWarning(); got != wantUnknown {
		t.Fatalf("unknown outcome = %v, want %v: %v", got, wantUnknown, err)
	}
}

type trialWarningPartialWriteConn struct {
	net.Conn
	wrote atomic.Bool
}

func (c *trialWarningPartialWriteConn) Write([]byte) (int, error) {
	c.wrote.Store(true)
	return 1, io.ErrUnexpectedEOF
}

type trialWarningUntracedTransport struct{}

func (trialWarningUntracedTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, io.ErrUnexpectedEOF
}
