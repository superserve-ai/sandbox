package api

import (
	"context"
	"io"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/config"
)

func TestYCConsoleOriginRequiresLocalConfigurationForHTTP(t *testing.T) {
	// Environment changes must not override the loaded bind or selected sender.
	t.Setenv("API_HOST", "127.0.0.1")
	t.Setenv("EMAIL_TRANSPORT", "smtp")
	t.Setenv("SMTP_HOST", "127.0.0.1")
	t.Setenv("OTEL_ENVIRONMENT", "dev")
	for _, tc := range []struct {
		name, bind, smtp string
		noConfig         bool
		allowed          bool
	}{
		{name: "local devbox", bind: "127.0.0.1", smtp: "127.0.0.1:1025", allowed: true},
		{name: "local IPv6", bind: "::1", smtp: "[::1]:1025", allowed: true},
		{name: "localhost SMTP", bind: "127.0.0.1", smtp: "localhost:1025", allowed: true},
		{name: "no configuration", noConfig: true, smtp: "127.0.0.1:1025"},
		{name: "default transport", bind: "127.0.0.1"},
		{name: "default bind", smtp: "127.0.0.1:1025"},
		{name: "wildcard bind", bind: "0.0.0.0", smtp: "127.0.0.1:1025"},
		{name: "IPv6 wildcard bind", bind: "::", smtp: "127.0.0.1:1025"},
		{name: "remote bind", bind: "192.0.2.1", smtp: "127.0.0.1:1025"},
		{name: "DNS bind", bind: "localhost", smtp: "127.0.0.1:1025"},
		{name: "remote SMTP", bind: "127.0.0.1", smtp: "192.0.2.1:1025"},
		{name: "DNS SMTP", bind: "127.0.0.1", smtp: "mail.example.test:1025"},
		{name: "missing SMTP port", bind: "127.0.0.1", smtp: "127.0.0.1"},
		{name: "invalid SMTP port", bind: "127.0.0.1", smtp: "127.0.0.1:0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handlers{EmailTransport: EmailTransport{SMTPAddr: tc.smtp}}
			if !tc.noConfig {
				h.Config = &config.Config{Host: tc.bind, SMTPAddr: "127.0.0.1:1025"}
			}
			t.Setenv("YC_CONSOLE_URL", "http://localhost:3000")
			got, err := h.ycConsoleOrigin()
			if (err == nil) != tc.allowed || (tc.allowed && got != "http://localhost:3000") {
				t.Fatalf("origin = %q, error = %v; allowed = %t", got, err, tc.allowed)
			}
			t.Setenv("YC_CONSOLE_URL", "https://console.example.test/")
			if got, err := h.ycConsoleOrigin(); err != nil || got != "https://console.example.test" {
				t.Fatalf("HTTPS origin = %q, error = %v", got, err)
			}
		})
	}
}

func TestYCConsoleOriginRejectsNonliteralAndUnsafeLocalURLs(t *testing.T) {
	h := &Handlers{Config: &config.Config{Host: "127.0.0.1"}, EmailTransport: EmailTransport{SMTPAddr: "127.0.0.1:1025"}}
	for _, origin := range []string{"http://localhost", "http://localhost:3000", "http://127.0.0.1:46300", "http://[::1]:3000", "http://[::1]"} {
		t.Run(origin, func(t *testing.T) {
			t.Setenv("YC_CONSOLE_URL", origin+"/")
			if got, err := h.ycConsoleOrigin(); err != nil || got != origin {
				t.Fatalf("origin = %q, error = %v", got, err)
			}
		})
	}
	for _, origin := range []string{
		"http://console.example.test", "http://192.0.2.1", "http://0.0.0.0", "http://[::]",
		"http://localhost.example.test", "http://console.localhost", "http://localhost.",
		"http://127.1", "http://2130706433", "http://127.0.0.2", "http://[::ffff:127.0.0.1]",
		"http://user@localhost:3000", "http://localhost:3000/path", "http://localhost:3000/%2f",
		"http://localhost:3000?query=yes", "http://localhost:3000?", "http://localhost:3000#fragment",
		"http://localhost:", "http://localhost:0", "http://localhost:65536", "http://localhost:abc",
		"http://[localhost]:3000", "http://[::1%25lo0]:3000", "//localhost:3000", "ftp://localhost:3000",
		"https://user@console.example.test", "https://console.example.test/path",
		"https://console.example.test?query=yes", "https://console.example.test#fragment", "",
	} {
		t.Run(origin, func(t *testing.T) {
			t.Setenv("YC_CONSOLE_URL", origin)
			if got, err := h.ycConsoleOrigin(); err == nil || got != "" {
				t.Fatalf("unsafe origin accepted: %q (%v)", got, err)
			}
		})
	}
}

func TestYCClaimMailDeliversGeneratedLocalConfirmationOverSMTP(t *testing.T) {
	srv := startSMTPTestServer(t, nil)
	h := &Handlers{Config: &config.Config{Host: "127.0.0.1"}, EmailTransport: EmailTransport{SMTPAddr: srv.addr}}
	t.Setenv("YC_CONSOLE_URL", "http://127.0.0.1:46300")
	origin, err := h.ycConsoleOrigin()
	if err != nil {
		t.Fatal(err)
	}
	j := ycMailJob{ClaimID: uuid.New(), MessageID: uuid.New(), Email: "founder@example.test", Token: strings.Repeat("a", 43)}
	var firstID string
	for range 2 {
		if err := sendYCClaimMail(context.Background(), h.EmailTransport.Sender(""), origin, "hello@example.test", j); err != nil {
			t.Fatal(err)
		}
		srv.mu.Lock()
		data, recipient := string(srv.data), srv.to
		srv.mu.Unlock()
		if recipient != "RCPT TO:<founder@example.test>" {
			t.Fatalf("recipient changed: %q", recipient)
		}
		message, err := mail.ReadMessage(strings.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(quotedprintable.NewReader(message.Body))
		if err != nil {
			t.Fatal(err)
		}
		link := "http://127.0.0.1:46300/yc/confirm#claim=" + j.ClaimID.String() + "&token=" + j.Token
		if !strings.Contains(string(body), link) || !strings.Contains(string(body), "This link expires in 24 hours.") {
			t.Fatal("generated local confirmation link or expiry changed")
		}
		id := message.Header.Get("Message-Id")
		if id == "" || (firstID != "" && id != firstID) {
			t.Fatal("confirmation retry message identity changed")
		}
		firstID = id
	}
}
