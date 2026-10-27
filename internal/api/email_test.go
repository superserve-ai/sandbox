package api

import (
	"bufio"
	"context"
	"errors"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEmailTransportSelectsSender(t *testing.T) {
	if s := (EmailTransport{}).Sender(""); s != nil {
		t.Fatalf("resend without a key = %T, want nil (feature disabled)", s)
	}
	if s, ok := (EmailTransport{}).Sender("re_key").(*ResendEmailSender); !ok || s.apiKey != "re_key" || s.endpoint != resendEmailEndpoint {
		t.Fatalf("default transport = %#v, want Resend with the feature key", s)
	}
	for _, key := range []string{"", "re_key"} {
		s, ok := (EmailTransport{SMTPAddr: "127.0.0.1:1025"}).Sender(key).(*SMTPEmailSender)
		if !ok || s.addr != "127.0.0.1:1025" {
			t.Fatalf("smtp transport with key %q = %#v, want SMTP and no Resend fallback", key, s)
		}
	}
}

type smtpTestServer struct {
	addr     string
	mu       sync.Mutex
	from, to string
	data     []byte
	messages [][]byte
	// Replies override the default 250 for a command ("MAIL", "RCPT", "DATA" end).
	replies map[string]string
}

func startSMTPTestServer(t *testing.T, replies map[string]string) *smtpTestServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &smtpTestServer{addr: ln.Addr().String(), replies: replies}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(conn)
		}
	}()
	return s
}

func (s *smtpTestServer) reply(cmd string) string {
	if r, ok := s.replies[cmd]; ok {
		return r
	}
	return "250 ok"
}

func (s *smtpTestServer) serve(conn net.Conn) {
	defer conn.Close()
	tp := textproto.NewConn(conn)
	_ = tp.PrintfLine("220 test ESMTP")
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		verb := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
		switch verb {
		case "EHLO", "HELO":
			_ = tp.PrintfLine("250 test")
		case "MAIL":
			s.mu.Lock()
			s.from = line
			s.mu.Unlock()
			_ = tp.PrintfLine("%s", s.reply("MAIL"))
		case "RCPT":
			s.mu.Lock()
			s.to = line
			s.mu.Unlock()
			_ = tp.PrintfLine("%s", s.reply("RCPT"))
		case "DATA":
			_ = tp.PrintfLine("354 go ahead")
			data, err := tp.ReadDotBytes()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.data = data
			s.messages = append(s.messages, append([]byte(nil), data...))
			s.mu.Unlock()
			_ = tp.PrintfLine("%s", s.reply("DATA"))
		case "QUIT":
			_ = tp.PrintfLine("221 bye")
			return
		default:
			_ = tp.PrintfLine("502 unsupported")
		}
	}
}

func TestSMTPEmailSenderDeliversMessage(t *testing.T) {
	srv := startSMTPTestServer(t, nil)
	sender := (EmailTransport{SMTPAddr: srv.addr}).Sender("")
	msg := EmailMessage{
		From:           "Superserve <billing@example.com>",
		To:             "owner@example.com",
		Subject:        "Your trial credit may run out soon — ünïcode",
		HTML:           "<p>Less than 24 hours: $1.23 remaining</p>",
		IdempotencyKey: "trial-credit-warning/example",
	}
	if err := sender.SendEmail(context.Background(), msg); err != nil {
		t.Fatalf("SendEmail: %v", err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.from != "MAIL FROM:<billing@example.com>" || srv.to != "RCPT TO:<owner@example.com>" {
		t.Fatalf("envelope = %q / %q", srv.from, srv.to)
	}
	parsed, err := mail.ReadMessage(strings.NewReader(string(srv.data)))
	if err != nil {
		t.Fatalf("message does not parse: %v", err)
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(parsed.Header.Get("Subject"))
	if err != nil || subject != msg.Subject {
		t.Fatalf("subject = %q (%v), want %q", subject, err, msg.Subject)
	}
	if got := parsed.Header.Get("Content-Type"); got != "text/html; charset=UTF-8" {
		t.Fatalf("content type = %q", got)
	}
	body, err := io.ReadAll(quotedprintable.NewReader(parsed.Body))
	if err != nil || strings.TrimSuffix(string(body), "\n") != msg.HTML {
		t.Fatalf("body = %q (%v), want %q", body, err, msg.HTML)
	}
	first := parsed.Header.Get("Message-Id")
	if first == "" || !strings.HasSuffix(first, "@example.com>") {
		t.Fatalf("message id = %q", first)
	}
	again, _, data, err := smtpMessage(msg, time.Now())
	if err != nil || again != "billing@example.com" || !strings.Contains(string(data), "Message-ID: "+first) {
		t.Fatal("message id must stay stable for the same idempotency key")
	}
}

func TestSMTPEmailSenderPlainTextBody(t *testing.T) {
	_, _, data, err := smtpMessage(EmailMessage{From: "a@example.com", To: "b@example.com", Subject: "s", Text: "line one\nline two"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "Content-Type: text/plain; charset=UTF-8\r\n") || !strings.Contains(string(data), "line one\r\nline two") {
		t.Fatalf("plain text message = %q", data)
	}
}

func TestSMTPEmailSenderErrorClassification(t *testing.T) {
	msg := EmailMessage{From: "billing@example.com", To: "owner@example.com", Subject: "s", Text: "t"}
	for _, tc := range []struct {
		name     string
		replies  map[string]string
		rejected bool
	}{
		{"recipient rejected", map[string]string{"RCPT": "550 no such user"}, true},
		{"sender refused is configuration", map[string]string{"MAIL": "553 sender not allowed"}, false},
		{"message rejected", map[string]string{"DATA": "554 message refused"}, true},
		{"recipient deferred", map[string]string{"RCPT": "451 try later"}, false},
		{"message deferred", map[string]string{"DATA": "452 insufficient storage"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := startSMTPTestServer(t, tc.replies)
			err := (EmailTransport{SMTPAddr: srv.addr}).Sender("").SendEmail(context.Background(), msg)
			var rejected *rejectedEmailError
			var unknown *unknownEmailOutcomeError
			if err == nil || errors.As(err, &rejected) != tc.rejected || errors.As(err, &unknown) {
				t.Fatalf("error = %v, want rejected=%t and a known outcome", err, tc.rejected)
			}
		})
	}
	t.Run("connection refused is retryable", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		_ = ln.Close()
		err = (EmailTransport{SMTPAddr: addr}).Sender("").SendEmail(context.Background(), msg)
		var rejected *rejectedEmailError
		var unknown *unknownEmailOutcomeError
		if err == nil || errors.As(err, &rejected) || errors.As(err, &unknown) {
			t.Fatalf("error = %v, want plain retryable error", err)
		}
	})
	t.Run("connection lost awaiting acceptance is unknown", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			r := bufio.NewReader(conn)
			_, _ = io.WriteString(conn, "220 test\r\n")
			for {
				line, err := r.ReadString('\n')
				if err != nil {
					return
				}
				switch {
				case strings.HasPrefix(line, "DATA"):
					_, _ = io.WriteString(conn, "354 go ahead\r\n")
				case line == ".\r\n":
					return
				case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "MAIL"), strings.HasPrefix(line, "RCPT"):
					_, _ = io.WriteString(conn, "250 ok\r\n")
				}
			}
		}()
		err = (EmailTransport{SMTPAddr: ln.Addr().String()}).Sender("").SendEmail(context.Background(), msg)
		var unknown *unknownEmailOutcomeError
		if !errors.As(err, &unknown) {
			t.Fatalf("error = %v, want unknown outcome", err)
		}
	})
}

func TestSMTPMessageRejectsHeaderInjection(t *testing.T) {
	for _, m := range []EmailMessage{
		{From: "billing@example.com\r\nBcc: x@example.com", To: "owner@example.com"},
		{From: "billing@example.com", To: "owner@example.com\r\nBcc: x@example.com"},
	} {
		if _, _, _, err := smtpMessage(m, time.Now()); err == nil {
			t.Fatalf("message %q/%q accepted, want address error", m.From, m.To)
		}
	}
	sender := &SMTPEmailSender{addr: "127.0.0.1:1", timeout: time.Second}
	var rejected *rejectedEmailError
	if err := sender.SendEmail(context.Background(), EmailMessage{From: "billing@example.com", To: "bad"}); !errors.As(err, &rejected) {
		t.Fatalf("invalid recipient error = %v, want permanent rejection", err)
	}
	if err := sender.SendEmail(context.Background(), EmailMessage{From: "bad", To: "owner@example.com"}); err == nil || errors.As(err, &rejected) {
		t.Fatalf("invalid sender error = %v, want retryable configuration error", err)
	}
}
