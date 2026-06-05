// Package sentrylog integrates zerolog with Sentry.
package sentrylog

import (
	"context"
	"encoding/json"

	"github.com/getsentry/sentry-go"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Writer forwards error-level zerolog events to Sentry; a no-op until Sentry is
// initialized. Use it in a zerolog.MultiLevelWriter beside the primary output.
type Writer struct{}

// Write satisfies io.Writer; actual forwarding happens in WriteLevel.
func (w *Writer) Write(p []byte) (int, error) { return len(p), nil }

// WriteLevel forwards error/fatal zerolog events to Sentry with their fields;
// warnings are not forwarded (they stay in the primary log output only).
func (w *Writer) WriteLevel(level zerolog.Level, p []byte) (int, error) {
	if level < zerolog.ErrorLevel || sentry.CurrentHub().Client() == nil {
		return len(p), nil
	}

	var fields map[string]interface{}
	if err := json.Unmarshal(p, &fields); err != nil {
		return len(p), nil
	}

	msg, _ := fields["message"].(string)
	if msg == "" {
		msg, _ = fields["msg"].(string)
	}
	errStr, _ := fields["error"].(string)
	caller, _ := fields["caller"].(string)

	extras := make(map[string]interface{}, len(fields))
	for k, v := range fields {
		extras[k] = v
	}
	// caller is promoted to a tag below, so drop it here to avoid duplication.
	for _, k := range []string{"level", "time", "message", "msg", "caller"} {
		delete(extras, k)
	}

	sentry.WithScope(func(scope *sentry.Scope) {
		scope.SetLevel(sentry.LevelError)
		// High-signal fields as tags (header + searchable); rest as context.
		for _, k := range []string{"component", "caller", "sandbox_id", "build_id", "template_id", "host_id"} {
			if v, ok := fields[k].(string); ok && v != "" {
				scope.SetTag(k, v)
			}
		}
		scope.SetContext("log", sentry.Context(extras))
		// Group by log site so variable error text doesn't fragment one issue.
		if caller != "" {
			scope.SetFingerprint([]string{msg, caller})
		}
		// Put the error in the title, not buried in a context.
		if errStr != "" {
			sentry.CaptureMessage(msg + ": " + errStr)
		} else {
			sentry.CaptureMessage(msg)
		}
	})

	return len(p), nil
}

// Recover reports a panic in the calling goroutine to Sentry instead of letting
// it crash the process. Use as the first deferred call in a goroutine.
func Recover(goroutine string) {
	r := recover()
	if r == nil {
		return
	}
	log.Error().Interface("panic", r).Str("goroutine", goroutine).Msg("goroutine panicked")
	sentry.CurrentHub().RecoverWithContext(context.Background(), r)
}

// RunSafe runs fn and recovers any panic (see Recover) so one panic doesn't kill
// a long-running loop.
func RunSafe(goroutine string, fn func()) {
	defer Recover(goroutine)
	fn()
}
