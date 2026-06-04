// Package sentrylog integrates zerolog with Sentry.
package sentrylog

import (
	"context"
	"encoding/json"

	"github.com/getsentry/sentry-go"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Writer is a zerolog LevelWriter that forwards warn and error events to
// Sentry. Use it inside a zerolog.MultiLevelWriter alongside the primary
// output writer. It is a no-op when Sentry has not been initialized.
type Writer struct{}

// Write satisfies io.Writer; actual forwarding happens in WriteLevel.
func (w *Writer) Write(p []byte) (int, error) { return len(p), nil }

// WriteLevel parses the zerolog JSON event and forwards warn/error/fatal
// levels to Sentry as captured messages with all log fields attached as extras.
func (w *Writer) WriteLevel(level zerolog.Level, p []byte) (int, error) {
	if level < zerolog.WarnLevel || sentry.CurrentHub().Client() == nil {
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

	extras := make(map[string]interface{}, len(fields))
	for k, v := range fields {
		extras[k] = v
	}
	for _, k := range []string{"level", "time", "message", "msg", "caller"} {
		delete(extras, k)
	}

	sentryLevel := sentry.LevelWarning
	if level >= zerolog.ErrorLevel {
		sentryLevel = sentry.LevelError
	}

	sentry.WithScope(func(scope *sentry.Scope) {
		scope.SetLevel(sentryLevel)
		scope.SetContext("log_fields", sentry.Context(extras))
		sentry.CaptureMessage(msg)
	})

	return len(p), nil
}

// RunSafe calls fn and recovers any panic, capturing it to Sentry and
// logging it via zerolog. The loop continues after the call returns.
// Use this for per-iteration work inside long-running goroutine loops so
// a single panic does not permanently kill the loop.
//
//	for {
//	    select {
//	    case <-ticker.C:
//	        sentrylog.RunSafe("reaper", func() { doWork(ctx) })
//	    }
//	}
func RunSafe(goroutine string, fn func()) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		log.Error().Interface("panic", r).Str("goroutine", goroutine).Msg("goroutine iteration panicked")
		sentry.CurrentHub().RecoverWithContext(context.Background(), r)
	}()
	fn()
}
