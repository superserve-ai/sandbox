package telemetry

import (
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/trace"
)

// ZerologTraceHook injects trace_id and span_id from the active span (if
// any) into every log event. Install once at process start:
//
//	log.Logger = log.Logger.Hook(telemetry.ZerologTraceHook{})
//
// Zerolog hooks don't have access to context.Context directly, so callers
// must use log.Ctx(ctx) / log.With().Ctx(ctx) when emitting logs they want
// correlated. Lines without a context get no trace fields — same as today.
type ZerologTraceHook struct{}

func (ZerologTraceHook) Run(e *zerolog.Event, _ zerolog.Level, _ string) {
	ctx := e.GetCtx()
	if ctx == nil {
		return
	}
	sc := trace.SpanContextFromContext(ctx)
	if sc.HasTraceID() {
		e.Str("trace_id", sc.TraceID().String())
	}
	if sc.HasSpanID() {
		e.Str("span_id", sc.SpanID().String())
	}
}
