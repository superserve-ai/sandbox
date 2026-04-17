package telemetry

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// ReportEvent attaches a named event with attributes to the active span in
// ctx. No-op when no span is active. Use this at lifecycle boundaries
// (snapshot restored, network attached, VM resumed) — it shows up in the
// trace UI as a clickable marker on the timeline.
func ReportEvent(ctx context.Context, name string, attrs ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	if !span.IsRecording() {
		return
	}
	span.AddEvent(name, trace.WithAttributes(attrs...))
}

// ReportError records err on the active span and marks the span as failed.
// Returns err unchanged so callers can write `return telemetry.ReportError(...)`.
// No-op when no span is active.
func ReportError(ctx context.Context, msg string, err error, attrs ...attribute.KeyValue) error {
	span := trace.SpanFromContext(ctx)
	if span.IsRecording() {
		span.RecordError(err, trace.WithAttributes(attrs...))
		span.SetStatus(codes.Error, msg)
	}
	return err
}

// SetAttrs sets attributes on the active span. No-op when no span is active.
func SetAttrs(ctx context.Context, attrs ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	if span.IsRecording() {
		span.SetAttributes(attrs...)
	}
}
