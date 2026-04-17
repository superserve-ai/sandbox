package telemetry

import (
	"context"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
)

// newLoggerProvider builds an OTLP/gRPC log provider with a batch processor.
// Wired but not yet bridged from zerolog — Phase 1.5 will add that bridge so
// logs flow alongside traces in the same backend. For now logs continue to
// go to stdout/journald and the trace_id/span_id hook (zerolog.go) lets
// operators correlate manually.
func newLoggerProvider(ctx context.Context, res *sdkresource.Resource) (*sdklog.LoggerProvider, error) {
	exp, err := otlploggrpc.New(ctx)
	if err != nil {
		return nil, err
	}
	lp := sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exp)),
	)
	return lp, nil
}
