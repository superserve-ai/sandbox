package telemetry

import (
	"context"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// newTracerProvider builds an OTLP/gRPC tracer provider with a batch
// processor. Sampling is AlwaysSample at the SDK; if volume becomes a
// problem we add tail sampling at the collector instead.
//
// Endpoint, headers, and TLS come from the standard OTEL_EXPORTER_OTLP_*
// env vars, so operators get the full OTel config surface for free.
func newTracerProvider(ctx context.Context, res *sdkresource.Resource) (*sdktrace.TracerProvider, error) {
	exp, err := otlptrace.New(ctx, otlptracegrpc.NewClient())
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	return tp, nil
}
