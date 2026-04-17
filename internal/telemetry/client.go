// Package telemetry wires OpenTelemetry traces, metrics, and logs through a
// single Client. All three signals export via OTLP/gRPC to the endpoint named
// by OTEL_EXPORTER_OTLP_ENDPOINT. When that env var is unset the Client is a
// no-op so local dev and tests have zero telemetry overhead.
//
// Usage from a binary's main:
//
//	tel, err := telemetry.New(ctx, "controlplane", version, nodeID)
//	if err != nil { return err }
//	defer tel.Shutdown(context.Background())
//
// The Client installs global tracer/meter/log providers, so downstream code
// uses otel.Tracer(...) / otel.Meter(...) without holding a reference.
package telemetry

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// EndpointEnv is the env var consulted by Client.New. When empty the client
// is a no-op.
const EndpointEnv = "OTEL_EXPORTER_OTLP_ENDPOINT"

// Client owns the SDK providers for one process. Hold the pointer for the
// lifetime of the binary and call Shutdown before exit.
type Client struct {
	TracerProvider *sdktrace.TracerProvider
	MeterProvider  *sdkmetric.MeterProvider
	LoggerProvider *sdklog.LoggerProvider

	enabled bool
}

// New initialises the telemetry providers. Returns a no-op Client when
// OTEL_EXPORTER_OTLP_ENDPOINT is unset; the returned Client is always safe
// to use and to Shutdown.
func New(ctx context.Context, serviceName, serviceVersion, nodeID string) (*Client, error) {
	endpoint := os.Getenv(EndpointEnv)
	if endpoint == "" {
		return &Client{}, nil
	}

	res, err := buildResource(ctx, serviceName, serviceVersion, nodeID)
	if err != nil {
		return nil, fmt.Errorf("build resource: %w", err)
	}

	tp, err := newTracerProvider(ctx, res)
	if err != nil {
		return nil, fmt.Errorf("tracer provider: %w", err)
	}
	mp, err := newMeterProvider(ctx, res)
	if err != nil {
		_ = tp.Shutdown(ctx)
		return nil, fmt.Errorf("meter provider: %w", err)
	}
	lp, err := newLoggerProvider(ctx, res)
	if err != nil {
		_ = tp.Shutdown(ctx)
		_ = mp.Shutdown(ctx)
		return nil, fmt.Errorf("logger provider: %w", err)
	}

	otel.SetTracerProvider(tp)
	otel.SetMeterProvider(mp)
	global.SetLoggerProvider(lp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return &Client{
		TracerProvider: tp,
		MeterProvider:  mp,
		LoggerProvider: lp,
		enabled:        true,
	}, nil
}

// Enabled reports whether the Client is exporting (i.e. EndpointEnv was set).
func (c *Client) Enabled() bool { return c != nil && c.enabled }

// Shutdown flushes and closes all providers. Safe to call on a no-op Client.
// Uses a bounded internal timeout so a stuck collector cannot hang process
// exit.
func (c *Client) Shutdown(ctx context.Context) error {
	if c == nil || !c.enabled {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var firstErr error
	if err := c.TracerProvider.Shutdown(ctx); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("tracer shutdown: %w", err)
	}
	if err := c.MeterProvider.Shutdown(ctx); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("meter shutdown: %w", err)
	}
	if err := c.LoggerProvider.Shutdown(ctx); err != nil && firstErr == nil {
		firstErr = fmt.Errorf("logger shutdown: %w", err)
	}
	return firstErr
}

func buildResource(_ context.Context, serviceName, serviceVersion, nodeID string) (*sdkresource.Resource, error) {
	if nodeID == "" {
		nodeID = os.Getenv("NODE_ID")
	}
	if nodeID == "" {
		if h, err := os.Hostname(); err == nil {
			nodeID = h
		} else {
			nodeID = "unknown"
		}
	}
	env := os.Getenv("ENVIRONMENT")
	if env == "" {
		env = "dev"
	}

	attrs := []attribute.KeyValue{
		semconv.ServiceName(serviceName),
		semconv.ServiceVersion(serviceVersion),
		semconv.ServiceInstanceID(uuid.NewString()),
		semconv.HostID(nodeID),
		semconv.DeploymentEnvironment(env),
	}
	return sdkresource.Merge(
		sdkresource.Default(),
		sdkresource.NewWithAttributes(semconv.SchemaURL, attrs...),
	)
}
