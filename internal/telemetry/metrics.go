package telemetry

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
)

// newMeterProvider builds an OTLP/gRPC meter provider.
//
// Two non-default choices that matter at scale:
//
//  1. Delta temporality. Per-sandbox gauges (Phase 2) only publish a series
//     while the sandbox is alive; cumulative temporality would keep stale
//     series forever and explode backend storage.
//
//  2. Base2 exponential histograms by default. Auto-bucketing means we don't
//     have to pre-tune buckets per metric, and the backend gets a uniformly
//     compact representation. MaxSize=160, MaxScale=20 mirrors what e2b uses
//     in production.
func newMeterProvider(ctx context.Context, res *sdkresource.Resource) (*sdkmetric.MeterProvider, error) {
	exp, err := otlpmetricgrpc.New(ctx,
		otlpmetricgrpc.WithTemporalitySelector(deltaTemporalitySelector),
	)
	if err != nil {
		return nil, err
	}

	reader := sdkmetric.NewPeriodicReader(exp,
		sdkmetric.WithInterval(15*time.Second),
	)

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(reader),
		sdkmetric.WithView(sdkmetric.NewView(
			sdkmetric.Instrument{Kind: sdkmetric.InstrumentKindHistogram},
			sdkmetric.Stream{Aggregation: sdkmetric.AggregationBase2ExponentialHistogram{
				MaxSize:  160,
				MaxScale: 20,
			}},
		)),
	)
	return mp, nil
}

// deltaTemporalitySelector forces delta temporality for sums and histograms
// (so per-sandbox series die on sandbox exit) while leaving up-down counters
// as cumulative — they represent steady-state values like "active sandboxes"
// where deltas would lose meaning.
func deltaTemporalitySelector(kind sdkmetric.InstrumentKind) metricdata.Temporality {
	switch kind {
	case sdkmetric.InstrumentKindCounter,
		sdkmetric.InstrumentKindHistogram,
		sdkmetric.InstrumentKindObservableCounter:
		return metricdata.DeltaTemporality
	default:
		return metricdata.CumulativeTemporality
	}
}
