package telemetry

import (
	"fmt"

	"go.opentelemetry.io/contrib/instrumentation/runtime"
)

// StartRuntimeInstrumentation registers the standard Go runtime metrics
// (goroutine count, heap, GC pauses, etc.) on the global meter provider.
// Safe to call on a no-op Client; in that case it returns nil immediately.
func (c *Client) StartRuntimeInstrumentation() error {
	if c == nil || !c.enabled {
		return nil
	}
	if err := runtime.Start(runtime.WithMeterProvider(c.MeterProvider)); err != nil {
		return fmt.Errorf("runtime instrumentation: %w", err)
	}
	return nil
}
