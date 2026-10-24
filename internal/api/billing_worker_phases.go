package api

import (
	"context"
	"errors"
	"time"
)

func runBillingPhases(ctx context.Context, budget time.Duration, phases ...func(context.Context) error) error {
	var errs []error
	for _, phase := range phases {
		phaseCtx, cancel := context.WithTimeout(ctx, budget)
		err := phase(phaseCtx)
		cancel()
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
