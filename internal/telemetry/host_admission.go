package telemetry

import (
	"context"
	"fmt"
	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

func (c *instrumentedVMDClient) HostAdmission(ctx context.Context, revision int64, closed bool) (vmdclient.HostAdmissionState, error) {
	next, ok := c.next.(vmdclient.HostAdmissionClient)
	if !ok {
		return vmdclient.HostAdmissionState{}, fmt.Errorf("host admission protocol unavailable")
	}
	return next.HostAdmission(ctx, revision, closed)
}
