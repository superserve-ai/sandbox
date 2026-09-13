package main

import (
	"context"
	"google.golang.org/api/idtoken"

	"github.com/superserve-ai/sandbox/internal/vmdclient"
	"github.com/superserve-ai/sandbox/proto/vmdpb"
	"google.golang.org/grpc/metadata"
)

func (c *grpcVMDClient) HostAdmission(ctx context.Context, revision int64, closed bool) (vmdclient.HostAdmissionState, error) {
	source, err := idtoken.NewTokenSource(ctx, "superserve-vmd-host-admission")
	if err != nil {
		return vmdclient.HostAdmissionState{}, err
	}
	token, err := source.Token()
	if err != nil {
		return vmdclient.HostAdmissionState{}, err
	}
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token.AccessToken)
	r, err := c.client.HostAdmission(ctx, &vmdpb.HostAdmissionRequest{Revision: revision, Closed: closed})
	if err != nil {
		return vmdclient.HostAdmissionState{}, err
	}
	return vmdclient.HostAdmissionState{PendingBoots: r.PendingBoots, Revision: r.Revision, Closed: r.Closed, Ready: r.Ready, Charged: r.Charged}, nil
}
