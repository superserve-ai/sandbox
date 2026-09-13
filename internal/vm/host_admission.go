package vm

import (
	"context"
	"google.golang.org/api/idtoken"
	"strings"

	"github.com/superserve-ai/sandbox/proto/vmdpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func (a *GRPCAdapter) WithHostAdmissionCaller(email string) *GRPCAdapter {
	a.admissionCaller = email
	return a
}

func (a *GRPCAdapter) HostAdmission(ctx context.Context, req *vmdpb.HostAdmissionRequest) (*vmdpb.HostAdmissionResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	values := md.Get("authorization")
	if a.admissionCaller == "" || len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return nil, status.Error(codes.Unauthenticated, "host admission requires control-plane identity")
	}
	payload, err := idtoken.Validate(ctx, strings.TrimPrefix(values[0], "Bearer "), "superserve-vmd-host-admission")
	if err != nil || !authorizedAdmissionPrincipal(payload, a.admissionCaller) {
		return nil, status.Error(codes.PermissionDenied, "unauthorized host admission principal")
	}

	gate := a.mgr.AdmissionGate()
	state, configured := gate.DrainStatus()
	if !configured {
		return nil, status.Error(codes.FailedPrecondition, "enable VMD_DRAIN_ENABLED before host admission transitions")
	}
	if req.Revision < 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid revision")
	}
	if req.Revision > 0 {
		if !req.Closed && !a.mgr.PressureReady() {
			return nil, status.Error(codes.FailedPrecondition, "host reconciliation is incomplete")
		}
		if err := gate.TransitionDrain(req.Revision, req.Closed); err != nil {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		state, _ = gate.DrainStatus()
	}
	return &vmdpb.HostAdmissionResponse{PendingBoots: int64(gate.PendingBoots()), Revision: state.Revision, Closed: state.Closed, Ready: a.mgr.PressureReady(), Charged: int64(gate.Charged())}, nil
}

func authorizedAdmissionPrincipal(payload *idtoken.Payload, email string) bool {
	return payload != nil && strings.HasSuffix(email, ".iam.gserviceaccount.com") &&
		(payload.Issuer == "https://accounts.google.com" || payload.Issuer == "accounts.google.com") &&
		payload.Audience == "superserve-vmd-host-admission" &&
		payload.Claims["email"] == email && payload.Claims["email_verified"] == true
}
