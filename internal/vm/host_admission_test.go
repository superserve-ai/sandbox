package vm

import (
	"context"
	"github.com/superserve-ai/sandbox/internal/admission"
	"github.com/superserve-ai/sandbox/proto/vmdpb"
	"google.golang.org/api/idtoken"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"testing"
)

func TestHostAdmissionRejectsUnauthenticatedBeforeHostAccess(t *testing.T) {
	a := NewGRPCAdapter(nil).WithHostAdmissionCaller("control@example.iam.gserviceaccount.com")
	if _, err := a.HostAdmission(context.Background(), &vmdpb.HostAdmissionRequest{Revision: 1}); status.Code(err) != codes.Unauthenticated {
		t.Fatal(err)
	}
}
func TestAdmissionPrincipalMustBeExactVerifiedControlPlane(t *testing.T) {
	email := "control@example.iam.gserviceaccount.com"
	valid := func() *idtoken.Payload {
		return &idtoken.Payload{Issuer: "https://accounts.google.com", Audience: "superserve-vmd-host-admission", Claims: map[string]interface{}{"email": email, "email_verified": true}}
	}
	if !authorizedAdmissionPrincipal(valid(), email) {
		t.Fatal("valid control-plane identity rejected")
	}
	for _, mutate := range []func(*idtoken.Payload){
		func(p *idtoken.Payload) { p.Claims["email"] = "vmd@example.iam.gserviceaccount.com" },
		func(p *idtoken.Payload) { p.Claims["email_verified"] = false },
		func(p *idtoken.Payload) { p.Audience = "another-service" },
		func(p *idtoken.Payload) { p.Issuer = "https://untrusted.example" },
	} {
		p := valid()
		mutate(p)
		if authorizedAdmissionPrincipal(p, email) {
			t.Fatal("unauthorized principal accepted", p)
		}
	}
}

func TestAdmissionReadinessIncludesLedgerReconstruction(t *testing.T) {
	m := newTestManager()
	m.admission = admission.NewGate(true, 1)
	m.reattachComplete.Store(true)
	if !m.PressureReady() {
		t.Fatal("test must isolate admission readiness")
	}
	if m.hostAdmissionReady() {
		t.Fatal("pressure readiness incorrectly opened admission")
	}
	m.admission.Reconstruct(m.admission.BeginReconstruct(), nil, nil)
	m.admission.Open()
	if !m.hostAdmissionReady() {
		t.Fatal("reconstructed host not ready")
	}
}
