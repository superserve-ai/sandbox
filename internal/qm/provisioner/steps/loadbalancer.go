package steps

import (
	"context"

	"github.com/superserve-ai/sandbox/internal/qm/provisioner"
)

// LoadBalancerAdmin adds the tenant hostname to the shared external HTTPS
// load balancer (Compute Engine API: urlMaps host rules + path matchers,
// and the serverless NEG / backend service for the tenant's Cloud Run
// service). The wildcard certificate for the base domain is Terraform-
// owned, so no per-tenant certificate is issued here.
type LoadBalancerAdmin interface {
	HostRuleExists(ctx context.Context, host string) (bool, error)
	AddHostRule(ctx context.Context, host, cloudRunService string) error
	RemoveHostRule(ctx context.Context, host string) error
}

// loadBalancer routes the tenant hostname. No row output: the hostname is
// derived from the slug and base domain.
type loadBalancer struct {
	c Clients
}

func (loadBalancer) Name() string { return "load_balancer" }

func (s loadBalancer) Run(ctx context.Context, t *provisioner.Tenant) error {
	if t.Env.Stub {
		return nil
	}
	return provisioner.NotImplemented(s.Name())
}

func (s loadBalancer) Rollback(ctx context.Context, t *provisioner.Tenant) error {
	if t.Env.Stub {
		return nil
	}
	return provisioner.NotImplemented(s.Name())
}
