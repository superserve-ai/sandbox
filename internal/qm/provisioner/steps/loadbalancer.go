package steps

import (
	"context"
	"errors"
	"fmt"

	"github.com/superserve-ai/sandbox/internal/qm/provisioner"
)

// LoadBalancerAdmin adds the tenant hostname to the shared external HTTPS
// load balancer: a serverless network endpoint group pointing at the
// tenant's Cloud Run service, a backend service in front of it, and a host
// rule on the shared URL map. The wildcard certificate for the base domain
// is Terraform-owned, so no per-tenant certificate is issued here.
//
// Every method must be idempotent, and RemoveHostRule must undo all three
// resources — a leaked backend service pins the NEG, and a leaked NEG pins
// nothing but accumulates against the project's quota.
type LoadBalancerAdmin interface {
	HostRuleExists(ctx context.Context, host string) (bool, error)
	AddHostRule(ctx context.Context, host, cloudRunService string) error
	RemoveHostRule(ctx context.Context, host string) error
}

var errNoLoadBalancerAdmin = errors.New("no load balancer client configured")

// loadBalancer routes the tenant hostname. No row output: the hostname is
// derived from the slug and base domain.
type loadBalancer struct {
	c Clients
}

func (loadBalancer) Name() string { return "load_balancer" }

func (s loadBalancer) Ready(env provisioner.Env) error {
	if env.Stub {
		return nil
	}
	if env.ExecutesPlan && s.c.LoadBalancer == nil {
		return errNoLoadBalancerAdmin
	}
	return env.Require("QM_LB_URL_MAP", env.URLMap, "QM_BASE_DOMAIN", env.BaseDomain)
}

func (s loadBalancer) Run(ctx context.Context, t *provisioner.Tenant) error {
	if t.Env.Stub {
		return nil
	}
	if s.c.LoadBalancer == nil {
		return errNoLoadBalancerAdmin
	}
	if t.Row.CloudRunService == nil {
		return fmt.Errorf("load_balancer: the tenant has no service recorded")
	}
	host := t.Hostname()
	exists, err := s.c.LoadBalancer.HostRuleExists(ctx, host)
	if err != nil {
		return fmt.Errorf("look up the tenant's host rule: %w", err)
	}
	if exists {
		return provisioner.Skip("the load balancer already routes " + host)
	}
	if err := s.c.LoadBalancer.AddHostRule(ctx, host, *t.Row.CloudRunService); err != nil {
		return fmt.Errorf("route the tenant's hostname: %w", err)
	}
	return nil
}

// Rollback removes the route. It does not check first: RemoveHostRule is
// idempotent, and the check would only add a call that can itself fail
// between the answer and the delete.
func (s loadBalancer) Rollback(ctx context.Context, t *provisioner.Tenant) error {
	if t.Env.Stub {
		return nil
	}
	if s.c.LoadBalancer == nil {
		return errNoLoadBalancerAdmin
	}
	if err := s.c.LoadBalancer.RemoveHostRule(ctx, t.Hostname()); err != nil {
		return fmt.Errorf("remove the tenant's route: %w", err)
	}
	return nil
}
