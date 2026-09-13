package steps

import (
	"context"
	"errors"
	"fmt"
	"net/url"

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
	// EnsureHostRule points host at the tenant's service, creating what is
	// missing and correcting what is stale. Reconciling rather than
	// creating once is what lets a retry repair a route left half-built or
	// pointing at a service that has since been redeployed.
	EnsureHostRule(ctx context.Context, host, cloudRunService string) error
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
	// No check first: EnsureHostRule reconciles, and a check that reported
	// "already routed" would make the repair unreachable — a route left
	// pointing at a stale backend would then survive every retry while the
	// probes after it went on failing.
	if err := s.c.LoadBalancer.EnsureHostRule(ctx, t.Hostname(), *t.Row.CloudRunService); err != nil {
		return fmt.Errorf("route the tenant's hostname: %w", err)
	}
	return nil
}

// Rollback removes the route. It does not check first: RemoveHostRule is
// idempotent, and the check would only add a call that can itself fail
// between the answer and the delete.
//
// Both the hostname recorded on the row and the one the current base domain
// derives, because they are not always the same one. QM_BASE_DOMAIN is
// deployment configuration; if it changes after a tenant is built, the rule
// on the URL map is still the old hostname, and a teardown that only looked
// for the new one would leave the route in place and then fail trying to
// delete the backend it still points at — on every retry, for good.
func (s loadBalancer) Rollback(ctx context.Context, t *provisioner.Tenant) error {
	if t.Env.Stub {
		return nil
	}
	if s.c.LoadBalancer == nil {
		return errNoLoadBalancerAdmin
	}
	for _, host := range routedHosts(t) {
		if err := s.c.LoadBalancer.RemoveHostRule(ctx, host); err != nil {
			return fmt.Errorf("remove the tenant's route: %w", err)
		}
	}
	return nil
}

// routedHosts is every hostname this tenant may be routed under: the one
// its recorded public URL names, first, and the one the current base domain
// derives. The recorded one goes first because the derived one's cleanup
// deletes the backend the recorded rule may still reference.
func routedHosts(t *provisioner.Tenant) []string {
	derived := t.Hostname()
	recorded := recordedHost(t)
	if recorded == "" || recorded == derived {
		return []string{derived}
	}
	return []string{recorded, derived}
}

// recordedHost is the hostname in the tenant's public URL, or "" when it
// has none or it cannot be parsed.
func recordedHost(t *provisioner.Tenant) string {
	if t.Row.PublicUrl == nil {
		return ""
	}
	u, err := url.Parse(*t.Row.PublicUrl)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
