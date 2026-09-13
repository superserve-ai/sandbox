package gcp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"net/http"

	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/option"

	"github.com/superserve-ai/sandbox/internal/qm/provisioner/steps"
)

// Routing one tenant hostname on the shared external HTTPS load balancer
// takes three resources, created in dependency order and removed in
// reverse:
//
//	serverless NEG  →  backend service  →  host rule + path matcher on the
//	                                       shared URL map
//
// The wildcard certificate for the base domain and the URL map itself are
// Terraform-owned; Terraform ignores host_rules and path_matchers on the
// map precisely so this can edit them.

const (
	// urlMapAttempts bounds the read-modify-write retry on the shared URL
	// map. Two tenants provisioning at once really do contend here — there
	// is one map for the whole environment — so the fingerprint check and
	// this retry are what keep one of them from erasing the other's route.
	urlMapAttempts = 5
	// backendTimeoutSec matches an agent turn, which is a long request.
	backendTimeoutSec = 3600
	operationTimeout  = 5 * time.Minute
	operationWait     = 3 * time.Second
)

// LoadBalancer is the compute-backed steps.LoadBalancerAdmin.
type LoadBalancer struct {
	svc     *compute.Service
	project string
	region  string
	urlMap  string
}

var _ steps.LoadBalancerAdmin = (*LoadBalancer)(nil)

func NewLoadBalancer(ctx context.Context, project, region, urlMap string, opts ...option.ClientOption) (*LoadBalancer, error) {
	if project == "" || region == "" || urlMap == "" {
		return nil, errors.New("load balancer: project, region and url map are required")
	}
	svc, err := compute.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("compute client: %w", err)
	}
	return &LoadBalancer{svc: svc, project: project, region: region, urlMap: urlMap}, nil
}

// EnsureHostRule creates the three resources if they are missing and
// corrects the host rule and path matcher if they point somewhere stale.
// Every part of it is idempotent, so it is safe on every run.
func (l *LoadBalancer) EnsureHostRule(ctx context.Context, host, cloudRunService string) error {
	// The NEG, the backend service and the path matcher all take the Cloud
	// Run service's name, so the four read as one set in the console.
	name := cloudRunService
	if err := l.ensureNEG(ctx, name, cloudRunService); err != nil {
		return err
	}
	backend, err := l.ensureBackendService(ctx, name)
	if err != nil {
		return err
	}
	return l.patchURLMap(ctx, func(m *compute.UrlMap) bool {
		return addRoute(m, host, name, backend)
	})
}

// RemoveHostRule unwinds all three, route first: the backend service cannot
// be deleted while the URL map still references it, and the NEG cannot be
// deleted while a backend service still points at it.
func (l *LoadBalancer) RemoveHostRule(ctx context.Context, host string) error {
	var name string
	var shared bool
	if err := l.patchURLMap(ctx, func(m *compute.UrlMap) bool {
		matcher, changed := removeRoute(m, host)
		name = matcher
		shared = changed && matcher == ""
		return changed
	}); err != nil {
		return err
	}
	if name == "" {
		// Either nothing referenced the host, or its rule carried other
		// hosts too. In the first case a run may still have created the
		// NEG and the backend before it failed, so the names are derived
		// from the hostname — whose first label is the tenant's slug — and
		// the deletes below are no-ops if they were never made. In the
		// second the matcher is still in use; deriving the same name and
		// deleting it would break the tenants sharing it, so nothing else
		// happens.
		if shared {
			return nil
		}
		name = steps.ServiceName(strings.Split(host, ".")[0])
	}
	if err := l.deleteBackendService(ctx, name); err != nil {
		return err
	}
	return l.deleteNEG(ctx, name)
}

func (l *LoadBalancer) ensureNEG(ctx context.Context, name, cloudRunService string) error {
	_, err := l.svc.RegionNetworkEndpointGroups.Get(l.project, l.region, name).Context(ctx).Do()
	if err == nil {
		return nil
	}
	if !notFound(err) {
		return fmt.Errorf("get the network endpoint group for %s: %w", name, err)
	}
	op, err := l.svc.RegionNetworkEndpointGroups.Insert(l.project, l.region, &compute.NetworkEndpointGroup{
		Name:                name,
		NetworkEndpointType: "SERVERLESS",
		Region:              l.region,
		CloudRun:            &compute.NetworkEndpointGroupCloudRun{Service: cloudRunService},
	}).Context(ctx).Do()
	if err != nil {
		if alreadyExists(err) {
			return nil
		}
		return fmt.Errorf("create the network endpoint group for %s: %w", name, err)
	}
	return l.waitRegion(ctx, op)
}

func (l *LoadBalancer) deleteNEG(ctx context.Context, name string) error {
	op, err := l.svc.RegionNetworkEndpointGroups.Delete(l.project, l.region, name).Context(ctx).Do()
	if err != nil {
		if notFound(err) {
			return nil
		}
		return fmt.Errorf("delete the network endpoint group %s: %w", name, err)
	}
	return l.waitRegion(ctx, op)
}

// ensureBackendService returns the backend service's self link, creating it
// if needed. External managed is the scheme the shared HTTPS load balancer
// uses; a serverless NEG carries no health check.
func (l *LoadBalancer) ensureBackendService(ctx context.Context, name string) (string, error) {
	existing, err := l.svc.BackendServices.Get(l.project, name).Context(ctx).Do()
	if err == nil {
		return existing.SelfLink, nil
	}
	if !notFound(err) {
		return "", fmt.Errorf("get the backend service %s: %w", name, err)
	}
	negLink := fmt.Sprintf("projects/%s/regions/%s/networkEndpointGroups/%s", l.project, l.region, name)
	op, err := l.svc.BackendServices.Insert(l.project, &compute.BackendService{
		Name:                name,
		LoadBalancingScheme: "EXTERNAL_MANAGED",
		Protocol:            "HTTPS",
		TimeoutSec:          backendTimeoutSec,
		Backends:            []*compute.Backend{{Group: negLink}},
	}).Context(ctx).Do()
	if err != nil && !alreadyExists(err) {
		return "", fmt.Errorf("create the backend service %s: %w", name, err)
	}
	if err == nil {
		if err := l.waitGlobal(ctx, op); err != nil {
			return "", err
		}
	}
	created, err := l.svc.BackendServices.Get(l.project, name).Context(ctx).Do()
	if err != nil {
		return "", fmt.Errorf("get the backend service %s after creating it: %w", name, err)
	}
	return created.SelfLink, nil
}

func (l *LoadBalancer) deleteBackendService(ctx context.Context, name string) error {
	op, err := l.svc.BackendServices.Delete(l.project, name).Context(ctx).Do()
	if err != nil {
		if notFound(err) {
			return nil
		}
		return fmt.Errorf("delete the backend service %s: %w", name, err)
	}
	return l.waitGlobal(ctx, op)
}

// patchURLMap applies mutate to the shared map under its fingerprint, so a
// concurrent edit is a retry rather than a silently lost route. mutate
// reports whether it changed anything; when it does not, nothing is sent.
func (l *LoadBalancer) patchURLMap(ctx context.Context, mutate func(*compute.UrlMap) bool) error {
	var lastErr error
	for attempt := 0; attempt < urlMapAttempts; attempt++ {
		current, err := l.svc.UrlMaps.Get(l.project, l.urlMap).Context(ctx).Do()
		if err != nil {
			return fmt.Errorf("read url map %s: %w", l.urlMap, err)
		}
		if !mutate(current) {
			return nil
		}
		op, err := l.svc.UrlMaps.Patch(l.project, l.urlMap, &compute.UrlMap{
			Fingerprint:  current.Fingerprint,
			HostRules:    current.HostRules,
			PathMatchers: current.PathMatchers,
			// Both lists can legitimately become empty, and omitempty would
			// turn that into "leave them alone".
			ForceSendFields: []string{"HostRules", "PathMatchers"},
		}).Context(ctx).Do()
		if err == nil {
			return l.waitGlobal(ctx, op)
		}
		lastErr = err
		if !isStatus(err, http.StatusConflict) && !isStatus(err, http.StatusPreconditionFailed) {
			break
		}
	}
	return fmt.Errorf("update url map %s: %w", l.urlMap, lastErr)
}

// addRoute adds the host rule and its path matcher, reporting whether the
// map changed. A host already routed to this matcher is left alone.
func addRoute(m *compute.UrlMap, host, matcher, backend string) bool {
	changed := false
	var rule *compute.HostRule
	for _, existing := range m.HostRules {
		if slices.Contains(existing.Hosts, host) {
			rule = existing
			break
		}
	}
	switch {
	case rule == nil:
		m.HostRules = append(m.HostRules, &compute.HostRule{Hosts: []string{host}, PathMatcher: matcher})
		changed = true
	case rule.PathMatcher != matcher:
		rule.PathMatcher = matcher
		changed = true
	}
	for _, pm := range m.PathMatchers {
		if pm.Name == matcher {
			if pm.DefaultService != backend {
				pm.DefaultService = backend
				changed = true
			}
			return changed
		}
	}
	m.PathMatchers = append(m.PathMatchers, &compute.PathMatcher{Name: matcher, DefaultService: backend})
	return true
}

// removeRoute drops the host's rule and, when nothing else used it, the
// path matcher it named. It returns that matcher's name so the caller knows
// which backend service and NEG to delete next, and whether the map
// changed. An empty name with changed=true means the rule carried other
// hosts too, so the matcher is still in use.
func removeRoute(m *compute.UrlMap, host string) (string, bool) {
	var matcher string
	var changed bool
	rules := make([]*compute.HostRule, 0, len(m.HostRules))
	for _, rule := range m.HostRules {
		if !slices.Contains(rule.Hosts, host) {
			rules = append(rules, rule)
			continue
		}
		changed = true
		others := without(rule.Hosts, host)
		if len(others) == 0 {
			// The rule existed only for this tenant, so its matcher goes
			// with it.
			matcher = rule.PathMatcher
			continue
		}
		rule.Hosts = others
		rules = append(rules, rule)
	}
	if !changed {
		return "", false
	}
	m.HostRules = rules
	if matcher == "" {
		return "", true
	}
	matchers := make([]*compute.PathMatcher, 0, len(m.PathMatchers))
	for _, pm := range m.PathMatchers {
		if pm.Name != matcher {
			matchers = append(matchers, pm)
		}
	}
	m.PathMatchers = matchers
	return matcher, true
}

func without(values []string, drop string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v != drop {
			out = append(out, v)
		}
	}
	return out
}

func (l *LoadBalancer) waitGlobal(ctx context.Context, op *compute.Operation) error {
	return l.waitOperation(ctx, op, func(ctx context.Context, name string) (*compute.Operation, error) {
		return l.svc.GlobalOperations.Wait(l.project, name).Context(ctx).Do()
	})
}

func (l *LoadBalancer) waitRegion(ctx context.Context, op *compute.Operation) error {
	return l.waitOperation(ctx, op, func(ctx context.Context, name string) (*compute.Operation, error) {
		return l.svc.RegionOperations.Wait(l.project, l.region, name).Context(ctx).Do()
	})
}

func (l *LoadBalancer) waitOperation(ctx context.Context, op *compute.Operation, wait func(context.Context, string) (*compute.Operation, error)) error {
	if op == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	for {
		if op.Status == "DONE" {
			return computeOperationError(op)
		}
		next, err := wait(ctx, op.Name)
		if err != nil {
			if notFound(err) {
				return nil
			}
			return fmt.Errorf("wait for compute operation %s: %w", op.Name, err)
		}
		op = next
		if op.Status == "DONE" {
			return computeOperationError(op)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for compute operation %s: %w", op.Name, ctx.Err())
		case <-time.After(operationWait):
		}
	}
}

func computeOperationError(op *compute.Operation) error {
	if op.Error == nil || len(op.Error.Errors) == 0 {
		return nil
	}
	reasons := make([]string, 0, len(op.Error.Errors))
	for _, e := range op.Error.Errors {
		reasons = append(reasons, e.Code+": "+e.Message)
	}
	return fmt.Errorf("compute reported: %s", strings.Join(reasons, "; "))
}
