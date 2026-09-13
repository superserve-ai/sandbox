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
func (l *LoadBalancer) EnsureHostRule(ctx context.Context, host, cloudRunService, owner string) error {
	// The NEG, the backend service and the path matcher all take the Cloud
	// Run service's name, so the four read as one set in the console.
	name := cloudRunService
	if err := l.ensureNEG(ctx, name, cloudRunService, owner); err != nil {
		return err
	}
	backend, err := l.ensureBackendService(ctx, name, owner)
	if err != nil {
		return err
	}
	// The ownership check runs inside the compare-and-swap, against the map
	// each attempt just read: a hostname another workload claims between a
	// check outside the loop and the patch would otherwise be lifted out of
	// its rule and pointed at this tenant.
	return l.patchURLMap(ctx, func(m *compute.UrlMap) (bool, error) {
		if err := l.routeIsOursIn(ctx, m, host, owner); err != nil {
			return false, err
		}
		return addRoute(m, host, name, backend), nil
	})
}

// RemoveHostRule unwinds all three, route first: the backend service cannot
// be deleted while the URL map still references it, and the NEG cannot be
// deleted while a backend service still points at it.
func (l *LoadBalancer) RemoveHostRule(ctx context.Context, host, owner string) error {
	// The ownership check is inside the compare-and-swap for the same
	// reason as on the way up, and it is what keeps a teardown from
	// removing another workload's hostname: a provision that stopped
	// because the derived NEG or backend was foreign still reaches here.
	var name string
	var shared bool
	if err := l.patchURLMap(ctx, func(m *compute.UrlMap) (bool, error) {
		if err := l.routeIsOursIn(ctx, m, host, owner); err != nil {
			return false, err
		}
		matcher, changed := removeRoute(m, host)
		name = matcher
		shared = changed && matcher == ""
		return changed, nil
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
	if err := l.deleteBackendService(ctx, name, owner); err != nil {
		return err
	}
	return l.deleteNEG(ctx, name, owner)
}

// routeIsOursIn refuses to touch a hostname whose backing resources belong
// to something else, judged against the map the caller is about to mutate.
// It resolves the host's path matcher to the backend service behind it and
// checks that backend's marker; a host with no rule, or a matcher with no
// backend, is nothing to protect.
func (l *LoadBalancer) routeIsOursIn(ctx context.Context, urlMap *compute.UrlMap, host, owner string) error {
	var matcher string
	for _, rule := range urlMap.HostRules {
		if slices.Contains(rule.Hosts, host) {
			matcher = rule.PathMatcher
			break
		}
	}
	if matcher == "" {
		return nil
	}
	var backend string
	for _, pm := range urlMap.PathMatchers {
		if pm.Name == matcher {
			backend = pm.DefaultService
			break
		}
	}
	if backend == "" {
		return nil
	}
	// DefaultService is a URL; the backend's own name is its last segment.
	name := backend[strings.LastIndex(backend, "/")+1:]
	existing, err := l.svc.BackendServices.Get(l.project, name).Context(ctx).Do()
	if err != nil {
		if notFound(err) {
			return nil
		}
		return fmt.Errorf("get the backend service %s behind %s: %w", name, host, err)
	}
	return ownedBy(existing.Description, owner, "backend service", name)
}

func (l *LoadBalancer) ensureNEG(ctx context.Context, name, cloudRunService, owner string) error {
	existing, err := l.svc.RegionNetworkEndpointGroups.Get(l.project, l.region, name).Context(ctx).Do()
	if err == nil {
		if err := ownedBy(existing.Description, owner, "network endpoint group", name); err != nil {
			return err
		}
		if target := negTarget(existing); target != cloudRunService {
			return fmt.Errorf("network endpoint group %s points at %q, not %q; delete it and retry", name, target, cloudRunService)
		}
		return nil
	}
	if !notFound(err) {
		return fmt.Errorf("get the network endpoint group for %s: %w", name, err)
	}
	op, err := l.svc.RegionNetworkEndpointGroups.Insert(l.project, l.region, negSpec(name, l.region, cloudRunService, owner)).Context(ctx).Do()
	if err != nil {
		if !alreadyExists(err) {
			return fmt.Errorf("create the network endpoint group for %s: %w", name, err)
		}
		// Raced with another attempt, or the first Get was stale. Either
		// way the group now exists and has to be checked like any other:
		// attaching a backend to one that targets a different service
		// would route this tenant's hostname at that service, and both
		// probes would pass.
		existing, err := l.svc.RegionNetworkEndpointGroups.Get(l.project, l.region, name).Context(ctx).Do()
		if err != nil {
			return fmt.Errorf("get the network endpoint group %s after it was already created: %w", name, err)
		}
		if err := ownedBy(existing.Description, owner, "network endpoint group", name); err != nil {
			return err
		}
		if target := negTarget(existing); target != cloudRunService {
			return fmt.Errorf("network endpoint group %s points at %q, not %q; delete it and retry", name, target, cloudRunService)
		}
		return nil
	}
	return l.waitRegion(ctx, op)
}

func negTarget(neg *compute.NetworkEndpointGroup) string {
	if neg == nil || neg.CloudRun == nil {
		return ""
	}
	return neg.CloudRun.Service
}

func (l *LoadBalancer) deleteNEG(ctx context.Context, name, owner string) error {
	existing, err := l.svc.RegionNetworkEndpointGroups.Get(l.project, l.region, name).Context(ctx).Do()
	if err == nil {
		if err := ownedBy(existing.Description, owner, "network endpoint group", name); err != nil {
			return err
		}
	} else if !notFound(err) {
		return fmt.Errorf("get the network endpoint group %s: %w", name, err)
	}
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
// if needed and repointing it at this tenant's NEG if it drifted. External
// managed is the scheme the shared HTTPS load balancer uses; a serverless
// NEG carries no health check.
func (l *LoadBalancer) ensureBackendService(ctx context.Context, name, owner string) (string, error) {
	negLink := fmt.Sprintf("projects/%s/regions/%s/networkEndpointGroups/%s", l.project, l.region, name)
	existing, err := l.svc.BackendServices.Get(l.project, name).Context(ctx).Do()
	if err == nil {
		if err := ownedBy(existing.Description, owner, "backend service", name); err != nil {
			return "", err
		}
		if backsNEG(existing, negLink) {
			return existing.SelfLink, nil
		}
		// Unlike the NEG's target, a backend service's backends are
		// mutable, so a drifted one is repaired rather than reported.
		op, err := l.svc.BackendServices.Patch(l.project, name, &compute.BackendService{
			Fingerprint:     existing.Fingerprint,
			Description:     owner,
			Backends:        []*compute.Backend{{Group: negLink}},
			ForceSendFields: []string{"Backends"},
		}).Context(ctx).Do()
		if err != nil {
			return "", fmt.Errorf("repoint the backend service %s at %s: %w", name, negLink, err)
		}
		if err := l.waitGlobal(ctx, op); err != nil {
			return "", err
		}
		return existing.SelfLink, nil
	}
	if !notFound(err) {
		return "", fmt.Errorf("get the backend service %s: %w", name, err)
	}
	op, err := l.svc.BackendServices.Insert(l.project, backendServiceSpec(name, negLink, owner)).Context(ctx).Do()
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
	// Read back rather than trusting the insert: it tolerates an
	// already-exists, which is how a backend somebody else made in the gap
	// since the look-up above would otherwise be adopted.
	if err := ownedBy(created.Description, owner, "backend service", name); err != nil {
		return "", err
	}
	return created.SelfLink, nil
}

// backsNEG reports whether the backend service's only backend is this
// tenant's NEG. Compared by suffix because the API returns a fully
// qualified URL where the create sends a relative path.
func backsNEG(svc *compute.BackendService, negLink string) bool {
	if len(svc.Backends) != 1 {
		return false
	}
	return strings.HasSuffix(svc.Backends[0].Group, negLink)
}

func (l *LoadBalancer) deleteBackendService(ctx context.Context, name, owner string) error {
	existing, err := l.svc.BackendServices.Get(l.project, name).Context(ctx).Do()
	if err == nil {
		if err := ownedBy(existing.Description, owner, "backend service", name); err != nil {
			return err
		}
	} else if !notFound(err) {
		return fmt.Errorf("get the backend service %s: %w", name, err)
	}
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
func (l *LoadBalancer) patchURLMap(ctx context.Context, mutate func(*compute.UrlMap) (bool, error)) error {
	var lastErr error
	for attempt := 0; attempt < urlMapAttempts; attempt++ {
		current, err := l.svc.UrlMaps.Get(l.project, l.urlMap).Context(ctx).Do()
		if err != nil {
			return fmt.Errorf("read url map %s: %w", l.urlMap, err)
		}
		changed, err := mutate(current)
		if err != nil {
			return err
		}
		if !changed {
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

// addRoute points host at matcher and matcher at backend, reporting whether
// the map changed.
//
// It also takes this tenant's matcher away from any other hostname. Host
// rules are shared state and QM_BASE_DOMAIN is deployment configuration:
// when it changes, the rule left on the map is the hostname the tenant used
// to answer at, and only its matcher name — which is derived from the slug
// and does not move — identifies it. Leaving it would keep the old hostname
// live and pin the backend service it points at, so teardown could never
// remove either.
//
// It never edits a rule that carries other hosts beyond changing which
// hosts are on it: repointing one to reconcile this tenant would silently
// reroute every other hostname riding on it.
func addRoute(m *compute.UrlMap, host, matcher, backend string) bool {
	changed := false
	var own *compute.HostRule
	kept := make([]*compute.HostRule, 0, len(m.HostRules)+1)
	for _, rule := range m.HostRules {
		mine := rule.PathMatcher == matcher
		if !mine && !slices.Contains(rule.Hosts, host) {
			kept = append(kept, rule)
			continue
		}
		// Everything on this rule that is not the hostname we want here:
		// other hosts on our own matcher are hostnames this tenant has
		// outgrown, and our host on somebody else's matcher has to move to
		// a rule of its own.
		var hosts []string
		for _, h := range rule.Hosts {
			if (mine && h != host) || (!mine && h == host) {
				changed = true
				continue
			}
			hosts = append(hosts, h)
		}
		switch {
		case len(hosts) == 0:
			// Nothing left on it.
		case mine && slices.Contains(hosts, host):
			rule.Hosts = hosts
			own = rule
			kept = append(kept, rule)
		default:
			rule.Hosts = hosts
			kept = append(kept, rule)
		}
	}
	m.HostRules = kept
	switch {
	case own == nil:
		m.HostRules = append(m.HostRules, &compute.HostRule{Hosts: []string{host}, PathMatcher: matcher})
		changed = true
	case own.PathMatcher != matcher:
		own.PathMatcher = matcher
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
	// Nothing says a path matcher may only be named by one host rule, and
	// a URL map with a rule pointing at a matcher that is not there is
	// rejected outright. So the matcher — and the backend service behind
	// it, which the caller deletes next — only goes when nothing else
	// still names it.
	for _, rule := range rules {
		if rule.PathMatcher == matcher {
			return "", true
		}
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

// negSpec and backendServiceSpec build what is sent to Compute. They are
// separate and pure because the ownership marker rides in a single field of
// each: a spec that forgets it creates a resource its own readback then
// rejects, and no fake of the steps above can see that.
func negSpec(name, region, cloudRunService, owner string) *compute.NetworkEndpointGroup {
	return &compute.NetworkEndpointGroup{
		Name:                name,
		NetworkEndpointType: "SERVERLESS",
		Region:              region,
		Description:         owner,
		CloudRun:            &compute.NetworkEndpointGroupCloudRun{Service: cloudRunService},
	}
}

func backendServiceSpec(name, negLink, owner string) *compute.BackendService {
	return &compute.BackendService{
		Name:                name,
		Description:         owner,
		LoadBalancingScheme: "EXTERNAL_MANAGED",
		Protocol:            "HTTPS",
		TimeoutSec:          backendTimeoutSec,
		Backends:            []*compute.Backend{{Group: negLink}},
	}
}

// ownedBy refuses a resource whose description is not this tenant's marker.
// Compute resources take no labels, so the description is where the marker
// lives — and these names are all derived from a user-chosen slug, so
// "it has the right name" is not evidence of anything.
func ownedBy(description, owner, kind, name string) error {
	if description == owner {
		return nil
	}
	return fmt.Errorf("%w: %s %s", steps.ErrNotOwned, kind, name)
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
