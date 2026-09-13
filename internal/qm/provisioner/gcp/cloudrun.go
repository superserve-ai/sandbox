package gcp

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"google.golang.org/api/option"
	run "google.golang.org/api/run/v2"

	"github.com/superserve-ai/sandbox/internal/qm/provisioner/steps"
)

// The tenant runtime's shape, which is the same for every tenant and is an
// architecture decision rather than a knob: one container, CPU always
// allocated (background work and cron fire between requests), and exactly
// one instance, so a tenant's in-memory state and its Postgres connection
// budget are both single-instance.
const (
	tenantPort        = 8080
	tenantCPU         = "1"
	tenantMemory      = "2Gi"
	tenantConcurrency = 80
	// tenantRequestTimeout is generous because an agent turn is a long
	// request.
	tenantRequestTimeout = "3600s"
	// Only RFC 1918 traffic goes through the VPC — the Cloud SQL private
	// IP. Google APIs and the model providers stay on the public path.
	tenantVPCEgress = "PRIVATE_RANGES_ONLY"
	// The service is reached through the shared load balancer, which needs
	// the service to accept traffic from it. Invoker IAM still applies.
	tenantIngress = "INGRESS_TRAFFIC_ALL"
)

// deployTimeout bounds how long a create or update waits for the new
// revision to serve. Cloud Run pulls the image, runs the tenant's database
// migrations and starts three processes before it reports ready.
const (
	deployTimeout  = 15 * time.Minute
	operationPoll  = 5 * time.Second
	operationChunk = "30s"
)

// Services is the run/v2-backed steps.CloudRunAdmin.
type Services struct {
	svc     *run.Service
	project string
	region  string
}

var _ steps.CloudRunAdmin = (*Services)(nil)

func NewServices(ctx context.Context, project, region string, opts ...option.ClientOption) (*Services, error) {
	if project == "" || region == "" {
		return nil, errors.New("cloud run: project and region are required")
	}
	// Regional endpoint: the global one cannot create services.
	opts = append([]option.ClientOption{option.WithEndpoint("https://" + region + "-run.googleapis.com/")}, opts...)
	svc, err := run.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("cloud run client: %w", err)
	}
	return &Services{svc: svc, project: project, region: region}, nil
}

func (s *Services) parent() string {
	return "projects/" + s.project + "/locations/" + s.region
}

func (s *Services) servicePath(name string) string {
	return s.parent() + "/services/" + name
}

func (s *Services) Get(ctx context.Context, name string) (steps.ServiceStatus, bool, error) {
	svc, err := s.svc.Projects.Locations.Services.Get(s.servicePath(name)).Context(ctx).Do()
	switch {
	case err == nil:
		return statusOf(svc), true, nil
	case notFound(err):
		return steps.ServiceStatus{}, false, nil
	default:
		return steps.ServiceStatus{}, false, fmt.Errorf("get service %s: %w", name, err)
	}
}

// Deploy creates the service or replaces its revision template, then waits
// for the new revision to serve. Patch rather than a read-modify-write of
// the existing template: the spec the step renders is the whole desired
// state, so anything edited onto the service by hand is deliberately
// reverted rather than merged.
func (s *Services) Deploy(ctx context.Context, spec steps.ServiceSpec) (steps.ServiceStatus, error) {
	desired := s.desiredService(spec)

	_, exists, err := s.Get(ctx, spec.Name)
	if err != nil {
		return steps.ServiceStatus{}, err
	}
	var op *run.GoogleLongrunningOperation
	if exists {
		op, err = s.svc.Projects.Locations.Services.Patch(s.servicePath(spec.Name), desired).Context(ctx).Do()
		if err != nil {
			return steps.ServiceStatus{}, fmt.Errorf("update service %s: %w", spec.Name, err)
		}
	} else {
		op, err = s.svc.Projects.Locations.Services.Create(s.parent(), desired).ServiceId(spec.Name).Context(ctx).Do()
		if alreadyExists(err) {
			// Raced with another attempt; the update path converges.
			op, err = s.svc.Projects.Locations.Services.Patch(s.servicePath(spec.Name), desired).Context(ctx).Do()
		}
		if err != nil {
			return steps.ServiceStatus{}, fmt.Errorf("create service %s: %w", spec.Name, err)
		}
	}
	if err := s.wait(ctx, op); err != nil {
		return steps.ServiceStatus{}, fmt.Errorf("deploy service %s: %w", spec.Name, err)
	}
	status, ok, err := s.Get(ctx, spec.Name)
	if err != nil {
		return steps.ServiceStatus{}, err
	}
	if !ok {
		return steps.ServiceStatus{}, fmt.Errorf("service %s vanished after its deploy", spec.Name)
	}
	return status, nil
}

func (s *Services) Delete(ctx context.Context, name string) error {
	op, err := s.svc.Projects.Locations.Services.Delete(s.servicePath(name)).Context(ctx).Do()
	if err != nil {
		if notFound(err) {
			return nil
		}
		return fmt.Errorf("delete service %s: %w", name, err)
	}
	// Waited out rather than fired and forgotten: teardown deletes the
	// tenant's service account next, and Cloud Run cannot finish removing a
	// service whose identity has gone.
	if err := s.wait(ctx, op); err != nil {
		return fmt.Errorf("delete service %s: %w", name, err)
	}
	return nil
}

func (s *Services) desiredService(spec steps.ServiceSpec) *run.GoogleCloudRunV2Service {
	env := make([]*run.GoogleCloudRunV2EnvVar, 0, len(spec.Env)+len(spec.SecretEnv))
	for _, name := range sortedKeys(spec.Env) {
		env = append(env, &run.GoogleCloudRunV2EnvVar{Name: name, Value: spec.Env[name]})
	}
	for _, name := range sortedKeys(spec.SecretEnv) {
		env = append(env, &run.GoogleCloudRunV2EnvVar{
			Name: name,
			ValueSource: &run.GoogleCloudRunV2EnvVarSource{
				SecretKeyRef: &run.GoogleCloudRunV2SecretKeySelector{
					Secret:  spec.SecretEnv[name],
					Version: "latest",
				},
			},
		})
	}
	var vpc *run.GoogleCloudRunV2VpcAccess
	if spec.Network != "" && spec.Subnetwork != "" {
		vpc = &run.GoogleCloudRunV2VpcAccess{
			Egress:            tenantVPCEgress,
			NetworkInterfaces: []*run.GoogleCloudRunV2NetworkInterface{{Network: spec.Network, Subnetwork: spec.Subnetwork}},
		}
	}
	return &run.GoogleCloudRunV2Service{
		Ingress: tenantIngress,
		Labels:  spec.Labels,
		Template: &run.GoogleCloudRunV2RevisionTemplate{
			ServiceAccount: spec.ServiceAccount,
			Labels:         spec.Labels,
			Scaling: &run.GoogleCloudRunV2RevisionScaling{
				MinInstanceCount: 1,
				MaxInstanceCount: 1,
				// Both bounds are meant, including the zero-looking one, so
				// they have to survive JSON omitempty.
				ForceSendFields: []string{"MinInstanceCount", "MaxInstanceCount"},
			},
			MaxInstanceRequestConcurrency: tenantConcurrency,
			Timeout:                       tenantRequestTimeout,
			VpcAccess:                     vpc,
			Containers: []*run.GoogleCloudRunV2Container{{
				Image: spec.Image,
				Env:   env,
				Ports: []*run.GoogleCloudRunV2ContainerPort{{ContainerPort: tenantPort}},
				Resources: &run.GoogleCloudRunV2ResourceRequirements{
					Limits: map[string]string{"cpu": tenantCPU, "memory": tenantMemory},
					// CPU stays allocated between requests: the tenant runs
					// cron and background work, which a throttled instance
					// would simply not do.
					CpuIdle:         false,
					ForceSendFields: []string{"CpuIdle"},
				},
			}},
		},
	}
}

// wait polls the operation to completion. Cloud Run's Wait is a long poll
// that returns early, so this loops until it is done or the budget is out.
func (s *Services) wait(ctx context.Context, op *run.GoogleLongrunningOperation) error {
	if op == nil || op.Done {
		return operationError(op)
	}
	ctx, cancel := context.WithTimeout(ctx, deployTimeout)
	defer cancel()
	name := op.Name
	for {
		waited, err := s.svc.Projects.Locations.Operations.Wait(name, &run.GoogleLongrunningWaitOperationRequest{
			Timeout: operationChunk,
		}).Context(ctx).Do()
		if err != nil {
			if notFound(err) {
				// A completed operation is eventually garbage collected;
				// treat that as success rather than failing a deploy that
				// already landed.
				return nil
			}
			return err
		}
		if waited.Done {
			return operationError(waited)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for the revision to serve: %w", ctx.Err())
		case <-time.After(operationPoll):
		}
	}
}

func operationError(op *run.GoogleLongrunningOperation) error {
	if op == nil || op.Error == nil {
		return nil
	}
	// The status message is what Cloud Run says went wrong — an image that
	// cannot be pulled, a secret the identity cannot read, a container that
	// never listened — and it is the most useful thing in the event log.
	return fmt.Errorf("cloud run reported: %s", op.Error.Message)
}

func statusOf(svc *run.GoogleCloudRunV2Service) steps.ServiceStatus {
	status := steps.ServiceStatus{URI: svc.Uri, Revision: svc.LatestReadyRevision}
	if svc.Template != nil && len(svc.Template.Containers) > 0 {
		status.ImageTag = svc.Template.Containers[0].Image
	}
	return status
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
