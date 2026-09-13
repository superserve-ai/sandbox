package provisioner

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
	run "google.golang.org/api/run/v2"
)

// CloudRunJob starts an execution of the provisioner Cloud Run Job. The job
// runs this same binary; the override only sets its arguments to the
// `provision` subcommand for one tenant. Overrides are visible in the
// execution's metadata, which is why nothing secret is passed here.
type CloudRunJob struct {
	svc *run.Service
	// name is the fully qualified job: projects/P/locations/R/jobs/J.
	name string
}

// NewCloudRunJob resolves the job by project, region and short name.
func NewCloudRunJob(ctx context.Context, project, region, job string, opts ...option.ClientOption) (*CloudRunJob, error) {
	if project == "" || region == "" || job == "" {
		return nil, errors.New("cloud run job trigger: project, region and job name are required")
	}
	svc, err := run.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("cloud run client: %w", err)
	}
	return &CloudRunJob{svc: svc, name: fmt.Sprintf("projects/%s/locations/%s/jobs/%s", project, region, job)}, nil
}

// JobArgs is the argument vector the job runs with; the provision
// subcommand in cmd/qm-api parses exactly this.
func JobArgs(teamID, tenantID uuid.UUID, mode Mode) []string {
	return []string{"provision", "--team", teamID.String(), "--tenant", tenantID.String(), "--mode", string(mode)}
}

func (c *CloudRunJob) Trigger(ctx context.Context, teamID, tenantID uuid.UUID, mode Mode) error {
	req := &run.GoogleCloudRunV2RunJobRequest{
		Overrides: &run.GoogleCloudRunV2Overrides{
			ContainerOverrides: []*run.GoogleCloudRunV2ContainerOverride{{Args: JobArgs(teamID, tenantID, mode)}},
		},
	}
	if _, err := c.svc.Projects.Locations.Jobs.Run(c.name, req).Context(ctx).Do(); err != nil {
		// A 4xx is the API refusing the request: no execution exists. Any
		// other failure (network, 5xx, deadline) may have created one.
		var gerr *googleapi.Error
		if errors.As(err, &gerr) && gerr.Code >= 400 && gerr.Code < 500 {
			return fmt.Errorf("%w: run job %s: %w", ErrTriggerRejected, c.name, err)
		}
		return fmt.Errorf("run job %s: %w", c.name, err)
	}
	return nil
}
