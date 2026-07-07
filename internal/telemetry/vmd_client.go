package telemetry

import (
	"context"
	"time"

	"github.com/superserve-ai/sandbox/internal/vmdclient"
)

type instrumentedVMDClient struct {
	next     vmdclient.Client
	recorder Recorder
	region   string
	hostID   string
}

// WrapVMDClient records bounded VMD RPC metrics for high-value lifecycle and
// build operations. It never records VM IDs, sandbox IDs, paths, URLs, or raw
// error strings as labels.
func WrapVMDClient(next vmdclient.Client, recorder Recorder, region, hostID string) vmdclient.Client {
	if next == nil || recorder == nil {
		return next
	}
	return &instrumentedVMDClient{next: next, recorder: recorder, region: region, hostID: hostID}
}

func (c *instrumentedVMDClient) record(ctx context.Context, method string, started time.Time, err error) {
	result := ResultSuccess
	if err != nil {
		result = ResultError
	}
	c.recorder.RecordVMDCall(ctx, VMDCall{
		Method:   method,
		Result:   result,
		Region:   c.region,
		HostID:   c.hostID,
		Duration: time.Since(started),
	})
}

func (c *instrumentedVMDClient) DestroyInstance(ctx context.Context, instanceID string, force bool) (err error) {
	started := time.Now()
	defer func() { c.record(ctx, "DeleteVM", started, err) }()
	return c.next.DestroyInstance(ctx, instanceID, force)
}

func (c *instrumentedVMDClient) PauseInstance(ctx context.Context, instanceID, snapshotDir string) (snapshotPath, memPath string, err error) {
	started := time.Now()
	defer func() { c.record(ctx, "PauseVM", started, err) }()
	return c.next.PauseInstance(ctx, instanceID, snapshotDir)
}

func (c *instrumentedVMDClient) ResumeInstance(ctx context.Context, instanceID, snapshotPath, memPath string) (ipAddress string, actualVcpu, actualMemMiB uint32, err error) {
	started := time.Now()
	defer func() { c.record(ctx, "ResumeVM", started, err) }()
	return c.next.ResumeInstance(ctx, instanceID, snapshotPath, memPath)
}

func (c *instrumentedVMDClient) RestoreSnapshot(ctx context.Context, instanceID, snapshotPath, memPath, basePath, deltaDir, teamID, ownerID string, envVars map[string]string) (ipAddress string, actualVcpu, actualMemMiB uint32, err error) {
	started := time.Now()
	defer func() { c.record(ctx, "CreateVM", started, err) }()
	return c.next.RestoreSnapshot(ctx, instanceID, snapshotPath, memPath, basePath, deltaDir, teamID, ownerID, envVars)
}

func (c *instrumentedVMDClient) InjectSandboxEnv(ctx context.Context, instanceID string, envVars map[string]string, secretsJWT string) error {
	return c.next.InjectSandboxEnv(ctx, instanceID, envVars, secretsJWT)
}

func (c *instrumentedVMDClient) DeleteSnapshot(ctx context.Context, instanceID, snapshotPath, memPath string) error {
	return c.next.DeleteSnapshot(ctx, instanceID, snapshotPath, memPath)
}

func (c *instrumentedVMDClient) DeleteSandboxSnapshots(ctx context.Context, instanceID string) error {
	return c.next.DeleteSandboxSnapshots(ctx, instanceID)
}

func (c *instrumentedVMDClient) DeleteTemplateArtifacts(ctx context.Context, templateID string) error {
	return c.next.DeleteTemplateArtifacts(ctx, templateID)
}

func (c *instrumentedVMDClient) DeleteBuildArtifacts(ctx context.Context, templateID, buildID string) error {
	return c.next.DeleteBuildArtifacts(ctx, templateID, buildID)
}

func (c *instrumentedVMDClient) ListBuildArtifacts(ctx context.Context) ([]vmdclient.BuildArtifactEntry, error) {
	return c.next.ListBuildArtifacts(ctx)
}

func (c *instrumentedVMDClient) ListDir(ctx context.Context, instanceID, path string) ([]vmdclient.DirEntry, error) {
	return c.next.ListDir(ctx, instanceID, path)
}

func (c *instrumentedVMDClient) UpdateSandboxNetwork(ctx context.Context, instanceID string, allowedCIDRs, deniedCIDRs, allowedDomains []string) error {
	return c.next.UpdateSandboxNetwork(ctx, instanceID, allowedCIDRs, deniedCIDRs, allowedDomains)
}

func (c *instrumentedVMDClient) InvalidateSecret(ctx context.Context, secretID string) error {
	return c.next.InvalidateSecret(ctx, secretID)
}

func (c *instrumentedVMDClient) RevokeSandbox(ctx context.Context, sandboxID string) error {
	return c.next.RevokeSandbox(ctx, sandboxID)
}

func (c *instrumentedVMDClient) InvalidateSandboxRules(ctx context.Context, sandboxID string) error {
	return c.next.InvalidateSandboxRules(ctx, sandboxID)
}

func (c *instrumentedVMDClient) BuildTemplate(ctx context.Context, req vmdclient.BuildTemplateInput) (buildVMID string, err error) {
	started := time.Now()
	defer func() { c.record(ctx, "BuildTemplate", started, err) }()
	return c.next.BuildTemplate(ctx, req)
}

func (c *instrumentedVMDClient) GetBuildStatus(ctx context.Context, buildVMID string) (res vmdclient.BuildStatusResult, err error) {
	started := time.Now()
	defer func() { c.record(ctx, "GetBuildStatus", started, err) }()
	return c.next.GetBuildStatus(ctx, buildVMID)
}

func (c *instrumentedVMDClient) CancelBuild(ctx context.Context, buildVMID string) (err error) {
	started := time.Now()
	defer func() { c.record(ctx, "CancelBuild", started, err) }()
	return c.next.CancelBuild(ctx, buildVMID)
}

func (c *instrumentedVMDClient) StreamBuildLogs(ctx context.Context, buildVMID string, onEvent func(vmdclient.BuildLogEvent) error) error {
	return c.next.StreamBuildLogs(ctx, buildVMID, onEvent)
}
