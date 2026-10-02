package db

// RoutingSandbox is the common create result, including the database observation
// time used to expire hints even when a lifecycle response is delayed.
type RoutingSandbox CreateSandboxRow

func (r RoutingSandbox) Sandbox() Sandbox {
	return Sandbox{
		ID:                   r.ID,
		TeamID:               r.TeamID,
		Name:                 r.Name,
		Status:               r.Status,
		VcpuCount:            r.VcpuCount,
		MemoryMib:            r.MemoryMib,
		HostID:               r.HostID,
		IpAddress:            r.IpAddress,
		Pid:                  r.Pid,
		SnapshotID:           r.SnapshotID,
		CreatedAt:            r.CreatedAt,
		UpdatedAt:            r.UpdatedAt,
		DestroyedAt:          r.DestroyedAt,
		NetworkConfig:        r.NetworkConfig,
		TimeoutSeconds:       r.TimeoutSeconds,
		Metadata:             r.Metadata,
		TemplateID:           r.TemplateID,
		SnapshotPath:         r.SnapshotPath,
		MemPath:              r.MemPath,
		BasePath:             r.BasePath,
		DeltaPath:            r.DeltaPath,
		DiskMib:              r.DiskMib,
		AutoDeleteSeconds:    r.AutoDeleteSeconds,
		AutoDeleteAt:         r.AutoDeleteAt,
		FailedAt:             r.FailedAt,
		HadSecretBindings:    r.HadSecretBindings,
		SecretEnvFingerprint: r.SecretEnvFingerprint,
		SecretEnvIp:          r.SecretEnvIp,
		SecretEnvInjectedAt:  r.SecretEnvInjectedAt,
		SecretEnvExpiresAt:   r.SecretEnvExpiresAt,
		PauseOpID:            r.PauseOpID,
		PauseOpStartedAt:     r.PauseOpStartedAt,
		PauseOpLeaseUntil:    r.PauseOpLeaseUntil,
		PauseOpLeaseVersion:  r.PauseOpLeaseVersion,
		PauseOpAttentionAt:   r.PauseOpAttentionAt,
		PauseOpTrigger:       r.PauseOpTrigger,
		PauseOpActorID:       r.PauseOpActorID,
		RoutingVersion:       r.RoutingVersion,
		SourceSnapshotID:     r.SourceSnapshotID,
	}
}
