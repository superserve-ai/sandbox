package db

import (
	"context"

	"github.com/google/uuid"
)

// SubmittedTemplateBuildInput is the immutable submission snapshot. It is kept apart
// from TemplateBuild so public build status never serializes guest secrets.
type SubmittedTemplateBuildInput struct {
	BuildSpec []byte
	Vcpu      int32
	MemoryMib int32
	DiskMib   int32
}

func (q *Queries) GetTemplateBuildInput(ctx context.Context, buildID uuid.UUID) (SubmittedTemplateBuildInput, error) {
	var input SubmittedTemplateBuildInput
	err := q.db.QueryRow(ctx, `SELECT build_spec, vcpu, memory_mib, disk_mib
		FROM template_build_input WHERE build_id = $1`, buildID).
		Scan(&input.BuildSpec, &input.Vcpu, &input.MemoryMib, &input.DiskMib)
	return input, err
}
