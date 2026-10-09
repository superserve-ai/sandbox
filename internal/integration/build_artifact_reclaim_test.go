//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/superserve-ai/sandbox/internal/db"
)

// rebuildFor submits a second build of the same template, the way a rebuild
// does once the template's resources or spec have moved.
func rebuildFor(t *testing.T, prior db.TemplateBuild) db.TemplateBuild {
	t.Helper()
	b, err := testQueries.CreateTemplateBuild(context.Background(), db.CreateTemplateBuildParams{
		TemplateID: prior.TemplateID, TeamID: prior.TeamID, BuildSpecHash: uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("submit rebuild: %v", err)
	}
	return b
}

// A promoted generation stays in 'ready' with its publication for good, so
// reading either as protection pinned every superseded generation on its host
// forever — the destroy-time GC skipped them and any reaper built on the same
// predicate would reclaim nothing. Protection means the generation is still
// owed to something, not that it was once promoted.
func TestIntegration_SupersededGenerationIsReclaimable(t *testing.T) {
	ctx := context.Background()
	older, cell := executionFixture(t)
	executionHost(t, cell, "active")
	olderAttempt := claimExecution(t, older, cell)
	admitExecution(t, olderAttempt)
	if !finalizeExecution(t, older.ID, olderAttempt) {
		t.Fatal("first generation was refused")
	}
	if !recordExecution(t, olderAttempt) {
		t.Fatal("first generation publication rejected")
	}

	// Its own generation owns the template, so it is protected while current.
	protected, err := testQueries.BuildArtifactProtected(ctx, olderAttempt.VMID)
	if err != nil {
		t.Fatal(err)
	}
	if !protected {
		t.Fatal("the template's current generation is reclaimable")
	}

	// A rebuild promotes a new generation over it. Resources differ so the
	// in-flight uniqueness admits a second build for the same template.
	if _, err := testPool.Exec(ctx, `UPDATE template SET vcpu = vcpu + 1 WHERE id = $1`, older.TemplateID); err != nil {
		t.Fatal(err)
	}
	newer := rebuildFor(t, older)
	newerAttempt := claimExecution(t, newer, cell)
	admitExecution(t, newerAttempt)
	if !finalizeExecution(t, newer.ID, newerAttempt) {
		t.Fatal("second generation was refused")
	}

	protected, err = testQueries.BuildArtifactProtected(ctx, olderAttempt.VMID)
	if err != nil {
		t.Fatal(err)
	}
	if protected {
		t.Fatal("a superseded generation is still pinned; its artifacts can never be reclaimed")
	}
	protected, err = testQueries.BuildArtifactProtected(ctx, newerAttempt.VMID)
	if err != nil {
		t.Fatal(err)
	}
	if !protected {
		t.Fatal("the generation the template now points at is reclaimable")
	}
}

// Live references are counted on the exact base path, not derived from the
// attempt, so the rule a collector applies is the predicate AND that count.
// A sandbox built from a superseded generation keeps it whatever the template
// points at now, and releases it only once the sandbox is gone.
func TestIntegration_SupersededGenerationStaysPinnedByALiveSandbox(t *testing.T) {
	ctx := context.Background()
	older, cell := executionFixture(t)
	executionHost(t, cell, "active")
	olderAttempt := claimExecution(t, older, cell)
	admitExecution(t, olderAttempt)
	if !finalizeExecution(t, older.ID, olderAttempt) {
		t.Fatal("first generation was refused")
	}
	// Durable, so the only thing that can still pin it is the sandbox below.
	if !recordExecution(t, olderAttempt) {
		t.Fatal("first generation publication rejected")
	}

	var sandboxID uuid.UUID
	base := "/artifacts/" + olderAttempt.TemplateID.String() + "/" + olderAttempt.VMID + "/base.ext4"
	if err := testPool.QueryRow(ctx, `
		INSERT INTO sandbox (team_id, name, status, host_id, base_path)
		VALUES ($1, 'pins-the-base', 'paused', $2, $3) RETURNING id`,
		older.TeamID, olderAttempt.HostID, base).Scan(&sandboxID); err != nil {
		t.Fatal(err)
	}

	if _, err := testPool.Exec(ctx, `UPDATE template SET vcpu = vcpu + 1 WHERE id = $1`, older.TemplateID); err != nil {
		t.Fatal(err)
	}
	newer := rebuildFor(t, older)
	newerAttempt := claimExecution(t, newer, cell)
	admitExecution(t, newerAttempt)
	if !finalizeExecution(t, newer.ID, newerAttempt) {
		t.Fatal("second generation was refused")
	}

	reclaimable := func() bool {
		t.Helper()
		protected, err := testQueries.BuildArtifactProtected(ctx, olderAttempt.VMID)
		if err != nil {
			t.Fatal(err)
		}
		refs, err := testQueries.CountActiveSandboxesAtBasePath(ctx, &base)
		if err != nil {
			t.Fatal(err)
		}
		return !protected && refs == 0
	}
	if reclaimable() {
		t.Fatal("a live sandbox's base image was left reclaimable")
	}

	// Once the sandbox is gone, nothing is owed the generation any more.
	if _, err := testPool.Exec(ctx, `UPDATE sandbox SET destroyed_at = now() WHERE id = $1`, sandboxID); err != nil {
		t.Fatal(err)
	}
	if !reclaimable() {
		t.Fatal("the generation stayed pinned after its last sandbox was destroyed")
	}
}

// Readiness runs ahead of the upload, so a promoted build can be superseded
// while its publication is still outstanding. Its artifacts are the only copy
// of it and the uploader is still reading those paths, so reclaiming them
// would strand the generation with no way to reconcile it later.
func TestIntegration_SupersededGenerationStaysPinnedUntilItsUploadIsAccepted(t *testing.T) {
	ctx := context.Background()
	older, cell := executionFixture(t)
	executionHost(t, cell, "active")
	olderAttempt := claimExecution(t, older, cell)
	admitExecution(t, olderAttempt)
	if !finalizeExecution(t, older.ID, olderAttempt) {
		t.Fatal("first generation was refused")
	}

	// Superseded with nothing referencing it, so only the outstanding upload
	// is left to protect it.
	if _, err := testPool.Exec(ctx, `UPDATE template SET vcpu = vcpu + 1 WHERE id = $1`, older.TemplateID); err != nil {
		t.Fatal(err)
	}
	newer := rebuildFor(t, older)
	newerAttempt := claimExecution(t, newer, cell)
	admitExecution(t, newerAttempt)
	if !finalizeExecution(t, newer.ID, newerAttempt) {
		t.Fatal("second generation was refused")
	}

	protected, err := testQueries.BuildArtifactProtected(ctx, olderAttempt.VMID)
	if err != nil {
		t.Fatal(err)
	}
	if !protected {
		t.Fatal("a generation whose upload has not been accepted was left reclaimable")
	}

	// The upload lands. A superseded generation is fenced out of adoption, so
	// accepted_at stays null, but its objects are verified in the bucket and
	// the host copy is free.
	if !recordExecution(t, olderAttempt) {
		t.Fatal("publication rejected")
	}
	var accepted bool
	if err := testPool.QueryRow(ctx,
		`SELECT accepted_at IS NOT NULL FROM template_build_publication WHERE attempt_id = $1`,
		olderAttempt.ID).Scan(&accepted); err != nil {
		t.Fatal(err)
	}
	if accepted {
		t.Fatal("fixture no longer covers the superseded case: the publication was adopted")
	}
	protected, err = testQueries.BuildArtifactProtected(ctx, olderAttempt.VMID)
	if err != nil {
		t.Fatal(err)
	}
	if protected {
		t.Fatal("the generation stayed pinned after its upload reached the bucket")
	}
}

// The orphan reconciler deletes what is on disk and absent from its live set,
// so a live set naming every generation ever promoted deletes nothing. The
// keys it takes from the attempts must cover only generations still owed.
func TestIntegration_LiveBuildKeysReleaseSupersededGenerations(t *testing.T) {
	ctx := context.Background()
	older, cell := executionFixture(t)
	executionHost(t, cell, "active")
	olderAttempt := claimExecution(t, older, cell)
	admitExecution(t, olderAttempt)
	if !finalizeExecution(t, older.ID, olderAttempt) {
		t.Fatal("first generation was refused")
	}
	if !recordExecution(t, olderAttempt) {
		t.Fatal("first generation publication rejected")
	}
	if _, err := testPool.Exec(ctx, `UPDATE template SET vcpu = vcpu + 1 WHERE id = $1`, older.TemplateID); err != nil {
		t.Fatal(err)
	}
	newer := rebuildFor(t, older)
	newerAttempt := claimExecution(t, newer, cell)
	admitExecution(t, newerAttempt)
	if !finalizeExecution(t, newer.ID, newerAttempt) {
		t.Fatal("second generation was refused")
	}

	keys, err := testQueries.ProtectedBuildAttemptKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	held := map[string]bool{}
	for _, k := range keys {
		held[k] = true
	}
	superseded := older.TemplateID.String() + "/" + olderAttempt.VMID
	current := newer.TemplateID.String() + "/" + newerAttempt.VMID
	if held[superseded] {
		t.Fatal("the live set still names a superseded generation, so the reconciler can never delete it")
	}
	if !held[current] {
		t.Fatal("the live set dropped the generation the template is serving")
	}
}

// Deleting a template that has build executions leaves its host artifacts
// behind for the reconciler, so the live set must release them: both the
// attempt rule and the template-pointer input are scoped to live templates.
func TestIntegration_DeletedTemplateReleasesItsGeneration(t *testing.T) {
	ctx := context.Background()
	tb, cell := executionFixture(t)
	executionHost(t, cell, "active")
	attempt := claimExecution(t, tb, cell)
	admitExecution(t, attempt)
	if !finalizeExecution(t, tb.ID, attempt) {
		t.Fatal("generation was refused")
	}
	if !recordExecution(t, attempt) {
		t.Fatal("publication rejected")
	}

	if _, err := testPool.Exec(ctx, `UPDATE template SET deleted_at = now() WHERE id = $1`, tb.TemplateID); err != nil {
		t.Fatal(err)
	}

	protected, err := testQueries.BuildArtifactProtected(ctx, attempt.VMID)
	if err != nil {
		t.Fatal(err)
	}
	if protected {
		t.Fatal("a deleted template's generation is still pinned; its artifacts can never be reclaimed")
	}
	keys, err := testQueries.ProtectedBuildAttemptKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if k == tb.TemplateID.String()+"/"+attempt.VMID {
			t.Fatal("the live set still names a deleted template's generation")
		}
	}
	paths, err := testQueries.ListAllTemplateBasePaths(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		if p.ID == tb.TemplateID {
			t.Fatal("the reconciler's template pointers still include a deleted template")
		}
	}
}

// Readiness runs ahead of the upload and record_template_publication refuses
// a deleted template's upload, so a template deleted in that window leaves an
// attempt that can never obtain a publication. Protecting it on the missing
// publication alone would hold its artifacts for the life of the host.
func TestIntegration_DeletedTemplateReleasesAnUnpublishedGeneration(t *testing.T) {
	ctx := context.Background()
	tb, cell := executionFixture(t)
	executionHost(t, cell, "active")
	attempt := claimExecution(t, tb, cell)
	admitExecution(t, attempt)
	if !finalizeExecution(t, tb.ID, attempt) {
		t.Fatal("generation was refused")
	}

	// Deleted before the upload lands, which is what makes it unreachable.
	if _, err := testPool.Exec(ctx, `UPDATE template SET deleted_at = now() WHERE id = $1`, tb.TemplateID); err != nil {
		t.Fatal(err)
	}
	if recordExecution(t, attempt) {
		t.Fatal("fixture no longer covers the case: the deleted template accepted a publication")
	}

	protected, err := testQueries.BuildArtifactProtected(ctx, attempt.VMID)
	if err != nil {
		t.Fatal(err)
	}
	if protected {
		t.Fatal("a generation whose upload can never be recorded is pinned for good")
	}
}
