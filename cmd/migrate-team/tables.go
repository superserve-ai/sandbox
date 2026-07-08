package main

// The team's dataset, in FK dependency order. copy walks this list forward;
// decommission walks it backward (profiles excluded — they are global and may
// belong to other teams).
//
// Scope conditions take the team id as $1 and must be valid in both a SELECT
// WHERE clause and a DELETE WHERE clause.

// profileScope is every profile the team's rows reference: members plus every
// actor/grantor/approver column. Copying members alone would break FKs from
// activity.actor_id etc. when a former member's events are still in scope.
const profileScope = `id IN (
	SELECT profile_id FROM team_member WHERE team_id = $1
	UNION SELECT user_id FROM team_memberships WHERE team_id = $1
	UNION SELECT user_id FROM user_role_assignments WHERE team_id = $1
	UNION SELECT granted_by FROM user_role_assignments WHERE team_id = $1 AND granted_by IS NOT NULL
	UNION SELECT created_by FROM api_key WHERE team_id = $1 AND created_by IS NOT NULL
	UNION SELECT actor_id FROM activity WHERE team_id = $1 AND actor_id IS NOT NULL
	UNION SELECT actor_id FROM sandbox_active_interval WHERE team_id = $1 AND actor_id IS NOT NULL
	UNION SELECT approved_by FROM team_billing_period WHERE team_id = $1 AND approved_by IS NOT NULL
	UNION SELECT resolved_by FROM billing_period_anomaly WHERE team_id = $1 AND resolved_by IS NOT NULL
	UNION SELECT assigned_by FROM team_pricing_plan WHERE team_id = $1 AND assigned_by IS NOT NULL
	UNION SELECT created_by FROM team_credit_grant WHERE team_id = $1 AND created_by IS NOT NULL
	UNION SELECT created_by FROM team_credit_ledger WHERE team_id = $1 AND created_by IS NOT NULL
)`

// sandboxScope covers tables keyed by sandbox_id without a team_id column.
const sandboxScope = `sandbox_id IN (SELECT id FROM sandbox WHERE team_id = $1)`

type tableSpec struct {
	name  string
	scope string
}

// copyScopes narrows what copy and validation see for a table; decommission
// still deletes by the full scope. Used to carve rows out of the generic
// pipeline that the tool manages explicitly: the rollup-hold flag row must
// not be copied, or an explicit TRUE from the source would overwrite the
// hold mid-copy and reopen the dest scheduler window before the interval
// and rollup tables have landed.
var copyScopes = map[string]string{
	"team_feature_flag": "team_id = $1 AND key <> 'billing_hourly_rollups'",
}

// effectiveCopyScope is the WHERE clause copy and validation share.
func (t tableSpec) effectiveCopyScope() string {
	if s, ok := copyScopes[t.name]; ok {
		return s
	}
	return t.scope
}

var migratedTables = []tableSpec{
	{"profile", profileScope},
	{"team", "id = $1"},
	{"team_feature_flag", "team_id = $1"},
	{"team_member", "team_id = $1"},
	// team_memberships before user_role_assignments: a dest-side trigger
	// requires an active membership before accepting an active team-scoped
	// role assignment.
	{"team_memberships", "team_id = $1"},
	// Platform-scoped assignments (team_id IS NULL) are per-cell operator
	// grants and are deliberately not part of a team migration.
	{"user_role_assignments", "team_id = $1 AND scope_type = 'team'"},
	{"api_key", "team_id = $1"},
	// Same KMS KEK in both cells (verified), so ciphertext + wrapped DEK
	// copy as-is.
	{"secret", "team_id = $1"},
	{"template", "team_id = $1"},
	// Only terminal builds travel: a copied 'pending' row would be
	// dispatched by the dest build supervisor, and 'building'/'snapshotting'
	// rows reference in-flight build VMs that don't exist in the dest cell.
	// In-flight builds additionally block the copy phase (see activeBuilds).
	{"template_build", "team_id = $1 AND status NOT IN ('pending', 'building', 'snapshotting')"},
	// sandbox inserts with snapshot_id NULL; snapshots follow; then the
	// circular sandbox.snapshot_id ↔ snapshot.sandbox_id FK is relinked.
	{"sandbox", "team_id = $1"},
	{"snapshot", "team_id = $1"},
	{"sandbox_secret", sandboxScope},
	{"sandbox_active_interval", "team_id = $1"},
	{"sandbox_compute_billing_interval", "team_id = $1"},
	{"sandbox_storage_interval", "team_id = $1"},
	{"team_billing_usage", "team_id = $1"},
	{"team_billing_usage_hourly", "team_id = $1"},
	{"team_billing_period", "team_id = $1"},
	{"billing_period_anomaly", "team_id = $1"},
	{"billing_rollup_job", "team_id = $1"},
	{"billing_rollup_team_backfill_state", "team_id = $1"},
	{"team_pricing_plan", "team_id = $1"},
	{"team_credit_grant", "team_id = $1"},
	{"team_credit_ledger", "team_id = $1"},
	{"quota_alert_state", "team_id = $1"},
	{"activity", "team_id = $1"},
	// Live revocations move with the team so a stale sandbox JWT can't be
	// replayed against the dest cell's proxy. Rows self-expire.
	{"sandbox_revocation", sandboxScope},
	{"revoked_proxy_token", sandboxScope},
}

// skippedTables are team-adjacent tables the migration deliberately leaves
// alone. Printed by plan and copy so the decision is visible in the runbook
// transcript.
var skippedTables = []struct{ name, reason string }{
	{"proxy_audit", "append-only request audit; stays in the source cell"},
	{"net_flow", "append-only egress-flow audit; stays in the source cell"},
	{"audit_logs", "append-only RBAC audit (delete-blocked by trigger); stays in the source cell"},
	{"reconciler_log", "audit of the source cell's hosts; meaningless in the dest cell"},
	{"device_code", "ephemeral per-user login flow; global Auth re-issues on next login"},
	{"host", "cell-local infrastructure"},
	{"roles, permissions, role_permissions", "migration-seeded per cell; assignments are remapped by role name"},
	{"feature_flag, pricing_plan, pricing_rate", "migration-seeded per cell"},
	{"billing_rollup_scheduler_lease, billing_rollup_backfill_state", "global scheduler state, not team-scoped"},
	{"early_access_request", "not team-scoped"},
}

// tableByName finds a migrated table's spec.
func tableByName(name string) (tableSpec, bool) {
	for _, t := range migratedTables {
		if t.name == name {
			return t, true
		}
	}
	return tableSpec{}, false
}
