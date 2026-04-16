-- Audit log for every reconciler action.

CREATE TABLE reconciler_log (
    id          bigserial PRIMARY KEY,
    host_id     text NOT NULL,
    sandbox_id  uuid,
    action      text NOT NULL,
    reason      text NOT NULL,
    drift_kind  text,
    created_at  timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT reconciler_log_action_valid CHECK (action IN (
        'mark_failed',
        'orphan_stop',
        'stale_cleanup',
        'budget_exhausted'
    ))
);

CREATE INDEX idx_reconciler_log_host ON reconciler_log(host_id, created_at DESC);
CREATE INDEX idx_reconciler_log_sandbox ON reconciler_log(sandbox_id, created_at DESC) WHERE sandbox_id IS NOT NULL;

ALTER TABLE public.reconciler_log ENABLE ROW LEVEL SECURITY;
