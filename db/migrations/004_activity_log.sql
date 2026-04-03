-- 004_activity_log.sql
-- Activity log for tracking system events (auto-wake, etc.)

CREATE TABLE activity (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vm_id      uuid NOT NULL REFERENCES vms(id),
    category   text NOT NULL,
    action     text NOT NULL,
    metadata   jsonb DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_activity_vm_id ON activity(vm_id, created_at DESC);
CREATE INDEX idx_activity_category_action ON activity(category, action);
