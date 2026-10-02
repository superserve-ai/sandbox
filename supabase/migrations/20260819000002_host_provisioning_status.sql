-- Host self-registration: a vmd heartbeating an unknown host id creates its
-- own row in 'provisioning'. The status is invisible to the scheduler (which
-- filters on 'active') and to the unhealthy-host detector (which only demotes
-- 'active'), so a provisioning host heartbeats freely without taking traffic
-- until an operator activates it.

ALTER TABLE host DROP CONSTRAINT IF EXISTS host_status_valid;
ALTER TABLE host ADD CONSTRAINT host_status_valid
    CHECK (status IN ('provisioning', 'active', 'draining', 'unhealthy'));
