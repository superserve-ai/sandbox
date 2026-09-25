-- Historical builds have no trustworthy submission snapshot; do not backfill
-- from mutable template rows. New submissions capture inputs in their own txn.
CREATE TABLE template_build_input (
    build_id uuid PRIMARY KEY REFERENCES template_build(id) ON DELETE CASCADE,
    build_spec jsonb NOT NULL,
    vcpu integer NOT NULL CHECK (vcpu > 0),
    memory_mib integer NOT NULL CHECK (memory_mib > 0),
    disk_mib integer NOT NULL CHECK (disk_mib > 0)
);
ALTER TABLE template_build_input ENABLE ROW LEVEL SECURITY;

CREATE FUNCTION capture_template_build_input() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    -- Explicit non-pending inserts are imported historical rows. Their original
    -- submission inputs cannot be recovered from a mutable template.
    IF NEW.status <> 'pending' THEN RETURN NEW; END IF;
    INSERT INTO template_build_input (build_id, build_spec, vcpu, memory_mib, disk_mib)
    SELECT NEW.id, t.build_spec, t.vcpu, t.memory_mib, t.disk_mib
    FROM template t
    WHERE t.id = NEW.template_id AND t.team_id = NEW.team_id AND t.deleted_at IS NULL
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'template is missing, deleted, or owned by another team';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER capture_template_build_input
AFTER INSERT ON template_build
FOR EACH ROW EXECUTE FUNCTION capture_template_build_input();

CREATE FUNCTION reject_template_build_input_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'submitted template build inputs are immutable';
END;
$$;
CREATE TRIGGER reject_template_build_input_update
BEFORE UPDATE ON template_build_input
FOR EACH ROW EXECUTE FUNCTION reject_template_build_input_update();
