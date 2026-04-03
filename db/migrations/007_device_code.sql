-- +goose Up
CREATE TABLE device_code (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    device_code text NOT NULL UNIQUE,
    user_code   text NOT NULL UNIQUE,
    user_id     uuid REFERENCES profile(id),
    status      text NOT NULL DEFAULT 'pending',
    expires_at  timestamptz NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT device_code_status_check CHECK (status IN ('pending', 'approved', 'denied', 'expired'))
);

-- +goose Down
DROP TABLE IF EXISTS device_code;
