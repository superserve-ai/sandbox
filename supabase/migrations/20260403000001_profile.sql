CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE profile (
    id                  uuid PRIMARY KEY,  -- matches auth.users.id
    email               text NOT NULL,
    full_name           text,
    avatar_url          text,
    provider            text,
    provider_id         text,
    storage_quota_bytes bigint NOT NULL DEFAULT 1073741824,
    storage_used_bytes  bigint NOT NULL DEFAULT 0,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now()
);

