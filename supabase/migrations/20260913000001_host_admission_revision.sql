CREATE SEQUENCE host_admission_revision_seq;
ALTER TABLE host ADD COLUMN admission_revision bigint NOT NULL DEFAULT 0;
