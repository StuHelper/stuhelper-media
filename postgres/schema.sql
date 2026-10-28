CREATE SCHEMA IF NOT EXISTS media;
CREATE TABLE IF NOT EXISTS media.files (
 id text PRIMARY KEY, owner_key text NOT NULL, data jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS media_files_owner ON media.files(owner_key);
CREATE INDEX IF NOT EXISTS media_files_owner_cursor ON media.files(owner_key,id);
CREATE TABLE IF NOT EXISTS media.versions (
 id text PRIMARY KEY, file_id text NOT NULL REFERENCES media.files(id),
 upload_id text NOT NULL UNIQUE, number integer NOT NULL, state text NOT NULL,
 data jsonb NOT NULL, UNIQUE(file_id,number)
);
CREATE TABLE IF NOT EXISTS media.references (
 id text PRIMARY KEY, version_id text NOT NULL REFERENCES media.versions(id), data jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS media_references_version ON media.references(version_id);
CREATE TABLE IF NOT EXISTS media.jobs (
 version_id text PRIMARY KEY REFERENCES media.versions(id), state text NOT NULL,
 available_at timestamptz NOT NULL, lease_until timestamptz NOT NULL, data jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS media_jobs_claim ON media.jobs(state,available_at,lease_until);
CREATE TABLE IF NOT EXISTS media.replays (key text PRIMARY KEY, data jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS media.outbox (id text PRIMARY KEY, data jsonb NOT NULL, delivered boolean NOT NULL DEFAULT false);
CREATE INDEX IF NOT EXISTS media_outbox_pending ON media.outbox(id) WHERE NOT delivered;
CREATE TABLE IF NOT EXISTS media.audit (id text PRIMARY KEY, data jsonb NOT NULL);
REVOKE ALL ON SCHEMA media FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA media FROM PUBLIC;
