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
-- A trigger also covers writers built before the owner-prefixed index.
ALTER TABLE media.versions ADD COLUMN IF NOT EXISTS owner_key text;
UPDATE media.versions v SET owner_key=f.owner_key FROM media.files f WHERE v.file_id=f.id AND v.owner_key IS NULL;
ALTER TABLE media.versions ALTER COLUMN owner_key SET NOT NULL;
CREATE OR REPLACE FUNCTION media.version_owner_key() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 SELECT f.owner_key INTO STRICT NEW.owner_key FROM media.files f WHERE f.id=NEW.file_id;
 RETURN NEW;
END $$;
CREATE OR REPLACE TRIGGER version_owner_key BEFORE INSERT OR UPDATE OF file_id,owner_key ON media.versions
FOR EACH ROW EXECUTE FUNCTION media.version_owner_key();
CREATE INDEX IF NOT EXISTS media_owner_content_reuse ON media.versions(owner_key,(data->>'sha256'),((data->>'size')::bigint),(data->>'content_type'),id) WHERE state IN ('awaiting_approval','approved','ready');
DROP INDEX IF EXISTS media.media_content_reuse;
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
