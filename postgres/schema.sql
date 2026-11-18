CREATE SCHEMA IF NOT EXISTS media;
CREATE TABLE IF NOT EXISTS media.files (
 id text PRIMARY KEY, owner_key text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), data jsonb NOT NULL
);
ALTER TABLE media.files ADD COLUMN IF NOT EXISTS created_at timestamptz;
UPDATE media.files SET created_at = COALESCE((data->>'created_at')::timestamptz, now()) WHERE created_at IS NULL;
ALTER TABLE media.files ALTER COLUMN created_at SET DEFAULT now();
ALTER TABLE media.files ALTER COLUMN created_at SET NOT NULL;
CREATE INDEX IF NOT EXISTS media_files_owner ON media.files(owner_key);
CREATE INDEX IF NOT EXISTS media_files_owner_cursor ON media.files(owner_key,id);
CREATE INDEX IF NOT EXISTS media_files_owner_created_cursor ON media.files(owner_key,created_at DESC,id DESC);
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
-- Retain historical identities and idempotency while releasing active quota.
UPDATE media.files f SET data=data || jsonb_build_object('retired',true,'disabled',true,'deleting',false,'revision',(data->>'revision')::bigint+1)
WHERE NOT (data @> '{"retired":true}')
 AND EXISTS (SELECT FROM media.versions WHERE file_id=f.id)
 AND NOT EXISTS (SELECT FROM media.versions WHERE file_id=f.id AND NOT(data @> '{"cleanup_complete":true}'));
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
-- Give undated legacy responses a full replay window from migration.
ALTER TABLE media.replays ADD COLUMN IF NOT EXISTS expires_at timestamptz NOT NULL DEFAULT (now()+interval '24 hours');
CREATE INDEX IF NOT EXISTS media_replays_expiry ON media.replays(expires_at,key);
CREATE TABLE IF NOT EXISTS media.outbox (id text PRIMARY KEY, data jsonb NOT NULL, delivered boolean NOT NULL DEFAULT false);
-- Existing rows have random ids. Preserve per-subject revision order when
-- assigning their initial delivery positions, then let PostgreSQL assign new ones.
DO $$
DECLARE next_seq bigint;
BEGIN
 LOCK TABLE media.outbox IN ACCESS EXCLUSIVE MODE;
 IF NOT EXISTS (SELECT FROM pg_attribute WHERE attrelid='media.outbox'::regclass AND attname='seq' AND NOT attisdropped) THEN
  ALTER TABLE media.outbox ADD COLUMN seq bigint;
  WITH ordered AS (
   SELECT id,row_number() OVER (ORDER BY data->>'subject',(data->'data'->>'revision')::bigint,(data->>'time')::timestamptz,id) AS pos FROM media.outbox
  ) UPDATE media.outbox o SET seq=ordered.pos FROM ordered WHERE o.id=ordered.id;
  ALTER TABLE media.outbox ALTER COLUMN seq SET NOT NULL;
  ALTER TABLE media.outbox ALTER COLUMN seq ADD GENERATED ALWAYS AS IDENTITY;
  SELECT coalesce(max(seq),0)+1 INTO next_seq FROM media.outbox;
  EXECUTE format('ALTER TABLE media.outbox ALTER COLUMN seq RESTART WITH %s',next_seq);
 END IF;
END $$;
CREATE INDEX IF NOT EXISTS media_outbox_pending_seq ON media.outbox(seq) WHERE NOT delivered;
CREATE TABLE IF NOT EXISTS media.audit (id text PRIMARY KEY, data jsonb NOT NULL);
REVOKE ALL ON SCHEMA media FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA media FROM PUBLIC;
