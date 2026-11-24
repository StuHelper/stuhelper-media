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

ALTER TABLE media.versions ADD COLUMN IF NOT EXISTS cleanup_started boolean NOT NULL DEFAULT false;
ALTER TABLE media.versions ADD COLUMN IF NOT EXISTS cleaned_at timestamptz;
CREATE INDEX IF NOT EXISTS media_cleaned_versions ON media.versions(cleaned_at,id) WHERE cleaned_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS media_cleaned_event ON media.audit((data#>>'{event,subject}')) WHERE data#>>'{event,type}'='media.version.cleaned';
CREATE INDEX IF NOT EXISTS media_legacy_cleanup_pending ON media.versions(id) WHERE cleaned_at IS NULL AND data @> '{"cleanup_complete":true}';
CREATE OR REPLACE FUNCTION media.record_cleanup_time() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.data @> '{"cleanup_complete":true}' AND NEW.cleaned_at IS NULL THEN NEW.cleaned_at:=statement_timestamp(); END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS media_cleanup_confirmed ON media.versions;
CREATE TRIGGER media_cleanup_confirmed BEFORE INSERT OR UPDATE OF data ON media.versions FOR EACH ROW EXECUTE FUNCTION media.record_cleanup_time();

ALTER TABLE media.outbox ADD COLUMN IF NOT EXISTS delivered_at timestamptz;
CREATE INDEX IF NOT EXISTS media_pending_delivery_time ON media.outbox(id) WHERE delivered AND delivered_at IS NULL;
CREATE INDEX IF NOT EXISTS media_delivered_expiry ON media.outbox(delivered_at,id) WHERE delivered;

CREATE TABLE IF NOT EXISTS media.retention_holds(
 kind text NOT NULL CHECK(kind IN ('content','version','audit','event','replay')),object_id text NOT NULL,case_ref text NOT NULL,
 basis text NOT NULL,purpose text NOT NULL,end_condition text NOT NULL,review_at timestamptz NOT NULL,
 held_evidence jsonb, until_at timestamptz NOT NULL CHECK(isfinite(until_at) AND review_at<=until_at),PRIMARY KEY(kind,object_id,case_ref)
);
REVOKE ALL ON media.retention_holds FROM PUBLIC;
CREATE OR REPLACE FUNCTION media.validate_retention_hold() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='UPDATE' AND (OLD.kind,OLD.object_id,OLD.case_ref)<>(NEW.kind,NEW.object_id,NEW.case_ref) THEN RAISE EXCEPTION 'immutable hold scope'; END IF;
 CASE NEW.kind
 WHEN 'content' THEN PERFORM id FROM media.versions WHERE id=NEW.object_id AND NOT cleanup_started AND cleaned_at IS NULL FOR UPDATE;
 WHEN 'version' THEN PERFORM id FROM media.versions WHERE id=NEW.object_id FOR UPDATE;
 WHEN 'event' THEN
   IF TG_OP='UPDATE' THEN NEW.held_evidence:=OLD.held_evidence; RETURN NEW; END IF;
   SELECT data INTO NEW.held_evidence FROM media.outbox WHERE id=NEW.object_id FOR UPDATE;
 WHEN 'audit' THEN
   IF TG_OP='UPDATE' THEN NEW.held_evidence:=OLD.held_evidence; RETURN NEW; END IF;
   SELECT data INTO NEW.held_evidence FROM media.audit WHERE id=NEW.object_id FOR UPDATE;
 WHEN 'replay' THEN
   IF TG_OP='UPDATE' THEN NEW.held_evidence:=OLD.held_evidence; RETURN NEW; END IF;
   SELECT data INTO NEW.held_evidence FROM media.replays WHERE key=NEW.object_id FOR UPDATE;
 END CASE;
 IF NOT FOUND THEN RAISE EXCEPTION 'retention target unavailable' USING ERRCODE='22023'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS validate_retention_hold ON media.retention_holds;
CREATE TRIGGER validate_retention_hold BEFORE INSERT OR UPDATE ON media.retention_holds FOR EACH ROW EXECUTE FUNCTION media.validate_retention_hold();

ALTER TABLE media.audit ADD COLUMN IF NOT EXISTS occurred_at timestamptz;
CREATE INDEX IF NOT EXISTS media_audit_legacy_time ON media.audit(id) WHERE occurred_at IS NULL AND data#>>'{event,time}' IS NOT NULL;
CREATE INDEX IF NOT EXISTS media_audit_retention ON media.audit(occurred_at,id);
CREATE OR REPLACE FUNCTION media.prune_terminal_metadata(p_limit integer) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET TimeZone='Asia/Shanghai' AS $$
DECLARE item record;
BEGIN
 IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 1000 THEN RAISE EXCEPTION 'invalid limit'; END IF;
UPDATE media.versions v SET cleaned_at=COALESCE((SELECT min((a.data#>>'{event,time}')::timestamptz) FROM media.audit a
 WHERE a.data#>>'{event,type}'='media.version.cleaned' AND a.data#>>'{event,subject}'=v.id),statement_timestamp()),cleanup_started=true
 WHERE v.id IN (SELECT id FROM media.versions WHERE cleaned_at IS NULL AND data @> '{"cleanup_complete":true}' ORDER BY id LIMIT p_limit FOR UPDATE SKIP LOCKED);

 UPDATE media.audit SET occurred_at=(data#>>'{event,time}')::timestamptz WHERE id IN
 (SELECT id FROM media.audit WHERE occurred_at IS NULL AND data#>>'{event,time}' IS NOT NULL ORDER BY id LIMIT p_limit FOR UPDATE SKIP LOCKED);
 UPDATE media.outbox SET delivered_at=statement_timestamp() WHERE id IN
 (SELECT id FROM media.outbox WHERE delivered AND delivered_at IS NULL ORDER BY id LIMIT p_limit FOR UPDATE SKIP LOCKED);
 FOR item IN SELECT id,file_id FROM media.versions v WHERE cleaned_at+interval '30 days'<=statement_timestamp()
   AND NOT EXISTS(SELECT 1 FROM media.retention_holds h WHERE h.kind IN ('content','version') AND h.object_id=v.id AND h.until_at>statement_timestamp())
   AND NOT EXISTS(SELECT 1 FROM media.references r WHERE r.version_id=v.id AND r.data->>'state'<>'released')
   AND NOT EXISTS(SELECT 1 FROM media.jobs j WHERE j.version_id=v.id AND j.state<>'done')
   ORDER BY cleaned_at,id LIMIT p_limit FOR UPDATE OF v SKIP LOCKED
 LOOP
   IF EXISTS(SELECT 1 FROM media.retention_holds h WHERE h.kind IN ('content','version') AND h.object_id=item.id AND h.until_at>statement_timestamp()) THEN CONTINUE; END IF;
   DELETE FROM media.jobs WHERE version_id=item.id AND state='done';
   DELETE FROM media.references WHERE version_id=item.id AND data->>'state'='released';
   DELETE FROM media.versions WHERE id=item.id;
   DELETE FROM media.files f WHERE f.id=item.file_id AND f.data @> '{"retired":true}' AND NOT EXISTS(SELECT 1 FROM media.versions v WHERE v.file_id=f.id);
 END LOOP;
 DELETE FROM media.audit WHERE id IN (
   SELECT id FROM media.audit WHERE occurred_at<statement_timestamp()-interval '11 months' AND occurred_at+interval '12 months'<=statement_timestamp()
   ORDER BY occurred_at,id LIMIT p_limit FOR UPDATE SKIP LOCKED);
 DELETE FROM media.retention_holds WHERE ctid IN (SELECT ctid FROM media.retention_holds WHERE until_at<=statement_timestamp() ORDER BY until_at LIMIT p_limit FOR UPDATE SKIP LOCKED);
END $$;
REVOKE ALL ON FUNCTION media.prune_terminal_metadata(integer) FROM PUBLIC;
