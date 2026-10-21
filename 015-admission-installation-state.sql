-- Source only. Independent journaling schema: create under a separately accepted
-- installation operator, after acquiring the pre-ledger session advisory fence.
-- No identities, grants, assignments, leases, receipts or activation are seeded.
BEGIN;
CREATE SCHEMA admission_installation;
REVOKE ALL ON SCHEMA admission_installation FROM PUBLIC;
CREATE TABLE admission_installation.attempts (
 attempt_id uuid PRIMARY KEY,
 request_sha256 text NOT NULL UNIQUE CHECK(request_sha256 ~ '^[0-9a-f]{64}$'),
 source_commit text NOT NULL CHECK(source_commit ~ '^[0-9a-f]{40}$'),
 manifest_sha256 text NOT NULL CHECK(manifest_sha256 ~ '^[0-9a-f]{64}$'),
 plan_sha256 text NOT NULL CHECK(plan_sha256 ~ '^[0-9a-f]{64}$'),
 operator_oid oid NOT NULL,
 system_identifier text NOT NULL,
 database_oid oid NOT NULL,
 catalog_before text NOT NULL CHECK(catalog_before ~ '^[0-9a-f]{64}$'),
 ledger_catalog_sha256 text NOT NULL CHECK(ledger_catalog_sha256 ~ '^[0-9a-f]{64}$'),
 catalog_after text CHECK(catalog_after ~ '^[0-9a-f]{64}$'),
 stage text NOT NULL CHECK(stage IN ('INTENT','DATABASE_APPLIED','FILES_DURABLE','CONFIGURATION_DURABLE','RECEIPTED','REVOKED')),
 receipt jsonb,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE admission_installation.migrations (
 source_path text PRIMARY KEY,
 sha256 text NOT NULL CHECK(sha256 ~ '^[0-9a-f]{64}$'),
 attempt_id uuid NOT NULL REFERENCES admission_installation.attempts(attempt_id),
 disposition text NOT NULL CHECK(disposition IN ('ADOPTED','APPLIED')),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE admission_installation.events (
 event_id bigserial PRIMARY KEY,
 attempt_id uuid NOT NULL REFERENCES admission_installation.attempts(attempt_id),
 stage text NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION admission_installation._immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'INSTALLATION_HISTORY_IMMUTABLE'; END $$;
CREATE TRIGGER immutable_versions BEFORE UPDATE OR DELETE ON admission_installation.migrations
FOR EACH ROW EXECUTE FUNCTION admission_installation._immutable();
CREATE TRIGGER immutable_events BEFORE UPDATE OR DELETE ON admission_installation.events
FOR EACH ROW EXECUTE FUNCTION admission_installation._immutable();
CREATE FUNCTION admission_installation._attempt_binding() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'INSTALLATION_HISTORY_IMMUTABLE'; END IF;
 IF (to_jsonb(NEW)-ARRAY['stage','catalog_after','receipt','updated_at']) IS DISTINCT FROM
    (to_jsonb(OLD)-ARRAY['stage','catalog_after','receipt','updated_at'])
 OR OLD.stage='REVOKED' AND NEW.stage<>'REVOKED'
 OR array_position(ARRAY['INTENT','DATABASE_APPLIED','FILES_DURABLE','CONFIGURATION_DURABLE','RECEIPTED','REVOKED'],NEW.stage)
    < array_position(ARRAY['INTENT','DATABASE_APPLIED','FILES_DURABLE','CONFIGURATION_DURABLE','RECEIPTED','REVOKED'],OLD.stage)
 THEN RAISE EXCEPTION 'INSTALLATION_BINDING_IMMUTABLE'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER immutable_attempt_binding BEFORE UPDATE OR DELETE ON admission_installation.attempts
FOR EACH ROW EXECUTE FUNCTION admission_installation._attempt_binding();
CREATE TRIGGER immutable_versions_truncate BEFORE TRUNCATE ON admission_installation.migrations
FOR EACH STATEMENT EXECUTE FUNCTION admission_installation._immutable();
CREATE TRIGGER immutable_events_truncate BEFORE TRUNCATE ON admission_installation.events
FOR EACH STATEMENT EXECUTE FUNCTION admission_installation._immutable();
CREATE TRIGGER immutable_attempts_truncate BEFORE TRUNCATE ON admission_installation.attempts
FOR EACH STATEMENT EXECUTE FUNCTION admission_installation._immutable();
REVOKE ALL ON ALL TABLES IN SCHEMA admission_installation FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA admission_installation FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA admission_installation FROM PUBLIC;
COMMIT;
