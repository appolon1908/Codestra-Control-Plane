CREATE TABLE IF NOT EXISTS promotion_requests (
  id BIGSERIAL PRIMARY KEY,
  repository TEXT NOT NULL,
  source_branch TEXT NOT NULL,
  target_branch TEXT NOT NULL,
  source_sha TEXT NOT NULL,
  target_sha_before TEXT,
  requested_by TEXT,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  decision TEXT NOT NULL DEFAULT 'PENDING'
    CHECK (decision IN ('PENDING','APPROVED','REJECTED','APPLIED')),
  reason TEXT,
  applied_at TIMESTAMPTZ
);

CREATE OR REPLACE FUNCTION codestra_certification_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  missing_deps integer;
BEGIN
  IF NEW.status='CERTIFIED' AND OLD.status IS DISTINCT FROM NEW.status THEN
    IF NEW.local_sha IS NULL OR NEW.remote_sha IS NULL OR NEW.local_sha <> NEW.remote_sha THEN
      RAISE EXCEPTION 'CERTIFICATION_DENIED: local/remote SHA mismatch';
    END IF;
    IF COALESCE(NEW.ci_result,'') <> 'PASS' THEN
      RAISE EXCEPTION 'CERTIFICATION_DENIED: exact-SHA CI is not PASS';
    END IF;
    IF COALESCE(NEW.review_result,'') <> 'PASS' THEN
      RAISE EXCEPTION 'CERTIFICATION_DENIED: independent review is not PASS';
    END IF;
    IF NEW.blocker IS NOT NULL AND btrim(NEW.blocker) <> '' THEN
      RAISE EXCEPTION 'CERTIFICATION_DENIED: unresolved blocker exists';
    END IF;
    SELECT count(*) INTO missing_deps
    FROM jsonb_array_elements_text(COALESCE(NEW.depends_on,'[]'::jsonb)) d(dep)
    WHERE NOT EXISTS (
      SELECT 1
      FROM workstation_ledger p
      WHERE p.repository=NEW.repository
        AND (p.section || '/' || p.subsection)=d.dep
        AND p.status='CERTIFIED'
    );
    IF missing_deps > 0 THEN
      RAISE EXCEPTION 'CERTIFICATION_DENIED: % dependencies are not CERTIFIED', missing_deps;
    END IF;
    NEW.certified_at := COALESCE(NEW.certified_at, now());
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_codestra_certification_guard ON workstation_ledger;
CREATE TRIGGER trg_codestra_certification_guard
BEFORE UPDATE OF status ON workstation_ledger
FOR EACH ROW
EXECUTE FUNCTION codestra_certification_guard();
