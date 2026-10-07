CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS workstation_ledger (
  id BIGSERIAL PRIMARY KEY,
  product TEXT NOT NULL,
  repository TEXT NOT NULL,
  section TEXT NOT NULL,
  subsection TEXT NOT NULL,
  branch TEXT NOT NULL,
  parent_branch TEXT NOT NULL,
  workstation TEXT NOT NULL,
  worktree TEXT,
  local_sha TEXT,
  remote_sha TEXT,
  parent_sha TEXT,
  agent TEXT,
  lease_id TEXT,
  lease_started_at TIMESTAMPTZ,
  heartbeat_at TIMESTAMPTZ,
  status TEXT NOT NULL DEFAULT 'NOT_STARTED'
    CHECK (status IN ('NOT_STARTED','CLAIMED','IN_PROGRESS','BLOCKED','REVIEW','COMPLETE','CERTIFIED')),
  current_atomic_task TEXT,
  last_test_run TIMESTAMPTZ,
  test_result TEXT,
  ci_result TEXT,
  review_result TEXT,
  blocker TEXT,
  completed_at TIMESTAMPTZ,
  certified_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(repository, section, subsection)
);
CREATE TABLE IF NOT EXISTS workstation_evidence (
  id BIGSERIAL PRIMARY KEY,
  ledger_id BIGINT NOT NULL REFERENCES workstation_ledger(id) ON DELETE CASCADE,
  evidence_type TEXT NOT NULL,
  exact_sha TEXT,
  result TEXT NOT NULL,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_workstation_ledger_status ON workstation_ledger(status);
CREATE INDEX IF NOT EXISTS idx_workstation_ledger_product ON workstation_ledger(product);
CREATE INDEX IF NOT EXISTS idx_workstation_ledger_heartbeat ON workstation_ledger(heartbeat_at);
