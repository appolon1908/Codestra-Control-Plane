CREATE TABLE IF NOT EXISTS workstations (
  workstation_id text PRIMARY KEY,
  product text NOT NULL,
  section text NOT NULL,
  subsection text NOT NULL,
  branch text NOT NULL,
  parent_branch text NOT NULL,
  worktree text NOT NULL,
  order_index integer NOT NULL,
  depends_on jsonb NOT NULL DEFAULT '[]'::jsonb,
  required_gates jsonb NOT NULL DEFAULT '[]'::jsonb,
  status text NOT NULL DEFAULT 'NOT_STARTED'
    CHECK (status IN ('NOT_STARTED','CLAIMED','IN_PROGRESS','BLOCKED','REVIEW','COMPLETE','CERTIFIED')),
  agent text,
  base_sha text,
  local_sha text,
  remote_sha text,
  parent_sha text,
  lease_started_at timestamptz,
  heartbeat_at timestamptz,
  lease_expires_at timestamptz,
  lease_state text NOT NULL DEFAULT 'FREE'
    CHECK (lease_state IN ('FREE','ACTIVE','WARNING','STALE','FROZEN')),
  current_atomic_task text,
  blocker text,
  last_test_run timestamptz,
  ci_result text,
  review_result text,
  evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
  completed_at timestamptz,
  certified_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_workstations_product_status ON workstations(product,status);
CREATE INDEX IF NOT EXISTS idx_workstations_heartbeat ON workstations(heartbeat_at);

CREATE TABLE IF NOT EXISTS events (
  id bigserial PRIMARY KEY,
  workstation_id text NOT NULL REFERENCES workstations(workstation_id) ON DELETE CASCADE,
  event_type text NOT NULL,
  actor text,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_events_workstation_time ON events(workstation_id,created_at DESC);
