BEGIN;

CREATE TABLE IF NOT EXISTS products (
  product text PRIMARY KEY,
  repository text NOT NULL UNIQUE,
  hierarchy_version integer NOT NULL DEFAULT 2,
  test_branch text NOT NULL DEFAULT 'test',
  promotion_chain jsonb NOT NULL DEFAULT '["development","test","staging","production"]'::jsonb,
  production_go boolean NOT NULL DEFAULT false,
  live_capabilities_enabled boolean NOT NULL DEFAULT false,
  external_effects_enabled boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sections (
  section_id text PRIMARY KEY,
  product text NOT NULL REFERENCES products(product) ON DELETE CASCADE,
  section_key text NOT NULL,
  branch text NOT NULL,
  order_index integer NOT NULL,
  depends_on jsonb NOT NULL DEFAULT '[]'::jsonb,
  status text NOT NULL DEFAULT 'NOT_STARTED'
    CHECK (status IN ('NOT_STARTED','IN_PROGRESS','BLOCKED','COMPLETE','CERTIFIED')),
  exact_sha text,
  certified_at timestamptz,
  UNIQUE(product,section_key),
  UNIQUE(product,branch)
);

CREATE TABLE IF NOT EXISTS atomic_tasks (
  task_id text PRIMARY KEY,
  workstation_id text NOT NULL REFERENCES workstations(workstation_id) ON DELETE CASCADE,
  title text NOT NULL,
  status text NOT NULL DEFAULT 'NOT_STARTED'
    CHECK (status IN ('NOT_STARTED','CLAIMED','IN_PROGRESS','BLOCKED','REVIEW','COMPLETE','CERTIFIED')),
  owner text,
  exact_sha text,
  evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS promotion_edges (
  source_level text NOT NULL,
  target_level text NOT NULL,
  ordinal integer NOT NULL,
  PRIMARY KEY(source_level,target_level),
  UNIQUE(ordinal),
  CHECK ((source_level,target_level) IN (
    ('atomic_task','subsection'),
    ('subsection','section'),
    ('section','development'),
    ('development','test'),
    ('test','staging'),
    ('staging','production')
  ))
);

INSERT INTO promotion_edges(source_level,target_level,ordinal) VALUES
 ('atomic_task','subsection',1),
 ('subsection','section',2),
 ('section','development',3),
 ('development','test',4),
 ('test','staging',5),
 ('staging','production',6)
ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS promotion_evidence (
  product text NOT NULL REFERENCES products(product) ON DELETE CASCADE,
  source_level text NOT NULL,
  source_ref text NOT NULL,
  target_level text NOT NULL,
  target_ref text NOT NULL,
  exact_sha text NOT NULL CHECK (exact_sha ~ '^[0-9a-f]{40}$'),
  ci_exact_sha text NOT NULL DEFAULT 'PENDING' CHECK (ci_exact_sha IN ('PENDING','PASS','FAIL')),
  review text NOT NULL DEFAULT 'PENDING' CHECK (review IN ('PENDING','PASS','FAIL')),
  regression text NOT NULL DEFAULT 'PENDING' CHECK (regression IN ('PENDING','PASS','FAIL')),
  security text NOT NULL DEFAULT 'PENDING' CHECK (security IN ('PENDING','PASS','FAIL')),
  clean_tree text NOT NULL DEFAULT 'PENDING' CHECK (clean_tree IN ('PENDING','PASS','FAIL')),
  remote_sha_match text NOT NULL DEFAULT 'PENDING' CHECK (remote_sha_match IN ('PENDING','PASS','FAIL')),
  contract text NOT NULL DEFAULT 'PENDING' CHECK (contract IN ('PENDING','PASS','FAIL','N/A')),
  migration text NOT NULL DEFAULT 'PENDING' CHECK (migration IN ('PENDING','PASS','FAIL','N/A')),
  performance text NOT NULL DEFAULT 'PENDING' CHECK (performance IN ('PENDING','PASS','FAIL','N/A')),
  evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
  recorded_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(product,source_level,source_ref,target_level,target_ref,exact_sha)
);

CREATE TABLE IF NOT EXISTS promotion_attempts (
  id bigserial PRIMARY KEY,
  product text NOT NULL REFERENCES products(product) ON DELETE CASCADE,
  source_level text NOT NULL,
  source_ref text NOT NULL,
  target_level text NOT NULL,
  target_ref text NOT NULL,
  exact_sha text NOT NULL,
  decision text NOT NULL CHECK (decision IN ('PASS','BLOCK')),
  reasons jsonb NOT NULL DEFAULT '[]'::jsonb,
  actor text,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE workstations
  ADD COLUMN IF NOT EXISTS hierarchy_version integer NOT NULL DEFAULT 2,
  ADD COLUMN IF NOT EXISTS manifest_path text,
  ADD COLUMN IF NOT EXISTS section_branch text,
  ADD COLUMN IF NOT EXISTS exact_sha_certified text;

CREATE INDEX IF NOT EXISTS idx_sections_product_order ON sections(product,order_index);
CREATE INDEX IF NOT EXISTS idx_promotion_evidence_sha ON promotion_evidence(product,exact_sha);
CREATE INDEX IF NOT EXISTS idx_promotion_attempts_time ON promotion_attempts(product,created_at DESC);

COMMIT;
