BEGIN;

CREATE TABLE IF NOT EXISTS family_programs (
  family_id text PRIMARY KEY,
  display_name text NOT NULL,
  hierarchy_version integer NOT NULL DEFAULT 3,
  status text NOT NULL DEFAULT 'NOT_STARTED'
    CHECK (status IN ('NOT_STARTED','IN_PROGRESS','BLOCKED','COMPLETE','CERTIFIED')),
  production_go boolean NOT NULL DEFAULT false,
  live_capabilities_enabled boolean NOT NULL DEFAULT false,
  external_effects_enabled boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS family_components (
  family_id text NOT NULL REFERENCES family_programs(family_id) ON DELETE CASCADE,
  product text NOT NULL REFERENCES products(product) ON DELETE CASCADE,
  order_index integer NOT NULL,
  required boolean NOT NULL DEFAULT true,
  role text NOT NULL DEFAULT 'component',
  PRIMARY KEY (family_id,product),
  UNIQUE (family_id,order_index)
);

CREATE OR REPLACE VIEW family_readiness AS
SELECT
  f.family_id,
  f.display_name,
  f.status AS family_status,
  count(DISTINCT fc.product) FILTER (WHERE fc.required) AS required_components,
  count(DISTINCT s.product) FILTER (
    WHERE fc.required AND NOT EXISTS (
      SELECT 1 FROM sections sx
      WHERE sx.product=fc.product AND sx.status <> 'CERTIFIED'
    )
  ) AS certified_components,
  count(s.section_id) FILTER (WHERE fc.required) AS required_sections,
  count(s.section_id) FILTER (WHERE fc.required AND s.status='CERTIFIED') AS certified_sections,
  count(w.workstation_id) FILTER (WHERE fc.required) AS required_subsections,
  count(w.workstation_id) FILTER (WHERE fc.required AND w.status='CERTIFIED') AS certified_subsections,
  bool_and(CASE WHEN fc.required THEN p.production_go=false ELSE true END) AS production_go_closed,
  bool_and(CASE WHEN fc.required THEN p.live_capabilities_enabled=false ELSE true END) AS live_capabilities_closed,
  bool_and(CASE WHEN fc.required THEN p.external_effects_enabled=false ELSE true END) AS external_effects_closed,
  (
    count(s.section_id) FILTER (WHERE fc.required) > 0
    AND count(s.section_id) FILTER (WHERE fc.required)
        = count(s.section_id) FILTER (WHERE fc.required AND s.status='CERTIFIED')
  ) AS all_sections_certified
FROM family_programs f
JOIN family_components fc USING(family_id)
JOIN products p ON p.product=fc.product
LEFT JOIN sections s ON s.product=fc.product
LEFT JOIN workstations w ON w.product=fc.product AND w.section=s.section_key
GROUP BY f.family_id,f.display_name,f.status;

COMMIT;
