BEGIN;

CREATE OR REPLACE VIEW section_readiness AS
SELECT
  s.section_id,
  s.product,
  s.section_key,
  s.branch,
  s.order_index,
  count(w.workstation_id) AS subsection_count,
  count(*) FILTER (WHERE w.status='CERTIFIED') AS certified_subsections,
  bool_and(w.status='CERTIFIED') AS all_subsections_certified,
  bool_and(w.exact_sha_certified IS NOT NULL) AS all_exact_sha_certified
FROM sections s
LEFT JOIN workstations w
  ON w.product=s.product AND w.section=s.section_key
GROUP BY s.section_id,s.product,s.section_key,s.branch,s.order_index;

CREATE OR REPLACE VIEW product_readiness AS
SELECT
  p.product,
  p.repository,
  count(s.section_id) AS section_count,
  count(*) FILTER (WHERE sr.all_subsections_certified) AS sections_ready,
  bool_and(COALESCE(sr.all_subsections_certified,false)) AS all_sections_ready,
  p.production_go,
  p.live_capabilities_enabled,
  p.external_effects_enabled
FROM products p
LEFT JOIN sections s ON s.product=p.product
LEFT JOIN section_readiness sr ON sr.section_id=s.section_id
GROUP BY p.product,p.repository,p.production_go,p.live_capabilities_enabled,p.external_effects_enabled;

COMMIT;
