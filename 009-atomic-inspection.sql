-- Source-only forward migration. Requires005 and007; provisions no authority.
BEGIN;
SET LOCAL timezone='UTC';
-- Pin the reviewed007 protocol's serializers to one timezone. Stored proof and
-- lease snapshots remain untouched: historical non-UTC snapshots fail exact
-- comparison and require explicit operator revocation plus fresh observations.
-- Explicit signatures prevent changes to unrelated or later-added functions.
ALTER FUNCTION assignment_leases._restricted(name,oid) SET timezone='UTC';
ALTER FUNCTION assignment_leases._actor() SET timezone='UTC';
ALTER FUNCTION assignment_leases._permission(text,text,boolean) SET timezone='UTC';
ALTER FUNCTION assignment_leases._lock(assignment_leases.bindings) SET timezone='UTC';
ALTER FUNCTION assignment_leases._binding(uuid,boolean) SET timezone='UTC';
ALTER FUNCTION assignment_leases._dependencies(uuid) SET timezone='UTC';
ALTER FUNCTION assignment_leases.describe(uuid) SET timezone='UTC';
ALTER FUNCTION assignment_leases.attest(uuid,jsonb) SET timezone='UTC';
ALTER FUNCTION assignment_leases._proof(assignment_leases.bindings,uuid) SET timezone='UTC';
ALTER FUNCTION assignment_leases._receipt(assignment_leases.leases) SET timezone='UTC';
ALTER FUNCTION assignment_leases._audit(uuid,uuid,text,text,jsonb) SET timezone='UTC';
ALTER FUNCTION assignment_leases.claim(uuid,uuid,text) SET timezone='UTC';
ALTER FUNCTION assignment_leases._owned(uuid,bigint) SET timezone='UTC';
ALTER FUNCTION assignment_leases.check_owned(uuid,bigint) SET timezone='UTC';
ALTER FUNCTION assignment_leases.renew(uuid,bigint,uuid,text) SET timezone='UTC';
ALTER FUNCTION assignment_leases.release(uuid,bigint,text) SET timezone='UTC';
ALTER FUNCTION assignment_leases.revoke(uuid,text,text) SET timezone='UTC';
ALTER FUNCTION assignment_leases.inspect_binding(uuid) SET timezone='UTC';
ALTER FUNCTION assignment_leases.lookup(text) SET timezone='UTC';
CREATE SCHEMA atomic_inspection;
REVOKE ALL ON SCHEMA atomic_inspection FROM PUBLIC;

CREATE FUNCTION atomic_inspection._registered(w public.workstations) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
DECLARE registered scoped_registration.workstations;
BEGIN
 SELECT * INTO registered FROM scoped_registration.workstations
 WHERE product=w.product AND workstation_id=w.workstation_id;
 IF NOT FOUND OR registered.branch IS DISTINCT FROM w.branch
 OR registered.worktree IS DISTINCT FROM w.worktree
 OR registered.payload IS DISTINCT FROM jsonb_build_object(
  'product',w.product,'workstation_id',w.workstation_id,'section',w.section,
  'subsection',w.subsection,'branch',w.branch,'parent_branch',w.parent_branch,
  'worktree',w.worktree,'order_index',w.order_index)
 OR w.section !~ '^[a-z0-9]+(-[a-z0-9]+)*$'
 OR w.subsection !~ '^[a-z0-9]+(-[a-z0-9]+)*$'
 OR w.branch IS DISTINCT FROM 'subsection/'||w.section||'--'||w.subsection
 OR w.parent_branch IS DISTINCT FROM 'section/'||w.section
 THEN RAISE EXCEPTION 'ATOMIC_REGISTRATION_DRIFT'; END IF;
 PERFORM 1 FROM public.sections s WHERE s.product=w.product
 AND s.section_key=w.section AND s.branch=w.parent_branch;
 IF NOT FOUND THEN RAISE EXCEPTION 'ATOMIC_SECTION_UNAVAILABLE'; END IF;
 PERFORM 1 FROM scoped_registration.lanes l WHERE l.product=w.product
 AND l.kind='workstation' AND l.identity=w.workstation_id
 AND l.branch=w.branch AND l.worktree=w.worktree;
 IF NOT FOUND THEN RAISE EXCEPTION 'ATOMIC_LANE_UNAVAILABLE'; END IF;
 RETURN registered.payload;
END $$;

CREATE FUNCTION atomic_inspection._canonical(value jsonb) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
DECLARE result text;
BEGIN
 -- Dependency protocol inputs are ASCII registry identities/refs/full SHAs.
 -- Canonical key order and separators match the existing Python digest protocol.
 CASE jsonb_typeof(value)
 WHEN 'object' THEN
  SELECT '{'||coalesce(string_agg(to_jsonb(e.key)::text||':'||atomic_inspection._canonical(e.value),
   ',' ORDER BY e.key COLLATE "C"),'')||'}' INTO result FROM jsonb_each(value) e;
 WHEN 'array' THEN
  SELECT '['||coalesce(string_agg(atomic_inspection._canonical(e.value),',' ORDER BY e.ordinality),'')||']'
  INTO result FROM jsonb_array_elements(value) WITH ORDINALITY e;
 ELSE result:=value::text;
 END CASE;
 RETURN result;
END $$;

CREATE FUNCTION atomic_inspection.inspect(binding_uuid uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
DECLARE actor_oid oid;b assignment_leases.bindings;lease jsonb;l assignment_leases.leases;
 w public.workstations;dependency_ws public.workstations;product_payload jsonb;
 workstation_payload jsonb;c scoped_registration.candidates;t public.atomic_tasks;
 dependency_id text;expected_prerequisite jsonb;d assignment_leases.dependencies;section_payload jsonb;
 required jsonb:='[]';dependencies jsonb;expected_binding jsonb;digest text;earliest timestamptz;
BEGIN
 IF system_user IS DISTINCT FROM 'scram-sha-256:'||session_user::text
 OR current_setting('role')<>'none'
 OR NOT EXISTS(SELECT 1 FROM pg_stat_ssl WHERE pid=pg_backend_pid() AND ssl)
 THEN RAISE EXCEPTION 'ATOMIC_INSPECTION_DENIED'; END IF;
 SELECT * INTO b FROM assignment_leases.bindings WHERE binding_id=binding_uuid;
 IF NOT FOUND THEN RAISE EXCEPTION 'ATOMIC_ASSIGNMENT_UNAVAILABLE'; END IF;
 actor_oid:=assignment_leases._permission(b.product,'read',false);
 IF actor_oid=b.principal_oid OR session_user=b.principal
 OR EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname='atomic_inspection'
  AND (pg_has_role(session_user,n.nspowner,'MEMBER') OR has_schema_privilege(session_user,n.oid,'CREATE')))
 OR EXISTS(SELECT 1 FROM pg_class r JOIN pg_namespace n ON n.oid=r.relnamespace
  WHERE n.nspname='public' AND r.relkind IN ('r','p')
  AND r.relname IN ('scope_certifications','events','promotion_evidence')
  AND has_table_privilege(session_user,r.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))
 THEN RAISE EXCEPTION 'ATOMIC_INSPECTION_DENIED'; END IF;
 lease:=assignment_leases.inspect_binding(binding_uuid);
 SELECT * INTO l FROM assignment_leases.leases WHERE lease_id=(lease->>'lease_id')::uuid
 AND binding_id=binding_uuid AND state='ACTIVE' AND epoch=(lease->>'epoch')::bigint;
 IF NOT FOUND OR l.workstation_id IS DISTINCT FROM b.workstation_id
 OR l.host IS DISTINCT FROM b.host
 OR l.directory_device<0 OR l.directory_inode<=0
 THEN RAISE EXCEPTION 'ATOMIC_MATERIALIZATION_UNAVAILABLE'; END IF;
 SELECT * INTO w FROM public.workstations WHERE workstation_id=b.workstation_id AND product=b.product;
 IF NOT FOUND THEN RAISE EXCEPTION 'ATOMIC_WORKSTATION_UNAVAILABLE'; END IF;
 workstation_payload:=atomic_inspection._registered(w);
 SELECT jsonb_build_object('section_key',s.section_key,'branch',s.branch) INTO section_payload
 FROM public.sections s WHERE s.product=w.product AND s.section_key=w.section AND s.branch=w.parent_branch;
 SELECT s.payload INTO product_payload FROM scoped_registration.products s
 JOIN public.products p USING(product) WHERE s.product=b.product
 AND s.payload=jsonb_build_object('product',p.product,'repository',p.repository,
  'test_branch',p.test_branch,'promotion_chain',p.promotion_chain)
 AND p.repository=b.repository AND NOT p.production_go
 AND NOT p.live_capabilities_enabled AND NOT p.external_effects_enabled;
 IF NOT FOUND THEN RAISE EXCEPTION 'ATOMIC_PRODUCT_UNAVAILABLE'; END IF;
 SELECT * INTO c FROM scoped_registration.candidates
 WHERE product=b.product AND workstation_id=w.workstation_id AND task_id=b.task_id AND principal=b.principal;
 IF NOT FOUND THEN RAISE EXCEPTION 'ATOMIC_CANDIDATE_UNAVAILABLE'; END IF;
 SELECT * INTO t FROM public.atomic_tasks WHERE task_id=b.task_id
 AND workstation_id=w.workstation_id AND owner=b.principal::text;
 IF NOT FOUND OR c.payload IS DISTINCT FROM jsonb_build_object(
  'product',b.product,'workstation_id',w.workstation_id,'task_id',b.task_id,'title',t.title,
  'branch',b.source_ref,'target_branch',w.branch,'worktree',b.worktree,
  'head_sha',b.head_sha,'base_sha',b.base_sha,'prerequisites',c.payload->'prerequisites')
 THEN RAISE EXCEPTION 'ATOMIC_CANDIDATE_DRIFT'; END IF;
 PERFORM 1 FROM scoped_registration.lanes x WHERE x.product=b.product AND x.kind='candidate'
 AND x.identity=b.task_id AND x.branch=b.source_ref AND x.worktree=b.worktree;
 IF NOT FOUND THEN RAISE EXCEPTION 'ATOMIC_LANE_UNAVAILABLE'; END IF;
 IF jsonb_typeof(w.depends_on) IS DISTINCT FROM 'array'
 OR jsonb_typeof(c.payload->'prerequisites') IS DISTINCT FROM 'array'
 OR jsonb_typeof(w.required_gates) IS DISTINCT FROM 'array'
 THEN RAISE EXCEPTION 'ATOMIC_INVENTORY_INVALID'; END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(w.depends_on) x WHERE jsonb_typeof(x)<>'string'
  OR x#>>'{}'='' OR x#>>'{}'=w.workstation_id)
 OR jsonb_array_length(w.depends_on)<>(SELECT count(DISTINCT x) FROM jsonb_array_elements(w.depends_on) x)
 OR jsonb_array_length(c.payload->'prerequisites')<>(SELECT count(DISTINCT x) FROM jsonb_array_elements(c.payload->'prerequisites') x)
 OR jsonb_array_length(c.payload->'prerequisites')<>jsonb_array_length(w.depends_on)
 OR (SELECT count(*) FROM assignment_leases.dependencies WHERE binding_id=binding_uuid)<>jsonb_array_length(w.depends_on)
 THEN RAISE EXCEPTION 'ATOMIC_DEPENDENCY_INVENTORY_MISMATCH'; END IF;
 earliest:=(lease->>'expires_at')::timestamptz;
 FOR dependency_id IN SELECT value FROM jsonb_array_elements_text(w.depends_on) ORDER BY value COLLATE "C" LOOP
  SELECT * INTO dependency_ws FROM public.workstations
  WHERE workstation_id=dependency_id AND product=b.product;
  IF NOT FOUND THEN RAISE EXCEPTION 'ATOMIC_DEPENDENCY_UNAVAILABLE'; END IF;
  PERFORM atomic_inspection._registered(dependency_ws);
  IF dependency_ws.status<>'CERTIFIED' OR dependency_ws.remote_sha IS NULL
  OR dependency_ws.remote_sha !~ '^[0-9a-f]{40}$' OR dependency_ws.remote_sha=repeat('0',40)
  OR dependency_ws.exact_sha_certified IS DISTINCT FROM dependency_ws.remote_sha
  THEN RAISE EXCEPTION 'ATOMIC_DEPENDENCY_NOT_CERTIFIED'; END IF;
  expected_prerequisite:=jsonb_build_object('product',b.product,'scope_type','SUBSECTION',
   'scope_name',dependency_ws.branch,'sha',dependency_ws.remote_sha);
  IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(c.payload->'prerequisites') x WHERE x=expected_prerequisite)
  OR (SELECT count(*) FROM assignment_leases.dependencies x WHERE x.binding_id=binding_uuid AND x.prerequisite=expected_prerequisite)<>1
  THEN RAISE EXCEPTION 'ATOMIC_DEPENDENCY_RECEIPT_UNAVAILABLE'; END IF;
  SELECT * INTO d FROM assignment_leases.dependencies
  WHERE binding_id=binding_uuid AND prerequisite=expected_prerequisite;
  IF NOT FOUND OR NOT d.active OR d.valid_until<=clock_timestamp()
  OR d.repository IS DISTINCT FROM b.repository OR d.repository_id IS DISTINCT FROM b.repository_id
  OR d.issuer_app_id<=0 OR d.issuer_app_id=15368
  OR d.issuer_name IN ('codestra-control-plane','codestra/control-plane','promotion-gate')
  OR btrim(d.issuer_name)='' OR btrim(d.capability_receipt)=''
  OR d.approved_by<>'Ralph L. Appolon' OR d.purpose<>'SCOPE_CERTIFICATION' OR d.check_id<=0
  OR jsonb_typeof(d.binding) IS DISTINCT FROM 'object'
  OR d.binding->>'target_base_sha' IS NULL OR d.binding->>'target_base_sha' !~ '^[0-9a-f]{40}$'
  OR d.binding->>'target_base_sha'=repeat('0',40)
  THEN RAISE EXCEPTION 'ATOMIC_DEPENDENCY_RECEIPT_INVALID'; END IF;
  expected_binding:=jsonb_build_object('repository',b.repository,'product',b.product,
   'source_ref',dependency_ws.branch,'target_ref',dependency_ws.parent_branch,
   'source_sha',dependency_ws.remote_sha,'target_base_sha',d.binding->>'target_base_sha');
  IF d.binding IS DISTINCT FROM expected_binding THEN RAISE EXCEPTION 'ATOMIC_DEPENDENCY_BINDING_MISMATCH'; END IF;
  digest:=encode(sha256(convert_to(atomic_inspection._canonical(jsonb_build_object(
   'schema','codestra.lease-dependency.v1','promotion',expected_binding,
   'scope_type','SUBSECTION','scope_name',dependency_ws.branch)),'UTF8')),'hex');
  IF d.binding_hash IS DISTINCT FROM digest THEN RAISE EXCEPTION 'ATOMIC_DEPENDENCY_DIGEST_MISMATCH'; END IF;
  earliest:=least(earliest,d.valid_until);
  required:=required||jsonb_build_array(jsonb_build_object('workstation_id',dependency_ws.workstation_id,
   'product',dependency_ws.product,'branch',dependency_ws.branch,'remote_sha',dependency_ws.remote_sha,
   'exact_sha_certified',dependency_ws.exact_sha_certified,'status',dependency_ws.status));
 END LOOP;
 SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY dependency_key),'[]') INTO dependencies
 FROM assignment_leases.dependencies x WHERE binding_id=binding_uuid;
 IF lease IS DISTINCT FROM assignment_leases.inspect_binding(binding_uuid) OR earliest<=clock_timestamp()
 THEN RAISE EXCEPTION 'ATOMIC_AUTHORITY_CHANGED_OR_EXPIRED'; END IF;
 RETURN jsonb_build_object('schema','codestra.atomic-inspection.v1','lease',lease,
  'product',product_payload,'section',section_payload,'workstation',workstation_payload,
  'candidate',c.payload,'dependencies',dependencies,'required_workstations',required,
  'required_gates',w.required_gates,'materialization',jsonb_build_object(
   'host',l.host,'directory_device',l.directory_device,'directory_inode',l.directory_inode));
END $$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA atomic_inspection FROM PUBLIC;

-- The reviewed005 register definition follows verbatim except its scope enum:
-- add SUBSECTION metadata support, retaining every authorization/conflict check.
-- Reviewed005 source SHA256: 266300e66f26d7c70ccb31435dcc00ae57c018d5dba29f18d932e345da0e3362
CREATE OR REPLACE FUNCTION scoped_registration.register(
 kind text, payload jsonb, request_id text, manifest_sha256 text
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
#variable_conflict use_variable
DECLARE
 actor name := session_user;
 product_name text := payload->>'product';
 repo text;
 old jsonb;
 old_audit scoped_registration.audit%ROWTYPE;
 ws public.workstations%ROWTYPE;
 task public.atomic_tasks%ROWTYPE;
 prerequisite jsonb;
 output jsonb;
 allowed text[];
BEGIN
 IF kind IS NULL OR kind NOT IN ('product','workstation','candidate') OR
    jsonb_typeof(payload) IS DISTINCT FROM 'object' OR
    product_name IS NULL OR product_name !~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$' OR
    request_id IS NULL OR request_id !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR
    manifest_sha256 IS NULL OR manifest_sha256 !~ '^[0-9a-f]{64}$' OR manifest_sha256=repeat('0',64)
 THEN RAISE EXCEPTION 'INVALID_PAYLOAD'; END IF;

 -- Do not mistake a definer or SET ROLE identity for the authenticated login.
 PERFORM 1 FROM scoped_registration.principals p WHERE p.principal=actor AND p.active
   AND EXISTS(SELECT 1 FROM pg_catalog.pg_roles r WHERE r.oid=p.role_oid AND r.rolname=p.principal
     AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolcreaterole AND NOT r.rolbypassrls) FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'REGISTRATION_DENIED'; END IF;
 -- Serializes retries and identity conflicts for one product. Hash collisions only
 -- serialize unrelated products; they never create authority or merge identities.
 PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(product_name, 73491));
 SELECT g.repository INTO repo FROM scoped_registration.grants g
 WHERE g.principal=actor AND g.product=product_name AND g.capability=kind FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'REGISTRATION_DENIED'; END IF;
 IF kind='product' AND repo IS DISTINCT FROM payload->>'repository'
 THEN RAISE EXCEPTION 'REGISTRATION_DENIED'; END IF;
 IF kind<>'product' THEN
   PERFORM 1 FROM public.products p JOIN scoped_registration.products b USING(product)
     WHERE p.product=product_name AND p.repository=repo AND b.payload->>'repository'=repo
       AND p.test_branch=b.payload->>'test_branch' AND p.promotion_chain=b.payload->'promotion_chain'
       AND NOT p.production_go AND NOT p.live_capabilities_enabled AND NOT p.external_effects_enabled FOR SHARE OF p,b;
   IF NOT FOUND THEN RAISE EXCEPTION 'REGISTRATION_DENIED'; END IF;
 END IF;

 IF kind='product' THEN
   allowed:=ARRAY['product','repository','test_branch','promotion_chain'];
 ELSIF kind='workstation' THEN
   allowed:=ARRAY['product','workstation_id','section','subsection','branch','parent_branch','worktree','order_index'];
 ELSE
   allowed:=ARRAY['product','workstation_id','task_id','title','branch','target_branch','worktree','head_sha','base_sha','prerequisites'];
 END IF;
 IF payload-allowed <> '{}'::jsonb OR NOT payload ?& allowed OR
    EXISTS(SELECT 1 FROM jsonb_each(payload) e WHERE e.value='null'::jsonb)
 THEN RAISE EXCEPTION 'INVALID_PAYLOAD'; END IF;
 SELECT * INTO old_audit FROM scoped_registration.audit a
 WHERE a.product=product_name AND a.principal=actor AND a.request_id=register.request_id;
 IF FOUND THEN
   IF old_audit.kind<>kind OR old_audit.payload<>payload OR old_audit.manifest_sha256<>manifest_sha256
   THEN RAISE EXCEPTION 'REQUEST_CONFLICT'; END IF;
   -- Revalidation below also enforces revoked assignments/prerequisites on retries.
 END IF;

 IF kind='product' THEN
   IF jsonb_typeof(payload->'product')<>'string' OR jsonb_typeof(payload->'repository')<>'string' OR jsonb_typeof(payload->'test_branch')<>'string' OR
      payload->>'test_branch' NOT IN ('test','testing') OR
      payload->'promotion_chain' NOT IN (jsonb_build_array('development','test','staging','production'),jsonb_build_array('development','testing','staging','production'))
   THEN RAISE EXCEPTION 'INVALID_PAYLOAD'; END IF;
   SELECT p.payload INTO old FROM scoped_registration.products p WHERE p.product=product_name;
   IF FOUND AND old<>payload THEN RAISE EXCEPTION 'BINDING_CONFLICT'; END IF;
   INSERT INTO public.products(product,repository,test_branch,promotion_chain)
   VALUES(product_name,repo,payload->>'test_branch',payload->'promotion_chain') ON CONFLICT DO NOTHING;
   IF NOT EXISTS(SELECT 1 FROM public.products p WHERE p.product=product_name AND p.repository=repo
      AND p.test_branch=payload->>'test_branch' AND p.promotion_chain=payload->'promotion_chain'
      AND NOT p.production_go AND NOT p.live_capabilities_enabled AND NOT p.external_effects_enabled)
   THEN RAISE EXCEPTION 'BINDING_CONFLICT'; END IF;
   INSERT INTO scoped_registration.products VALUES(product_name,payload) ON CONFLICT DO NOTHING;
 ELSIF kind='workstation' THEN
   IF EXISTS(SELECT 1 FROM jsonb_each(payload) e WHERE e.key<>'order_index' AND jsonb_typeof(e.value)<>'string') OR
      payload->>'workstation_id' !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR
      payload->>'section' !~ '^[a-z0-9]+(-[a-z0-9]+)*$' OR
      payload->>'subsection' !~ '^[a-z0-9]+(-[a-z0-9]+)*$' OR
      payload->>'branch'<> 'subsection/'||(payload->>'section')||'--'||(payload->>'subsection') OR
      payload->>'parent_branch'<> 'section/'||(payload->>'section') OR
      payload->>'worktree' !~ '^/([A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+$' OR
      payload->>'worktree' ~ '(^|/)\.\.?(/|$)' OR
      jsonb_typeof(payload->'order_index')<>'number' OR payload->>'order_index' !~ '^[0-9]{1,8}$'
   THEN RAISE EXCEPTION 'INVALID_PAYLOAD'; END IF;
   IF NOT EXISTS(SELECT 1 FROM public.sections s WHERE s.product=product_name AND s.section_key=payload->>'section' AND s.branch=payload->>'parent_branch')
   THEN RAISE EXCEPTION 'SECTION_REQUIRED'; END IF;
   IF EXISTS(SELECT 1 FROM scoped_registration.candidates c WHERE c.worktree=payload->>'worktree') OR
      EXISTS(SELECT 1 FROM public.workstations w WHERE w.worktree=payload->>'worktree' AND w.workstation_id<>payload->>'workstation_id')
   THEN RAISE EXCEPTION 'BINDING_CONFLICT'; END IF;
   SELECT w.payload INTO old FROM scoped_registration.workstations w WHERE w.workstation_id=payload->>'workstation_id';
   IF FOUND AND old<>payload THEN RAISE EXCEPTION 'BINDING_CONFLICT'; END IF;
   INSERT INTO scoped_registration.lanes(worktree,product,kind,identity,branch)
   VALUES(payload->>'worktree',product_name,'workstation',payload->>'workstation_id',payload->>'branch') ON CONFLICT DO NOTHING;
   IF NOT EXISTS(SELECT 1 FROM scoped_registration.lanes l WHERE l.worktree=payload->>'worktree'
       AND l.product=product_name AND l.kind='workstation' AND l.identity=payload->>'workstation_id' AND l.branch=payload->>'branch')
   THEN RAISE EXCEPTION 'BINDING_CONFLICT'; END IF;
   INSERT INTO public.workstations(workstation_id,product,section,subsection,branch,parent_branch,worktree,order_index)
   VALUES(payload->>'workstation_id',product_name,payload->>'section',payload->>'subsection',payload->>'branch',payload->>'parent_branch',payload->>'worktree',(payload->>'order_index')::integer)
   ON CONFLICT DO NOTHING;
   SELECT * INTO ws FROM public.workstations w WHERE w.workstation_id=payload->>'workstation_id' FOR UPDATE;
   IF ws.product IS DISTINCT FROM product_name OR ws.section IS DISTINCT FROM payload->>'section' OR
      ws.subsection IS DISTINCT FROM payload->>'subsection' OR ws.branch IS DISTINCT FROM payload->>'branch' OR
      ws.parent_branch IS DISTINCT FROM payload->>'parent_branch' OR ws.worktree IS DISTINCT FROM payload->>'worktree' OR
      ws.order_index IS DISTINCT FROM (payload->>'order_index')::integer
   THEN RAISE EXCEPTION 'BINDING_CONFLICT'; END IF;
   INSERT INTO scoped_registration.workstations VALUES(product_name,ws.workstation_id,ws.branch,ws.worktree,payload) ON CONFLICT DO NOTHING;
   IF NOT EXISTS(SELECT 1 FROM scoped_registration.workstations w WHERE w.product=product_name AND w.workstation_id=ws.workstation_id AND w.payload=payload)
   THEN RAISE EXCEPTION 'BINDING_CONFLICT'; END IF;
 ELSE
   IF EXISTS(SELECT 1 FROM jsonb_each(payload) e WHERE e.key<>'prerequisites' AND jsonb_typeof(e.value)<>'string') OR
      payload->>'workstation_id' !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR
      payload->>'task_id' !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR
      length(payload->>'title') NOT BETWEEN 1 AND 256 OR
      payload->>'head_sha' !~ '^[0-9a-f]{40}$' OR payload->>'head_sha'=repeat('0',40) OR
      payload->>'base_sha' !~ '^[0-9a-f]{40}$' OR payload->>'base_sha'=repeat('0',40) OR
      payload->>'worktree' !~ '^/([A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+$' OR
      payload->>'worktree' ~ '(^|/)\.\.?(/|$)' OR jsonb_typeof(payload->'prerequisites')<>'array'
   THEN RAISE EXCEPTION 'INVALID_PAYLOAD'; END IF;
   PERFORM 1 FROM scoped_registration.task_assignments a WHERE a.product=product_name
    AND a.workstation_id=payload->>'workstation_id' AND a.task_id=payload->>'task_id' AND a.principal=actor AND a.active FOR SHARE;
   IF NOT FOUND THEN RAISE EXCEPTION 'ASSIGNMENT_REQUIRED'; END IF;
   SELECT w.payload INTO old FROM scoped_registration.workstations w WHERE w.product=product_name AND w.workstation_id=payload->>'workstation_id' FOR SHARE;
   SELECT * INTO ws FROM public.workstations w WHERE w.workstation_id=payload->>'workstation_id' FOR UPDATE;
   IF old IS NULL OR ws.product IS DISTINCT FROM product_name OR ws.branch IS DISTINCT FROM old->>'branch' OR ws.worktree IS DISTINCT FROM old->>'worktree'
      OR ws.section IS DISTINCT FROM old->>'section' OR ws.subsection IS DISTINCT FROM old->>'subsection'
      OR ws.parent_branch IS DISTINCT FROM old->>'parent_branch' OR ws.order_index IS DISTINCT FROM (old->>'order_index')::integer
   THEN RAISE EXCEPTION 'BINDING_CONFLICT'; END IF;
   IF payload->>'target_branch' IS DISTINCT FROM ws.branch OR
      payload->>'branch' !~ ('^atomic/'||ws.section||'--'||ws.subsection||'--[a-z0-9]+(-[a-z0-9]+)*$') OR
      EXISTS(SELECT 1 FROM public.workstations w WHERE w.worktree=payload->>'worktree')
   THEN RAISE EXCEPTION 'INVALID_CANDIDATE_LANE'; END IF;
   FOR prerequisite IN SELECT value FROM jsonb_array_elements(payload->'prerequisites') LOOP
     IF jsonb_typeof(prerequisite)<>'object' OR prerequisite-ARRAY['product','scope_type','scope_name','sha']<>'{}'::jsonb OR
        NOT prerequisite ?& ARRAY['product','scope_type','scope_name','sha'] OR
        prerequisite->>'product' IS DISTINCT FROM product_name OR
        EXISTS(SELECT 1 FROM jsonb_each(prerequisite) e WHERE jsonb_typeof(e.value)<>'string') OR
        prerequisite->>'scope_type' NOT IN ('SUBSECTION','SECTION','DEVELOPMENT','TESTING','STAGING','PRODUCTION') OR
        prerequisite->>'sha' !~ '^[0-9a-f]{40}$' OR prerequisite->>'sha'=repeat('0',40)
     THEN RAISE EXCEPTION 'INVALID_PREREQUISITE'; END IF;
     -- A matching legacy certificate is only a metadata prerequisite observation;
     -- it does not upgrade its producer to an authenticated certifier.
     PERFORM 1 FROM public.scope_certifications s WHERE s.product=product_name
       AND s.scope_type=prerequisite->>'scope_type' AND s.scope_name=prerequisite->>'scope_name'
       AND s.sha=prerequisite->>'sha' AND s.status='CERTIFIED' FOR SHARE;
     IF NOT FOUND THEN RAISE EXCEPTION 'PREREQUISITE_NOT_CERTIFIED'; END IF;
   END LOOP;
   SELECT c.payload INTO old FROM scoped_registration.candidates c WHERE c.task_id=payload->>'task_id';
   IF FOUND AND old<>payload THEN RAISE EXCEPTION 'BINDING_CONFLICT'; END IF;
   INSERT INTO scoped_registration.lanes(worktree,product,kind,identity,branch)
   VALUES(payload->>'worktree',product_name,'candidate',payload->>'task_id',payload->>'branch') ON CONFLICT DO NOTHING;
   IF NOT EXISTS(SELECT 1 FROM scoped_registration.lanes l WHERE l.worktree=payload->>'worktree'
       AND l.product=product_name AND l.kind='candidate' AND l.identity=payload->>'task_id' AND l.branch=payload->>'branch')
   THEN RAISE EXCEPTION 'BINDING_CONFLICT'; END IF;
   INSERT INTO public.atomic_tasks(task_id,workstation_id,title,owner)
   VALUES(payload->>'task_id',ws.workstation_id,payload->>'title',actor) ON CONFLICT DO NOTHING;
   SELECT * INTO task FROM public.atomic_tasks a WHERE a.task_id=payload->>'task_id' FOR UPDATE;
   IF task.workstation_id IS DISTINCT FROM ws.workstation_id OR task.title IS DISTINCT FROM payload->>'title' OR task.owner IS DISTINCT FROM actor::text
   THEN RAISE EXCEPTION 'BINDING_CONFLICT'; END IF;
   INSERT INTO scoped_registration.candidates VALUES(product_name,ws.workstation_id,task.task_id,actor,payload->>'branch',payload->>'worktree',payload) ON CONFLICT DO NOTHING;
   IF NOT EXISTS(SELECT 1 FROM scoped_registration.candidates c WHERE c.product=product_name AND c.task_id=task.task_id AND c.principal=actor AND c.payload=payload)
   THEN RAISE EXCEPTION 'BINDING_CONFLICT'; END IF;
 END IF;
 output:=jsonb_build_object('product',product_name,'principal',actor,'kind',kind,'authority',false,'ready',false);
 INSERT INTO scoped_registration.audit(product,request_id,principal,kind,manifest_sha256,payload,result)
 VALUES(product_name,request_id,actor,kind,manifest_sha256,payload,output) ON CONFLICT DO NOTHING;
 RETURN output;
END
$function$;
COMMIT;
