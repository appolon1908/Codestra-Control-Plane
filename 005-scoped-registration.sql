-- Source-only forward migration. Install as a separate operator-controlled owner.
-- No roles, credentials, product grants, assignments or live registrations created.
BEGIN;
CREATE SCHEMA IF NOT EXISTS scoped_registration;
REVOKE ALL ON SCHEMA scoped_registration FROM PUBLIC;

CREATE TABLE IF NOT EXISTS scoped_registration.principals (
 principal name PRIMARY KEY, role_oid oid NOT NULL UNIQUE, active boolean NOT NULL DEFAULT true
);
CREATE TABLE IF NOT EXISTS scoped_registration.grants (
 principal name NOT NULL REFERENCES scoped_registration.principals(principal), product text NOT NULL,
 capability text NOT NULL CHECK(capability IN ('product','workstation','candidate')),
 repository text NOT NULL CHECK(repository ~ '^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$'),
 PRIMARY KEY(principal,product,capability)
);
CREATE TABLE IF NOT EXISTS scoped_registration.products (
 product text PRIMARY KEY REFERENCES public.products(product),
 payload jsonb NOT NULL
);
-- One physical namespace across subsection and atomic registrations.
CREATE TABLE IF NOT EXISTS scoped_registration.lanes (
 worktree text PRIMARY KEY, product text NOT NULL REFERENCES scoped_registration.products(product),
 kind text NOT NULL CHECK(kind IN ('workstation','candidate')), identity text NOT NULL,
 branch text NOT NULL, UNIQUE(product,kind,identity), UNIQUE(product,branch)
);
CREATE TABLE IF NOT EXISTS scoped_registration.workstations (
 product text NOT NULL REFERENCES scoped_registration.products(product),
 workstation_id text NOT NULL UNIQUE REFERENCES public.workstations(workstation_id),
 branch text NOT NULL, worktree text NOT NULL UNIQUE, payload jsonb NOT NULL,
 PRIMARY KEY(product,workstation_id), UNIQUE(product,branch)
);
CREATE TABLE IF NOT EXISTS scoped_registration.task_assignments (
 product text NOT NULL, workstation_id text NOT NULL, task_id text NOT NULL,
 principal name NOT NULL REFERENCES scoped_registration.principals(principal),
 active boolean NOT NULL DEFAULT true,
 PRIMARY KEY(product,workstation_id,task_id,principal),
 UNIQUE(task_id),
 FOREIGN KEY(product,workstation_id) REFERENCES scoped_registration.workstations(product,workstation_id)
);
CREATE TABLE IF NOT EXISTS scoped_registration.candidates (
 product text NOT NULL, workstation_id text NOT NULL, task_id text NOT NULL UNIQUE REFERENCES public.atomic_tasks(task_id),
 principal name NOT NULL, branch text NOT NULL, worktree text NOT NULL UNIQUE,
 payload jsonb NOT NULL,
 PRIMARY KEY(product,task_id), UNIQUE(product,branch),
 FOREIGN KEY(product,workstation_id,task_id,principal)
 REFERENCES scoped_registration.task_assignments(product,workstation_id,task_id,principal)
);
CREATE TABLE IF NOT EXISTS scoped_registration.audit (
 product text NOT NULL, request_id text NOT NULL, principal name NOT NULL,
 kind text NOT NULL, manifest_sha256 text NOT NULL, payload jsonb NOT NULL,
 result jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(product,principal,request_id)
);
REVOKE ALL ON ALL TABLES IN SCHEMA scoped_registration FROM PUBLIC;

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
        prerequisite->>'scope_type' NOT IN ('SECTION','DEVELOPMENT','TESTING','STAGING','PRODUCTION') OR
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
REVOKE ALL ON FUNCTION scoped_registration.register(text,jsonb,text,text) FROM PUBLIC;
COMMIT;
