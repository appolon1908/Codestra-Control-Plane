-- Source only. Requires reviewed005 metadata schema. No roles/grants/policies,
-- assignments, credentials, proofs or live leases are provisioned by this file.
BEGIN;
CREATE SCHEMA assignment_leases;
REVOKE ALL ON SCHEMA assignment_leases FROM PUBLIC;
CREATE TABLE assignment_leases.policies (
 product text PRIMARY KEY REFERENCES scoped_registration.products(product),
 lease_seconds integer NOT NULL CHECK(lease_seconds>0),
 renewal_seconds integer NOT NULL CHECK(renewal_seconds>0),
 max_lifetime_seconds integer NOT NULL CHECK(max_lifetime_seconds>=lease_seconds AND max_lifetime_seconds>=renewal_seconds),
 attestation_seconds integer NOT NULL CHECK(attestation_seconds>0),
 active boolean NOT NULL DEFAULT false
);
CREATE TABLE assignment_leases.permissions (
 principal name NOT NULL REFERENCES scoped_registration.principals(principal),
 product text NOT NULL REFERENCES scoped_registration.products(product),
 capability text NOT NULL CHECK(capability IN ('attest','revoke','read')),
 active boolean NOT NULL DEFAULT false, PRIMARY KEY(principal,product,capability)
);
CREATE TABLE assignment_leases.bindings (
 binding_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), product text NOT NULL,
 workstation_id text NOT NULL,task_id text NOT NULL UNIQUE,principal name NOT NULL,principal_oid oid NOT NULL,
 repository text NOT NULL,repository_id bigint NOT NULL CHECK(repository_id>0),
 source_ref text NOT NULL,target_ref text NOT NULL,
 head_sha text NOT NULL CHECK(head_sha ~ '^[0-9a-f]{40}$' AND head_sha<>repeat('0',40)),
 base_sha text NOT NULL CHECK(base_sha ~ '^[0-9a-f]{40}$' AND base_sha<>repeat('0',40)),
 worktree text NOT NULL CHECK(worktree ~ '^/([A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+$' AND worktree !~ '(^|/)\.\.?(/|$)'),
 host text NOT NULL CHECK(length(host) BETWEEN 1 AND 256),
 root_path text NOT NULL CHECK(root_path ~ '^/([A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+$' AND root_path !~ '(^|/)\.\.?(/|$)'),
 git_common_dir text NOT NULL CHECK(git_common_dir ~ '^/([A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+$' AND git_common_dir !~ '(^|/)\.\.?(/|$)'),
 worktree_uid bigint NOT NULL CHECK(worktree_uid>=0),valid_until timestamptz NOT NULL,active boolean NOT NULL DEFAULT false,
 CHECK(left(worktree,length(root_path)+1)=root_path||'/'),
 FOREIGN KEY(product,workstation_id,task_id,principal) REFERENCES scoped_registration.task_assignments(product,workstation_id,task_id,principal)
);
CREATE UNIQUE INDEX unique_active_worktree_binding ON assignment_leases.bindings(worktree) WHERE active;
CREATE TABLE assignment_leases.dependencies (
 binding_id uuid NOT NULL REFERENCES assignment_leases.bindings(binding_id),dependency_key text NOT NULL,
 prerequisite jsonb NOT NULL,repository text NOT NULL,repository_id bigint NOT NULL CHECK(repository_id>0),
 binding jsonb NOT NULL, binding_hash text NOT NULL CHECK(binding_hash ~ '^[0-9a-f]{64}$'),
 issuer_app_id bigint NOT NULL CHECK(issuer_app_id>0 AND issuer_app_id<>15368),issuer_name text NOT NULL,
 capability_receipt text NOT NULL CHECK(length(capability_receipt)>0),approved_by text NOT NULL CHECK(approved_by='Ralph L. Appolon'),purpose text NOT NULL CHECK(purpose='SCOPE_CERTIFICATION'),
 check_id bigint NOT NULL CHECK(check_id>0),valid_until timestamptz NOT NULL,active boolean NOT NULL DEFAULT false,
 PRIMARY KEY(binding_id,dependency_key)
);
CREATE TABLE assignment_leases.slots (
 workstation_id text PRIMARY KEY REFERENCES public.workstations(workstation_id),epoch bigint NOT NULL DEFAULT 0 CHECK(epoch>=0)
);
CREATE TABLE assignment_leases.proofs (
 proof_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),binding_id uuid NOT NULL REFERENCES assignment_leases.bindings(binding_id),
 verifier name NOT NULL,verifier_oid oid NOT NULL,binding_snapshot jsonb NOT NULL,observations jsonb NOT NULL,
 issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),expires_at timestamptz NOT NULL,consumed boolean NOT NULL DEFAULT false
);
CREATE TABLE assignment_leases.leases (
 lease_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),binding_id uuid NOT NULL REFERENCES assignment_leases.bindings(binding_id),
 workstation_id text NOT NULL REFERENCES public.workstations(workstation_id),principal name NOT NULL,principal_oid oid NOT NULL,
 epoch bigint NOT NULL,host text NOT NULL,directory_device bigint NOT NULL,directory_inode bigint NOT NULL,
 proof_id uuid NOT NULL REFERENCES assignment_leases.proofs(proof_id),binding_snapshot jsonb NOT NULL,
 state text NOT NULL CHECK(state IN ('ACTIVE','RELEASED','REVOKED')),
 started_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,
 request_id text NOT NULL,UNIQUE(principal_oid,request_id)
);
CREATE UNIQUE INDEX one_active_workstation_lease ON assignment_leases.leases(workstation_id) WHERE state='ACTIVE';
CREATE UNIQUE INDEX one_active_materialization_lease ON assignment_leases.leases(host,directory_device,directory_inode) WHERE state='ACTIVE';
CREATE TABLE assignment_leases.audit (
 audit_id bigserial PRIMARY KEY,binding_id uuid NOT NULL REFERENCES assignment_leases.bindings(binding_id),lease_id uuid,
 actor name NOT NULL,actor_oid oid NOT NULL,action text NOT NULL,request_id text NOT NULL,
 receipt jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(actor_oid,action,request_id)
);
REVOKE ALL ON ALL TABLES IN SCHEMA assignment_leases FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA assignment_leases FROM PUBLIC;

CREATE FUNCTION assignment_leases._restricted(principal_name name,expected_oid oid) RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM pg_roles r JOIN scoped_registration.principals p ON p.principal=r.rolname AND p.role_oid=r.oid
 WHERE r.rolname=principal_name AND r.oid=expected_oid AND p.active AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolcreaterole
 AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT r.rolbypassrls)
 AND NOT (EXISTS(SELECT 1 FROM pg_roles bad WHERE (bad.rolsuper OR bad.rolcreaterole OR bad.rolcreatedb OR bad.rolreplication OR bad.rolbypassrls OR bad.oid IN (SELECT nspowner FROM pg_namespace WHERE nspname IN ('assignment_leases','scoped_registration'))) AND pg_has_role(principal_name,bad.oid,'MEMBER'))
 OR EXISTS(SELECT 1 FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace WHERE t.relkind IN ('r','p') AND (n.nspname IN ('assignment_leases','scoped_registration') OR n.nspname='public' AND t.relname IN ('products','workstations','atomic_tasks','sections')) AND has_table_privilege(principal_name,t.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))
 OR has_schema_privilege(principal_name,'assignment_leases','CREATE') OR has_schema_privilege(principal_name,'scoped_registration','CREATE'))
$$;
CREATE FUNCTION assignment_leases._actor() RETURNS oid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE actor_oid oid;
BEGIN
 SELECT r.oid INTO actor_oid FROM pg_roles r JOIN scoped_registration.principals p ON p.principal=r.rolname AND p.role_oid=r.oid
 WHERE r.rolname=session_user AND p.active AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolcreaterole
 AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT r.rolbypassrls;
 IF actor_oid IS NULL OR NOT EXISTS(SELECT 1 FROM pg_stat_ssl WHERE pid=pg_backend_pid() AND ssl)
 THEN RAISE EXCEPTION 'LEASE_DENIED'; END IF;
 IF NOT assignment_leases._restricted(session_user,actor_oid)
 THEN RAISE EXCEPTION 'LEASE_DENIED'; END IF;
 RETURN actor_oid;
END $$;
CREATE FUNCTION assignment_leases._permission(product_name text,kind text,locked boolean DEFAULT true) RETURNS oid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE actor_oid oid;
BEGIN
 actor_oid:=assignment_leases._actor();
 IF locked THEN PERFORM 1 FROM assignment_leases.permissions p WHERE p.principal=session_user AND p.product=product_name AND p.capability=kind FOR SHARE; END IF;
 PERFORM 1 FROM assignment_leases.permissions p WHERE p.principal=session_user AND p.product=product_name AND p.capability=kind AND p.active;
 IF NOT FOUND THEN RAISE EXCEPTION 'LEASE_DENIED'; END IF;
 RETURN actor_oid;
END $$;
CREATE FUNCTION assignment_leases._lock(b assignment_leases.bindings) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE key bigint;
BEGIN
 FOR key IN SELECT DISTINCT value FROM unnest(ARRAY[hashtextextended('workstation:'||b.workstation_id,7281),hashtextextended('worktree:'||b.worktree,7281)]) value ORDER BY value LOOP
  PERFORM pg_advisory_xact_lock(key);
 END LOOP;
END $$;
CREATE FUNCTION assignment_leases._binding(binding_uuid uuid,locked boolean DEFAULT true) RETURNS assignment_leases.bindings LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE b assignment_leases.bindings;w public.workstations;p assignment_leases.policies;c scoped_registration.candidates;
BEGIN
 IF locked THEN PERFORM 1 FROM assignment_leases.bindings WHERE binding_id=binding_uuid FOR SHARE; END IF;
 SELECT * INTO b FROM assignment_leases.bindings WHERE binding_id=binding_uuid;
 IF NOT FOUND OR NOT b.active OR b.valid_until<=clock_timestamp() THEN RAISE EXCEPTION 'ASSIGNMENT_UNAVAILABLE'; END IF;
 IF locked THEN
  PERFORM 1 FROM scoped_registration.principals WHERE principal=b.principal FOR SHARE;
  PERFORM 1 FROM scoped_registration.task_assignments WHERE task_id=b.task_id FOR SHARE;
  PERFORM 1 FROM scoped_registration.grants WHERE principal=b.principal AND product=b.product FOR SHARE;
  PERFORM 1 FROM public.products WHERE product=b.product FOR SHARE;
  PERFORM 1 FROM scoped_registration.products WHERE product=b.product FOR SHARE;
  PERFORM 1 FROM public.workstations WHERE workstation_id=b.workstation_id FOR SHARE;
  PERFORM 1 FROM scoped_registration.workstations WHERE workstation_id=b.workstation_id FOR SHARE;
  PERFORM 1 FROM scoped_registration.candidates WHERE task_id=b.task_id FOR SHARE;
  PERFORM 1 FROM public.atomic_tasks WHERE task_id=b.task_id FOR SHARE;
  PERFORM 1 FROM assignment_leases.policies WHERE product=b.product FOR SHARE;
  PERFORM 1 FROM assignment_leases.dependencies WHERE binding_id=b.binding_id FOR SHARE;
 END IF;

 PERFORM 1 FROM scoped_registration.principals s JOIN pg_roles r ON r.oid=s.role_oid AND r.rolname=s.principal
 WHERE s.principal=b.principal AND s.role_oid=b.principal_oid AND s.active AND r.rolcanlogin
 AND NOT r.rolsuper AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT r.rolbypassrls;
 IF NOT FOUND OR NOT assignment_leases._restricted(b.principal,b.principal_oid) THEN RAISE EXCEPTION 'ASSIGNMENT_UNAVAILABLE'; END IF;
 PERFORM 1 FROM scoped_registration.task_assignments a WHERE a.product=b.product AND a.workstation_id=b.workstation_id
 AND a.task_id=b.task_id AND a.principal=b.principal AND a.active;
 IF NOT FOUND THEN RAISE EXCEPTION 'ASSIGNMENT_UNAVAILABLE'; END IF;
 PERFORM 1 FROM scoped_registration.grants g WHERE g.principal=b.principal AND g.product=b.product AND g.capability='candidate' AND g.repository=b.repository;
 IF NOT FOUND THEN RAISE EXCEPTION 'ASSIGNMENT_UNAVAILABLE'; END IF;
 PERFORM 1 FROM public.products x JOIN scoped_registration.products s USING(product)
 WHERE x.product=b.product AND x.repository=b.repository AND s.payload->>'repository'=x.repository
 AND s.payload->>'test_branch'=x.test_branch AND s.payload->'promotion_chain'=x.promotion_chain
 AND NOT x.production_go AND NOT x.live_capabilities_enabled AND NOT x.external_effects_enabled;
 IF NOT FOUND THEN RAISE EXCEPTION 'REGISTRY_DRIFT'; END IF;
 SELECT w0.* INTO w FROM public.workstations w0 JOIN scoped_registration.workstations s ON s.workstation_id=w0.workstation_id AND s.product=w0.product
 WHERE w0.workstation_id=b.workstation_id AND w0.product=b.product AND w0.branch=s.branch AND w0.worktree=s.worktree
 AND s.payload->>'section'=w0.section AND s.payload->>'subsection'=w0.subsection AND s.payload->>'parent_branch'=w0.parent_branch;
 IF NOT FOUND OR w.lease_state IN ('FROZEN','STALE','WARNING') OR w.status IN ('BLOCKED','COMPLETE','CERTIFIED') OR w.blocker IS NOT NULL
 THEN RAISE EXCEPTION 'LANE_UNAVAILABLE'; END IF;
 IF b.target_ref<>w.branch OR b.source_ref !~ ('^atomic/'||w.section||'--'||w.subsection||'--[a-z0-9]+(-[a-z0-9]+)*$')
 THEN RAISE EXCEPTION 'LANE_BINDING_MISMATCH'; END IF;
 SELECT * INTO c FROM scoped_registration.candidates WHERE product=b.product AND workstation_id=b.workstation_id AND task_id=b.task_id AND principal=b.principal;
 IF NOT FOUND OR c.branch IS DISTINCT FROM b.source_ref OR c.worktree IS DISTINCT FROM b.worktree OR c.payload->>'head_sha' IS DISTINCT FROM b.head_sha
 OR c.payload->>'base_sha' IS DISTINCT FROM b.base_sha OR c.payload->>'target_branch' IS DISTINCT FROM b.target_ref THEN RAISE EXCEPTION 'CANDIDATE_DRIFT'; END IF;
 PERFORM 1 FROM public.atomic_tasks t WHERE t.task_id=b.task_id AND t.workstation_id=b.workstation_id AND t.owner=b.principal::text
 AND t.status NOT IN ('BLOCKED','COMPLETE','CERTIFIED');
 IF NOT FOUND THEN RAISE EXCEPTION 'TASK_UNAVAILABLE'; END IF;
 SELECT * INTO p FROM assignment_leases.policies WHERE product=b.product AND active;
 IF NOT FOUND THEN RAISE EXCEPTION 'LEASE_POLICY_UNAVAILABLE'; END IF;
 PERFORM 1 FROM assignment_leases.dependencies d WHERE d.binding_id=b.binding_id;
 IF jsonb_typeof(c.payload->'prerequisites') IS DISTINCT FROM 'array' OR EXISTS(SELECT 1 FROM assignment_leases.dependencies d WHERE d.binding_id=b.binding_id AND (NOT d.active OR d.valid_until<=clock_timestamp()))
 OR (SELECT count(*) FROM assignment_leases.dependencies d WHERE d.binding_id=b.binding_id)<>jsonb_array_length(c.payload->'prerequisites')
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(c.payload->'prerequisites') x WHERE NOT EXISTS(SELECT 1 FROM assignment_leases.dependencies d WHERE d.binding_id=b.binding_id AND d.prerequisite=x))
 THEN RAISE EXCEPTION 'DEPENDENCY_UNAVAILABLE'; END IF;
 RETURN b;
END $$;
CREATE FUNCTION assignment_leases._dependencies(binding_uuid uuid) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT coalesce(jsonb_object_agg(d.dependency_key,to_jsonb(d)),'{}'::jsonb)
 FROM assignment_leases.dependencies d WHERE d.binding_id=binding_uuid
$$;
CREATE FUNCTION assignment_leases.describe(binding_uuid uuid) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE b assignment_leases.bindings;
BEGIN
 SELECT * INTO b FROM assignment_leases.bindings WHERE binding_id=binding_uuid;
 IF NOT FOUND THEN RAISE EXCEPTION 'ASSIGNMENT_UNAVAILABLE'; END IF;
 PERFORM assignment_leases._permission(b.product,'attest',false);
 IF b.principal=session_user THEN RAISE EXCEPTION 'INDEPENDENT_VERIFIER_REQUIRED'; END IF;
 b:=assignment_leases._binding(binding_uuid,false);
 RETURN jsonb_build_object('binding',to_jsonb(b),'dependencies',coalesce((SELECT jsonb_agg(to_jsonb(d) ORDER BY dependency_key) FROM assignment_leases.dependencies d WHERE d.binding_id=binding_uuid),'[]'::jsonb));
END $$;
CREATE FUNCTION assignment_leases.attest(binding_uuid uuid,observed jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE b assignment_leases.bindings;actor_oid oid;proof assignment_leases.proofs;policy assignment_leases.policies;expected jsonb;stamp timestamptz;
BEGIN
 SELECT * INTO b FROM assignment_leases.bindings WHERE binding_id=binding_uuid;
 IF NOT FOUND THEN RAISE EXCEPTION 'ASSIGNMENT_UNAVAILABLE'; END IF;
 actor_oid:=assignment_leases._permission(b.product,'attest');
 IF b.principal=session_user THEN RAISE EXCEPTION 'INDEPENDENT_VERIFIER_REQUIRED'; END IF;
 b:=assignment_leases._binding(binding_uuid);
 SELECT * INTO policy FROM assignment_leases.policies WHERE product=b.product;
 expected:=jsonb_build_object('repository',b.repository,'repository_id',b.repository_id,'source_ref',b.source_ref,'target_ref',b.target_ref,'head_sha',b.head_sha,'base_sha',b.base_sha,'worktree',b.worktree,'host',b.host,'git_common_dir',b.git_common_dir,'worktree_uid',b.worktree_uid);
 IF jsonb_typeof(observed) IS DISTINCT FROM 'object' OR NOT observed ?& ARRAY['repository','repository_id','source_ref','target_ref','head_sha','base_sha','worktree','host','git_common_dir','worktree_uid','directory_device','directory_inode','observed_at','dependencies'] OR observed-ARRAY['directory_device','directory_inode','observed_at','dependencies']<>expected
 OR observed->'dependencies' IS DISTINCT FROM assignment_leases._dependencies(binding_uuid)
 OR jsonb_typeof(observed->'directory_device')<>'number' OR jsonb_typeof(observed->'directory_inode')<>'number'
 OR (observed->>'directory_device')::bigint<0 OR (observed->>'directory_inode')::bigint<=0 THEN RAISE EXCEPTION 'MATERIALIZATION_MISMATCH'; END IF;
 stamp:=(observed->>'observed_at')::timestamptz;
 IF jsonb_typeof(observed->'observed_at') IS DISTINCT FROM 'string' OR observed->>'observed_at' !~ '(Z|[+-][0-9]{2}:[0-9]{2})$' OR stamp IS NULL OR stamp>clock_timestamp() OR stamp<clock_timestamp()-make_interval(secs=>policy.attestation_seconds)
 THEN RAISE EXCEPTION 'MATERIALIZATION_EXPIRED'; END IF;
 INSERT INTO assignment_leases.proofs(binding_id,verifier,verifier_oid,binding_snapshot,observations,expires_at)
 VALUES(binding_uuid,session_user,actor_oid,to_jsonb(b),observed,least(b.valid_until,stamp+make_interval(secs=>policy.attestation_seconds))) RETURNING * INTO proof;
 RETURN jsonb_build_object('proof_id',proof.proof_id,'expires_at',proof.expires_at,'binding_id',binding_uuid,'authority','ONLINE_DATABASE_RECEIPT');
END $$;
CREATE FUNCTION assignment_leases._proof(b assignment_leases.bindings,proof_uuid uuid) RETURNS assignment_leases.proofs LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE proof assignment_leases.proofs;
BEGIN
 SELECT * INTO proof FROM assignment_leases.proofs WHERE proof_id=proof_uuid FOR UPDATE;
 IF NOT FOUND OR proof.binding_id<>b.binding_id OR proof.binding_snapshot<>to_jsonb(b)
 OR proof.observations->'dependencies' IS DISTINCT FROM assignment_leases._dependencies(b.binding_id) THEN RAISE EXCEPTION 'MATERIALIZATION_MISMATCH'; END IF;
 IF proof.consumed THEN RAISE EXCEPTION 'PROOF_CONSUMED'; END IF;
 IF proof.expires_at<=clock_timestamp() OR (proof.observations->>'observed_at')::timestamptz<clock_timestamp()-make_interval(secs=>(SELECT attestation_seconds FROM assignment_leases.policies WHERE product=b.product)) THEN RAISE EXCEPTION 'MATERIALIZATION_EXPIRED'; END IF;
 PERFORM 1 FROM scoped_registration.principals s JOIN pg_roles r ON r.oid=s.role_oid AND r.rolname=s.principal
 JOIN assignment_leases.permissions p ON p.principal=s.principal AND p.product=b.product AND p.capability='attest'
 WHERE s.principal=proof.verifier AND s.role_oid=proof.verifier_oid AND s.active AND p.active AND r.rolcanlogin
 AND NOT r.rolsuper AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT r.rolbypassrls FOR SHARE OF s,p;
 IF NOT FOUND OR proof.verifier=b.principal OR NOT assignment_leases._restricted(proof.verifier,proof.verifier_oid) THEN RAISE EXCEPTION 'VERIFIER_REVOKED'; END IF;
 RETURN proof;
END $$;
CREATE FUNCTION assignment_leases._receipt(l assignment_leases.leases) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('lease_id',l.lease_id,'binding_id',l.binding_id,'principal',l.principal,'epoch',l.epoch,'state',l.state,'started_at',l.started_at,'expires_at',l.expires_at,'binding',l.binding_snapshot,'authority','ONLINE_DATABASE_RECEIPT')
$$;
CREATE FUNCTION assignment_leases._audit(b uuid,l uuid,action_name text,request text,receipt jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF request IS NULL OR request !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' THEN RAISE EXCEPTION 'INVALID_REQUEST'; END IF;
 INSERT INTO assignment_leases.audit(binding_id,lease_id,actor,actor_oid,action,request_id,receipt)
 VALUES(b,l,session_user,assignment_leases._actor(),action_name,request,receipt);
END $$;
CREATE FUNCTION assignment_leases.claim(binding_uuid uuid,proof_uuid uuid,request text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE b assignment_leases.bindings;initial assignment_leases.bindings;proof assignment_leases.proofs;policy assignment_leases.policies;l assignment_leases.leases;actor_oid oid;fence bigint;receipt jsonb;now_at timestamptz;
BEGIN
 actor_oid:=assignment_leases._actor();
 SELECT * INTO initial FROM assignment_leases.bindings WHERE binding_id=binding_uuid;
 IF NOT FOUND OR initial.principal<>session_user OR initial.principal_oid<>actor_oid THEN RAISE EXCEPTION 'LEASE_DENIED'; END IF;
 PERFORM assignment_leases._lock(initial);b:=assignment_leases._binding(binding_uuid);
 IF b<>initial THEN RAISE EXCEPTION 'ASSIGNMENT_CHANGED'; END IF;
 IF EXISTS(SELECT 1 FROM assignment_leases.leases WHERE principal_oid=actor_oid AND request_id=request) THEN RAISE EXCEPTION 'REQUEST_CONSUMED'; END IF;
 SELECT * INTO l FROM assignment_leases.leases WHERE workstation_id=b.workstation_id AND state='ACTIVE' FOR UPDATE;
 IF FOUND THEN
  IF l.expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'RECOVERY_REQUIRED'; END IF;
  RAISE EXCEPTION 'LEASE_HELD';
 END IF;
 IF EXISTS(SELECT 1 FROM public.workstations WHERE workstation_id=b.workstation_id AND (lease_state<>'FREE' OR agent IS NOT NULL OR current_atomic_task IS NOT NULL)) THEN RAISE EXCEPTION 'LEGACY_LEASE_OR_RECOVERY_REQUIRED'; END IF;
 proof:=assignment_leases._proof(b,proof_uuid);
 SELECT * INTO policy FROM assignment_leases.policies WHERE product=b.product;
 INSERT INTO assignment_leases.slots(workstation_id) VALUES(b.workstation_id) ON CONFLICT DO NOTHING;
 UPDATE assignment_leases.slots SET epoch=epoch+1 WHERE workstation_id=b.workstation_id RETURNING epoch INTO fence;
 now_at:=clock_timestamp();
 IF proof.expires_at<=now_at OR b.valid_until<=now_at THEN RAISE EXCEPTION 'MATERIALIZATION_EXPIRED'; END IF;
 INSERT INTO assignment_leases.leases(binding_id,workstation_id,principal,principal_oid,epoch,host,directory_device,directory_inode,proof_id,binding_snapshot,state,started_at,expires_at,request_id)
 VALUES(binding_uuid,b.workstation_id,session_user,actor_oid,fence,b.host,(proof.observations->>'directory_device')::bigint,(proof.observations->>'directory_inode')::bigint,proof_uuid,to_jsonb(b),'ACTIVE',now_at,least(b.valid_until,now_at+make_interval(secs=>policy.lease_seconds)),request) RETURNING * INTO l;
 UPDATE assignment_leases.proofs SET consumed=true WHERE proof_id=proof_uuid;
 UPDATE public.workstations SET agent=session_user,current_atomic_task=b.task_id,lease_state='ACTIVE',lease_started_at=now_at,heartbeat_at=now_at,lease_expires_at=l.expires_at WHERE workstation_id=b.workstation_id;
 UPDATE public.atomic_tasks SET status='CLAIMED',updated_at=now_at WHERE task_id=b.task_id;
 receipt:=assignment_leases._receipt(l);PERFORM assignment_leases._audit(binding_uuid,l.lease_id,'CLAIM',request,receipt);RETURN receipt;
END $$;
CREATE FUNCTION assignment_leases._owned(lease_uuid uuid,expected_epoch bigint) RETURNS assignment_leases.leases LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE l assignment_leases.leases;b assignment_leases.bindings;actor_oid oid;policy assignment_leases.policies;
BEGIN
 actor_oid:=assignment_leases._actor();SELECT * INTO l FROM assignment_leases.leases WHERE lease_id=lease_uuid;
 IF NOT FOUND OR l.principal<>session_user OR l.principal_oid<>actor_oid THEN RAISE EXCEPTION 'LEASE_DENIED'; END IF;
 SELECT * INTO b FROM assignment_leases.bindings WHERE binding_id=l.binding_id;PERFORM assignment_leases._lock(b);
 b:=assignment_leases._binding(l.binding_id);
 SELECT * INTO l FROM assignment_leases.leases WHERE lease_id=lease_uuid FOR UPDATE;
 SELECT * INTO policy FROM assignment_leases.policies WHERE product=b.product;
 IF l.state<>'ACTIVE' OR l.epoch<>expected_epoch OR l.expires_at<=clock_timestamp() OR l.binding_snapshot<>to_jsonb(b)
 OR l.started_at+make_interval(secs=>policy.max_lifetime_seconds)<=clock_timestamp()
 OR NOT EXISTS(SELECT 1 FROM assignment_leases.slots WHERE workstation_id=l.workstation_id AND epoch=l.epoch)
 THEN RAISE EXCEPTION 'LEASE_NOT_ACTIVE'; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.workstations WHERE workstation_id=b.workstation_id AND lease_state='ACTIVE' AND agent=l.principal::text AND current_atomic_task=b.task_id AND lease_expires_at=l.expires_at)
 THEN RAISE EXCEPTION 'LEGACY_LEASE_DRIFT'; END IF;
 RETURN l;
END $$;
CREATE FUNCTION assignment_leases.check_owned(lease_uuid uuid,expected_epoch bigint) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN RETURN assignment_leases._receipt(assignment_leases._owned(lease_uuid,expected_epoch));END $$;
CREATE FUNCTION assignment_leases.renew(lease_uuid uuid,expected_epoch bigint,proof_uuid uuid,request text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE l assignment_leases.leases;b assignment_leases.bindings;proof assignment_leases.proofs;policy assignment_leases.policies;receipt jsonb;
BEGIN
 l:=assignment_leases._owned(lease_uuid,expected_epoch);b:=assignment_leases._binding(l.binding_id);
 proof:=assignment_leases._proof(b,proof_uuid);SELECT * INTO policy FROM assignment_leases.policies WHERE product=b.product;
 IF l.expires_at<=clock_timestamp() OR l.started_at+make_interval(secs=>policy.max_lifetime_seconds)<=clock_timestamp() THEN RAISE EXCEPTION 'LEASE_NOT_ACTIVE'; END IF;
 IF (proof.observations->>'directory_device')::bigint<>l.directory_device OR (proof.observations->>'directory_inode')::bigint<>l.directory_inode THEN RAISE EXCEPTION 'MATERIALIZATION_REPLACED'; END IF;
 UPDATE assignment_leases.leases SET expires_at=least(b.valid_until,clock_timestamp()+make_interval(secs=>policy.renewal_seconds),started_at+make_interval(secs=>policy.max_lifetime_seconds)),proof_id=proof_uuid WHERE lease_id=lease_uuid RETURNING * INTO l;
 UPDATE assignment_leases.proofs SET consumed=true WHERE proof_id=proof_uuid;
 UPDATE public.workstations SET heartbeat_at=clock_timestamp(),lease_expires_at=l.expires_at WHERE workstation_id=b.workstation_id;
 receipt:=assignment_leases._receipt(l);PERFORM assignment_leases._audit(b.binding_id,lease_uuid,'RENEW',request,receipt);RETURN receipt;
END $$;
CREATE FUNCTION assignment_leases.release(lease_uuid uuid,expected_epoch bigint,request text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE l assignment_leases.leases;receipt jsonb;
BEGIN
 l:=assignment_leases._owned(lease_uuid,expected_epoch);
 UPDATE assignment_leases.leases SET state='RELEASED' WHERE lease_id=lease_uuid RETURNING * INTO l;
 UPDATE assignment_leases.slots SET epoch=epoch+1 WHERE workstation_id=l.workstation_id;
 UPDATE public.workstations SET agent=NULL,current_atomic_task=NULL,lease_state='FREE',lease_expires_at=NULL,heartbeat_at=NULL WHERE workstation_id=l.workstation_id AND agent=l.principal::text;
 receipt:=assignment_leases._receipt(l);PERFORM assignment_leases._audit(l.binding_id,lease_uuid,'RELEASE',request,receipt);RETURN receipt;
END $$;
CREATE FUNCTION assignment_leases.revoke(binding_uuid uuid,reason text,request text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE b assignment_leases.bindings;l assignment_leases.leases;receipt jsonb;
BEGIN
 SELECT * INTO b FROM assignment_leases.bindings WHERE binding_id=binding_uuid;
 IF NOT FOUND THEN RAISE EXCEPTION 'ASSIGNMENT_UNAVAILABLE'; END IF;
 PERFORM assignment_leases._permission(b.product,'revoke');PERFORM assignment_leases._lock(b);
 IF reason IS NULL OR length(reason) NOT BETWEEN 1 AND 512 THEN RAISE EXCEPTION 'INVALID_REASON'; END IF;
 UPDATE assignment_leases.bindings SET active=false WHERE binding_id=binding_uuid;
 FOR l IN UPDATE assignment_leases.leases SET state='REVOKED' WHERE binding_id=binding_uuid AND state='ACTIVE' RETURNING * LOOP
  UPDATE assignment_leases.slots SET epoch=epoch+1 WHERE workstation_id=l.workstation_id;
  -- Never recover a frozen/blocked/unrelated legacy lane or erase its blocker.
  UPDATE public.workstations SET agent=NULL,current_atomic_task=NULL,lease_state='FREE',lease_expires_at=NULL,heartbeat_at=NULL
   WHERE workstation_id=l.workstation_id AND agent=l.principal::text AND current_atomic_task=b.task_id AND lease_state='ACTIVE' AND status<>'BLOCKED' AND blocker IS NULL;
 END LOOP;
 receipt:=jsonb_build_object('binding_id',binding_uuid,'state','REVOKED','reason',reason);
 PERFORM assignment_leases._audit(binding_uuid,NULL,'REVOKE',request,receipt);RETURN receipt;
END $$;
CREATE FUNCTION assignment_leases.inspect_binding(binding_uuid uuid) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE b assignment_leases.bindings;l assignment_leases.leases;actor_oid oid;policy assignment_leases.policies;proof assignment_leases.proofs;
BEGIN
 actor_oid:=assignment_leases._actor();SELECT * INTO b FROM assignment_leases.bindings WHERE binding_id=binding_uuid;
 IF NOT FOUND THEN RAISE EXCEPTION 'ASSIGNMENT_UNAVAILABLE'; END IF;
 IF b.principal<>session_user OR b.principal_oid<>actor_oid THEN PERFORM assignment_leases._permission(b.product,'read',false); END IF;
 b:=assignment_leases._binding(binding_uuid,false);
 SELECT * INTO policy FROM assignment_leases.policies WHERE product=b.product;
 SELECT * INTO l FROM assignment_leases.leases WHERE binding_id=binding_uuid AND state='ACTIVE';
 IF NOT FOUND OR l.expires_at<=clock_timestamp() OR l.started_at+make_interval(secs=>policy.max_lifetime_seconds)<=clock_timestamp()
 OR l.binding_snapshot<>to_jsonb(b) OR l.principal_oid<>b.principal_oid
 OR NOT EXISTS(SELECT 1 FROM assignment_leases.slots WHERE workstation_id=l.workstation_id AND epoch=l.epoch)
 OR NOT EXISTS(SELECT 1 FROM public.workstations WHERE workstation_id=b.workstation_id AND lease_state='ACTIVE' AND agent=l.principal::text AND current_atomic_task=b.task_id AND lease_expires_at=l.expires_at)
 THEN RAISE EXCEPTION 'LEASE_NOT_ACTIVE'; END IF;
 SELECT * INTO proof FROM assignment_leases.proofs WHERE proof_id=l.proof_id;
 IF NOT assignment_leases._restricted(proof.verifier,proof.verifier_oid) OR proof.binding_snapshot<>to_jsonb(b) OR proof.observations->'dependencies' IS DISTINCT FROM assignment_leases._dependencies(binding_uuid)
 OR NOT EXISTS(SELECT 1 FROM scoped_registration.principals s JOIN pg_roles r ON r.oid=s.role_oid AND r.rolname=s.principal JOIN assignment_leases.permissions p ON p.principal=s.principal AND p.product=b.product AND p.capability='attest' WHERE s.principal=proof.verifier AND s.role_oid=proof.verifier_oid AND s.active AND p.active AND NOT r.rolsuper AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT r.rolbypassrls)
 THEN RAISE EXCEPTION 'VERIFIER_REVOKED'; END IF;
 RETURN assignment_leases._receipt(l);
END $$;
CREATE FUNCTION assignment_leases.lookup(request text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE l assignment_leases.leases;actor_oid oid;
BEGIN
 actor_oid:=assignment_leases._actor();SELECT * INTO l FROM assignment_leases.leases WHERE principal_oid=actor_oid AND principal=session_user AND request_id=request;
 IF NOT FOUND THEN RAISE EXCEPTION 'REQUEST_NOT_FOUND'; END IF;
 RETURN assignment_leases._receipt(assignment_leases._owned(l.lease_id,l.epoch));
END $$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA assignment_leases FROM PUBLIC;
COMMIT;
