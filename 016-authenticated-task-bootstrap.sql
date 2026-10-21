-- Source only, after the admission-v1 dependency closure. Independent profiles,
-- sessions, registered products/workstations and restricted role grants are
-- administrative prerequisites. This migration seeds no identity or authority.
BEGIN;
CREATE SCHEMA task_bootstrap;
REVOKE ALL ON SCHEMA task_bootstrap FROM PUBLIC;
-- Current assignments remain unique; immutable prior vectors remain in the
-- bootstrap ledger and inactive assignment/binding rows after a CAS handoff.
ALTER TABLE scoped_registration.task_assignments DROP CONSTRAINT task_assignments_task_id_key;
CREATE UNIQUE INDEX one_active_task_assignment ON scoped_registration.task_assignments(task_id) WHERE active;
ALTER TABLE assignment_leases.bindings DROP CONSTRAINT bindings_task_id_key;
CREATE UNIQUE INDEX one_active_task_binding ON assignment_leases.bindings(task_id) WHERE active;

CREATE TABLE task_bootstrap.profiles (
 profile_id uuid PRIMARY KEY,revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
 operator name NOT NULL,operator_oid oid NOT NULL,verifier name NOT NULL,verifier_oid oid NOT NULL,
 product text NOT NULL REFERENCES scoped_registration.products(product),
 repository text NOT NULL,repository_id bigint NOT NULL CHECK(repository_id>0),
 target_ref text NOT NULL,permitted_remote text NOT NULL,host text NOT NULL,root_path text NOT NULL,
 paths jsonb NOT NULL CHECK(scoped_admission._paths(paths)),
 custody_sha256 text NOT NULL CHECK(custody_sha256 ~ '^[0-9a-f]{64}$'),
 max_seconds integer NOT NULL DEFAULT 300 CHECK(max_seconds BETWEEN 1 AND 3600),
 valid_until timestamptz NOT NULL,active boolean NOT NULL DEFAULT false,
 CHECK(operator<>verifier AND operator_oid<>verifier_oid),
 CHECK(permitted_remote='https://github.com/'||repository||'.git')
);
CREATE TABLE task_bootstrap.sessions (
 session_id uuid PRIMARY KEY,profile_id uuid NOT NULL REFERENCES task_bootstrap.profiles(profile_id),
 revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),principal name NOT NULL,principal_oid oid NOT NULL,
 custody_sha256 text NOT NULL CHECK(custody_sha256 ~ '^[0-9a-f]{64}$'),
 valid_until timestamptz NOT NULL,active boolean NOT NULL DEFAULT false
);
-- One accepted work session per authenticated credential identity; a caller UUID
-- never selects another session belonging to the same active login.
CREATE UNIQUE INDEX one_active_authenticated_session ON task_bootstrap.sessions(principal_oid) WHERE active;
CREATE TABLE task_bootstrap.requests (
 request_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),operator_oid oid NOT NULL,client_request_id text NOT NULL,
 request_digest text NOT NULL CHECK(request_digest ~ '^[0-9a-f]{64}$'),payload jsonb NOT NULL,
 binding_id uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),profile_snapshot jsonb NOT NULL,session_snapshot jsonb NOT NULL,
 expires_at timestamptz NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(operator_oid,client_request_id)
);
CREATE TABLE task_bootstrap.acknowledgements (
 request_id uuid PRIMARY KEY REFERENCES task_bootstrap.requests(request_id),request_digest text NOT NULL,
 principal name NOT NULL,principal_oid oid NOT NULL,authentication text NOT NULL,
 session_snapshot jsonb NOT NULL,acknowledged_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE task_bootstrap.proofs (
 proof_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),request_id uuid NOT NULL REFERENCES task_bootstrap.requests(request_id),
 verifier name NOT NULL,verifier_oid oid NOT NULL,authentication text NOT NULL,request_snapshot jsonb NOT NULL,
 observations jsonb NOT NULL,expires_at timestamptz NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE task_bootstrap.issued (
 request_id uuid PRIMARY KEY REFERENCES task_bootstrap.requests(request_id),binding_id uuid NOT NULL UNIQUE,
 revision bigint NOT NULL CHECK(revision>0),epoch bigint GENERATED ALWAYS AS IDENTITY CHECK(epoch>0),
 l1_grant uuid NOT NULL UNIQUE,l2_grant uuid NOT NULL UNIQUE,proof_id uuid NOT NULL REFERENCES task_bootstrap.proofs(proof_id),
 binding_snapshot jsonb NOT NULL,receipt jsonb NOT NULL,
 predecessor_request uuid UNIQUE REFERENCES task_bootstrap.issued(request_id),
 state text NOT NULL CHECK(state IN ('ISSUED','REVOKED')),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),revoked_at timestamptz
);
CREATE TABLE task_bootstrap.lease_proofs (
 proof_id uuid PRIMARY KEY REFERENCES assignment_leases.proofs(proof_id),
 request_id uuid NOT NULL REFERENCES task_bootstrap.requests(request_id),binding_id uuid NOT NULL,
 bootstrap_digest text NOT NULL,permitted_remote text NOT NULL,verifier_oid oid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE task_bootstrap.stage_proofs (
 proof_id uuid PRIMARY KEY REFERENCES scoped_admission.proofs(proof_id),
 intent_id uuid NOT NULL REFERENCES scoped_admission.intents(intent_id),
 request_id uuid NOT NULL REFERENCES task_bootstrap.requests(request_id),
 bootstrap_digest text NOT NULL,intent_digest text NOT NULL,permitted_remote text NOT NULL,verifier_oid oid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE task_bootstrap.audit (
 audit_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,request_id uuid NOT NULL REFERENCES task_bootstrap.requests(request_id),
 actor name NOT NULL,actor_oid oid NOT NULL,authentication text NOT NULL,action text NOT NULL,
 receipt jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON ALL TABLES IN SCHEMA task_bootstrap FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA task_bootstrap FROM PUBLIC;

CREATE FUNCTION task_bootstrap._restricted(actor name,actor_oid oid) RETURNS boolean LANGUAGE sql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
 SELECT scoped_admission._restricted(actor,actor_oid) AND NOT EXISTS(
 SELECT 1 FROM pg_roles role WHERE (role.oid=actor_oid OR pg_has_role(actor_oid,role.oid,'MEMBER')) AND (
  EXISTS(SELECT 1 FROM pg_database d WHERE d.datname=current_database() AND
    (d.datdba=role.oid OR has_database_privilege(role.oid,d.oid,'CREATE')))
  OR EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema'
    AND (n.nspowner=role.oid OR has_schema_privilege(role.oid,n.oid,'CREATE')))
  OR EXISTS(SELECT 1 FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace
    WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema' AND
     (t.relowner=role.oid OR t.relkind IN ('r','p','v','m','f') AND
      (has_table_privilege(role.oid,t.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
       OR has_any_column_privilege(role.oid,t.oid,'INSERT,UPDATE,REFERENCES'))
      OR t.relkind='S' AND has_sequence_privilege(role.oid,t.oid,'USAGE,UPDATE')))
  OR EXISTS(SELECT 1 FROM pg_proc f JOIN pg_namespace n ON n.oid=f.pronamespace
    WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema' AND f.proowner=role.oid)
  OR EXISTS(SELECT 1 FROM pg_proc f JOIN pg_namespace n ON n.oid=f.pronamespace WHERE n.nspname='pg_catalog'
    AND f.proname IN ('lo_import','lo_export','pg_read_file','pg_read_binary_file','pg_stat_file','pg_ls_dir',
      'pg_ls_logdir','pg_ls_waldir','pg_ls_archive_statusdir','pg_ls_tmpdir','pg_ls_logicalsnapdir','pg_ls_logicalmapdir','pg_ls_replslotdir',
      'pg_backup_start','pg_backup_stop','pg_create_restore_point','pg_switch_wal','pg_log_standby_snapshot','pg_wal_replay_pause','pg_wal_replay_resume',
      'pg_rotate_logfile','pg_reload_conf','pg_promote','pg_log_backend_memory_contexts','pg_stat_reset','pg_stat_reset_shared','pg_stat_reset_slru',
      'pg_stat_reset_single_table_counters','pg_stat_reset_single_function_counters','pg_stat_reset_replication_slot','pg_stat_reset_subscription_stats',
      'pg_replication_origin_advance','pg_replication_origin_create','pg_replication_origin_drop','pg_replication_origin_session_reset',
      'pg_replication_origin_session_setup','pg_replication_origin_xact_reset','pg_replication_origin_xact_setup')
    AND has_function_privilege(role.oid,f.oid,'EXECUTE'))
 ))
$$;
CREATE FUNCTION task_bootstrap._actor() RETURNS oid LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE actor_oid oid;
BEGIN
 IF system_user IS DISTINCT FROM 'scram-sha-256:'||session_user::text OR current_setting('role')<>'none'
 OR current_setting('transaction_isolation')<>'read committed'
 THEN RAISE EXCEPTION 'BOOTSTRAP_AUTHENTICATION_REQUIRED'; END IF;
 actor_oid:=assignment_leases._actor();
 IF NOT task_bootstrap._restricted(session_user,actor_oid) OR EXISTS(
  SELECT 1 FROM pg_roles role JOIN pg_class t ON t.relkind IN ('r','p')
  JOIN pg_namespace n ON n.oid=t.relnamespace AND n.nspname='task_bootstrap'
  WHERE (role.oid=actor_oid OR pg_has_role(actor_oid,role.oid,'MEMBER'))
  AND (role.oid=t.relowner OR role.oid=n.nspowner OR has_schema_privilege(role.oid,n.oid,'CREATE')
   OR has_table_privilege(role.oid,t.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')))
 THEN RAISE EXCEPTION 'BOOTSTRAP_AUTHENTICATION_REQUIRED'; END IF;
 RETURN actor_oid;
END $$;

CREATE FUNCTION task_bootstrap._validate(payload jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE p task_bootstrap.profiles;s task_bootstrap.sessions;b assignment_leases.bindings;
 w public.workstations;dependency jsonb;prerequisite jsonb;dependency_id text;dep_ws public.workstations;
BEGIN
 IF jsonb_typeof(payload) IS DISTINCT FROM 'object'
 OR NOT payload ?& ARRAY['schema','profile_id','session_id','binding','title','prerequisites','dependencies','paths','permitted_remote','route','custody_sha256','expected_predecessor']
 OR payload-ARRAY['schema','profile_id','session_id','binding','title','prerequisites','dependencies','paths','permitted_remote','route','custody_sha256','expected_predecessor']<>'{}'::jsonb
 OR payload->>'schema' IS DISTINCT FROM 'codestra.task-bootstrap-request.v1'
 OR jsonb_typeof(payload->'binding') IS DISTINCT FROM 'object'
 OR NOT payload->'binding' ?& ARRAY['product','workstation_id','task_id','principal','principal_oid','repository','repository_id','source_ref','target_ref','head_sha','base_sha','worktree','host','root_path','git_common_dir','worktree_uid','valid_until']
 OR (payload->'binding')-ARRAY['product','workstation_id','task_id','principal','principal_oid','repository','repository_id','source_ref','target_ref','head_sha','base_sha','worktree','host','root_path','git_common_dir','worktree_uid','valid_until']<>'{}'::jsonb
 OR EXISTS(SELECT 1 FROM jsonb_each(payload->'binding') item WHERE
  CASE WHEN item.key IN ('principal_oid','repository_id','worktree_uid') THEN jsonb_typeof(item.value)<>'number' ELSE jsonb_typeof(item.value)<>'string' END)
 OR jsonb_typeof(payload->'title') IS DISTINCT FROM 'string' OR length(payload->>'title') NOT BETWEEN 1 AND 256
 OR NOT scoped_admission._paths(payload->'paths')
 OR jsonb_typeof(payload->'prerequisites') IS DISTINCT FROM 'array'
 OR jsonb_typeof(payload->'dependencies') IS DISTINCT FROM 'array'
 THEN RAISE EXCEPTION 'BOOTSTRAP_INVALID_REQUEST'; END IF;
 SELECT * INTO p FROM task_bootstrap.profiles WHERE profile_id=(payload->>'profile_id')::uuid;
 IF NOT FOUND OR NOT p.active OR p.valid_until<=clock_timestamp()
 OR NOT task_bootstrap._restricted(p.operator,p.operator_oid)
 OR NOT task_bootstrap._restricted(p.verifier,p.verifier_oid)
 OR NOT EXISTS(SELECT 1 FROM assignment_leases.permissions WHERE principal=p.verifier AND product=p.product AND capability='attest' AND active)
 OR NOT EXISTS(SELECT 1 FROM assignment_leases.permissions WHERE principal=p.verifier AND product=p.product AND capability='read' AND active)
 THEN RAISE EXCEPTION 'BOOTSTRAP_PROFILE_DENIED'; END IF;
 SELECT * INTO s FROM task_bootstrap.sessions WHERE session_id=(payload->>'session_id')::uuid;
 IF NOT FOUND OR NOT s.active OR s.valid_until<=clock_timestamp() OR s.profile_id<>p.profile_id
 OR NOT task_bootstrap._restricted(s.principal,s.principal_oid)
 OR s.principal IN (p.operator,p.verifier) OR s.principal_oid IN (p.operator_oid,p.verifier_oid)
 THEN RAISE EXCEPTION 'BOOTSTRAP_SESSION_DENIED'; END IF;
 b:=jsonb_populate_record(NULL::assignment_leases.bindings,payload->'binding');
 IF left(b.worktree,1) ~ '^[A-Za-z]$' AND substring(b.worktree,2,1)=':' AND substring(b.worktree,3,1) IN ('/',chr(92))
 THEN RAISE EXCEPTION 'BOOTSTRAP_EXECUTOR_UNSUPPORTED'; END IF;
 IF b.worktree ~ '/[A-Za-z]:' OR position(chr(92) in b.worktree)>0
 THEN RAISE EXCEPTION 'BOOTSTRAP_EXECUTOR_MALFORMED'; END IF;
 IF b.principal IS DISTINCT FROM s.principal OR b.principal_oid IS DISTINCT FROM s.principal_oid
 THEN RAISE EXCEPTION 'BOOTSTRAP_SESSION_DENIED'; END IF;
 IF payload->>'custody_sha256' IS DISTINCT FROM s.custody_sha256 OR s.custody_sha256<>p.custody_sha256
 THEN RAISE EXCEPTION 'BOOTSTRAP_CUSTODY_MISMATCH'; END IF;
 IF payload->'route' IS DISTINCT FROM '{"source_level":"atomic","target_level":"subsection"}'::jsonb
 OR b.product IS DISTINCT FROM p.product OR b.repository IS DISTINCT FROM p.repository OR b.repository_id IS DISTINCT FROM p.repository_id
 OR b.target_ref IS DISTINCT FROM p.target_ref OR b.host IS DISTINCT FROM p.host OR b.root_path IS DISTINCT FROM p.root_path
 OR payload->>'permitted_remote' IS DISTINCT FROM p.permitted_remote OR NOT (p.paths @> (payload->'paths'))
 THEN RAISE EXCEPTION 'BOOTSTRAP_ROUTE_DENIED'; END IF;
 IF b.task_id IS NULL OR b.task_id !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR b.head_sha IS NULL OR b.head_sha !~ '^[0-9a-f]{40}$' OR b.head_sha=repeat('0',40)
 OR b.base_sha IS NULL OR b.base_sha !~ '^[0-9a-f]{40}$' OR b.base_sha=repeat('0',40)
 OR b.worktree IS NULL OR b.worktree !~ '^/([A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+$' OR b.worktree ~ '(^|/)\.\.?(/|$)'
 OR b.root_path IS NULL OR b.root_path !~ '^/([A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+$' OR b.root_path ~ '(^|/)\.\.?(/|$)'
 OR left(b.worktree,length(b.root_path)+1)<>b.root_path||'/'
 OR b.git_common_dir IS NULL OR b.git_common_dir !~ '^/([A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+$' OR b.git_common_dir ~ '(^|/)\.\.?(/|$)'
 OR b.worktree_uid IS NULL OR b.worktree_uid<0 OR b.valid_until IS NULL OR b.valid_until<=clock_timestamp()
 OR b.valid_until>least(p.valid_until,s.valid_until,clock_timestamp()+make_interval(secs=>p.max_seconds))
 THEN RAISE EXCEPTION 'BOOTSTRAP_INVALID_BINDING'; END IF;
 PERFORM 1 FROM public.products x JOIN scoped_registration.products r USING(product)
 WHERE x.product=b.product AND x.repository=b.repository AND r.payload->>'repository'=x.repository
 AND r.payload->>'test_branch'=x.test_branch AND r.payload->'promotion_chain'=x.promotion_chain
 AND NOT x.production_go AND NOT x.live_capabilities_enabled AND NOT x.external_effects_enabled;
 IF NOT FOUND THEN RAISE EXCEPTION 'BOOTSTRAP_REGISTRY_DRIFT'; END IF;
 SELECT * INTO w FROM public.workstations WHERE workstation_id=b.workstation_id AND product=b.product;
 IF NOT FOUND OR w.branch IS DISTINCT FROM b.target_ref OR w.lease_state IN ('FROZEN','STALE','WARNING')
 OR w.status IN ('BLOCKED','COMPLETE','CERTIFIED') OR w.blocker IS NOT NULL
 OR b.source_ref !~ ('^atomic/'||w.section||'--'||w.subsection||'--[a-z0-9]+(-[a-z0-9]+)*$')
 OR EXISTS(SELECT 1 FROM public.workstations WHERE worktree=b.worktree)
 THEN RAISE EXCEPTION 'BOOTSTRAP_ROUTE_DENIED'; END IF;
 PERFORM atomic_inspection._registered(w);
 PERFORM 1 FROM public.sections WHERE product=b.product AND section_key=w.section AND branch=w.parent_branch;
 IF NOT FOUND THEN RAISE EXCEPTION 'BOOTSTRAP_ROUTE_DENIED'; END IF;
 PERFORM 1 FROM assignment_leases.policies WHERE product=b.product AND active;
 IF NOT FOUND THEN RAISE EXCEPTION 'BOOTSTRAP_POLICY_REQUIRED'; END IF;
 IF jsonb_array_length(payload->'prerequisites')<>jsonb_array_length(payload->'dependencies')
 OR (SELECT count(DISTINCT x) FROM jsonb_array_elements(payload->'prerequisites') x)<>jsonb_array_length(payload->'prerequisites')
 OR (SELECT count(DISTINCT x->>'dependency_key') FROM jsonb_array_elements(payload->'dependencies') x)<>jsonb_array_length(payload->'dependencies')
 THEN RAISE EXCEPTION 'BOOTSTRAP_DEPENDENCY_DENIED'; END IF;
 FOR dependency IN SELECT value FROM jsonb_array_elements(payload->'dependencies') LOOP
  prerequisite:=dependency->'prerequisite';
  IF jsonb_typeof(dependency) IS DISTINCT FROM 'object'
  OR NOT dependency ?& ARRAY['dependency_key','prerequisite','repository','repository_id','binding','binding_hash','issuer_app_id','issuer_name','capability_receipt','approved_by','purpose','check_id','valid_until','active']
  OR dependency-ARRAY['dependency_key','prerequisite','repository','repository_id','binding','binding_hash','issuer_app_id','issuer_name','capability_receipt','approved_by','purpose','check_id','valid_until','active']<>'{}'::jsonb
  OR NOT payload->'prerequisites' @> jsonb_build_array(prerequisite)
  OR prerequisite->>'product' IS DISTINCT FROM b.product
  OR prerequisite->>'scope_type' NOT IN ('SUBSECTION','SECTION','DEVELOPMENT','TESTING','STAGING','PRODUCTION')
  OR prerequisite->>'sha' IS NULL OR prerequisite->>'sha' !~ '^[0-9a-f]{40}$'
  OR dependency->>'repository' IS DISTINCT FROM b.repository OR (dependency->>'repository_id')::bigint IS DISTINCT FROM b.repository_id
  OR dependency->>'approved_by' IS DISTINCT FROM 'Ralph L. Appolon' OR dependency->>'purpose' IS DISTINCT FROM 'SCOPE_CERTIFICATION'
  OR (dependency->>'issuer_app_id')::bigint<=0 OR (dependency->>'issuer_app_id')::bigint=15368
  OR dependency->>'issuer_name' IN ('codestra-control-plane','codestra/control-plane','promotion-gate')
  OR btrim(dependency->>'issuer_name')='' OR btrim(dependency->>'capability_receipt')=''
  OR dependency->'active' IS DISTINCT FROM 'true'::jsonb OR (dependency->>'valid_until')::timestamptz<=clock_timestamp()
  THEN RAISE EXCEPTION 'BOOTSTRAP_DEPENDENCY_DENIED'; END IF;
 END LOOP;
 IF jsonb_typeof(w.depends_on) IS DISTINCT FROM 'array'
 OR (SELECT count(*) FROM jsonb_array_elements(payload->'prerequisites') x WHERE x->>'scope_type'='SUBSECTION')<>jsonb_array_length(w.depends_on)
 THEN RAISE EXCEPTION 'BOOTSTRAP_DEPENDENCY_DENIED'; END IF;
 FOR dependency_id IN SELECT value FROM jsonb_array_elements_text(w.depends_on) LOOP
  SELECT * INTO dep_ws FROM public.workstations WHERE workstation_id=dependency_id AND product=b.product;
  IF NOT FOUND OR dep_ws.status<>'CERTIFIED' OR dep_ws.remote_sha IS NULL OR dep_ws.exact_sha_certified IS DISTINCT FROM dep_ws.remote_sha
  THEN RAISE EXCEPTION 'BOOTSTRAP_DEPENDENCY_DENIED'; END IF;
  PERFORM atomic_inspection._registered(dep_ws);
  IF NOT payload->'prerequisites' @> jsonb_build_array(jsonb_build_object('product',b.product,'scope_type','SUBSECTION','scope_name',dep_ws.branch,'sha',dep_ws.remote_sha))
  THEN RAISE EXCEPTION 'BOOTSTRAP_DEPENDENCY_DENIED'; END IF;
 END LOOP;
 IF payload->'expected_predecessor'<>'null'::jsonb AND (
  jsonb_typeof(payload->'expected_predecessor') IS DISTINCT FROM 'object'
  OR NOT payload->'expected_predecessor' ?& ARRAY['binding_id','revision','epoch','session_id']
  OR (payload->'expected_predecessor')-ARRAY['binding_id','revision','epoch','session_id']<>'{}'::jsonb
  OR jsonb_typeof(payload->'expected_predecessor'->'binding_id') IS DISTINCT FROM 'string'
  OR jsonb_typeof(payload->'expected_predecessor'->'session_id') IS DISTINCT FROM 'string'
  OR jsonb_typeof(payload->'expected_predecessor'->'revision') IS DISTINCT FROM 'number'
  OR jsonb_typeof(payload->'expected_predecessor'->'epoch') IS DISTINCT FROM 'number'
  OR payload->'expected_predecessor'->>'revision' !~ '^[1-9][0-9]*$'
  OR payload->'expected_predecessor'->>'epoch' !~ '^[1-9][0-9]*$'
  OR payload->'expected_predecessor'->>'binding_id' IS DISTINCT FROM ((payload->'expected_predecessor'->>'binding_id')::uuid)::text
  OR payload->'expected_predecessor'->>'session_id' IS DISTINCT FROM ((payload->'expected_predecessor'->>'session_id')::uuid)::text)
 THEN RAISE EXCEPTION 'BOOTSTRAP_CAS_MISMATCH'; END IF;
 RETURN jsonb_build_object('profile',to_jsonb(p),'session',to_jsonb(s));
END $$;

CREATE FUNCTION task_bootstrap._current(request_uuid uuid) RETURNS task_bootstrap.requests LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE r task_bootstrap.requests;context jsonb;
BEGIN
 SELECT * INTO r FROM task_bootstrap.requests WHERE request_id=request_uuid;
 IF NOT FOUND THEN RAISE EXCEPTION 'BOOTSTRAP_REQUEST_NOT_FOUND'; END IF;
 IF EXISTS(SELECT 1 FROM task_bootstrap.audit WHERE request_id=request_uuid AND action='REVOKE')
 OR EXISTS(SELECT 1 FROM task_bootstrap.issued WHERE request_id=request_uuid AND state='REVOKED')
 THEN RAISE EXCEPTION 'BOOTSTRAP_REVOKED'; END IF;
 context:=task_bootstrap._validate(r.payload);
 IF context->'profile' IS DISTINCT FROM r.profile_snapshot OR context->'session' IS DISTINCT FROM r.session_snapshot
 OR r.expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'BOOTSTRAP_AUTHORITY_CHANGED'; END IF;
 RETURN r;
END $$;
CREATE FUNCTION task_bootstrap._audit(request_uuid uuid,action_name text,value jsonb) RETURNS void LANGUAGE sql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
 INSERT INTO task_bootstrap.audit(request_id,actor,actor_oid,authentication,action,receipt)
 VALUES(request_uuid,session_user,task_bootstrap._actor(),system_user,action_name,value)
$$;
CREATE FUNCTION task_bootstrap.request(payload jsonb,client_request_id text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE actor_oid oid;context jsonb;r task_bootstrap.requests;digest text;
BEGIN
 actor_oid:=task_bootstrap._actor();context:=task_bootstrap._validate(payload);
 IF context->'profile'->>'operator' IS DISTINCT FROM session_user::text
 OR (context->'profile'->>'operator_oid')::oid<>actor_oid THEN RAISE EXCEPTION 'BOOTSTRAP_PROFILE_DENIED'; END IF;
 IF client_request_id IS NULL OR client_request_id !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 THEN RAISE EXCEPTION 'BOOTSTRAP_INVALID_REQUEST_ID'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('bootstrap-request:'||actor_oid::text||':'||client_request_id,1616));
 digest:=encode(sha256(convert_to(payload::text,'UTF8')),'hex');
 SELECT * INTO r FROM task_bootstrap.requests q WHERE q.operator_oid=actor_oid AND q.client_request_id=request.client_request_id;
 IF FOUND THEN
  IF r.payload IS DISTINCT FROM payload OR r.request_digest<>digest THEN RAISE EXCEPTION 'BOOTSTRAP_REQUEST_CONFLICT'; END IF;
  PERFORM task_bootstrap._current(r.request_id);
 ELSE
  INSERT INTO task_bootstrap.requests(operator_oid,client_request_id,request_digest,payload,profile_snapshot,session_snapshot,expires_at)
  VALUES(actor_oid,client_request_id,digest,payload,context->'profile',context->'session',(payload->'binding'->>'valid_until')::timestamptz) RETURNING * INTO r;
  PERFORM task_bootstrap._audit(r.request_id,'REQUEST',jsonb_build_object('request_digest',digest));
 END IF;
 RETURN jsonb_build_object('request_id',r.request_id,'request_digest',r.request_digest,'state','PENDING','usable',false);
END $$;
CREATE FUNCTION task_bootstrap._verifier(r task_bootstrap.requests) RETURNS oid LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE actor_oid oid;
BEGIN
 actor_oid:=task_bootstrap._actor();
 IF r.profile_snapshot->>'verifier' IS DISTINCT FROM session_user::text
 OR (r.profile_snapshot->>'verifier_oid')::oid<>actor_oid THEN RAISE EXCEPTION 'BOOTSTRAP_VERIFIER_REQUIRED'; END IF;
 PERFORM assignment_leases._permission(r.payload->'binding'->>'product','attest',false);
 PERFORM assignment_leases._permission(r.payload->'binding'->>'product','read',false);
 RETURN actor_oid;
END $$;
CREATE FUNCTION task_bootstrap.describe(request_uuid uuid) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE r task_bootstrap.requests;
BEGIN
 r:=task_bootstrap._current(request_uuid);PERFORM task_bootstrap._verifier(r);
 RETURN jsonb_build_object('request_id',r.request_id,'request_digest',r.request_digest,
 'binding',r.payload->'binding'||jsonb_build_object('binding_id',r.binding_id),
 'dependencies',coalesce((SELECT jsonb_agg(d||jsonb_build_object('binding_id',r.binding_id) ORDER BY d->>'dependency_key') FROM jsonb_array_elements(r.payload->'dependencies') d),'[]'::jsonb),
 'paths',r.payload->'paths','permitted_remote',r.payload->'permitted_remote','route',r.payload->'route',
 'custody_sha256',r.payload->'custody_sha256','session_id',r.payload->'session_id','profile_id',r.payload->'profile_id',
 'profile_revision',r.profile_snapshot->'revision','expected_predecessor',r.payload->'expected_predecessor');
END $$;
CREATE FUNCTION task_bootstrap.acknowledge(request_uuid uuid) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE r task_bootstrap.requests;actor_oid oid;value jsonb;
BEGIN
 actor_oid:=task_bootstrap._actor();r:=task_bootstrap._current(request_uuid);
 IF r.session_snapshot->>'principal' IS DISTINCT FROM session_user::text
 OR (r.session_snapshot->>'principal_oid')::oid<>actor_oid THEN RAISE EXCEPTION 'BOOTSTRAP_SESSION_DENIED'; END IF;
 INSERT INTO task_bootstrap.acknowledgements(request_id,request_digest,principal,principal_oid,authentication,session_snapshot)
 VALUES(r.request_id,r.request_digest,session_user,actor_oid,system_user,r.session_snapshot) ON CONFLICT DO NOTHING;
 value:=jsonb_build_object('request_id',r.request_id,'request_digest',r.request_digest,'state','ACKNOWLEDGED','usable',false);
 PERFORM task_bootstrap._audit(r.request_id,'ACKNOWLEDGE',value);RETURN value;
END $$;
CREATE FUNCTION task_bootstrap.attest(request_uuid uuid,observations jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE r task_bootstrap.requests;actor_oid oid;b jsonb;m jsonb;expected jsonb;dependencies jsonb;stamp timestamptz;seconds integer;proof task_bootstrap.proofs;
BEGIN
 r:=task_bootstrap._current(request_uuid);actor_oid:=task_bootstrap._verifier(r);b:=r.payload->'binding';m:=observations->'materialization';
 expected:=jsonb_build_object('repository',b->'repository','repository_id',b->'repository_id','source_ref',b->'source_ref','target_ref',b->'target_ref',
 'head_sha',b->'head_sha','base_sha',b->'base_sha','worktree',b->'worktree','host',b->'host','git_common_dir',b->'git_common_dir','worktree_uid',b->'worktree_uid',
 'permitted_remote',r.payload->'permitted_remote');
 SELECT coalesce(jsonb_object_agg(d->>'dependency_key',d||jsonb_build_object('binding_id',r.binding_id)),'{}'::jsonb) INTO dependencies FROM jsonb_array_elements(r.payload->'dependencies') d;
 IF jsonb_typeof(observations) IS DISTINCT FROM 'object' OR NOT observations ?& ARRAY['request_digest','materialization']
 OR observations-ARRAY['request_digest','materialization']<>'{}'::jsonb OR observations->>'request_digest' IS DISTINCT FROM r.request_digest
 OR jsonb_typeof(m) IS DISTINCT FROM 'object'
 OR NOT m ?& ARRAY['repository','repository_id','source_ref','target_ref','head_sha','base_sha','worktree','host','git_common_dir','worktree_uid','directory_device','directory_inode','observed_at','dependencies','permitted_remote']
 OR m-ARRAY['directory_device','directory_inode','observed_at','dependencies'] IS DISTINCT FROM expected
 OR m->'dependencies' IS DISTINCT FROM dependencies
 OR jsonb_typeof(m->'directory_device') IS DISTINCT FROM 'number' OR jsonb_typeof(m->'directory_inode') IS DISTINCT FROM 'number'
 OR (m->>'directory_device')::bigint<0 OR (m->>'directory_inode')::bigint<=0
 THEN RAISE EXCEPTION 'BOOTSTRAP_OBSERVATION_MISMATCH'; END IF;
 SELECT attestation_seconds INTO seconds FROM assignment_leases.policies WHERE product=b->>'product' AND active;
 stamp:=(m->>'observed_at')::timestamptz;
 IF stamp IS NULL OR m->>'observed_at' !~ '(Z|[+-][0-9]{2}:[0-9]{2})$'
 OR stamp>clock_timestamp() OR stamp<clock_timestamp()-make_interval(secs=>seconds)
 THEN RAISE EXCEPTION 'BOOTSTRAP_PROOF_EXPIRED'; END IF;
 INSERT INTO task_bootstrap.proofs(request_id,verifier,verifier_oid,authentication,request_snapshot,observations,expires_at)
 VALUES(r.request_id,session_user,actor_oid,system_user,to_jsonb(r),observations,least(r.expires_at,stamp+make_interval(secs=>seconds))) RETURNING * INTO proof;
 PERFORM task_bootstrap._audit(r.request_id,'ATTEST',jsonb_build_object('proof_id',proof.proof_id));
 RETURN jsonb_build_object('request_id',r.request_id,'request_digest',r.request_digest,'proof_id',proof.proof_id,'state','ATTESTED','usable',false);
END $$;

CREATE FUNCTION task_bootstrap._repo_lock(repository_id bigint) RETURNS void LANGUAGE sql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
 SELECT pg_advisory_xact_lock(hashtextextended('bootstrap-repository:'||repository_id::text,1616))
$$;
CREATE FUNCTION task_bootstrap._retire(request_uuid uuid) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE i task_bootstrap.issued;b assignment_leases.bindings;l assignment_leases.leases;
BEGIN
 SELECT * INTO i FROM task_bootstrap.issued WHERE request_id=request_uuid FOR UPDATE;
 IF NOT FOUND OR i.state='REVOKED' THEN RETURN; END IF;
 SELECT * INTO b FROM assignment_leases.bindings WHERE binding_id=i.binding_id;
 PERFORM assignment_leases._lock(b);
 UPDATE task_bootstrap.issued SET state='REVOKED',revoked_at=clock_timestamp() WHERE request_id=request_uuid;
 UPDATE assignment_leases.bindings SET active=false WHERE binding_id=i.binding_id;
 UPDATE scoped_admission.grants SET active=false WHERE grant_id IN (i.l1_grant,i.l2_grant);
 FOR l IN UPDATE assignment_leases.leases SET state='REVOKED' WHERE binding_id=i.binding_id AND state='ACTIVE' RETURNING * LOOP
  UPDATE assignment_leases.slots SET epoch=epoch+1 WHERE workstation_id=l.workstation_id;
  UPDATE public.workstations SET agent=NULL,current_atomic_task=NULL,lease_state='FREE',lease_expires_at=NULL,heartbeat_at=NULL
  WHERE workstation_id=l.workstation_id AND agent=l.principal::text AND current_atomic_task=b.task_id
   AND lease_state='ACTIVE' AND status<>'BLOCKED' AND blocker IS NULL;
 END LOOP;
END $$;
CREATE FUNCTION task_bootstrap._require_issued(binding_uuid uuid) RETURNS task_bootstrap.issued LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE i task_bootstrap.issued;r task_bootstrap.requests;b assignment_leases.bindings;
BEGIN
 SELECT * INTO i FROM task_bootstrap.issued WHERE binding_id=binding_uuid AND state='ISSUED';
 IF NOT FOUND THEN RAISE EXCEPTION 'BOOTSTRAP_AUTHORITY_REQUIRED'; END IF;
 r:=task_bootstrap._current(i.request_id);
 SELECT * INTO b FROM assignment_leases.bindings WHERE binding_id=binding_uuid;
 IF NOT FOUND OR to_jsonb(b) IS DISTINCT FROM i.binding_snapshot THEN RAISE EXCEPTION 'BOOTSTRAP_AUTHORITY_REQUIRED'; END IF;
 IF (SELECT count(*) FROM scoped_admission.grants g WHERE g.grant_id IN (i.l1_grant,i.l2_grant)
  AND g.binding_id=i.binding_id AND g.active AND g.revision=1 AND g.paths=r.payload->'paths'
  AND g.valid_until=b.valid_until AND ((g.grant_id=i.l1_grant AND g.operation='L1') OR (g.grant_id=i.l2_grant AND g.operation='L2')))<>2
 THEN RAISE EXCEPTION 'BOOTSTRAP_AUTHORITY_REQUIRED'; END IF;
 RETURN i;
END $$;
-- Static reviewed007 implementation, under a private name. Preserve the original
-- _binding OID with CREATE OR REPLACE so cached callers also enter the new guard.
CREATE FUNCTION assignment_leases._binding_before_bootstrap(binding_uuid uuid,locked boolean DEFAULT true) RETURNS assignment_leases.bindings LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
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
REVOKE ALL ON FUNCTION assignment_leases._binding_before_bootstrap(uuid,boolean) FROM PUBLIC;
CREATE OR REPLACE FUNCTION assignment_leases._binding(binding_uuid uuid,locked boolean DEFAULT true) RETURNS assignment_leases.bindings LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
BEGIN
 PERFORM task_bootstrap._actor();PERFORM task_bootstrap._require_issued(binding_uuid);
 RETURN assignment_leases._binding_before_bootstrap(binding_uuid,locked);
END $$;
CREATE FUNCTION task_bootstrap.lease_description(binding_uuid uuid) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE i task_bootstrap.issued;r task_bootstrap.requests;description jsonb;
BEGIN
 i:=task_bootstrap._require_issued(binding_uuid);r:=task_bootstrap._current(i.request_id);PERFORM task_bootstrap._verifier(r);
 description:=assignment_leases.describe(binding_uuid);
 RETURN jsonb_build_object('request_id',binding_uuid,'request_digest',r.request_digest,
 'bootstrap_request_id',r.request_id,'bootstrap_request_digest',r.request_digest,
 'permitted_remote',r.payload->'permitted_remote','description',description);
END $$;
CREATE FUNCTION task_bootstrap.lease_attest(binding_uuid uuid,observations jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE i task_bootstrap.issued;r task_bootstrap.requests;actor_oid oid;proof jsonb;
BEGIN
 i:=task_bootstrap._require_issued(binding_uuid);r:=task_bootstrap._current(i.request_id);actor_oid:=task_bootstrap._verifier(r);
 IF jsonb_typeof(observations) IS DISTINCT FROM 'object' OR observations-ARRAY['request_digest','materialization']<>'{}'::jsonb
 OR observations->>'request_digest' IS DISTINCT FROM r.request_digest
 OR observations->'materialization'->>'permitted_remote' IS DISTINCT FROM r.payload->>'permitted_remote'
 THEN RAISE EXCEPTION 'BOOTSTRAP_OBSERVATION_MISMATCH'; END IF;
 proof:=assignment_leases.attest(binding_uuid,(observations->'materialization')-'permitted_remote');
 INSERT INTO task_bootstrap.lease_proofs(proof_id,request_id,binding_id,bootstrap_digest,permitted_remote,verifier_oid)
 VALUES((proof->>'proof_id')::uuid,r.request_id,binding_uuid,r.request_digest,r.payload->>'permitted_remote',actor_oid);
 RETURN jsonb_build_object('request_id',binding_uuid,'request_digest',r.request_digest,'proof_id',proof->'proof_id','state','ATTESTED','usable',false);
END $$;
CREATE FUNCTION task_bootstrap.stage_description(intent_uuid uuid) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE i task_bootstrap.issued;r task_bootstrap.requests;description jsonb;intent scoped_admission.intents;
BEGIN
 SELECT * INTO intent FROM scoped_admission.intents WHERE intent_id=intent_uuid;
 IF NOT FOUND THEN RAISE EXCEPTION 'BOOTSTRAP_REQUEST_NOT_FOUND'; END IF;
 i:=task_bootstrap._require_issued(intent.binding_id);r:=task_bootstrap._current(i.request_id);PERFORM task_bootstrap._verifier(r);
 description:=scoped_admission.describe(intent_uuid);
 RETURN jsonb_build_object('request_id',intent_uuid,'request_digest',intent.request_digest,
 'bootstrap_request_id',r.request_id,'bootstrap_request_digest',r.request_digest,
 'permitted_remote',r.payload->'permitted_remote','description',description);
END $$;
CREATE FUNCTION task_bootstrap.stage_attest(intent_uuid uuid,observations jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE i task_bootstrap.issued;r task_bootstrap.requests;actor_oid oid;proof jsonb;intent scoped_admission.intents;
BEGIN
 SELECT * INTO intent FROM scoped_admission.intents WHERE intent_id=intent_uuid;
 IF NOT FOUND THEN RAISE EXCEPTION 'BOOTSTRAP_REQUEST_NOT_FOUND'; END IF;
 i:=task_bootstrap._require_issued(intent.binding_id);r:=task_bootstrap._current(i.request_id);actor_oid:=task_bootstrap._verifier(r);
 IF jsonb_typeof(observations) IS DISTINCT FROM 'object' OR observations-ARRAY['request_digest','materialization']<>'{}'::jsonb
 OR observations->>'request_digest' IS DISTINCT FROM intent.request_digest
 OR observations->'materialization'->>'permitted_remote' IS DISTINCT FROM r.payload->>'permitted_remote'
 THEN RAISE EXCEPTION 'BOOTSTRAP_OBSERVATION_MISMATCH'; END IF;
 proof:=scoped_admission.attest(intent_uuid,(observations->'materialization')-'permitted_remote');
 INSERT INTO task_bootstrap.stage_proofs(proof_id,intent_id,request_id,bootstrap_digest,intent_digest,permitted_remote,verifier_oid)
 VALUES((proof->>'proof_id')::uuid,intent_uuid,r.request_id,r.request_digest,intent.request_digest,r.payload->>'permitted_remote',actor_oid);
 RETURN jsonb_build_object('request_id',intent_uuid,'request_digest',intent.request_digest,'proof_id',proof->'proof_id','state','ATTESTED','usable',false);
END $$;
CREATE FUNCTION task_bootstrap.issue(request_uuid uuid,proof_uuid uuid) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE actor_oid oid;r task_bootstrap.requests;initial task_bootstrap.requests;proof task_bootstrap.proofs;
 i task_bootstrap.issued;old task_bootstrap.issued;other task_bootstrap.issued;old_request task_bootstrap.requests;
 b assignment_leases.bindings;d jsonb;predecessor jsonb;path text;other_path text;next_revision bigint:=1;l1 uuid:=gen_random_uuid();l2 uuid:=gen_random_uuid();result_receipt jsonb;
BEGIN
 actor_oid:=task_bootstrap._actor();initial:=task_bootstrap._current(request_uuid);
 PERFORM task_bootstrap._repo_lock((initial.payload->'binding'->>'repository_id')::bigint);
 PERFORM 1 FROM task_bootstrap.profiles WHERE profile_id=(initial.payload->>'profile_id')::uuid FOR SHARE;
 PERFORM 1 FROM task_bootstrap.sessions WHERE session_id=(initial.payload->>'session_id')::uuid FOR SHARE;
 PERFORM 1 FROM assignment_leases.permissions WHERE principal=(initial.profile_snapshot->>'verifier')::name
  AND product=initial.payload->'binding'->>'product' FOR SHARE;
 SELECT * INTO r FROM task_bootstrap.requests WHERE request_id=request_uuid FOR UPDATE;
 IF r IS DISTINCT FROM initial THEN RAISE EXCEPTION 'BOOTSTRAP_AUTHORITY_CHANGED'; END IF;
 r:=task_bootstrap._current(request_uuid);
 IF r.operator_oid<>actor_oid OR r.profile_snapshot->>'operator'<>session_user::text THEN RAISE EXCEPTION 'BOOTSTRAP_PROFILE_DENIED'; END IF;
 SELECT * INTO i FROM task_bootstrap.issued WHERE request_id=request_uuid;
 IF FOUND THEN
  IF i.state<>'ISSUED' THEN RAISE EXCEPTION 'BOOTSTRAP_REVOKED'; END IF;
  PERFORM task_bootstrap._require_issued(i.binding_id);RETURN i.receipt;
 END IF;
 PERFORM 1 FROM task_bootstrap.acknowledgements a WHERE a.request_id=r.request_id AND a.request_digest=r.request_digest
 AND a.principal_oid=(r.session_snapshot->>'principal_oid')::oid AND a.principal::text=r.session_snapshot->>'principal'
 AND a.authentication='scram-sha-256:'||a.principal::text AND a.session_snapshot=r.session_snapshot;
 IF NOT FOUND THEN RAISE EXCEPTION 'BOOTSTRAP_ACK_REQUIRED'; END IF;
 SELECT * INTO proof FROM task_bootstrap.proofs WHERE proof_id=proof_uuid AND request_id=request_uuid FOR SHARE;
 IF NOT FOUND OR proof.request_snapshot IS DISTINCT FROM to_jsonb(r) OR proof.expires_at<=clock_timestamp()
 OR proof.verifier::text IS DISTINCT FROM r.profile_snapshot->>'verifier'
 OR proof.verifier_oid<>(r.profile_snapshot->>'verifier_oid')::oid
 OR proof.authentication<>'scram-sha-256:'||proof.verifier::text
 THEN RAISE EXCEPTION 'BOOTSTRAP_PROOF_REQUIRED'; END IF;
 b:=jsonb_populate_record(NULL::assignment_leases.bindings,r.payload->'binding'||jsonb_build_object('binding_id',r.binding_id,'active',true));
 predecessor:=r.payload->'expected_predecessor';
 IF predecessor<>'null'::jsonb THEN
  SELECT * INTO old FROM task_bootstrap.issued WHERE binding_id=(predecessor->>'binding_id')::uuid FOR UPDATE;
  IF NOT FOUND OR old.revision IS DISTINCT FROM (predecessor->>'revision')::bigint OR old.epoch IS DISTINCT FROM (predecessor->>'epoch')::bigint
  OR EXISTS(SELECT 1 FROM task_bootstrap.issued WHERE predecessor_request=old.request_id)
  THEN RAISE EXCEPTION 'BOOTSTRAP_CAS_MISMATCH'; END IF;
  SELECT * INTO old_request FROM task_bootstrap.requests WHERE request_id=old.request_id;
  IF old_request.payload->'session_id' IS DISTINCT FROM predecessor->'session_id'
  OR old_request.payload->'binding'->>'repository_id' IS DISTINCT FROM b.repository_id::text
  OR old_request.payload->'binding'->>'product' IS DISTINCT FROM b.product
  OR old_request.payload->'binding'->>'workstation_id' IS DISTINCT FROM b.workstation_id
  OR old_request.payload->'profile_id' IS DISTINCT FROM r.payload->'profile_id'
  THEN RAISE EXCEPTION 'BOOTSTRAP_CAS_MISMATCH'; END IF;
  next_revision:=old.revision+1;
 END IF;
 FOR other IN SELECT issued.* FROM task_bootstrap.issued issued JOIN task_bootstrap.requests q USING(request_id)
  WHERE issued.state='ISSUED' AND (q.payload->'binding'->>'repository_id')::bigint=b.repository_id
  AND (old.request_id IS NULL OR issued.request_id<>old.request_id) LOOP
  SELECT * INTO old_request FROM task_bootstrap.requests WHERE request_id=other.request_id;
  IF old_request.payload->'binding'->>'source_ref'=b.source_ref OR old_request.payload->'binding'->>'worktree'=b.worktree
  OR left(old_request.payload->'binding'->>'worktree',length(b.worktree)+1)=b.worktree||'/'
  OR left(b.worktree,length(old_request.payload->'binding'->>'worktree')+1)=(old_request.payload->'binding'->>'worktree')||'/'
  OR ((other.binding_snapshot->>'host')=b.host AND (other.receipt->>'directory_device')::bigint=(proof.observations->'materialization'->>'directory_device')::bigint
   AND (other.receipt->>'directory_inode')::bigint=(proof.observations->'materialization'->>'directory_inode')::bigint)
  THEN RAISE EXCEPTION 'BOOTSTRAP_OVERLAP'; END IF;
  FOR path IN SELECT jsonb_array_elements_text(r.payload->'paths') LOOP
   FOR other_path IN SELECT jsonb_array_elements_text(old_request.payload->'paths') LOOP
    IF path=other_path OR left(path,length(other_path)+1)=other_path||'/' OR left(other_path,length(path)+1)=path||'/'
    THEN RAISE EXCEPTION 'BOOTSTRAP_OVERLAP'; END IF;
   END LOOP;
  END LOOP;
 END LOOP;
 IF (EXISTS(SELECT 1 FROM scoped_registration.task_assignments WHERE task_id=b.task_id)
 OR EXISTS(SELECT 1 FROM assignment_leases.bindings WHERE task_id=b.task_id)
 OR EXISTS(SELECT 1 FROM public.atomic_tasks WHERE task_id=b.task_id))
 AND (old.request_id IS NULL OR (old.binding_snapshot->>'task_id') IS DISTINCT FROM b.task_id)
 THEN RAISE EXCEPTION 'BOOTSTRAP_TASK_HISTORY_CONFLICT'; END IF;
 IF old.request_id IS NOT NULL THEN PERFORM task_bootstrap._retire(old.request_id); END IF;
 IF old.request_id IS NOT NULL AND old.binding_snapshot->>'task_id'=b.task_id THEN
  IF EXISTS(SELECT 1 FROM public.atomic_tasks WHERE task_id=b.task_id AND status IN ('BLOCKED','COMPLETE','CERTIFIED'))
  THEN RAISE EXCEPTION 'BOOTSTRAP_TASK_HISTORY_CONFLICT'; END IF;
  IF EXISTS(SELECT 1 FROM public.atomic_tasks t WHERE t.task_id=b.task_id AND
   (t.workstation_id IS DISTINCT FROM old.binding_snapshot->>'workstation_id' OR t.owner IS DISTINCT FROM old.binding_snapshot->>'principal'))
  THEN RAISE EXCEPTION 'BOOTSTRAP_CAS_MISMATCH'; END IF;
  -- Only current materialization metadata is replaced. Previous exact vectors,
  -- receipts, proofs and audit rows remain immutable in their original ledgers.
  DELETE FROM scoped_registration.candidates WHERE task_id=b.task_id;
  DELETE FROM scoped_registration.lanes WHERE product=b.product AND kind='candidate' AND identity=b.task_id;
  UPDATE scoped_registration.task_assignments SET active=false WHERE task_id=b.task_id;
  UPDATE public.atomic_tasks SET owner=b.principal::text,title=r.payload->>'title',status='NOT_STARTED',updated_at=clock_timestamp() WHERE task_id=b.task_id;
  INSERT INTO public.atomic_tasks(task_id,workstation_id,title,owner)
  VALUES(b.task_id,b.workstation_id,r.payload->>'title',b.principal::text) ON CONFLICT DO NOTHING;
 END IF;
 INSERT INTO scoped_registration.grants(principal,product,capability,repository) VALUES(b.principal,b.product,'candidate',b.repository) ON CONFLICT DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM scoped_registration.grants WHERE principal=b.principal AND product=b.product AND capability='candidate' AND repository=b.repository)
 THEN RAISE EXCEPTION 'BOOTSTRAP_PROFILE_DENIED'; END IF;
 INSERT INTO scoped_registration.task_assignments(product,workstation_id,task_id,principal) VALUES(b.product,b.workstation_id,b.task_id,b.principal)
 ON CONFLICT(product,workstation_id,task_id,principal) DO UPDATE SET active=true;
 INSERT INTO assignment_leases.bindings SELECT b.*;
 INSERT INTO assignment_leases.coordinator_tasks VALUES(b.binding_id,r.payload->>'title',r.payload->'prerequisites',true);
 IF old.request_id IS NOT NULL AND old.binding_snapshot->>'task_id'=b.task_id THEN
  INSERT INTO scoped_registration.lanes(worktree,product,kind,identity,branch)
  VALUES(b.worktree,b.product,'candidate',b.task_id,b.source_ref);
  INSERT INTO scoped_registration.candidates(product,workstation_id,task_id,principal,branch,worktree,payload)
  VALUES(b.product,b.workstation_id,b.task_id,b.principal,b.source_ref,b.worktree,
   jsonb_build_object('product',b.product,'workstation_id',b.workstation_id,'task_id',b.task_id,'title',r.payload->>'title',
    'branch',b.source_ref,'target_branch',b.target_ref,'worktree',b.worktree,'head_sha',b.head_sha,'base_sha',b.base_sha,'prerequisites',r.payload->'prerequisites'));
 END IF;
 FOR d IN SELECT value FROM jsonb_array_elements(r.payload->'dependencies') LOOP
  INSERT INTO assignment_leases.dependencies SELECT (jsonb_populate_record(NULL::assignment_leases.dependencies,d||jsonb_build_object('binding_id',b.binding_id))).*;
 END LOOP;
 INSERT INTO scoped_admission.grants(grant_id,binding_id,operation,paths,valid_until,active)
 VALUES(l1,b.binding_id,'L1',r.payload->'paths',b.valid_until,true),(l2,b.binding_id,'L2',r.payload->'paths',b.valid_until,true);
 INSERT INTO task_bootstrap.issued(request_id,binding_id,revision,l1_grant,l2_grant,proof_id,binding_snapshot,receipt,predecessor_request,state)
 VALUES(r.request_id,b.binding_id,next_revision,l1,l2,proof_uuid,to_jsonb(b),'{}'::jsonb,old.request_id,'ISSUED') RETURNING * INTO i;
 result_receipt:=jsonb_build_object('request_id',r.request_id,'request_digest',r.request_digest,'binding_id',b.binding_id,'revision',i.revision,'epoch',i.epoch,
 'session_id',r.payload->'session_id','profile_id',r.payload->'profile_id','profile_revision',r.profile_snapshot->'revision',
 'state','ISSUED','authority','ONLINE_TASK_BOOTSTRAP_BINDING','ready_for_admission',true,'usable',false,
 'source_authorized',false,'publication_authorized',false,'certified',false,'l1_grant_id',l1,'l2_grant_id',l2,
 'directory_device',proof.observations->'materialization'->'directory_device','directory_inode',proof.observations->'materialization'->'directory_inode',
 'missing_authority',jsonb_build_array('ACTIVE_ASSIGNMENT_LEASE_REQUIRED','L1_OPERATION_RECEIPT_REQUIRED','L2_OPERATION_RECEIPT_REQUIRED'));
 UPDATE task_bootstrap.issued SET receipt=result_receipt WHERE request_id=r.request_id;
 PERFORM task_bootstrap._audit(r.request_id,'ISSUE',result_receipt);RETURN result_receipt;
END $$;
CREATE FUNCTION task_bootstrap.inspect(request_uuid uuid) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE r task_bootstrap.requests;i task_bootstrap.issued;actor_oid oid;
BEGIN
 actor_oid:=task_bootstrap._actor();SELECT * INTO r FROM task_bootstrap.requests WHERE request_id=request_uuid;
 IF NOT FOUND OR r.operator_oid<>actor_oid THEN RAISE EXCEPTION 'BOOTSTRAP_PROFILE_DENIED'; END IF;
 SELECT * INTO i FROM task_bootstrap.issued WHERE request_id=request_uuid;
 IF NOT FOUND THEN
  IF EXISTS(SELECT 1 FROM task_bootstrap.audit WHERE request_id=request_uuid AND action='REVOKE')
  THEN RETURN jsonb_build_object('request_id',r.request_id,'request_digest',r.request_digest,'state','REVOKED','usable',false,'ready_for_admission',false,'historical',true,'authority','NONE'); END IF;
  PERFORM task_bootstrap._current(request_uuid);RETURN jsonb_build_object('request_id',r.request_id,'request_digest',r.request_digest,'state','PENDING','usable',false);
 END IF;
 IF i.state='ISSUED' THEN
  BEGIN
   PERFORM task_bootstrap._require_issued(i.binding_id);RETURN i.receipt;
  EXCEPTION WHEN SQLSTATE 'P0001' THEN NULL;
  END;
 END IF;
 RETURN i.receipt||jsonb_build_object('state',i.state,'ready_for_admission',false,'usable',false,'historical',true,'authority','NONE');
END $$;
CREATE FUNCTION task_bootstrap.revoke(request_uuid uuid) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE r task_bootstrap.requests;actor_oid oid;value jsonb;
BEGIN
 actor_oid:=task_bootstrap._actor();SELECT * INTO r FROM task_bootstrap.requests WHERE request_id=request_uuid;
 IF NOT FOUND OR r.operator_oid<>actor_oid THEN RAISE EXCEPTION 'BOOTSTRAP_PROFILE_DENIED'; END IF;
 -- Accepted operator identity is still mandatory; damaged/expired target bindings
 -- and missing verifier credentials must not prevent durable revocation.
 IF NOT EXISTS(SELECT 1 FROM task_bootstrap.profiles p WHERE p.profile_id=(r.payload->>'profile_id')::uuid
 AND p.operator=session_user AND p.operator_oid=actor_oid AND p.active AND p.valid_until>clock_timestamp())
 THEN RAISE EXCEPTION 'BOOTSTRAP_PROFILE_DENIED'; END IF;
 PERFORM task_bootstrap._repo_lock((r.payload->'binding'->>'repository_id')::bigint);
 PERFORM task_bootstrap._retire(request_uuid);
 value:=jsonb_build_object('request_id',r.request_id,'request_digest',r.request_digest,'state','REVOKED','usable',false,'ready_for_admission',false);
 PERFORM task_bootstrap._audit(request_uuid,'REVOKE',value);RETURN value;
END $$;

CREATE FUNCTION task_bootstrap._lease_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE i task_bootstrap.issued;
BEGIN
 IF NEW.state='ACTIVE' THEN
  IF task_bootstrap._actor()<>NEW.principal_oid OR session_user<>NEW.principal THEN RAISE EXCEPTION 'BOOTSTRAP_AUTHENTICATION_REQUIRED'; END IF;
  i:=task_bootstrap._require_issued(NEW.binding_id);
  IF NEW.principal::text<>i.binding_snapshot->>'principal' OR NEW.principal_oid<>(i.binding_snapshot->>'principal_oid')::oid
  OR NEW.expires_at>(i.binding_snapshot->>'valid_until')::timestamptz
  OR NEW.directory_device<>(i.receipt->>'directory_device')::bigint OR NEW.directory_inode<>(i.receipt->>'directory_inode')::bigint
  OR NOT EXISTS(SELECT 1 FROM task_bootstrap.lease_proofs seal JOIN assignment_leases.proofs proof USING(proof_id)
   WHERE seal.proof_id=NEW.proof_id AND seal.request_id=i.request_id AND seal.binding_id=i.binding_id
    AND seal.bootstrap_digest=(SELECT request_digest FROM task_bootstrap.requests WHERE request_id=i.request_id)
    AND seal.permitted_remote=(SELECT payload->>'permitted_remote' FROM task_bootstrap.requests WHERE request_id=i.request_id)
    AND seal.verifier_oid=proof.verifier_oid)
  THEN RAISE EXCEPTION 'BOOTSTRAP_AUTHORITY_REQUIRED'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER bootstrap_lease_authority BEFORE INSERT OR UPDATE ON assignment_leases.leases
FOR EACH ROW EXECUTE FUNCTION task_bootstrap._lease_guard();
CREATE FUNCTION task_bootstrap._intent_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE i task_bootstrap.issued;
BEGIN
 IF TG_OP='INSERT' OR NEW.state='CONSUMED' THEN
  IF task_bootstrap._actor()<>NEW.principal_oid OR session_user<>NEW.principal THEN RAISE EXCEPTION 'BOOTSTRAP_AUTHENTICATION_REQUIRED'; END IF;
  i:=task_bootstrap._require_issued(NEW.binding_id);
  IF (NEW.operation='L1' AND NEW.grant_id<>i.l1_grant) OR (NEW.operation='L2' AND NEW.grant_id<>i.l2_grant)
  THEN RAISE EXCEPTION 'BOOTSTRAP_AUTHORITY_REQUIRED'; END IF;
  IF NEW.state='CONSUMED' AND NOT EXISTS(
   SELECT 1 FROM task_bootstrap.stage_proofs seal JOIN scoped_admission.proofs proof USING(proof_id)
   JOIN task_bootstrap.requests r ON r.request_id=seal.request_id
   WHERE seal.intent_id=NEW.intent_id AND proof.intent_id=NEW.intent_id AND proof.consumed
    AND seal.request_id=i.request_id AND seal.bootstrap_digest=r.request_digest AND seal.intent_digest=NEW.request_digest
    AND seal.permitted_remote=r.payload->>'permitted_remote' AND seal.verifier_oid=proof.verifier_oid)
  THEN RAISE EXCEPTION 'BOOTSTRAP_AUTHORITY_REQUIRED'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER bootstrap_operation_authority BEFORE INSERT OR UPDATE ON scoped_admission.intents
FOR EACH ROW EXECUTE FUNCTION task_bootstrap._intent_guard();
CREATE FUNCTION task_bootstrap._profile_revision() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE r task_bootstrap.requests;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'BOOTSTRAP_HISTORY_IMMUTABLE'; END IF;
 IF TG_OP='UPDATE' THEN
  IF (TG_TABLE_NAME='profiles' AND to_jsonb(NEW)->'profile_id' IS DISTINCT FROM to_jsonb(OLD)->'profile_id')
   OR (TG_TABLE_NAME='sessions' AND to_jsonb(NEW)->'session_id' IS DISTINCT FROM to_jsonb(OLD)->'session_id') THEN RAISE EXCEPTION 'BOOTSTRAP_ID_IMMUTABLE'; END IF;
  NEW.revision:=OLD.revision+1;
  FOR r IN SELECT q.* FROM task_bootstrap.requests q JOIN task_bootstrap.issued i USING(request_id)
   WHERE i.state='ISSUED' AND ((TG_TABLE_NAME='profiles' AND q.payload->>'profile_id'=to_jsonb(OLD)->>'profile_id')
    OR (TG_TABLE_NAME='sessions' AND q.payload->>'session_id'=to_jsonb(OLD)->>'session_id')) LOOP
   PERFORM task_bootstrap._retire(r.request_id);
  END LOOP;
 ELSE NEW.revision:=1;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER bootstrap_profile_revision BEFORE INSERT OR UPDATE OR DELETE ON task_bootstrap.profiles
FOR EACH ROW EXECUTE FUNCTION task_bootstrap._profile_revision();
CREATE TRIGGER bootstrap_session_revision BEFORE INSERT OR UPDATE OR DELETE ON task_bootstrap.sessions
FOR EACH ROW EXECUTE FUNCTION task_bootstrap._profile_revision();
CREATE FUNCTION task_bootstrap._immutable() RETURNS trigger LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp AS $$ BEGIN RAISE EXCEPTION 'BOOTSTRAP_HISTORY_IMMUTABLE'; END $$;
CREATE TRIGGER immutable_bootstrap_requests BEFORE UPDATE OR DELETE ON task_bootstrap.requests FOR EACH ROW EXECUTE FUNCTION task_bootstrap._immutable();
CREATE TRIGGER immutable_bootstrap_acks BEFORE UPDATE OR DELETE ON task_bootstrap.acknowledgements FOR EACH ROW EXECUTE FUNCTION task_bootstrap._immutable();
CREATE TRIGGER immutable_bootstrap_proofs BEFORE UPDATE OR DELETE ON task_bootstrap.proofs FOR EACH ROW EXECUTE FUNCTION task_bootstrap._immutable();
CREATE TRIGGER immutable_bootstrap_audit BEFORE UPDATE OR DELETE ON task_bootstrap.audit FOR EACH ROW EXECUTE FUNCTION task_bootstrap._immutable();
CREATE TRIGGER immutable_bootstrap_lease_proofs BEFORE UPDATE OR DELETE ON task_bootstrap.lease_proofs FOR EACH ROW EXECUTE FUNCTION task_bootstrap._immutable();
CREATE TRIGGER immutable_bootstrap_stage_proofs BEFORE UPDATE OR DELETE ON task_bootstrap.stage_proofs FOR EACH ROW EXECUTE FUNCTION task_bootstrap._immutable();
CREATE FUNCTION task_bootstrap._issued_history() RETURNS trigger LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'BOOTSTRAP_HISTORY_IMMUTABLE'; END IF;
 IF OLD.receipt='{}'::jsonb AND NEW.receipt<>'{}'::jsonb
 AND to_jsonb(NEW)-'receipt'=to_jsonb(OLD)-'receipt' THEN RETURN NEW; END IF;
 IF to_jsonb(NEW)-ARRAY['state','revoked_at'] IS DISTINCT FROM to_jsonb(OLD)-ARRAY['state','revoked_at']
 OR OLD.state<>'ISSUED' OR NEW.state<>'REVOKED' OR NEW.revoked_at IS NULL
 THEN RAISE EXCEPTION 'BOOTSTRAP_HISTORY_IMMUTABLE'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER immutable_bootstrap_issued BEFORE UPDATE OR DELETE ON task_bootstrap.issued FOR EACH ROW EXECUTE FUNCTION task_bootstrap._issued_history();
CREATE TRIGGER immutable_bootstrap_profiles_truncate BEFORE TRUNCATE ON task_bootstrap.profiles FOR EACH STATEMENT EXECUTE FUNCTION task_bootstrap._immutable();
CREATE TRIGGER immutable_bootstrap_sessions_truncate BEFORE TRUNCATE ON task_bootstrap.sessions FOR EACH STATEMENT EXECUTE FUNCTION task_bootstrap._immutable();
CREATE TRIGGER immutable_bootstrap_requests_truncate BEFORE TRUNCATE ON task_bootstrap.requests FOR EACH STATEMENT EXECUTE FUNCTION task_bootstrap._immutable();
CREATE TRIGGER immutable_bootstrap_acks_truncate BEFORE TRUNCATE ON task_bootstrap.acknowledgements FOR EACH STATEMENT EXECUTE FUNCTION task_bootstrap._immutable();
CREATE TRIGGER immutable_bootstrap_proofs_truncate BEFORE TRUNCATE ON task_bootstrap.proofs FOR EACH STATEMENT EXECUTE FUNCTION task_bootstrap._immutable();
CREATE TRIGGER immutable_bootstrap_issued_truncate BEFORE TRUNCATE ON task_bootstrap.issued FOR EACH STATEMENT EXECUTE FUNCTION task_bootstrap._immutable();
CREATE TRIGGER immutable_bootstrap_audit_truncate BEFORE TRUNCATE ON task_bootstrap.audit FOR EACH STATEMENT EXECUTE FUNCTION task_bootstrap._immutable();
CREATE TRIGGER immutable_bootstrap_lease_proofs_truncate BEFORE TRUNCATE ON task_bootstrap.lease_proofs FOR EACH STATEMENT EXECUTE FUNCTION task_bootstrap._immutable();
CREATE TRIGGER immutable_bootstrap_stage_proofs_truncate BEFORE TRUNCATE ON task_bootstrap.stage_proofs FOR EACH STATEMENT EXECUTE FUNCTION task_bootstrap._immutable();
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA task_bootstrap FROM PUBLIC;
COMMIT;
