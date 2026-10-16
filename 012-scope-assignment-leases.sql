-- Source-only scope lease protocol. Requires reviewed002/005 registry tables.
-- Separate operator owner only: no roles, runtime execution grants, assignments,
-- policies, credentials, leases or live database changes are provisioned here.
-- Atomic assignment_leases remains unchanged. No renewal or automatic reseal.
BEGIN;
CREATE SCHEMA scope_assignment_leases;
REVOKE ALL ON SCHEMA scope_assignment_leases FROM PUBLIC;

CREATE FUNCTION scope_assignment_leases._ref(value text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT value ~ '^[A-Za-z0-9_][A-Za-z0-9_./-]*$' AND value !~ '^refs/'
 AND value !~ '\.\.' AND value !~ '[/\.]$'
 AND NOT EXISTS(SELECT 1 FROM unnest(string_to_array(value,'/')) part
 WHERE part='' OR part LIKE '.%' OR part LIKE '%.lock')
$$;
CREATE TABLE scope_assignment_leases.principals (
 principal name PRIMARY KEY,role_oid oid NOT NULL UNIQUE,
 account_owner text NOT NULL CHECK(account_owner ~ '^[A-Za-z0-9][A-Za-z0-9-]*$'),
 expires_at timestamptz NOT NULL,active boolean NOT NULL DEFAULT false
);
CREATE TABLE scope_assignment_leases.products (
 product text PRIMARY KEY REFERENCES public.products(product),
 repository text NOT NULL UNIQUE CHECK(repository ~ '^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$'),
 repository_id bigint NOT NULL UNIQUE CHECK(repository_id>0),
 account_owner text NOT NULL CHECK(account_owner=split_part(repository,'/',1)),
 development_ref text NOT NULL CHECK(scope_assignment_leases._ref(development_ref)),
 testing_ref text NOT NULL CHECK(scope_assignment_leases._ref(testing_ref)),
 staging_ref text NOT NULL CHECK(scope_assignment_leases._ref(staging_ref)),
 production_ref text NOT NULL CHECK(scope_assignment_leases._ref(production_ref)),
 release_ref text NOT NULL CHECK(release_ref='main'),
 expires_at timestamptz NOT NULL,active boolean NOT NULL DEFAULT false,
 CHECK(development_ref<>testing_ref AND development_ref<>staging_ref AND development_ref<>production_ref
 AND development_ref<>release_ref AND testing_ref<>staging_ref AND testing_ref<>production_ref
 AND testing_ref<>release_ref AND staging_ref<>production_ref AND staging_ref<>release_ref AND production_ref<>release_ref)
);
CREATE TABLE scope_assignment_leases.grants (
 principal name NOT NULL REFERENCES scope_assignment_leases.principals(principal),role_oid oid NOT NULL,
 product text NOT NULL REFERENCES scope_assignment_leases.products(product),
 capability text NOT NULL CHECK(capability IN ('claim','read')),
 expires_at timestamptz NOT NULL,active boolean NOT NULL DEFAULT false,
 PRIMARY KEY(principal,product,capability)
);
CREATE TABLE scope_assignment_leases.assignments (
 assignment_id uuid PRIMARY KEY,task_id text NOT NULL UNIQUE CHECK(length(btrim(task_id)) BETWEEN 1 AND 256),
 product text NOT NULL REFERENCES scope_assignment_leases.products(product),
 principal name NOT NULL REFERENCES scope_assignment_leases.principals(principal),principal_oid oid NOT NULL,
 repository text NOT NULL,repository_id bigint NOT NULL CHECK(repository_id>0),
 source_level text NOT NULL,target_level text NOT NULL,
 source_ref text NOT NULL CHECK(scope_assignment_leases._ref(source_ref)),
 target_ref text NOT NULL CHECK(scope_assignment_leases._ref(target_ref)),
 head_sha text NOT NULL CHECK(head_sha ~ '^[0-9a-f]{40}$' AND head_sha<>repeat('0',40)),
 base_sha text NOT NULL CHECK(base_sha ~ '^[0-9a-f]{40}$' AND base_sha<>repeat('0',40)),
 expires_at timestamptz NOT NULL,active boolean NOT NULL DEFAULT false,
 CHECK((source_level,target_level) IN (('subsection','section'),('section','development'),
 ('development','testing'),('testing','staging'),('staging','production'),('production','main'))),
 CHECK(source_ref<>target_ref)
);
-- Expiry alone never frees a scope: the operator must explicitly deactivate the
-- previous assignment before assigning the same source scope to another task.
CREATE UNIQUE INDEX one_active_scope_assignment
 ON scope_assignment_leases.assignments(product,source_ref) WHERE active;
CREATE TABLE scope_assignment_leases.leases (
 lease_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 assignment_id uuid NOT NULL UNIQUE REFERENCES scope_assignment_leases.assignments(assignment_id),
 product text NOT NULL REFERENCES scope_assignment_leases.products(product),
 source_ref text NOT NULL CHECK(scope_assignment_leases._ref(source_ref)),
 principal name NOT NULL,principal_oid oid NOT NULL,
 request_id uuid NOT NULL UNIQUE,epoch bigint GENERATED ALWAYS AS IDENTITY CHECK(epoch>0),
 binding_snapshot jsonb NOT NULL,assignment_snapshot jsonb NOT NULL,
 state text NOT NULL DEFAULT 'ACTIVE' CHECK(state IN ('ACTIVE','REVOKED')),
 started_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,
 CHECK(expires_at>started_at AND expires_at<=started_at+interval '5 minutes')
);
-- Retain the scope fence even after expiry or assignment deactivation. Only an
-- explicit operator revocation of the old row permits a new assignment's claim.
CREATE UNIQUE INDEX one_active_scope_lease
 ON scope_assignment_leases.leases(product,source_ref) WHERE state='ACTIVE';
CREATE TABLE scope_assignment_leases.audit (
 audit_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 assignment_id uuid NOT NULL REFERENCES scope_assignment_leases.assignments(assignment_id),
 lease_id uuid NOT NULL REFERENCES scope_assignment_leases.leases(lease_id),
 principal name NOT NULL,principal_oid oid NOT NULL,authentication text NOT NULL,
 request_id uuid NOT NULL UNIQUE,receipt jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON ALL TABLES IN SCHEMA scope_assignment_leases FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA scope_assignment_leases FROM PUBLIC;

CREATE FUNCTION scope_assignment_leases._restricted(actor name,actor_oid oid) RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
 SELECT EXISTS(SELECT 1 FROM pg_roles r JOIN scope_assignment_leases.principals p
 ON p.principal=r.rolname AND p.role_oid=r.oid WHERE r.rolname=actor AND r.oid=actor_oid
 AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolcreaterole AND NOT r.rolcreatedb
 AND NOT r.rolreplication AND NOT r.rolbypassrls)
 AND NOT EXISTS(SELECT 1 FROM pg_roles reachable WHERE pg_has_role(actor,reachable.oid,'MEMBER') AND
 (reachable.rolsuper OR reachable.rolcreaterole OR reachable.rolcreatedb OR reachable.rolreplication OR reachable.rolbypassrls
 OR reachable.rolname IN ('pg_read_server_files','pg_write_server_files','pg_execute_server_program')
 OR EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname IN
 ('scope_assignment_leases','scoped_registration','assignment_leases','publisher_authority','atomic_inspection','certifier_authority','scope_certifier','scope_certifier_pending','public')
 AND (reachable.oid=n.nspowner OR has_schema_privilege(reachable.oid,n.oid,'CREATE')))
 OR EXISTS(SELECT 1 FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace
 WHERE t.relkind IN ('r','p') AND (n.nspname IN
 ('scope_assignment_leases','scoped_registration','assignment_leases','publisher_authority','atomic_inspection','certifier_authority','scope_certifier','scope_certifier_pending')
 OR n.nspname='public' AND t.relname IN ('products','workstations','sections','atomic_tasks','scope_certifications','promotion_evidence','events'))
 AND has_table_privilege(reachable.oid,t.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))))
$$;
CREATE FUNCTION scope_assignment_leases._actor() RETURNS oid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
DECLARE actor_oid oid;
BEGIN
 -- SECURITY DEFINER changes current_user; role=none pins the invoker to its
 -- authenticated session role. SET ROLE/session authorization cannot transfer
 -- SCRAM system_user provenance. No caller actor string is accepted.
 IF system_user IS DISTINCT FROM 'scram-sha-256:'||session_user::text
 OR current_setting('role')<>'none'
 OR current_setting('transaction_isolation')<>'read committed'
 OR NOT EXISTS(SELECT 1 FROM pg_stat_ssl WHERE pid=pg_backend_pid() AND ssl)
 THEN RAISE EXCEPTION 'SCOPE_AUTHENTICATION_REQUIRED'; END IF;
 SELECT r.oid INTO actor_oid FROM pg_roles r JOIN scope_assignment_leases.principals p
 ON p.principal=r.rolname AND p.role_oid=r.oid
 WHERE r.rolname=session_user AND p.active AND p.expires_at>clock_timestamp();
 IF actor_oid IS NULL OR NOT scope_assignment_leases._restricted(session_user,actor_oid)
 THEN RAISE EXCEPTION 'SCOPE_LEASE_DENIED'; END IF;
 RETURN actor_oid;
END $$;
CREATE FUNCTION scope_assignment_leases._binding(a scope_assignment_leases.assignments) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
 SELECT jsonb_build_object('repository',a.repository,'repository_id',a.repository_id,'product',a.product,
 'source_level',a.source_level,'target_level',a.target_level,'source_ref',a.source_ref,'target_ref',a.target_ref,
 'head_sha',a.head_sha,'base_sha',a.base_sha,'principal',a.principal)
$$;
CREATE FUNCTION scope_assignment_leases._registered(a scope_assignment_leases.assignments) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
DECLARE p scope_assignment_leases.products;valid_edge boolean:=false;
BEGIN
 SELECT * INTO p FROM scope_assignment_leases.products WHERE product=a.product;
 IF NOT FOUND OR a.repository IS DISTINCT FROM p.repository OR a.repository_id IS DISTINCT FROM p.repository_id
 OR NOT EXISTS(SELECT 1 FROM public.products r JOIN scoped_registration.products s USING(product)
 WHERE r.product=p.product AND r.repository=p.repository AND r.test_branch=p.testing_ref
 AND r.promotion_chain=jsonb_build_array(p.development_ref,p.testing_ref,p.staging_ref,p.production_ref)
 AND NOT r.production_go AND NOT r.live_capabilities_enabled AND NOT r.external_effects_enabled
 AND s.payload=jsonb_build_object('product',r.product,'repository',r.repository,'test_branch',r.test_branch,'promotion_chain',r.promotion_chain))
 THEN RAISE EXCEPTION 'SCOPE_REGISTRY_DRIFT'; END IF;
 CASE a.source_level
 WHEN 'subsection' THEN
  valid_edge:=a.target_level='section' AND EXISTS(SELECT 1 FROM public.workstations w
  JOIN scoped_registration.workstations s ON s.product=w.product AND s.workstation_id=w.workstation_id
  JOIN scoped_registration.lanes l ON l.product=w.product AND l.kind='workstation' AND l.identity=w.workstation_id
  JOIN public.sections sec ON sec.product=w.product AND sec.section_key=w.section AND sec.branch=w.parent_branch
  WHERE w.product=a.product AND w.branch=a.source_ref AND w.parent_branch=a.target_ref
  AND s.branch=w.branch AND s.worktree=w.worktree AND l.branch=w.branch AND l.worktree=w.worktree
  AND w.branch='subsection/'||w.section||'--'||w.subsection AND w.parent_branch='section/'||w.section
  AND s.payload=jsonb_build_object('product',w.product,'workstation_id',w.workstation_id,'section',w.section,
   'subsection',w.subsection,'branch',w.branch,'parent_branch',w.parent_branch,'worktree',w.worktree,'order_index',w.order_index));
 WHEN 'section' THEN
  valid_edge:=a.target_level='development' AND a.target_ref=p.development_ref
  AND EXISTS(SELECT 1 FROM public.sections s WHERE s.product=a.product AND s.branch=a.source_ref
   AND s.branch='section/'||s.section_key);
 WHEN 'development' THEN valid_edge:=a.target_level='testing' AND a.source_ref=p.development_ref AND a.target_ref=p.testing_ref;
 WHEN 'testing' THEN valid_edge:=a.target_level='staging' AND a.source_ref=p.testing_ref AND a.target_ref=p.staging_ref;
 WHEN 'staging' THEN valid_edge:=a.target_level='production' AND a.source_ref=p.staging_ref AND a.target_ref=p.production_ref;
 WHEN 'production' THEN valid_edge:=a.target_level='main' AND a.source_ref=p.production_ref AND a.target_ref=p.release_ref;
 ELSE valid_edge:=false;
 END CASE;
 IF NOT coalesce(valid_edge,false) THEN RAISE EXCEPTION 'SCOPE_UNREGISTERED_EDGE'; END IF;
END $$;
CREATE FUNCTION scope_assignment_leases._permission(actor_oid oid,product_name text,kind text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM scope_assignment_leases.grants g
 JOIN scope_assignment_leases.principals a ON a.principal=g.principal AND a.role_oid=g.role_oid
 JOIN scope_assignment_leases.products p ON p.product=g.product AND p.account_owner=a.account_owner
 WHERE g.principal=session_user AND g.role_oid=actor_oid AND g.product=product_name AND g.capability=kind
 AND g.active AND a.active AND p.active AND g.expires_at>clock_timestamp()
 AND a.expires_at>clock_timestamp() AND p.expires_at>clock_timestamp())
 THEN RAISE EXCEPTION 'SCOPE_PRODUCT_GRANT_REQUIRED'; END IF;
END $$;
CREATE FUNCTION scope_assignment_leases._receipt(l scope_assignment_leases.leases,current_state text,current_expiry timestamptz) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
 SELECT jsonb_build_object('authority','ONLINE_DATABASE_RECEIPT','binding_id',l.assignment_id,
 'lease_id',l.lease_id,'epoch',l.epoch,'principal',l.principal,'state',current_state,
 'started_at',l.started_at,'expires_at',current_expiry,'binding',l.binding_snapshot)
$$;
CREATE FUNCTION scope_assignment_leases.claim(assignment_uuid uuid,request_uuid uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
DECLARE actor_oid oid;a scope_assignment_leases.assignments;l scope_assignment_leases.leases;
 p scope_assignment_leases.products;actor scope_assignment_leases.principals;g scope_assignment_leases.grants;
 stamp timestamptz;expiry timestamptz;receipt jsonb;
BEGIN
 actor_oid:=scope_assignment_leases._actor();
 IF assignment_uuid IS NULL OR request_uuid IS NULL THEN RAISE EXCEPTION 'SCOPE_REQUEST_REQUIRED'; END IF;
 -- Serialize both competing assignment claims and nonce reuse across assignments.
 PERFORM pg_advisory_xact_lock(hashtextextended('scope-request:'||request_uuid::text,1212));
 SELECT * INTO a FROM scope_assignment_leases.assignments WHERE assignment_id=assignment_uuid FOR UPDATE;
 IF NOT FOUND OR NOT a.active OR a.expires_at<=clock_timestamp()
 THEN RAISE EXCEPTION 'SCOPE_ASSIGNMENT_UNAVAILABLE'; END IF;
 IF a.principal<>session_user OR a.principal_oid<>actor_oid THEN RAISE EXCEPTION 'SCOPE_ASSIGNMENT_OWNER_MISMATCH'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('scope:'||a.product||':'||a.source_ref,1212));
 PERFORM scope_assignment_leases._permission(actor_oid,a.product,'claim');
 SELECT * INTO actor FROM scope_assignment_leases.principals WHERE principal=session_user FOR SHARE;
 SELECT * INTO g FROM scope_assignment_leases.grants WHERE principal=session_user AND product=a.product AND capability='claim' FOR SHARE;
 SELECT * INTO p FROM scope_assignment_leases.products WHERE product=a.product FOR SHARE;
 -- Hold registry rows for the claim, but inspection below remains read-only.
 PERFORM 1 FROM public.products WHERE product=a.product FOR SHARE;
 PERFORM 1 FROM scoped_registration.products WHERE product=a.product FOR SHARE;
 PERFORM 1 FROM public.sections WHERE product=a.product FOR SHARE;
 PERFORM 1 FROM public.workstations WHERE product=a.product FOR SHARE;
 PERFORM 1 FROM scoped_registration.workstations WHERE product=a.product FOR SHARE;
 PERFORM 1 FROM scoped_registration.lanes WHERE product=a.product FOR SHARE;
 PERFORM scope_assignment_leases._permission(actor_oid,a.product,'claim');
 PERFORM scope_assignment_leases._registered(a);
 IF scope_assignment_leases._actor() IS DISTINCT FROM actor_oid THEN RAISE EXCEPTION 'SCOPE_LEASE_DENIED'; END IF;
 IF EXISTS(SELECT 1 FROM scope_assignment_leases.leases WHERE assignment_id=assignment_uuid OR request_id=request_uuid)
 THEN RAISE EXCEPTION 'SCOPE_REQUEST_OR_ASSIGNMENT_CONSUMED'; END IF;
 IF EXISTS(SELECT 1 FROM scope_assignment_leases.leases WHERE product=a.product AND source_ref=a.source_ref AND state='ACTIVE')
 THEN RAISE EXCEPTION 'SCOPE_SCOPE_ALREADY_LEASED'; END IF;
 stamp:=clock_timestamp();expiry:=least(stamp+interval '5 minutes',a.expires_at,p.expires_at,actor.expires_at,g.expires_at);
 IF expiry<=stamp THEN RAISE EXCEPTION 'SCOPE_ASSIGNMENT_UNAVAILABLE'; END IF;
 INSERT INTO scope_assignment_leases.leases(assignment_id,product,source_ref,principal,principal_oid,request_id,
 binding_snapshot,assignment_snapshot,started_at,expires_at)
 VALUES(a.assignment_id,a.product,a.source_ref,session_user,actor_oid,request_uuid,scope_assignment_leases._binding(a),
 to_jsonb(a)-ARRAY['active','expires_at'],stamp,expiry) RETURNING * INTO l;
 receipt:=scope_assignment_leases._receipt(l,'ACTIVE',expiry);
 INSERT INTO scope_assignment_leases.audit(assignment_id,lease_id,principal,principal_oid,authentication,request_id,receipt)
 VALUES(a.assignment_id,l.lease_id,session_user,actor_oid,system_user,request_uuid,receipt);
 RETURN receipt;
END $$;
CREATE FUNCTION scope_assignment_leases.inspect_binding(assignment_uuid uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
DECLARE actor_oid oid;a scope_assignment_leases.assignments;l scope_assignment_leases.leases;
 p scope_assignment_leases.products;owner scope_assignment_leases.principals;g scope_assignment_leases.grants;
 current_state text:='ACTIVE';expiry timestamptz;
BEGIN
 actor_oid:=scope_assignment_leases._actor();
 SELECT * INTO a FROM scope_assignment_leases.assignments WHERE assignment_id=assignment_uuid;
 IF NOT FOUND THEN RAISE EXCEPTION 'SCOPE_ASSIGNMENT_UNAVAILABLE'; END IF;
 PERFORM scope_assignment_leases._permission(actor_oid,a.product,'read');
 -- Independent verifier only; builder cannot attest its own lease as a reader.
 IF a.principal=session_user OR a.principal_oid=actor_oid THEN RAISE EXCEPTION 'SCOPE_INDEPENDENT_VERIFIER_REQUIRED'; END IF;
 SELECT * INTO l FROM scope_assignment_leases.leases WHERE assignment_id=assignment_uuid;
 IF NOT FOUND THEN RAISE EXCEPTION 'SCOPE_LEASE_UNAVAILABLE'; END IF;
 IF l.binding_snapshot IS DISTINCT FROM scope_assignment_leases._binding(a)
 OR l.assignment_snapshot IS DISTINCT FROM to_jsonb(a)-ARRAY['active','expires_at']
 OR l.principal<>a.principal OR l.principal_oid<>a.principal_oid OR l.product<>a.product OR l.source_ref<>a.source_ref
 THEN RAISE EXCEPTION 'SCOPE_BINDING_CHANGED'; END IF;
 PERFORM scope_assignment_leases._registered(a);
 SELECT * INTO p FROM scope_assignment_leases.products WHERE product=a.product;
 SELECT * INTO owner FROM scope_assignment_leases.principals WHERE principal=a.principal;
 SELECT * INTO g FROM scope_assignment_leases.grants WHERE principal=a.principal AND product=a.product AND capability='claim';
 IF NOT a.active OR l.state<>'ACTIVE' OR NOT p.active OR owner.principal IS NULL OR NOT owner.active
 OR owner.role_oid IS DISTINCT FROM a.principal_oid OR owner.account_owner IS DISTINCT FROM p.account_owner
 OR g.principal IS NULL OR NOT g.active OR g.role_oid IS DISTINCT FROM a.principal_oid
 OR NOT scope_assignment_leases._restricted(a.principal,a.principal_oid)
 THEN current_state:='REVOKED'; END IF;
 expiry:=least(l.expires_at,a.expires_at,p.expires_at,owner.expires_at,g.expires_at);
 IF current_state='ACTIVE' AND expiry<=clock_timestamp() THEN current_state:='EXPIRED'; END IF;
 RETURN scope_assignment_leases._receipt(l,current_state,expiry);
END $$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA scope_assignment_leases FROM PUBLIC;
COMMIT;
