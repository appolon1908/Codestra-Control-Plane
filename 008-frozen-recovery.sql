-- Source-only forward migration. Requires005 and007. Installs no identities,
-- policies, permissions, credentials or grants. Never execute against live DB as a test.
BEGIN;
SET LOCAL timezone='UTC';
CREATE SCHEMA frozen_recovery;
REVOKE ALL ON SCHEMA frozen_recovery FROM PUBLIC;
CREATE TABLE frozen_recovery.policies (
 product text PRIMARY KEY REFERENCES scoped_registration.products(product),
 grant_seconds integer NOT NULL CHECK(grant_seconds>0),
 proof_seconds integer NOT NULL CHECK(proof_seconds>0 AND proof_seconds<=grant_seconds),
 active boolean NOT NULL DEFAULT false
);
CREATE TABLE frozen_recovery.permissions (
 principal name NOT NULL REFERENCES scoped_registration.principals(principal),
 product text NOT NULL REFERENCES scoped_registration.products(product),
 capability text NOT NULL CHECK(capability IN ('authorize','review','attest','execute')),
 active boolean NOT NULL DEFAULT false, PRIMARY KEY(principal,product,capability)
);
CREATE TABLE frozen_recovery.incidents (
 workstation_id text PRIMARY KEY REFERENCES public.workstations(workstation_id),
 incident_id uuid NOT NULL DEFAULT gen_random_uuid(),revision bigint NOT NULL CHECK(revision>0),
 snapshot jsonb NOT NULL,active boolean NOT NULL
);
CREATE TABLE frozen_recovery.grants (
 grant_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 version integer NOT NULL DEFAULT 2 CHECK(version=2),
 action text NOT NULL DEFAULT 'RELEASE_STALE_WORKTREE_TO_FREE'
 CHECK(action='RELEASE_STALE_WORKTREE_TO_FREE'),
 workstation_id text NOT NULL REFERENCES public.workstations(workstation_id),
 product text NOT NULL REFERENCES frozen_recovery.policies(product),
 incident_id uuid NOT NULL,revision bigint NOT NULL,snapshot jsonb NOT NULL,
 checkout jsonb NOT NULL,policy_snapshot jsonb NOT NULL,
 operator name NOT NULL,operator_oid oid NOT NULL,
 executor name NOT NULL,executor_oid oid NOT NULL,
 reviewer name NOT NULL,reviewer_oid oid NOT NULL,
 verifier name NOT NULL,verifier_oid oid NOT NULL,
 request_digest text NOT NULL CHECK(request_digest ~ '^[0-9a-f]{64}$'),
 request_id text NOT NULL CHECK(request_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
 issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),expires_at timestamptz NOT NULL,
 consumed boolean NOT NULL DEFAULT false,revoked boolean NOT NULL DEFAULT false,
 UNIQUE(operator_oid,request_id)
);
CREATE TABLE frozen_recovery.reviews (
 grant_id uuid PRIMARY KEY REFERENCES frozen_recovery.grants(grant_id),
 reviewer name NOT NULL,reviewer_oid oid NOT NULL,request_digest text NOT NULL,
 reviewed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE frozen_recovery.proofs (
 proof_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 grant_id uuid NOT NULL REFERENCES frozen_recovery.grants(grant_id),
 verifier name NOT NULL,verifier_oid oid NOT NULL,request_digest text NOT NULL,
 observations jsonb NOT NULL,expires_at timestamptz NOT NULL,
 consumed boolean NOT NULL DEFAULT false
);
CREATE TABLE frozen_recovery.audit (
 audit_id bigserial PRIMARY KEY,grant_id uuid NOT NULL REFERENCES frozen_recovery.grants(grant_id),
 actor name NOT NULL,actor_oid oid NOT NULL,action text NOT NULL CHECK(action IN ('RECOVER','REVOKE')),
 request_id text NOT NULL CHECK(request_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
 receipt jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(actor_oid,action,request_id)
);
REVOKE ALL ON ALL TABLES IN SCHEMA frozen_recovery FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA frozen_recovery FROM PUBLIC;

CREATE FUNCTION frozen_recovery._track() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
BEGIN
 IF TG_OP='UPDATE' AND to_jsonb(NEW)=to_jsonb(OLD) THEN RETURN NEW; END IF;
 IF NEW.lease_state='FROZEN' THEN
  INSERT INTO frozen_recovery.incidents(workstation_id,revision,snapshot,active)
  VALUES(NEW.workstation_id,1,to_jsonb(NEW),true)
  ON CONFLICT(workstation_id) DO UPDATE
  SET incident_id=gen_random_uuid(),revision=frozen_recovery.incidents.revision+1,
      snapshot=excluded.snapshot,active=true;
 ELSIF TG_OP='UPDATE' AND OLD.lease_state='FROZEN' THEN
  UPDATE frozen_recovery.incidents SET revision=revision+1,active=false
  WHERE workstation_id=NEW.workstation_id;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER scoped_frozen_incident AFTER INSERT OR UPDATE ON public.workstations
FOR EACH ROW EXECUTE FUNCTION frozen_recovery._track();
INSERT INTO frozen_recovery.incidents(workstation_id,revision,snapshot,active)
SELECT workstation_id,1,to_jsonb(w),true FROM public.workstations w WHERE lease_state='FROZEN';

CREATE FUNCTION frozen_recovery._principal(who name,expected oid,product_name text,kind text)
RETURNS oid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
DECLARE actual oid;
BEGIN
 SELECT p.role_oid INTO actual FROM scoped_registration.principals p
 JOIN pg_roles r ON r.rolname=p.principal AND r.oid=p.role_oid
 JOIN frozen_recovery.permissions g ON g.principal=p.principal
 WHERE p.principal=who AND (expected IS NULL OR p.role_oid=expected)
 AND p.active AND g.product=product_name AND g.capability=kind AND g.active
 AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolcreaterole AND NOT r.rolcreatedb
 AND NOT r.rolreplication AND NOT r.rolbypassrls FOR SHARE OF p,g;
 IF actual IS NULL OR NOT assignment_leases._restricted(who,actual)
 OR EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname='frozen_recovery'
           AND (pg_has_role(who,n.nspowner,'MEMBER') OR has_schema_privilege(who,n.oid,'CREATE')))
 OR EXISTS(SELECT 1 FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace
           WHERE t.relkind IN ('r','p') AND
           (n.nspname='frozen_recovery' OR n.nspname='public' AND
            t.relname IN ('events','scope_certifications','promotion_evidence'))
           AND has_table_privilege(who,t.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))
 THEN RAISE EXCEPTION 'RECOVERY_DENIED'; END IF;
 RETURN actual;
END $$;
CREATE FUNCTION frozen_recovery._actor(product_name text,kind text) RETURNS oid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
BEGIN
 IF system_user IS DISTINCT FROM 'scram-sha-256:'||session_user::text
 OR current_setting('role')<>'none'
 OR NOT EXISTS(SELECT 1 FROM pg_stat_ssl WHERE pid=pg_backend_pid() AND ssl)
 THEN RAISE EXCEPTION 'RECOVERY_DENIED'; END IF;
 RETURN frozen_recovery._principal(session_user,NULL,product_name,kind);
END $$;
CREATE FUNCTION frozen_recovery._request(request text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
BEGIN
 IF request IS NULL OR request !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 THEN RAISE EXCEPTION 'INVALID_RECOVERY_REQUEST'; END IF;
END $$;
CREATE FUNCTION frozen_recovery._lock(workstation text,worktree text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
DECLARE key bigint;
BEGIN
 FOR key IN SELECT DISTINCT value FROM unnest(ARRAY[
 hashtextextended('workstation:'||workstation,7281),
 hashtextextended('worktree:'||worktree,7281)]) value ORDER BY value LOOP
  PERFORM pg_advisory_xact_lock(key);
 END LOOP;
END $$;
CREATE FUNCTION frozen_recovery._eligible(w public.workstations) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
BEGIN
 IF w.lease_state<>'FROZEN' OR w.status<>'BLOCKED'
 OR w.blocker IS DISTINCT FROM 'STALE_DIRTY_WORKTREE'
 OR coalesce(length(w.agent),0)=0 OR coalesce(length(w.current_atomic_task),0)=0
 OR w.completed_at IS NOT NULL OR w.certified_at IS NOT NULL
 THEN RAISE EXCEPTION 'FROZEN_RECOVERY_UNAVAILABLE'; END IF;
END $$;
CREATE FUNCTION frozen_recovery._digest(g frozen_recovery.grants) RETURNS text
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
 SELECT encode(sha256(convert_to((to_jsonb(g)-ARRAY['request_digest','consumed','revoked'])::text,'UTF8')),'hex')
$$;
CREATE FUNCTION frozen_recovery._registered(w public.workstations) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
BEGIN
 PERFORM 1 FROM scoped_registration.workstations s
 JOIN scoped_registration.lanes l ON l.worktree=s.worktree AND l.product=s.product
 JOIN public.sections p ON p.product=s.product AND p.section_key=w.section
 WHERE s.workstation_id=w.workstation_id AND s.product=w.product
 AND s.branch=w.branch AND s.worktree=w.worktree
 AND s.payload->>'section'=w.section AND s.payload->>'subsection'=w.subsection
 AND s.payload->>'parent_branch'=w.parent_branch
 AND s.payload->'order_index'=to_jsonb(w.order_index)
 AND l.kind='workstation' AND l.identity=w.workstation_id AND l.branch=w.branch
 AND p.branch=w.parent_branch FOR SHARE OF s,l,p;
 IF NOT FOUND THEN RAISE EXCEPTION 'RECOVERY_REGISTRY_DRIFT'; END IF;
END $$;
CREATE FUNCTION frozen_recovery._current(grant_uuid uuid) RETURNS frozen_recovery.grants
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
DECLARE initial frozen_recovery.grants;g frozen_recovery.grants;
 w public.workstations;i frozen_recovery.incidents;p frozen_recovery.policies;
BEGIN
 SELECT * INTO initial FROM frozen_recovery.grants WHERE grant_id=grant_uuid;
 IF NOT FOUND THEN RAISE EXCEPTION 'RECOVERY_GRANT_UNAVAILABLE'; END IF;
 PERFORM frozen_recovery._lock(initial.workstation_id,initial.snapshot->>'worktree');
 SELECT * INTO w FROM public.workstations WHERE workstation_id=initial.workstation_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'FROZEN_RECOVERY_UNAVAILABLE'; END IF;
 SELECT * INTO i FROM frozen_recovery.incidents WHERE workstation_id=w.workstation_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'RECOVERY_INCIDENT_UNAVAILABLE'; END IF;
 SELECT * INTO g FROM frozen_recovery.grants WHERE grant_id=grant_uuid FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'RECOVERY_GRANT_UNAVAILABLE'; END IF;
 PERFORM frozen_recovery._eligible(w);
 IF g.consumed OR g.revoked OR g.expires_at<=clock_timestamp()
 OR NOT i.active OR i.incident_id<>g.incident_id OR i.revision<>g.revision
 OR i.snapshot<>g.snapshot OR to_jsonb(w)<>g.snapshot OR w.product<>g.product
 OR g.request_digest<>frozen_recovery._digest(g)
 THEN RAISE EXCEPTION 'RECOVERY_GRANT_UNAVAILABLE'; END IF;
 PERFORM frozen_recovery._registered(w);
 SELECT * INTO p FROM frozen_recovery.policies WHERE product=g.product FOR SHARE;
 IF NOT FOUND OR NOT p.active OR to_jsonb(p)<>g.policy_snapshot
 THEN RAISE EXCEPTION 'RECOVERY_POLICY_UNAVAILABLE'; END IF;
 PERFORM 1 FROM public.products x JOIN scoped_registration.products s USING(product)
 WHERE x.product=g.product AND x.repository=g.checkout->>'repository'
 AND s.payload->>'repository'=x.repository AND s.payload->>'test_branch'=x.test_branch
 AND s.payload->'promotion_chain'=x.promotion_chain
 AND NOT x.production_go AND NOT x.live_capabilities_enabled AND NOT x.external_effects_enabled
 FOR SHARE OF x,s;
 IF NOT FOUND THEN RAISE EXCEPTION 'RECOVERY_REGISTRY_DRIFT'; END IF;
 PERFORM frozen_recovery._principal(g.operator,g.operator_oid,g.product,'authorize');
 PERFORM frozen_recovery._principal(g.executor,g.executor_oid,g.product,'execute');
 PERFORM frozen_recovery._principal(g.reviewer,g.reviewer_oid,g.product,'review');
 PERFORM frozen_recovery._principal(g.verifier,g.verifier_oid,g.product,'attest');
 RETURN g;
END $$;
CREATE FUNCTION frozen_recovery.authorize(workstation text,checkout jsonb,
 executor name,reviewer name,verifier name,request text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
#variable_conflict use_variable
DECLARE w public.workstations;i frozen_recovery.incidents;p frozen_recovery.policies;
 g frozen_recovery.grants;actor_oid oid;executor_role oid;reviewer_role oid;verifier_role oid;field text;
BEGIN
 PERFORM frozen_recovery._request(request);
 SELECT * INTO w FROM public.workstations WHERE workstation_id=workstation;
 IF NOT FOUND THEN RAISE EXCEPTION 'FROZEN_RECOVERY_UNAVAILABLE'; END IF;
 PERFORM frozen_recovery._lock(w.workstation_id,w.worktree);
 SELECT * INTO w FROM public.workstations WHERE workstation_id=workstation FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'FROZEN_RECOVERY_UNAVAILABLE'; END IF;
 PERFORM frozen_recovery._eligible(w);
 PERFORM frozen_recovery._registered(w);
 SELECT * INTO i FROM frozen_recovery.incidents WHERE workstation_id=workstation FOR UPDATE;
 IF NOT FOUND OR NOT i.active OR i.snapshot<>to_jsonb(w)
 THEN RAISE EXCEPTION 'FROZEN_RECOVERY_UNAVAILABLE'; END IF;
 actor_oid:=frozen_recovery._actor(w.product,'authorize');
 executor_role:=frozen_recovery._principal(executor,NULL,w.product,'execute');
 reviewer_role:=frozen_recovery._principal(reviewer,NULL,w.product,'review');
 verifier_role:=frozen_recovery._principal(verifier,NULL,w.product,'attest');
 IF cardinality(ARRAY(SELECT DISTINCT v FROM unnest(ARRAY[
 actor_oid,executor_role,reviewer_role,verifier_role]) v))<>4
 OR w.agent=ANY(ARRAY[session_user::text,executor::text,reviewer::text,verifier::text])
 THEN RAISE EXCEPTION 'INDEPENDENT_RECOVERY_ROLES_REQUIRED'; END IF;
 SELECT * INTO p FROM frozen_recovery.policies WHERE product=w.product FOR SHARE;
 IF NOT FOUND OR NOT p.active THEN RAISE EXCEPTION 'RECOVERY_POLICY_UNAVAILABLE'; END IF;
 IF jsonb_typeof(checkout) IS DISTINCT FROM 'object'
 OR NOT checkout ?& ARRAY['repository','repository_id','source_ref','target_ref','head_sha','base_sha','worktree','host','root_path','git_common_dir','worktree_uid']
 OR checkout-ARRAY['repository','repository_id','source_ref','target_ref','head_sha','base_sha','worktree','host','root_path','git_common_dir','worktree_uid']<>'{}'::jsonb
 OR EXISTS(SELECT 1 FROM jsonb_each(checkout) x WHERE x.value='null'::jsonb)
 OR EXISTS(SELECT 1 FROM jsonb_each(checkout) x WHERE x.key NOT IN ('repository_id','worktree_uid') AND jsonb_typeof(x.value)<>'string')
 OR jsonb_typeof(checkout->'repository_id')<>'number' OR (checkout->>'repository_id') !~ '^[1-9][0-9]*$'
 OR jsonb_typeof(checkout->'worktree_uid')<>'number' OR (checkout->>'worktree_uid') !~ '^[0-9]+$'
 OR checkout->>'source_ref' IS DISTINCT FROM w.branch
 OR checkout->>'target_ref' IS DISTINCT FROM w.parent_branch
 OR checkout->>'worktree' IS DISTINCT FROM w.worktree
 OR w.branch IS DISTINCT FROM 'subsection/'||w.section||'--'||w.subsection
 OR w.parent_branch IS DISTINCT FROM 'section/'||w.section
 OR length(checkout->>'host') NOT BETWEEN 1 AND 256
 THEN RAISE EXCEPTION 'RECOVERY_CHECKOUT_MISMATCH'; END IF;
 FOREACH field IN ARRAY ARRAY['head_sha','base_sha'] LOOP
  IF checkout->>field !~ '^[0-9a-f]{40}$' OR checkout->>field=repeat('0',40)
  THEN RAISE EXCEPTION 'RECOVERY_CHECKOUT_MISMATCH'; END IF;
 END LOOP;
 FOREACH field IN ARRAY ARRAY['worktree','root_path','git_common_dir'] LOOP
  IF checkout->>field !~ '^/([A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+$'
  OR checkout->>field ~ '(^|/)\.\.?(/|$)'
  THEN RAISE EXCEPTION 'RECOVERY_CHECKOUT_MISMATCH'; END IF;
 END LOOP;
 IF left(checkout->>'worktree',length(checkout->>'root_path')+1)<>checkout->>'root_path'||'/'
 THEN RAISE EXCEPTION 'RECOVERY_CHECKOUT_MISMATCH'; END IF;
 PERFORM 1 FROM public.products x JOIN scoped_registration.products s USING(product)
 WHERE x.product=w.product AND x.repository=checkout->>'repository'
 AND s.payload->>'repository'=x.repository AND s.payload->>'test_branch'=x.test_branch
 AND s.payload->'promotion_chain'=x.promotion_chain
 AND NOT x.production_go AND NOT x.live_capabilities_enabled AND NOT x.external_effects_enabled
 FOR SHARE OF x,s;
 IF NOT FOUND THEN RAISE EXCEPTION 'RECOVERY_REGISTRY_DRIFT'; END IF;
 INSERT INTO frozen_recovery.grants(workstation_id,product,incident_id,revision,snapshot,
 checkout,policy_snapshot,operator,operator_oid,executor,executor_oid,reviewer,reviewer_oid,
 verifier,verifier_oid,request_digest,request_id,expires_at)
 VALUES(w.workstation_id,w.product,i.incident_id,i.revision,to_jsonb(w),checkout,to_jsonb(p),
 session_user,actor_oid,executor,executor_role,reviewer,reviewer_role,verifier,verifier_role,
 repeat('0',64),request,clock_timestamp()+make_interval(secs=>p.grant_seconds)) RETURNING * INTO g;
 UPDATE frozen_recovery.grants SET request_digest=frozen_recovery._digest(g)
 WHERE grant_id=g.grant_id RETURNING * INTO g;
 RETURN jsonb_build_object('grant_id',g.grant_id,'request_digest',g.request_digest,'expires_at',g.expires_at,'certified',false);
END $$;
CREATE FUNCTION frozen_recovery.describe(grant_uuid uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
DECLARE g frozen_recovery.grants;kind text;actor_oid oid;
BEGIN
 g:=frozen_recovery._current(grant_uuid);
 kind:=CASE session_user WHEN g.operator THEN 'authorize' WHEN g.reviewer THEN 'review'
       WHEN g.verifier THEN 'attest' WHEN g.executor THEN 'execute' ELSE NULL END;
 IF kind IS NULL THEN RAISE EXCEPTION 'RECOVERY_DENIED'; END IF;
 actor_oid:=frozen_recovery._actor(g.product,kind);
 RETURN jsonb_build_object('schema','codestra.frozen-recovery.v2','action','RELEASE_STALE_WORKTREE_TO_FREE',
 'grant_id',g.grant_id,'request_digest',g.request_digest,'binding',g.checkout,'dependencies','[]'::jsonb,
 'request',to_jsonb(g)-ARRAY['consumed','revoked'],'certified',false);
END $$;
CREATE FUNCTION frozen_recovery.review(grant_uuid uuid,digest text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
DECLARE g frozen_recovery.grants;actor_oid oid;
BEGIN
 g:=frozen_recovery._current(grant_uuid);actor_oid:=frozen_recovery._actor(g.product,'review');
 IF g.reviewer<>session_user OR g.reviewer_oid<>actor_oid OR digest IS DISTINCT FROM g.request_digest
 THEN RAISE EXCEPTION 'RECOVERY_REVIEW_MISMATCH'; END IF;
 INSERT INTO frozen_recovery.reviews(grant_id,reviewer,reviewer_oid,request_digest)
 VALUES(grant_uuid,session_user,actor_oid,digest);
 RETURN jsonb_build_object('grant_id',grant_uuid,'reviewed',true,'certified',false);
END $$;
CREATE FUNCTION frozen_recovery.attest(grant_uuid uuid,digest text,observed jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
DECLARE g frozen_recovery.grants;actor_oid oid;p frozen_recovery.policies;
 proof frozen_recovery.proofs;stamp timestamptz;
BEGIN
 g:=frozen_recovery._current(grant_uuid);actor_oid:=frozen_recovery._actor(g.product,'attest');
 IF g.verifier<>session_user OR g.verifier_oid<>actor_oid OR digest IS DISTINCT FROM g.request_digest
 THEN RAISE EXCEPTION 'RECOVERY_PROOF_MISMATCH'; END IF;
 SELECT * INTO p FROM frozen_recovery.policies WHERE product=g.product;
 IF jsonb_typeof(observed) IS DISTINCT FROM 'object'
 OR NOT observed ?& ARRAY['directory_device','directory_inode','observed_at','dependencies']
 OR observed-ARRAY['directory_device','directory_inode','observed_at','dependencies']<>g.checkout-'root_path'
 OR observed->'dependencies' IS DISTINCT FROM '{}'::jsonb
 OR jsonb_typeof(observed->'directory_device') IS DISTINCT FROM 'number'
 OR jsonb_typeof(observed->'directory_inode') IS DISTINCT FROM 'number'
 OR observed->>'directory_device' !~ '^[0-9]+$' OR observed->>'directory_inode' !~ '^[1-9][0-9]*$'
 OR jsonb_typeof(observed->'observed_at') IS DISTINCT FROM 'string'
 OR observed->>'observed_at' !~ '(Z|[+-][0-9]{2}:[0-9]{2})$'
 THEN RAISE EXCEPTION 'RECOVERY_PROOF_MISMATCH'; END IF;
 stamp:=(observed->>'observed_at')::timestamptz;
 IF stamp IS NULL OR NOT isfinite(stamp) OR stamp>clock_timestamp()
 OR stamp<clock_timestamp()-make_interval(secs=>p.proof_seconds)
 THEN RAISE EXCEPTION 'RECOVERY_PROOF_EXPIRED'; END IF;
 INSERT INTO frozen_recovery.proofs(grant_id,verifier,verifier_oid,request_digest,observations,expires_at)
 VALUES(grant_uuid,session_user,actor_oid,digest,observed,
 least(g.expires_at,stamp+make_interval(secs=>p.proof_seconds))) RETURNING * INTO proof;
 RETURN jsonb_build_object('grant_id',grant_uuid,'proof_id',proof.proof_id,'expires_at',proof.expires_at,'certified',false);
END $$;
CREATE FUNCTION frozen_recovery.execute(grant_uuid uuid,proof_uuid uuid,digest text,request text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
DECLARE g frozen_recovery.grants;actor_oid oid;r frozen_recovery.reviews;
 p frozen_recovery.proofs;before_row public.workstations;after_row public.workstations;
 fence bigint;receipt jsonb;now_at timestamptz;
BEGIN
 PERFORM frozen_recovery._request(request);
 g:=frozen_recovery._current(grant_uuid);actor_oid:=frozen_recovery._actor(g.product,'execute');
 IF g.executor<>session_user OR g.executor_oid<>actor_oid OR digest IS DISTINCT FROM g.request_digest
 THEN RAISE EXCEPTION 'RECOVERY_DENIED'; END IF;
 SELECT * INTO r FROM frozen_recovery.reviews WHERE grant_id=grant_uuid FOR UPDATE;
 IF NOT FOUND OR r.reviewer<>g.reviewer OR r.reviewer_oid<>g.reviewer_oid OR r.request_digest<>digest
 THEN RAISE EXCEPTION 'RECOVERY_REVIEW_UNAVAILABLE'; END IF;
 SELECT * INTO p FROM frozen_recovery.proofs WHERE proof_id=proof_uuid FOR UPDATE;
 IF NOT FOUND OR p.consumed OR p.grant_id<>grant_uuid OR p.verifier<>g.verifier
 OR p.verifier_oid<>g.verifier_oid OR p.request_digest<>digest
 THEN RAISE EXCEPTION 'RECOVERY_PROOF_UNAVAILABLE'; END IF;
 now_at:=clock_timestamp();
 IF g.expires_at<=now_at OR p.expires_at<=now_at
 OR (p.observations->>'observed_at')::timestamptz<now_at-make_interval(secs=>(g.policy_snapshot->>'proof_seconds')::integer)
 THEN RAISE EXCEPTION 'RECOVERY_PROOF_EXPIRED'; END IF;
 PERFORM 1 FROM assignment_leases.leases WHERE workstation_id=g.workstation_id AND state='ACTIVE' FOR UPDATE;
 IF FOUND THEN RAISE EXCEPTION 'ACTIVE_LEASE_REQUIRES_REVOCATION'; END IF;
 INSERT INTO assignment_leases.slots(workstation_id) VALUES(g.workstation_id) ON CONFLICT DO NOTHING;
 UPDATE assignment_leases.slots SET epoch=epoch+1 WHERE workstation_id=g.workstation_id RETURNING epoch INTO fence;
 SELECT * INTO before_row FROM public.workstations WHERE workstation_id=g.workstation_id;
 UPDATE frozen_recovery.grants SET consumed=true WHERE grant_id=grant_uuid;
 UPDATE frozen_recovery.proofs SET consumed=true WHERE proof_id=proof_uuid;
 IF g.expires_at<=clock_timestamp() OR p.expires_at<=clock_timestamp()
 THEN RAISE EXCEPTION 'RECOVERY_PROOF_EXPIRED'; END IF;
 UPDATE public.workstations w SET lease_state='FREE',status='NOT_STARTED',blocker=NULL,
 agent=NULL,current_atomic_task=NULL,lease_started_at=NULL,heartbeat_at=NULL,lease_expires_at=NULL,
 updated_at=clock_timestamp()
 WHERE w.workstation_id=g.workstation_id AND to_jsonb(w)=g.snapshot RETURNING * INTO after_row;
 IF NOT FOUND THEN RAISE EXCEPTION 'RECOVERY_COMPARE_AND_SET_FAILED'; END IF;
 receipt:=jsonb_build_object('schema','codestra.frozen-recovery.v2','grant_id',grant_uuid,
 'workstation_id',g.workstation_id,'incident_id',g.incident_id,'revision',g.revision,
 'request_digest',digest,'epoch',fence,'released',true,'certified',false,'lease_granted',false,
 'before',to_jsonb(before_row),'after',to_jsonb(after_row),'authority','TRANSACTION_RESULT');
 INSERT INTO frozen_recovery.audit(grant_id,actor,actor_oid,action,request_id,receipt)
 VALUES(grant_uuid,session_user,actor_oid,'RECOVER',request,receipt);
 INSERT INTO public.events(workstation_id,event_type,actor,details)
 VALUES(g.workstation_id,'SCOPED_FROZEN_RECOVERY',session_user,receipt);
 IF g.expires_at<=clock_timestamp() OR p.expires_at<=clock_timestamp()
 THEN RAISE EXCEPTION 'RECOVERY_PROOF_EXPIRED'; END IF;
 RETURN receipt;
END $$;
CREATE FUNCTION frozen_recovery.revoke(grant_uuid uuid,digest text,reason text,request text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
DECLARE g frozen_recovery.grants;actor_oid oid;receipt jsonb;
BEGIN
 PERFORM frozen_recovery._request(request);
 SELECT * INTO g FROM frozen_recovery.grants WHERE grant_id=grant_uuid;
 IF NOT FOUND THEN RAISE EXCEPTION 'RECOVERY_GRANT_UNAVAILABLE'; END IF;
 PERFORM frozen_recovery._lock(g.workstation_id,g.snapshot->>'worktree');
 PERFORM 1 FROM public.workstations WHERE workstation_id=g.workstation_id FOR UPDATE;
 SELECT * INTO g FROM frozen_recovery.grants WHERE grant_id=grant_uuid FOR UPDATE;
 actor_oid:=frozen_recovery._actor(g.product,'authorize');
 IF digest IS DISTINCT FROM g.request_digest OR g.request_digest<>frozen_recovery._digest(g)
 OR reason IS NULL OR length(reason) NOT BETWEEN 1 AND 512
 THEN RAISE EXCEPTION 'INVALID_RECOVERY_REQUEST'; END IF;
 UPDATE frozen_recovery.grants SET revoked=true WHERE grant_id=grant_uuid;
 receipt:=jsonb_build_object('grant_id',grant_uuid,'revoked',true,'reason',reason,'certified',false);
 INSERT INTO frozen_recovery.audit(grant_id,actor,actor_oid,action,request_id,receipt)
 VALUES(grant_uuid,session_user,actor_oid,'REVOKE',request,receipt);
 RETURN receipt;
END $$;
CREATE FUNCTION frozen_recovery.lookup(request text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
DECLARE a frozen_recovery.audit;g frozen_recovery.grants;actor_oid oid;
BEGIN
 PERFORM frozen_recovery._request(request);
 SELECT * INTO a FROM frozen_recovery.audit
 WHERE actor=session_user AND action='RECOVER' AND request_id=request;
 IF NOT FOUND THEN RAISE EXCEPTION 'RECOVERY_RECEIPT_UNAVAILABLE'; END IF;
 SELECT * INTO g FROM frozen_recovery.grants WHERE grant_id=a.grant_id;
 actor_oid:=frozen_recovery._actor(g.product,'execute');
 IF actor_oid<>a.actor_oid THEN RAISE EXCEPTION 'RECOVERY_DENIED'; END IF;
 RETURN a.receipt||jsonb_build_object('authority','HISTORICAL_RECOVERY_RECEIPT','usable_as_lease',false);
END $$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA frozen_recovery FROM PUBLIC;
COMMIT;
