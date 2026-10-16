-- Source-only forward migration after 005/007/009. No roles, execution grants,
-- policy, assignments, operation grants, proofs or admissions are provisioned.
BEGIN;
CREATE SCHEMA scoped_admission;
REVOKE ALL ON SCHEMA scoped_admission FROM PUBLIC;

CREATE FUNCTION scoped_admission._paths(paths jsonb,allow_empty boolean DEFAULT false)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE item jsonb;previous text;value text;
BEGIN
 IF jsonb_typeof(paths) IS DISTINCT FROM 'array' OR NOT allow_empty AND jsonb_array_length(paths)=0 THEN RETURN false; END IF;
 FOR item IN SELECT x FROM jsonb_array_elements(paths) x LOOP
  IF jsonb_typeof(item) IS DISTINCT FROM 'string' THEN RETURN false; END IF;
  value:=item#>>'{}';
  IF length(value)>1024 OR value !~ '^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$'
  OR EXISTS(SELECT 1 FROM unnest(string_to_array(value,'/')) component WHERE component IN ('.','..','.git'))
  OR previous IS NOT NULL AND previous COLLATE "C">=value COLLATE "C" THEN RETURN false; END IF;
  previous:=value;
 END LOOP;
 RETURN true;
END $$;

CREATE TABLE scoped_admission.grants (
 grant_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 binding_id uuid NOT NULL REFERENCES assignment_leases.bindings(binding_id),
 operation text NOT NULL CHECK(operation IN ('L1','L2')),
 paths jsonb NOT NULL CHECK(scoped_admission._paths(paths)),
 revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
 valid_until timestamptz NOT NULL,active boolean NOT NULL DEFAULT false
);
CREATE FUNCTION scoped_admission._revision() RETURNS trigger LANGUAGE plpgsql
SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'OPERATION_GRANT_DELETE_DENIED'; END IF;
 IF TG_OP='UPDATE' THEN
  IF NEW.grant_id<>OLD.grant_id THEN RAISE EXCEPTION 'OPERATION_GRANT_ID_IMMUTABLE'; END IF;
  NEW.revision:=OLD.revision+1;
 ELSE NEW.revision:=1; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER operation_grant_revision BEFORE INSERT OR UPDATE OR DELETE ON scoped_admission.grants
 FOR EACH ROW EXECUTE FUNCTION scoped_admission._revision();

CREATE TABLE scoped_admission.intents (
 intent_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),grant_id uuid NOT NULL REFERENCES scoped_admission.grants(grant_id),
 binding_id uuid NOT NULL REFERENCES assignment_leases.bindings(binding_id),
 lease_id uuid NOT NULL REFERENCES assignment_leases.leases(lease_id),epoch bigint NOT NULL CHECK(epoch>0),
 principal name NOT NULL,principal_oid oid NOT NULL,operation text NOT NULL CHECK(operation IN ('L1','L2')),
 payload jsonb NOT NULL,request_id text NOT NULL,request_digest text NOT NULL,
 grant_snapshot jsonb NOT NULL,context_snapshot jsonb NOT NULL,
 state text NOT NULL DEFAULT 'PENDING' CHECK(state IN ('PENDING','CONSUMED')),
 issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),expires_at timestamptz NOT NULL,outcome jsonb,
 UNIQUE(principal_oid,request_id)
);
CREATE TABLE scoped_admission.proofs (
 proof_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),intent_id uuid NOT NULL REFERENCES scoped_admission.intents(intent_id),
 verifier name NOT NULL,verifier_oid oid NOT NULL,verifier_authentication text NOT NULL,
 intent_snapshot jsonb NOT NULL,observations jsonb NOT NULL,
 issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),expires_at timestamptz NOT NULL,
 consumed boolean NOT NULL DEFAULT false
);
CREATE TABLE scoped_admission.audit (
 audit_id bigserial PRIMARY KEY,intent_id uuid NOT NULL REFERENCES scoped_admission.intents(intent_id),
 actor name NOT NULL,actor_oid oid NOT NULL,authentication text NOT NULL,action text NOT NULL,
 receipt jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON ALL TABLES IN SCHEMA scoped_admission FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA scoped_admission FROM PUBLIC;

CREATE FUNCTION scoped_admission._restricted(actor name,actor_oid oid) RETURNS boolean LANGUAGE sql
SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT assignment_leases._restricted(actor,actor_oid)
 -- MEMBER deliberately includes noninherited memberships. An actor must not
 -- SET ROLE into an authority writer, mutate protected state, then RESET ROLE
 -- and regain an apparently restricted profile at the operation boundary.
 AND NOT EXISTS(SELECT 1 FROM pg_roles reachable WHERE pg_has_role(actor,reachable.oid,'MEMBER') AND
 (reachable.rolname IN ('pg_read_server_files','pg_write_server_files','pg_execute_server_program')
 OR EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname IN
 ('assignment_leases','scoped_registration','scoped_admission','frozen_recovery','atomic_inspection','publisher_authority','public')
 AND (reachable.oid=n.nspowner OR has_schema_privilege(reachable.oid,n.oid,'CREATE')))
 OR EXISTS(SELECT 1 FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace
 WHERE t.relkind IN ('r','p') AND (n.nspname IN
 ('assignment_leases','scoped_registration','scoped_admission','frozen_recovery','atomic_inspection','publisher_authority')
 OR n.nspname='public' AND t.relname IN ('products','workstations','atomic_tasks','sections','scope_certifications'))
 AND has_table_privilege(reachable.oid,t.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))))
$$;
CREATE FUNCTION scoped_admission._actor() RETURNS oid LANGUAGE plpgsql
SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE actor_oid oid;
BEGIN
 -- This version's accepted identity profile is SCRAM, not arbitrary non-null
 -- provenance. SET SESSION AUTHORIZATION cannot transfer the authenticating ID.
 IF system_user IS DISTINCT FROM 'scram-sha-256:'||session_user::text OR current_setting('role')<>'none'
 THEN RAISE EXCEPTION 'OPERATION_AUTHENTICATION_REQUIRED'; END IF;
 actor_oid:=assignment_leases._actor();
 IF NOT scoped_admission._restricted(session_user,actor_oid) THEN RAISE EXCEPTION 'OPERATION_DENIED'; END IF;
 RETURN actor_oid;
END $$;

-- Compare every immutable field. Only the known valid_until timestamp uses
-- instant equality: jsonb renders timestamptz in the current session timezone.
-- Original lease/proof snapshots are never rewritten or partially discarded.
CREATE FUNCTION scoped_admission._same_expiring_object(snapshot jsonb,current_value jsonb)
RETURNS boolean LANGUAGE plpgsql STABLE SET search_path=pg_catalog SET timezone='UTC' AS $$
BEGIN
 IF jsonb_typeof(snapshot) IS DISTINCT FROM 'object' OR jsonb_typeof(current_value) IS DISTINCT FROM 'object'
 OR snapshot-'valid_until' IS DISTINCT FROM current_value-'valid_until'
 OR jsonb_typeof(snapshot->'valid_until') IS DISTINCT FROM 'string'
 OR jsonb_typeof(current_value->'valid_until') IS DISTINCT FROM 'string'
 OR snapshot->>'valid_until' !~ '(Z|[+-][0-9]{2}:[0-9]{2})$'
 OR current_value->>'valid_until' !~ '(Z|[+-][0-9]{2}:[0-9]{2})$' THEN RETURN false; END IF;
 RETURN (snapshot->>'valid_until')::timestamptz=(current_value->>'valid_until')::timestamptz;
END $$;
CREATE FUNCTION scoped_admission._same_dependencies(snapshot jsonb,current_value jsonb)
RETURNS boolean LANGUAGE plpgsql STABLE SET search_path=pg_catalog AS $$
DECLARE item record;
BEGIN
 IF jsonb_typeof(snapshot) IS DISTINCT FROM 'object' OR jsonb_typeof(current_value) IS DISTINCT FROM 'object'
 OR (SELECT count(*) FROM jsonb_each(snapshot))<>(SELECT count(*) FROM jsonb_each(current_value)) THEN RETURN false; END IF;
 FOR item IN SELECT * FROM jsonb_each(current_value) LOOP
  IF NOT scoped_admission._same_expiring_object(snapshot->item.key,item.value) THEN RETURN false; END IF;
 END LOOP;
 RETURN true;
END $$;

CREATE FUNCTION scoped_admission._context(binding_uuid uuid,lease_uuid uuid,expected_epoch bigint)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
DECLARE b assignment_leases.bindings;initial assignment_leases.bindings;m assignment_leases.coordinator_tasks;
 l assignment_leases.leases;candidate jsonb;receipt jsonb;proof assignment_leases.proofs;policy assignment_leases.policies;dependencies jsonb;
BEGIN
 SELECT * INTO initial FROM assignment_leases.bindings WHERE binding_id=binding_uuid;
 IF NOT FOUND THEN RAISE EXCEPTION 'OPERATION_BINDING_UNAVAILABLE'; END IF;
 -- Existing advisory materialization lock order precedes every authority row lock.
 PERFORM assignment_leases._lock(initial);
 b:=assignment_leases._binding(binding_uuid);
 IF b IS DISTINCT FROM initial THEN RAISE EXCEPTION 'OPERATION_BINDING_CHANGED'; END IF;
 IF NOT scoped_admission._restricted(b.principal,b.principal_oid) THEN RAISE EXCEPTION 'OPERATION_OWNER_REVOKED'; END IF;
 SELECT * INTO m FROM assignment_leases.coordinator_tasks WHERE binding_id=binding_uuid AND active FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'OPERATION_MAPPING_UNAVAILABLE'; END IF;
 candidate:=jsonb_build_object('product',b.product,'workstation_id',b.workstation_id,'task_id',b.task_id,
 'title',m.title,'branch',b.source_ref,'target_branch',b.target_ref,'worktree',b.worktree,
 'head_sha',b.head_sha,'base_sha',b.base_sha,'prerequisites',m.prerequisites);
 IF NOT EXISTS(SELECT 1 FROM scoped_registration.candidates c WHERE c.task_id=b.task_id AND c.payload=candidate)
 OR NOT EXISTS(SELECT 1 FROM public.workstations w JOIN scoped_registration.workstations s ON s.workstation_id=w.workstation_id
 JOIN public.sections section ON section.product=w.product AND section.section_key=w.section AND section.branch=w.parent_branch
 WHERE w.workstation_id=b.workstation_id AND s.payload->>'order_index'=w.order_index::text)
 OR EXISTS(SELECT 1 FROM public.workstations WHERE worktree=b.worktree)
 THEN RAISE EXCEPTION 'OPERATION_MAPPING_CHANGED'; END IF;
 SELECT * INTO l FROM assignment_leases.leases WHERE lease_id=lease_uuid FOR UPDATE;
 IF NOT FOUND OR l.binding_id<>binding_uuid OR l.epoch<>expected_epoch THEN RAISE EXCEPTION 'OPERATION_LEASE_UNAVAILABLE'; END IF;
 SELECT * INTO policy FROM assignment_leases.policies WHERE product=b.product;
 IF l.state<>'ACTIVE' OR l.expires_at<=clock_timestamp() OR l.principal<>b.principal OR l.principal_oid<>b.principal_oid
 OR l.workstation_id IS DISTINCT FROM b.workstation_id OR l.host IS DISTINCT FROM b.host
 OR l.directory_device<0 OR l.directory_inode<=0
 OR l.started_at+make_interval(secs=>policy.max_lifetime_seconds)<=clock_timestamp()
 OR NOT scoped_admission._same_expiring_object(l.binding_snapshot,to_jsonb(b))
 OR NOT EXISTS(SELECT 1 FROM assignment_leases.slots WHERE workstation_id=l.workstation_id AND epoch=l.epoch)
 OR NOT EXISTS(SELECT 1 FROM public.workstations WHERE workstation_id=b.workstation_id AND lease_state='ACTIVE'
 AND agent=l.principal::text AND current_atomic_task=b.task_id AND lease_expires_at=l.expires_at)
 THEN RAISE EXCEPTION 'OPERATION_LEASE_UNAVAILABLE'; END IF;
 -- Forward equivalent of inspect_binding/coordinator receipt checks. The old
 -- APIs' raw timestamp-JSON equality cannot safely cross session timezones.
 SELECT * INTO proof FROM assignment_leases.proofs WHERE proof_id=l.proof_id FOR SHARE;
 dependencies:=assignment_leases._dependencies(binding_uuid);
 PERFORM 1 FROM scoped_registration.principals p JOIN assignment_leases.permissions permission ON permission.principal=p.principal
 WHERE p.principal=proof.verifier AND permission.product=b.product FOR SHARE OF p,permission;
 IF proof.proof_id IS NULL OR proof.binding_id<>b.binding_id OR NOT proof.consumed
 OR proof.verifier_authentication IS DISTINCT FROM 'scram-sha-256:'||proof.verifier::text
 OR NOT scoped_admission._same_expiring_object(proof.binding_snapshot,to_jsonb(b))
 OR NOT scoped_admission._same_dependencies(proof.observations->'dependencies',dependencies)
 OR proof.verifier=b.principal OR proof.verifier_oid=b.principal_oid
 OR NOT scoped_admission._restricted(proof.verifier,proof.verifier_oid)
 OR NOT EXISTS(SELECT 1 FROM assignment_leases.permissions WHERE principal=proof.verifier AND product=b.product AND capability='attest' AND active)
 THEN RAISE EXCEPTION 'OPERATION_VERIFIER_REVOKED'; END IF;
 receipt:=assignment_leases._receipt(l);
 RETURN jsonb_build_object('binding',to_jsonb(b),'mapping',to_jsonb(m),'lease',to_jsonb(l),
 'receipt',receipt,'dependencies',dependencies);
END $$;

CREATE FUNCTION scoped_admission._payload(operation text,payload jsonb,g scoped_admission.grants,b jsonb)
RETURNS void LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE field text;
BEGIN
 IF jsonb_typeof(payload) IS DISTINCT FROM 'object' OR NOT scoped_admission._paths(payload->'paths')
 OR NOT (g.paths @> (payload->'paths')) THEN RAISE EXCEPTION 'OPERATION_SCOPE_MISMATCH'; END IF;
 IF operation='L1' THEN
  IF NOT payload ?& ARRAY['paths','mutation_sha256'] OR payload-ARRAY['paths','mutation_sha256']<>'{}'::jsonb
  OR jsonb_typeof(payload->'mutation_sha256') IS DISTINCT FROM 'string'
  OR payload->>'mutation_sha256' !~ '^[0-9a-f]{64}$' OR payload->>'mutation_sha256'=repeat('0',64)
  THEN RAISE EXCEPTION 'INVALID_L1_PAYLOAD'; END IF;
 ELSIF operation='L2' THEN
  IF NOT payload ?& ARRAY['paths','candidate_sha','candidate_tree_sha','expected_remote_sha','target_base_sha']
  OR payload-ARRAY['paths','candidate_sha','candidate_tree_sha','expected_remote_sha','target_base_sha']<>'{}'::jsonb
  THEN RAISE EXCEPTION 'INVALID_L2_PAYLOAD'; END IF;
  FOREACH field IN ARRAY ARRAY['candidate_sha','candidate_tree_sha','expected_remote_sha','target_base_sha'] LOOP
   IF jsonb_typeof(payload->field) IS DISTINCT FROM 'string' OR payload->>field !~ '^[0-9a-f]{40}$'
   OR payload->>field=repeat('0',40) THEN RAISE EXCEPTION 'INVALID_L2_PAYLOAD'; END IF;
  END LOOP;
  IF payload->>'expected_remote_sha' IS DISTINCT FROM b->>'head_sha'
  OR payload->>'target_base_sha' IS DISTINCT FROM b->>'base_sha' THEN RAISE EXCEPTION 'INVALID_L2_BASELINE'; END IF;
 ELSE RAISE EXCEPTION 'INVALID_OPERATION'; END IF;
END $$;

CREATE FUNCTION scoped_admission._current(intent_uuid uuid) RETURNS scoped_admission.intents
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
DECLARE i scoped_admission.intents;initial scoped_admission.intents;g scoped_admission.grants;context jsonb;
BEGIN
 SELECT * INTO initial FROM scoped_admission.intents WHERE intent_id=intent_uuid;
 IF NOT FOUND THEN RAISE EXCEPTION 'OPERATION_INTENT_UNAVAILABLE'; END IF;
 context:=scoped_admission._context(initial.binding_id,initial.lease_id,initial.epoch);
 SELECT * INTO g FROM scoped_admission.grants WHERE grant_id=initial.grant_id FOR SHARE;
 SELECT * INTO i FROM scoped_admission.intents WHERE intent_id=intent_uuid FOR UPDATE;
 IF i IS DISTINCT FROM initial OR NOT g.active OR g.valid_until<=clock_timestamp()
 OR to_jsonb(g) IS DISTINCT FROM i.grant_snapshot OR context IS DISTINCT FROM i.context_snapshot
 OR i.expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'OPERATION_AUTHORITY_CHANGED'; END IF;
 RETURN i;
END $$;
CREATE FUNCTION scoped_admission._verifier(i scoped_admission.intents,locked boolean DEFAULT false) RETURNS oid LANGUAGE plpgsql
SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE actor_oid oid;product_name text;
BEGIN
 actor_oid:=scoped_admission._actor();product_name:=i.context_snapshot->'binding'->>'product';
 IF session_user=i.principal OR actor_oid=i.principal_oid THEN RAISE EXCEPTION 'INDEPENDENT_VERIFIER_REQUIRED'; END IF;
 PERFORM assignment_leases._permission(product_name,'attest',locked);
 PERFORM assignment_leases._permission(product_name,'read',locked);
 RETURN actor_oid;
END $$;
CREATE FUNCTION scoped_admission._audit(i scoped_admission.intents,action_name text,receipt jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 INSERT INTO scoped_admission.audit(intent_id,actor,actor_oid,authentication,action,receipt)
 VALUES(i.intent_id,session_user,scoped_admission._actor(),system_user,action_name,receipt);
END $$;
CREATE FUNCTION scoped_admission._pending(i scoped_admission.intents) RETURNS jsonb LANGUAGE sql
SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('intent_id',i.intent_id,'operation',i.operation,'request_digest',i.request_digest,
 'payload',i.payload,'expires_at',i.expires_at,'state',i.state,'authority','NONE_PENDING','usable',false)
$$;

CREATE FUNCTION scoped_admission.request(grant_uuid uuid,lease_uuid uuid,epoch bigint,payload jsonb,request_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
DECLARE actor_oid oid;initial scoped_admission.grants;g scoped_admission.grants;i scoped_admission.intents;
 context jsonb;digest text;expires timestamptz;seconds integer;
BEGIN
 actor_oid:=scoped_admission._actor();
 IF request_id IS NULL OR request_id !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR epoch IS NULL OR epoch<=0
 THEN RAISE EXCEPTION 'INVALID_OPERATION_REQUEST'; END IF;
 SELECT * INTO initial FROM scoped_admission.grants WHERE grant_id=grant_uuid;
 IF NOT FOUND THEN RAISE EXCEPTION 'OPERATION_GRANT_UNAVAILABLE'; END IF;
 context:=scoped_admission._context(initial.binding_id,lease_uuid,epoch);
 IF context->'binding'->>'principal' IS DISTINCT FROM session_user::text
 OR (context->'binding'->>'principal_oid')::oid<>actor_oid THEN RAISE EXCEPTION 'OPERATION_DENIED'; END IF;
 SELECT * INTO g FROM scoped_admission.grants WHERE grant_id=grant_uuid FOR SHARE;
 IF g IS DISTINCT FROM initial OR NOT g.active OR g.valid_until<=clock_timestamp()
 THEN RAISE EXCEPTION 'OPERATION_GRANT_UNAVAILABLE'; END IF;
 PERFORM scoped_admission._payload(g.operation,payload,g,context->'binding');
 SELECT * INTO i FROM scoped_admission.intents x WHERE x.principal_oid=actor_oid AND x.request_id=request.request_id FOR UPDATE;
 IF FOUND THEN
  IF i.grant_id<>grant_uuid OR i.lease_id<>lease_uuid OR i.epoch<>epoch OR i.payload<>payload THEN RAISE EXCEPTION 'OPERATION_REQUEST_CONFLICT'; END IF;
  i:=scoped_admission._current(i.intent_id);
  IF i.state<>'PENDING' THEN RAISE EXCEPTION 'OPERATION_REQUEST_CONSUMED'; END IF;
  RETURN scoped_admission._pending(i);
 END IF;
 SELECT attestation_seconds INTO seconds FROM assignment_leases.policies WHERE product=context->'binding'->>'product';
 expires:=least(g.valid_until,(context->'lease'->>'expires_at')::timestamptz,clock_timestamp()+make_interval(secs=>seconds));
 digest:=encode(sha256(convert_to(jsonb_build_object('grant',to_jsonb(g),'context',context,'operation',g.operation,
 'payload',payload,'principal',session_user,'principal_oid',actor_oid,'request_id',request_id)::text,'UTF8')),'hex');
 INSERT INTO scoped_admission.intents(grant_id,binding_id,lease_id,epoch,principal,principal_oid,operation,payload,request_id,
 request_digest,grant_snapshot,context_snapshot,expires_at)
 VALUES(grant_uuid,g.binding_id,lease_uuid,epoch,session_user,actor_oid,g.operation,payload,request_id,digest,to_jsonb(g),context,expires) RETURNING * INTO i;
 PERFORM scoped_admission._audit(i,'REQUEST',scoped_admission._pending(i));RETURN scoped_admission._pending(i);
END $$;

CREATE FUNCTION scoped_admission.describe(intent_uuid uuid) RETURNS jsonb LANGUAGE plpgsql
SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
DECLARE i scoped_admission.intents;
BEGIN
 SELECT * INTO i FROM scoped_admission.intents WHERE intent_id=intent_uuid;
 IF NOT FOUND THEN RAISE EXCEPTION 'OPERATION_INTENT_UNAVAILABLE'; END IF;
 PERFORM scoped_admission._verifier(i);i:=scoped_admission._current(intent_uuid);
 PERFORM scoped_admission._verifier(i,true);
 IF i.state<>'PENDING' THEN RAISE EXCEPTION 'OPERATION_REQUEST_CONSUMED'; END IF;
 RETURN jsonb_build_object('intent_id',i.intent_id,'operation',i.operation,'request_digest',i.request_digest,
 'payload',i.payload,'grant',i.grant_snapshot,'binding',i.context_snapshot->'binding','lease',i.context_snapshot->'lease',
 'dependencies',coalesce((SELECT jsonb_agg(value ORDER BY key) FROM jsonb_each(i.context_snapshot->'dependencies')),'[]'::jsonb));
END $$;

CREATE FUNCTION scoped_admission.attest(intent_uuid uuid,observations jsonb) RETURNS jsonb LANGUAGE plpgsql
SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
DECLARE i scoped_admission.intents;actor_oid oid;proof scoped_admission.proofs;stamp timestamptz;seconds integer;field text;
BEGIN
 SELECT * INTO i FROM scoped_admission.intents WHERE intent_id=intent_uuid;
 IF NOT FOUND THEN RAISE EXCEPTION 'OPERATION_INTENT_UNAVAILABLE'; END IF;
 PERFORM scoped_admission._verifier(i);i:=scoped_admission._current(intent_uuid);
 actor_oid:=scoped_admission._verifier(i,true);
 IF i.state<>'PENDING' THEN RAISE EXCEPTION 'OPERATION_REQUEST_CONSUMED'; END IF;
 IF jsonb_typeof(observations) IS DISTINCT FROM 'object'
 OR NOT observations ?& ARRAY['intent_id','request_digest','operation','lease_id','epoch','head_sha','tree_sha','changed_paths','directory_device','directory_inode','dependencies','observed_at']
 OR observations-ARRAY['intent_id','request_digest','operation','lease_id','epoch','head_sha','tree_sha','changed_paths','directory_device','directory_inode','dependencies','observed_at']<>'{}'::jsonb
 OR observations->>'intent_id' IS DISTINCT FROM i.intent_id::text OR observations->>'request_digest' IS DISTINCT FROM i.request_digest
 OR observations->>'operation' IS DISTINCT FROM i.operation OR observations->>'lease_id' IS DISTINCT FROM i.lease_id::text
 OR observations->'epoch' IS DISTINCT FROM to_jsonb(i.epoch)
 OR observations->'directory_device' IS DISTINCT FROM i.context_snapshot->'lease'->'directory_device'
 OR observations->'directory_inode' IS DISTINCT FROM i.context_snapshot->'lease'->'directory_inode'
 OR observations->'dependencies' IS DISTINCT FROM i.context_snapshot->'dependencies'
 OR NOT scoped_admission._paths(observations->'changed_paths',true)
 OR NOT ((i.grant_snapshot->'paths') @> (observations->'changed_paths')) THEN RAISE EXCEPTION 'OPERATION_OBSERVATION_MISMATCH'; END IF;
 FOREACH field IN ARRAY ARRAY['head_sha','tree_sha'] LOOP
  IF jsonb_typeof(observations->field) IS DISTINCT FROM 'string' OR observations->>field !~ '^[0-9a-f]{40}$'
  OR observations->>field=repeat('0',40) THEN RAISE EXCEPTION 'OPERATION_OBSERVATION_MISMATCH'; END IF;
 END LOOP;
 IF i.operation='L2' AND (observations->>'head_sha' IS DISTINCT FROM i.payload->>'candidate_sha'
 OR observations->>'tree_sha' IS DISTINCT FROM i.payload->>'candidate_tree_sha'
 OR observations->'changed_paths' IS DISTINCT FROM i.payload->'paths') THEN RAISE EXCEPTION 'OPERATION_CANDIDATE_MISMATCH'; END IF;
 SELECT attestation_seconds INTO seconds FROM assignment_leases.policies WHERE product=i.context_snapshot->'binding'->>'product';
 stamp:=(observations->>'observed_at')::timestamptz;
 IF jsonb_typeof(observations->'observed_at') IS DISTINCT FROM 'string' OR observations->>'observed_at' !~ '(Z|[+-][0-9]{2}:[0-9]{2})$'
 OR stamp IS NULL OR stamp>clock_timestamp() OR stamp<clock_timestamp()-make_interval(secs=>seconds)
 THEN RAISE EXCEPTION 'OPERATION_OBSERVATION_EXPIRED'; END IF;
 INSERT INTO scoped_admission.proofs(intent_id,verifier,verifier_oid,verifier_authentication,intent_snapshot,observations,expires_at)
 VALUES(intent_uuid,session_user,actor_oid,system_user,to_jsonb(i),observations,least(i.expires_at,stamp+make_interval(secs=>seconds))) RETURNING * INTO proof;
 PERFORM scoped_admission._audit(i,'ATTEST',jsonb_build_object('proof_id',proof.proof_id));
 RETURN jsonb_build_object('intent_id',i.intent_id,'proof_id',proof.proof_id,'expires_at',proof.expires_at,'authority','ONLINE_SCOPED_OPERATION_PROOF','usable',false);
END $$;

CREATE FUNCTION scoped_admission.consume(intent_uuid uuid,proof_uuid uuid) RETURNS jsonb LANGUAGE plpgsql
SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
DECLARE i scoped_admission.intents;proof scoped_admission.proofs;actor_oid oid;product_name text;receipt jsonb;seconds integer;
BEGIN
 actor_oid:=scoped_admission._actor();
 SELECT * INTO i FROM scoped_admission.intents WHERE intent_id=intent_uuid;
 IF NOT FOUND OR i.principal<>session_user OR i.principal_oid<>actor_oid THEN RAISE EXCEPTION 'OPERATION_DENIED'; END IF;
 i:=scoped_admission._current(intent_uuid);
 IF i.state<>'PENDING' THEN RAISE EXCEPTION 'OPERATION_REQUEST_CONSUMED'; END IF;
 SELECT * INTO proof FROM scoped_admission.proofs WHERE proof_id=proof_uuid FOR UPDATE;
 IF NOT FOUND OR proof.intent_id<>intent_uuid OR proof.intent_snapshot IS DISTINCT FROM to_jsonb(i)
 OR proof.consumed OR proof.expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'OPERATION_PROOF_UNAVAILABLE'; END IF;
 product_name:=i.context_snapshot->'binding'->>'product';
 PERFORM 1 FROM scoped_registration.principals p JOIN assignment_leases.permissions permission ON permission.principal=p.principal
 WHERE p.principal=proof.verifier AND permission.product=product_name FOR SHARE OF p,permission;
 IF proof.verifier=i.principal OR proof.verifier_oid=i.principal_oid
 OR proof.verifier_authentication IS DISTINCT FROM 'scram-sha-256:'||proof.verifier::text
 OR NOT scoped_admission._restricted(proof.verifier,proof.verifier_oid)
 OR NOT EXISTS(SELECT 1 FROM assignment_leases.permissions WHERE principal=proof.verifier AND product=product_name AND capability='attest' AND active)
 OR NOT EXISTS(SELECT 1 FROM assignment_leases.permissions WHERE principal=proof.verifier AND product=product_name AND capability='read' AND active)
 THEN RAISE EXCEPTION 'OPERATION_VERIFIER_REVOKED'; END IF;
 SELECT attestation_seconds INTO seconds FROM assignment_leases.policies WHERE product=product_name;
 IF (proof.observations->>'observed_at')::timestamptz<clock_timestamp()-make_interval(secs=>seconds)
 THEN RAISE EXCEPTION 'OPERATION_PROOF_EXPIRED'; END IF;
 receipt:=jsonb_build_object('intent_id',i.intent_id,'operation',i.operation,'request_digest',i.request_digest,'payload',i.payload,
 'grant_id',i.grant_id,'grant_revision',i.grant_snapshot->'revision','binding_id',i.binding_id,'binding',i.context_snapshot->'binding',
 'lease_id',i.lease_id,'epoch',i.epoch,'principal',i.principal,'principal_oid',i.principal_oid,'expires_at',least(i.expires_at,proof.expires_at),
 'state','CONSUMED','authority','ONLINE_SCOPED_OPERATION_RECEIPT','usable',true);
 UPDATE scoped_admission.proofs SET consumed=true WHERE proof_id=proof_uuid;
 UPDATE scoped_admission.intents SET state='CONSUMED',outcome=receipt WHERE intent_id=intent_uuid;
 PERFORM scoped_admission._audit(i,'CONSUME',receipt);RETURN receipt;
END $$;
CREATE FUNCTION scoped_admission.inspect(intent_uuid uuid) RETURNS jsonb LANGUAGE plpgsql
SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
DECLARE i scoped_admission.intents;actor_oid oid;
BEGIN
 actor_oid:=scoped_admission._actor();
 SELECT * INTO i FROM scoped_admission.intents WHERE intent_id=intent_uuid;
 IF NOT FOUND OR i.principal<>session_user OR i.principal_oid<>actor_oid THEN RAISE EXCEPTION 'OPERATION_DENIED'; END IF;
 -- Lost-response reconciliation must survive grant/lease/intent expiry and
 -- revocation. Authenticate the original identity, but never turn its stored
 -- outcome into a current permission or an authorization to retry an effect.
 RETURN coalesce(i.outcome,scoped_admission._pending(i))||jsonb_build_object('usable',false,'authority','NONE','historical',true);
END $$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA scoped_admission FROM PUBLIC;
COMMIT;
