-- Source-only integration after005,007 and both009 migrations. Provisions no
-- runtime identity, permission, assignment, registration, proof or lease.
-- Replaces only the five PR43 functions, preserving their OIDs, ACLs and trigger.
-- Historical proof provenance and binding snapshots remain unchanged/fail closed.
BEGIN;
SET LOCAL timezone='UTC';
CREATE OR REPLACE FUNCTION assignment_leases._authenticate_proof() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
BEGIN
 IF system_user IS DISTINCT FROM 'scram-sha-256:'||session_user::text
 OR current_setting('role')<>'none' OR NEW.verifier IS DISTINCT FROM session_user
 OR NOT EXISTS(SELECT 1 FROM pg_stat_ssl WHERE pid=pg_backend_pid() AND ssl)
 THEN RAISE EXCEPTION 'CREDENTIAL_AUTHENTICATION_REQUIRED'; END IF;
 NEW.verifier_authentication:=system_user;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION assignment_leases.resolve_task(task text,repository_name text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
DECLARE actor_oid oid;b assignment_leases.bindings;m assignment_leases.coordinator_tasks;
 initial assignment_leases.bindings;w public.workstations;c scoped_registration.candidates;candidate jsonb;prerequisite jsonb;
 dependency_id text;dependency_ws public.workstations;expected_prerequisite jsonb;
 dependency_receipt assignment_leases.dependencies;expected_binding jsonb;digest text;
BEGIN
 IF system_user IS DISTINCT FROM 'scram-sha-256:'||session_user::text
 OR current_setting('role')<>'none' THEN RAISE EXCEPTION 'COORDINATOR_DENIED'; END IF;
 IF current_setting('transaction_isolation')<>'read committed'
 THEN RAISE EXCEPTION 'COORDINATOR_ISOLATION_REQUIRED'; END IF;
 actor_oid:=assignment_leases._actor();
 IF task IS NULL OR task !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 OR repository_name IS NULL OR repository_name !~ '^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$'
 THEN RAISE EXCEPTION 'INVALID_TASK_REQUEST'; END IF;
 SELECT * INTO initial FROM assignment_leases.bindings
 WHERE task_id=task AND principal=session_user AND principal_oid=actor_oid
 AND repository=repository_name AND active AND valid_until>clock_timestamp();
 IF NOT FOUND THEN RAISE EXCEPTION 'TASK_MAPPING_UNAVAILABLE'; END IF;
 -- Same order as claim/revoke: advisory materialization locks before row locks.
 PERFORM assignment_leases._lock(initial);
 SELECT * INTO b FROM assignment_leases.bindings WHERE binding_id=initial.binding_id FOR SHARE;
 IF NOT FOUND OR b IS DISTINCT FROM initial OR NOT b.active OR b.valid_until<=clock_timestamp()
 THEN RAISE EXCEPTION 'TASK_MAPPING_UNAVAILABLE'; END IF;
 SELECT * INTO m FROM assignment_leases.coordinator_tasks WHERE binding_id=b.binding_id AND active FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'TASK_MAPPING_UNAVAILABLE'; END IF;
 PERFORM 1 FROM scoped_registration.task_assignments a WHERE a.product=b.product AND a.workstation_id=b.workstation_id
 AND a.task_id=b.task_id AND a.principal=b.principal AND a.active;
 IF NOT FOUND THEN RAISE EXCEPTION 'ASSIGNMENT_UNAVAILABLE'; END IF;
 PERFORM 1 FROM scoped_registration.grants g WHERE g.principal=b.principal AND g.product=b.product
 AND g.capability='candidate' AND g.repository=b.repository;
 IF NOT FOUND THEN RAISE EXCEPTION 'ASSIGNMENT_UNAVAILABLE'; END IF;
 PERFORM 1 FROM public.products p JOIN scoped_registration.products s USING(product)
 WHERE p.product=b.product AND p.repository=b.repository AND s.payload->>'repository'=p.repository
 AND s.payload->>'test_branch'=p.test_branch AND s.payload->'promotion_chain'=p.promotion_chain
 AND NOT p.production_go AND NOT p.live_capabilities_enabled AND NOT p.external_effects_enabled;
 IF NOT FOUND THEN RAISE EXCEPTION 'REGISTRY_DRIFT'; END IF;
 SELECT p.* INTO w FROM public.workstations p JOIN scoped_registration.workstations s
 ON s.workstation_id=p.workstation_id AND s.product=p.product
 WHERE p.workstation_id=b.workstation_id AND p.product=b.product AND s.branch=p.branch AND s.worktree=p.worktree
 AND s.payload->>'section'=p.section AND s.payload->>'subsection'=p.subsection
 AND s.payload->>'parent_branch'=p.parent_branch AND s.payload->>'order_index'=p.order_index::text;
 IF NOT FOUND OR w.lease_state IN ('FROZEN','STALE','WARNING') OR w.status IN ('BLOCKED','COMPLETE','CERTIFIED')
 OR w.blocker IS NOT NULL THEN RAISE EXCEPTION 'LANE_UNAVAILABLE'; END IF;
 IF b.target_ref<>w.branch OR b.source_ref !~ ('^atomic/'||w.section||'--'||w.subsection||'--[a-z0-9]+(-[a-z0-9]+)*$')
 OR EXISTS(SELECT 1 FROM public.workstations WHERE worktree=b.worktree)
 OR NOT EXISTS(SELECT 1 FROM public.sections WHERE product=b.product AND section_key=w.section AND branch=w.parent_branch)
 THEN RAISE EXCEPTION 'LANE_BINDING_MISMATCH'; END IF;
 PERFORM 1 FROM assignment_leases.policies WHERE product=b.product AND active;
 IF NOT FOUND THEN RAISE EXCEPTION 'LEASE_POLICY_UNAVAILABLE'; END IF;
 FOR prerequisite IN SELECT value FROM jsonb_array_elements(m.prerequisites) LOOP
  IF jsonb_typeof(prerequisite)<>'object' OR prerequisite-ARRAY['product','scope_type','scope_name','sha']<>'{}'::jsonb
  OR NOT prerequisite ?& ARRAY['product','scope_type','scope_name','sha']
  OR EXISTS(SELECT 1 FROM jsonb_each(prerequisite) WHERE jsonb_typeof(value)<>'string')
  OR prerequisite->>'product' IS DISTINCT FROM b.product
  OR prerequisite->>'scope_type' NOT IN ('SUBSECTION','SECTION','DEVELOPMENT','TESTING','STAGING','PRODUCTION')
  OR prerequisite->>'sha' !~ '^[0-9a-f]{40}$' OR prerequisite->>'sha'=repeat('0',40)
  THEN RAISE EXCEPTION 'DEPENDENCY_UNAVAILABLE'; END IF;
 END LOOP;
 IF (SELECT count(DISTINCT value) FROM jsonb_array_elements(m.prerequisites))<>jsonb_array_length(m.prerequisites)
 OR (SELECT count(*) FROM assignment_leases.dependencies WHERE binding_id=b.binding_id)<>jsonb_array_length(m.prerequisites)
 OR EXISTS(SELECT 1 FROM assignment_leases.dependencies d WHERE d.binding_id=b.binding_id AND
   (NOT d.active OR d.valid_until<=clock_timestamp() OR NOT m.prerequisites @> jsonb_build_array(d.prerequisite)))
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(m.prerequisites) x WHERE NOT EXISTS(
   SELECT 1 FROM assignment_leases.dependencies d WHERE d.binding_id=b.binding_id AND d.prerequisite=x))
 THEN RAISE EXCEPTION 'DEPENDENCY_UNAVAILABLE'; END IF;
 -- Match the complete configured workstation graph without inventing missing
 -- operator prerequisites. Legacy SECTION/environment extras stay explicit.
 -- No new cross-workstation row locks: final receipt validation rereads the
 -- graph, while the issuer retains its established authority lock ordering.
 PERFORM atomic_inspection._registered(w);
 IF jsonb_typeof(w.depends_on) IS DISTINCT FROM 'array'
 THEN RAISE EXCEPTION 'COORDINATOR_DEPENDENCY_GRAPH_INVALID'; END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(w.depends_on) x
  WHERE jsonb_typeof(x)<>'string' OR x#>>'{}'='' OR x#>>'{}'=w.workstation_id)
 OR jsonb_array_length(w.depends_on)<>(SELECT count(DISTINCT x) FROM jsonb_array_elements(w.depends_on) x)
 THEN RAISE EXCEPTION 'COORDINATOR_DEPENDENCY_GRAPH_INVALID'; END IF;
 IF (SELECT count(*) FROM jsonb_array_elements(m.prerequisites) x WHERE x->>'scope_type'='SUBSECTION')
  <>jsonb_array_length(w.depends_on)
 THEN RAISE EXCEPTION 'COORDINATOR_DEPENDENCY_UNAVAILABLE'; END IF;
 FOR dependency_id IN SELECT value FROM jsonb_array_elements_text(w.depends_on) ORDER BY value COLLATE "C" LOOP
  SELECT * INTO dependency_ws FROM public.workstations WHERE workstation_id=dependency_id AND product=b.product;
  IF NOT FOUND THEN RAISE EXCEPTION 'COORDINATOR_DEPENDENCY_UNAVAILABLE'; END IF;
  PERFORM atomic_inspection._registered(dependency_ws);
  IF dependency_ws.status<>'CERTIFIED' OR dependency_ws.remote_sha IS NULL
  OR dependency_ws.remote_sha !~ '^[0-9a-f]{40}$' OR dependency_ws.remote_sha=repeat('0',40)
  OR dependency_ws.exact_sha_certified IS DISTINCT FROM dependency_ws.remote_sha
  THEN RAISE EXCEPTION 'COORDINATOR_DEPENDENCY_UNAVAILABLE'; END IF;
  expected_prerequisite:=jsonb_build_object('product',b.product,'scope_type','SUBSECTION',
   'scope_name',dependency_ws.branch,'sha',dependency_ws.remote_sha);
  IF NOT m.prerequisites @> jsonb_build_array(expected_prerequisite)
  OR (SELECT count(*) FROM assignment_leases.dependencies x WHERE x.binding_id=b.binding_id
   AND x.prerequisite=expected_prerequisite)<>1
  THEN RAISE EXCEPTION 'COORDINATOR_DEPENDENCY_UNAVAILABLE'; END IF;
  SELECT dependency_row.* INTO dependency_receipt FROM assignment_leases.dependencies dependency_row
  WHERE dependency_row.binding_id=b.binding_id AND dependency_row.prerequisite=expected_prerequisite;
  IF NOT FOUND OR NOT dependency_receipt.active OR dependency_receipt.valid_until<=clock_timestamp()
  OR dependency_receipt.repository IS DISTINCT FROM b.repository OR dependency_receipt.repository_id IS DISTINCT FROM b.repository_id
  OR dependency_receipt.issuer_name IN ('codestra-control-plane','codestra/control-plane','promotion-gate')
  OR btrim(dependency_receipt.issuer_name)='' OR btrim(dependency_receipt.capability_receipt)=''
  OR jsonb_typeof(dependency_receipt.binding) IS DISTINCT FROM 'object'
  OR dependency_receipt.binding->>'target_base_sha' IS NULL OR dependency_receipt.binding->>'target_base_sha' !~ '^[0-9a-f]{40}$'
  OR dependency_receipt.binding->>'target_base_sha'=repeat('0',40)
  THEN RAISE EXCEPTION 'COORDINATOR_DEPENDENCY_UNAVAILABLE'; END IF;
  expected_binding:=jsonb_build_object('repository',b.repository,'product',b.product,
   'source_ref',dependency_ws.branch,'target_ref',dependency_ws.parent_branch,
   'source_sha',dependency_ws.remote_sha,'target_base_sha',dependency_receipt.binding->>'target_base_sha');
  IF dependency_receipt.binding IS DISTINCT FROM expected_binding THEN RAISE EXCEPTION 'COORDINATOR_DEPENDENCY_UNAVAILABLE'; END IF;
  digest:=encode(sha256(convert_to(atomic_inspection._canonical(jsonb_build_object(
   'schema','codestra.lease-dependency.v1','promotion',expected_binding,
   'scope_type','SUBSECTION','scope_name',dependency_ws.branch)),'UTF8')),'hex');
  IF dependency_receipt.binding_hash IS DISTINCT FROM digest THEN RAISE EXCEPTION 'COORDINATOR_DEPENDENCY_UNAVAILABLE'; END IF;
 END LOOP;
 candidate:=jsonb_build_object('product',b.product,'workstation_id',b.workstation_id,'task_id',b.task_id,
 'title',m.title,'branch',b.source_ref,'target_branch',b.target_ref,'worktree',b.worktree,
 'head_sha',b.head_sha,'base_sha',b.base_sha,'prerequisites',m.prerequisites);
 SELECT * INTO c FROM scoped_registration.candidates WHERE task_id=b.task_id;
 IF FOUND THEN
  IF c.product<>b.product OR c.workstation_id<>b.workstation_id OR c.principal<>b.principal
  OR c.branch<>b.source_ref OR c.worktree<>b.worktree OR c.payload<>candidate
  THEN RAISE EXCEPTION 'CANDIDATE_DRIFT'; END IF;
  PERFORM assignment_leases._binding(b.binding_id,false);
 ELSE
  IF EXISTS(SELECT 1 FROM public.atomic_tasks WHERE task_id=b.task_id)
  OR EXISTS(SELECT 1 FROM scoped_registration.lanes WHERE worktree=b.worktree OR (product=b.product AND branch=b.source_ref))
  THEN RAISE EXCEPTION 'CANDIDATE_DRIFT'; END IF;
 END IF;
 RETURN jsonb_build_object('binding',to_jsonb(b),'candidate',candidate,'authority',false,'ready',false);
END $$;

CREATE OR REPLACE FUNCTION assignment_leases._coordinator_receipt(mapping jsonb,receipt jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
BEGIN
 -- Owned lookup alone does not revalidate the issuing verifier or exact
 -- dependency capability/check receipt. Every returned admission must do so.
 PERFORM 1 FROM assignment_leases.leases l JOIN assignment_leases.proofs proof USING(proof_id)
 JOIN scoped_registration.principals principal ON principal.principal=proof.verifier
 JOIN assignment_leases.permissions permission ON permission.principal=proof.verifier
  AND permission.product=mapping->'binding'->>'product' AND permission.capability='attest'
 WHERE l.lease_id=(receipt->>'lease_id')::uuid FOR SHARE OF proof,principal,permission;
 -- Re-resolve after claim/lookup, retaining the issuer's lock order and adding
 -- no cross-workstation row locks. READ COMMITTED callers read a fresh graph
 -- here; later public-row or remote revocation still requires fresh evidence.
 IF assignment_leases.resolve_task(mapping->'binding'->>'task_id',mapping->'binding'->>'repository')
  IS DISTINCT FROM mapping
 THEN RAISE EXCEPTION 'ADMISSION_RECEIPT_MISMATCH'; END IF;
 IF assignment_leases.inspect_binding((mapping->'binding'->>'binding_id')::uuid) IS DISTINCT FROM receipt
 THEN RAISE EXCEPTION 'ADMISSION_RECEIPT_MISMATCH'; END IF;
 IF receipt->'binding' IS DISTINCT FROM mapping->'binding' OR NOT EXISTS(
  SELECT 1 FROM assignment_leases.leases l JOIN assignment_leases.proofs p USING(proof_id)
  WHERE l.lease_id=(receipt->>'lease_id')::uuid AND p.verifier_authentication='scram-sha-256:'||p.verifier::text)
 THEN RAISE EXCEPTION 'ADMISSION_RECEIPT_MISMATCH'; END IF;
 RETURN receipt;
END $$;

CREATE OR REPLACE FUNCTION assignment_leases.lookup_task(task text,repository_name text,request text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
DECLARE mapping jsonb;
BEGIN
 mapping:=assignment_leases.resolve_task(task,repository_name);
 RETURN assignment_leases._coordinator_receipt(mapping,assignment_leases.lookup(request));
END $$;

CREATE OR REPLACE FUNCTION assignment_leases.admit_task(task text,repository_name text,request text,proof_uuid uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $$
DECLARE mapping jsonb;b uuid;
BEGIN
 mapping:=assignment_leases.resolve_task(task,repository_name);
 b:=(mapping->'binding'->>'binding_id')::uuid;
 IF NOT EXISTS(SELECT 1 FROM assignment_leases.proofs WHERE proof_id=proof_uuid AND binding_id=b AND verifier_authentication='scram-sha-256:'||verifier::text)
 THEN RAISE EXCEPTION 'CREDENTIAL_AUTHENTICATION_REQUIRED'; END IF;
 RETURN assignment_leases._coordinator_receipt(mapping,assignment_leases.claim(b,proof_uuid,request));
END $$;
COMMIT;
