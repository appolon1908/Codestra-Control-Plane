-- Source-only forward migration after 007. No runtime identities, grants,
-- mappings, dependency capabilities, registrations or admissions are provisioned.
BEGIN;
CREATE TABLE assignment_leases.coordinator_tasks (
 binding_id uuid PRIMARY KEY REFERENCES assignment_leases.bindings(binding_id),
 title text NOT NULL CHECK(length(title) BETWEEN 1 AND 256),
 prerequisites jsonb NOT NULL CHECK(jsonb_typeof(prerequisites)='array'),
 active boolean NOT NULL DEFAULT false
);
REVOKE ALL ON TABLE assignment_leases.coordinator_tasks FROM PUBLIC;

-- Pre-migration proofs have no credential provenance and cannot be admitted by
-- the coordinator. New proofs must originate in a credential-authenticated TLS
-- verifier session, including when attest() is called outside the coordinator.
ALTER TABLE assignment_leases.proofs ADD COLUMN verifier_authentication text;
CREATE FUNCTION assignment_leases._authenticate_proof() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF system_user IS NULL OR NEW.verifier IS DISTINCT FROM session_user
 OR NOT EXISTS(SELECT 1 FROM pg_stat_ssl WHERE pid=pg_backend_pid() AND ssl)
 THEN RAISE EXCEPTION 'CREDENTIAL_AUTHENTICATION_REQUIRED'; END IF;
 NEW.verifier_authentication:=system_user;
 RETURN NEW;
END $$;
CREATE TRIGGER authenticate_verifier_proof BEFORE INSERT ON assignment_leases.proofs
 FOR EACH ROW EXECUTE FUNCTION assignment_leases._authenticate_proof();

CREATE FUNCTION assignment_leases.resolve_task(task text,repository_name text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE actor_oid oid;b assignment_leases.bindings;m assignment_leases.coordinator_tasks;
 initial assignment_leases.bindings;w public.workstations;c scoped_registration.candidates;candidate jsonb;prerequisite jsonb;
BEGIN
 IF system_user IS NULL THEN RAISE EXCEPTION 'COORDINATOR_DENIED'; END IF;
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
  OR prerequisite->>'scope_type' NOT IN ('SECTION','DEVELOPMENT','TESTING','STAGING','PRODUCTION')
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

CREATE FUNCTION assignment_leases._coordinator_receipt(mapping jsonb,receipt jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 -- Owned lookup alone does not revalidate the issuing verifier or exact
 -- dependency capability/check receipt. Every returned admission must do so.
 PERFORM 1 FROM assignment_leases.leases l JOIN assignment_leases.proofs proof USING(proof_id)
 JOIN scoped_registration.principals principal ON principal.principal=proof.verifier
 JOIN assignment_leases.permissions permission ON permission.principal=proof.verifier
  AND permission.product=mapping->'binding'->>'product' AND permission.capability='attest'
 WHERE l.lease_id=(receipt->>'lease_id')::uuid FOR SHARE OF proof,principal,permission;
 IF assignment_leases.inspect_binding((mapping->'binding'->>'binding_id')::uuid) IS DISTINCT FROM receipt
 THEN RAISE EXCEPTION 'ADMISSION_RECEIPT_MISMATCH'; END IF;
 IF receipt->'binding' IS DISTINCT FROM mapping->'binding' OR NOT EXISTS(
  SELECT 1 FROM assignment_leases.leases l JOIN assignment_leases.proofs p USING(proof_id)
  WHERE l.lease_id=(receipt->>'lease_id')::uuid AND p.verifier_authentication IS NOT NULL)
 THEN RAISE EXCEPTION 'ADMISSION_RECEIPT_MISMATCH'; END IF;
 RETURN receipt;
END $$;

CREATE FUNCTION assignment_leases.lookup_task(task text,repository_name text,request text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE mapping jsonb;
BEGIN
 mapping:=assignment_leases.resolve_task(task,repository_name);
 RETURN assignment_leases._coordinator_receipt(mapping,assignment_leases.lookup(request));
END $$;

CREATE FUNCTION assignment_leases.admit_task(task text,repository_name text,request text,proof_uuid uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE mapping jsonb;b uuid;
BEGIN
 mapping:=assignment_leases.resolve_task(task,repository_name);
 b:=(mapping->'binding'->>'binding_id')::uuid;
 IF NOT EXISTS(SELECT 1 FROM assignment_leases.proofs WHERE proof_id=proof_uuid AND binding_id=b AND verifier_authentication IS NOT NULL)
 THEN RAISE EXCEPTION 'CREDENTIAL_AUTHENTICATION_REQUIRED'; END IF;
 RETURN assignment_leases._coordinator_receipt(mapping,assignment_leases.claim(b,proof_uuid,request));
END $$;
REVOKE ALL ON FUNCTION assignment_leases._authenticate_proof(),assignment_leases.resolve_task(text,text),
 assignment_leases._coordinator_receipt(jsonb,jsonb),assignment_leases.lookup_task(text,text,text),
 assignment_leases.admit_task(text,text,text,uuid) FROM PUBLIC;
COMMIT;
