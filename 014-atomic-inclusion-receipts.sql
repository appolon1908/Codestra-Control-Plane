-- EMPTY SOURCE ONLY. Requires reviewed005/007/009-coordinator/011/013.
-- No roles, execution grants, rows, secrets or operational authority are created.
-- A dedicated accepted issuer owns the GitHub verification boundary. This API
-- records its authenticated observation; SQL does not authenticate GitHub itself.
BEGIN;
CREATE SCHEMA atomic_receipts;
REVOKE ALL ON SCHEMA atomic_receipts FROM PUBLIC;
CREATE TABLE atomic_receipts.product_grants (
 principal name NOT NULL,role_oid oid NOT NULL,product text NOT NULL REFERENCES public.products(product),
 capability text NOT NULL CHECK(capability IN ('issue','read','revoke')),
 expires_at timestamptz NOT NULL,active boolean NOT NULL DEFAULT false,
 PRIMARY KEY(principal,product,capability)
);
CREATE TABLE atomic_receipts.delegations (
 delegation_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 binding_id uuid NOT NULL REFERENCES assignment_leases.bindings(binding_id),
 lease_id uuid NOT NULL REFERENCES assignment_leases.leases(lease_id),epoch bigint NOT NULL CHECK(epoch>0),
 principal name NOT NULL,role_oid oid NOT NULL,product text NOT NULL REFERENCES public.products(product),
 purpose text NOT NULL CHECK(purpose='ATOMIC_INCLUSION'),
 context jsonb NOT NULL CHECK(jsonb_typeof(context)='object'),
 accepted_by text NOT NULL CHECK(accepted_by='Ralph L. Appolon'),acceptance_ref text NOT NULL CHECK(length(trim(acceptance_ref))>0),
 expires_at timestamptz NOT NULL,receipt_expires_at timestamptz NOT NULL,
 active boolean NOT NULL DEFAULT false
);
CREATE TABLE atomic_receipts.task_dependencies (
 product text NOT NULL REFERENCES public.products(product),workstation_id text NOT NULL REFERENCES public.workstations(workstation_id),
 task_id text PRIMARY KEY,depends_on jsonb NOT NULL CHECK(jsonb_typeof(depends_on)='array')
);
CREATE TABLE atomic_receipts.preparations (
 preparation_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 delegation_id uuid NOT NULL UNIQUE REFERENCES atomic_receipts.delegations(delegation_id),
 principal name NOT NULL,role_oid oid NOT NULL,authentication text NOT NULL,
 request_id uuid NOT NULL,prepared_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 payload jsonb NOT NULL,UNIQUE(role_oid,request_id)
);
CREATE TABLE atomic_receipts.receipts (
 receipt_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 preparation_id uuid NOT NULL UNIQUE REFERENCES atomic_receipts.preparations(preparation_id),
 check_id bigint NOT NULL CHECK(check_id>0),suite_id bigint NOT NULL CHECK(suite_id>0),
 external_id text NOT NULL CHECK(external_id ~ '^[0-9a-f]{64}$'),
 observation_digest text NOT NULL CHECK(observation_digest ~ '^[0-9a-f]{64}$'),
 completed_at timestamptz NOT NULL,sealed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL,UNIQUE(check_id)
);
CREATE TABLE atomic_receipts.revocations (
 revocation_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 receipt_id uuid REFERENCES atomic_receipts.receipts(receipt_id),
 binding_id uuid REFERENCES assignment_leases.bindings(binding_id),
 principal name NOT NULL,role_oid oid NOT NULL,authentication text NOT NULL,
 reason text NOT NULL CHECK(length(trim(reason)) BETWEEN 1 AND 512),
 request_id uuid NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK((receipt_id IS NULL)<>(binding_id IS NULL)),UNIQUE(role_oid,request_id)
);
REVOKE ALL ON ALL TABLES IN SCHEMA atomic_receipts FROM PUBLIC;
-- Read-only consumers can inspect current identity integrity without EXECUTE on
-- any authority function. Includes noninherited memberships and writer roles.
CREATE VIEW atomic_receipts.principal_integrity AS
 SELECT r.rolname,r.oid,r.rolcanlogin AND NOT(r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls)
 AND NOT EXISTS(SELECT 1 FROM pg_roles reachable WHERE pg_has_role(r.oid,reachable.oid,'MEMBER') AND
 (reachable.rolsuper OR reachable.rolcreaterole OR reachable.rolcreatedb OR reachable.rolreplication OR reachable.rolbypassrls
 OR reachable.rolname IN ('pg_read_server_files','pg_write_server_files','pg_execute_server_program')
 OR EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname IN
 ('public','atomic_receipts','certifier_authority','publisher_authority','assignment_leases','scoped_registration',
 'scoped_admission','controller_coordinator','scope_assignment_leases','frozen_recovery','atomic_inspection')
 AND (n.nspowner=reachable.oid OR has_schema_privilege(reachable.oid,n.oid,'CREATE')))
 OR EXISTS(SELECT 1 FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace
 WHERE t.relkind IN ('r','p','v','m','f') AND n.nspname IN
 ('public','atomic_receipts','certifier_authority','publisher_authority','assignment_leases','scoped_registration',
 'scoped_admission','controller_coordinator','scope_assignment_leases','frozen_recovery','atomic_inspection')
 AND (t.relowner=reachable.oid OR has_table_privilege(reachable.oid,t.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))))) AS restricted
 FROM pg_roles r;
REVOKE ALL ON atomic_receipts.principal_integrity FROM PUBLIC;

CREATE FUNCTION atomic_receipts._immutable() RETURNS trigger LANGUAGE plpgsql
SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'ATOMIC_HISTORY_IMMUTABLE'; END $$;
CREATE TRIGGER immutable_preparation BEFORE UPDATE OR DELETE ON atomic_receipts.preparations
 FOR EACH ROW EXECUTE FUNCTION atomic_receipts._immutable();
CREATE TRIGGER immutable_receipt BEFORE UPDATE OR DELETE ON atomic_receipts.receipts
 FOR EACH ROW EXECUTE FUNCTION atomic_receipts._immutable();
CREATE TRIGGER immutable_revocation BEFORE UPDATE OR DELETE ON atomic_receipts.revocations
 FOR EACH ROW EXECUTE FUNCTION atomic_receipts._immutable();

CREATE FUNCTION atomic_receipts._permit(product_name text,kind text) RETURNS oid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE actor_oid oid;
BEGIN
 IF system_user IS DISTINCT FROM 'scram-sha-256:'||session_user::text OR current_setting('role')<>'none'
 OR current_setting('transaction_isolation')<>'read committed'
 OR NOT EXISTS(SELECT 1 FROM pg_stat_ssl WHERE pid=pg_backend_pid() AND ssl)
 THEN RAISE EXCEPTION 'ATOMIC_AUTHENTICATION_REQUIRED'; END IF;
 SELECT oid INTO actor_oid FROM pg_roles WHERE rolname=session_user AND rolcanlogin
 AND NOT(rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls);
 IF actor_oid IS NULL OR EXISTS(SELECT 1 FROM pg_roles reachable WHERE pg_has_role(session_user,reachable.oid,'MEMBER') AND
 (reachable.rolsuper OR reachable.rolcreaterole OR reachable.rolcreatedb OR reachable.rolreplication OR reachable.rolbypassrls
 OR reachable.rolname IN ('pg_read_server_files','pg_write_server_files','pg_execute_server_program')
 OR EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname IN
 ('public','atomic_receipts','certifier_authority','publisher_authority','assignment_leases','scoped_registration',
 'scoped_admission','controller_coordinator','scope_assignment_leases','frozen_recovery','atomic_inspection')
 AND (n.nspowner=reachable.oid OR has_schema_privilege(reachable.oid,n.oid,'CREATE')))
 OR EXISTS(SELECT 1 FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace
 WHERE t.relkind IN ('r','p','v','m','f') AND n.nspname IN
 ('public','atomic_receipts','certifier_authority','publisher_authority','assignment_leases','scoped_registration',
 'scoped_admission','controller_coordinator','scope_assignment_leases','frozen_recovery','atomic_inspection')
 AND (t.relowner=reachable.oid OR has_table_privilege(reachable.oid,t.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')))))
 THEN RAISE EXCEPTION 'ATOMIC_RESTRICTED_PRINCIPAL_REQUIRED'; END IF;
 PERFORM 1 FROM atomic_receipts.product_grants g WHERE g.principal=session_user AND g.role_oid=actor_oid
 AND g.product=product_name AND g.capability=kind AND g.active AND g.expires_at>clock_timestamp() FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'ATOMIC_PRODUCT_GRANT_REQUIRED'; END IF;
 RETURN actor_oid;
END $$;

CREATE FUNCTION atomic_receipts.prepare(delegation_uuid uuid,request_uuid uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE d atomic_receipts.delegations;actor_oid oid;live jsonb;l assignment_leases.leases;
 proof assignment_leases.proofs;result atomic_receipts.preparations;
 graph jsonb;new_payload jsonb;
BEGIN
 SELECT * INTO d FROM atomic_receipts.delegations WHERE delegation_id=delegation_uuid FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'ATOMIC_DELEGATION_REQUIRED'; END IF;
 actor_oid:=atomic_receipts._permit(d.product,'issue');
 IF NOT d.active OR d.expires_at<=clock_timestamp() OR d.principal<>session_user OR d.role_oid<>actor_oid
 OR d.receipt_expires_at<=clock_timestamp() OR d.receipt_expires_at>clock_timestamp()+interval '1 day'
 THEN RAISE EXCEPTION 'ATOMIC_DELEGATION_REQUIRED'; END IF;
 SELECT * INTO result FROM atomic_receipts.preparations WHERE role_oid=actor_oid AND request_id=request_uuid;
 IF FOUND THEN
  IF result.delegation_id<>delegation_uuid THEN RAISE EXCEPTION 'ATOMIC_REQUEST_REUSED'; END IF;
 END IF;
 live:=assignment_leases.inspect_binding(d.binding_id);
 IF live->>'state'<>'ACTIVE' OR live->>'authority'<>'ONLINE_DATABASE_RECEIPT'
 OR (live->>'lease_id')::uuid<>d.lease_id OR (live->>'epoch')::bigint<>d.epoch
 OR live->'binding'->>'product'<>d.product OR live->>'principal'=session_user::text
 THEN RAISE EXCEPTION 'ATOMIC_ACTIVE_EXCLUSIVE_LEASE_REQUIRED'; END IF;
 SELECT * INTO l FROM assignment_leases.leases WHERE lease_id=d.lease_id FOR SHARE;
 SELECT * INTO proof FROM assignment_leases.proofs WHERE proof_id=l.proof_id FOR SHARE;
 IF NOT FOUND OR NOT proof.consumed OR proof.expires_at<=clock_timestamp()
 OR proof.verifier_authentication IS DISTINCT FROM 'scram-sha-256:'||proof.verifier::text
 OR proof.verifier IN (session_user,l.principal) THEN RAISE EXCEPTION 'ATOMIC_INDEPENDENT_MATERIALIZER_REQUIRED'; END IF;
 SELECT to_jsonb(t) INTO graph FROM atomic_receipts.task_dependencies t
 WHERE t.task_id=live->'binding'->>'task_id' AND t.product=d.product AND t.workstation_id=l.workstation_id FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'ATOMIC_TASK_GRAPH_REQUIRED'; END IF;
 new_payload:=jsonb_build_object('purpose','ATOMIC_INCLUSION','delegation',to_jsonb(d),'lease',to_jsonb(l),
 'binding',live->'binding','proof',to_jsonb(proof),'task_dependencies',graph,
 'issue_grant_expires_at',(SELECT expires_at FROM atomic_receipts.product_grants
 WHERE principal=session_user AND product=d.product AND capability='issue'));
 IF result.preparation_id IS NOT NULL THEN
  IF result.payload IS DISTINCT FROM new_payload THEN RAISE EXCEPTION 'ATOMIC_PREPARATION_CHANGED'; END IF;
  RETURN to_jsonb(result);
 END IF;
 INSERT INTO atomic_receipts.preparations(delegation_id,principal,role_oid,authentication,request_id,payload)
 VALUES(d.delegation_id,session_user,actor_oid,system_user,request_uuid,
 new_payload) RETURNING * INTO result;
 RETURN to_jsonb(result);
END $$;

CREATE FUNCTION atomic_receipts.seal(preparation_uuid uuid,check_number bigint,suite_number bigint,
 external_digest text,observation_hash text,completed timestamptz) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE p atomic_receipts.preparations;d atomic_receipts.delegations;actor_oid oid;live jsonb;
 result atomic_receipts.receipts;proof assignment_leases.proofs;
BEGIN
 SELECT * INTO p FROM atomic_receipts.preparations WHERE preparation_id=preparation_uuid FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'ATOMIC_PREPARATION_REQUIRED'; END IF;
 SELECT * INTO d FROM atomic_receipts.delegations WHERE delegation_id=p.delegation_id FOR SHARE;
 actor_oid:=atomic_receipts._permit(d.product,'issue');
 IF p.principal<>session_user OR p.role_oid<>actor_oid OR NOT d.active OR d.expires_at<=clock_timestamp()
 OR to_jsonb(d) IS DISTINCT FROM p.payload->'delegation'
 OR p.authentication IS DISTINCT FROM system_user OR completed<p.prepared_at OR completed>clock_timestamp()
 OR EXISTS(SELECT 1 FROM atomic_receipts.revocations WHERE binding_id=d.binding_id)
 THEN RAISE EXCEPTION 'ATOMIC_PREPARATION_CHANGED_OR_REVOKED'; END IF;
 IF NOT EXISTS(SELECT 1 FROM atomic_receipts.task_dependencies t
 WHERE to_jsonb(t)=p.payload->'task_dependencies')
 THEN RAISE EXCEPTION 'ATOMIC_TASK_GRAPH_CHANGED'; END IF;
 live:=assignment_leases.inspect_binding(d.binding_id);
 SELECT * INTO proof FROM assignment_leases.proofs WHERE proof_id=(p.payload->'proof'->>'proof_id')::uuid FOR SHARE;
 IF live->>'state'<>'ACTIVE' OR (live->>'lease_id')::uuid<>d.lease_id OR (live->>'epoch')::bigint<>d.epoch
 OR live->'binding' IS DISTINCT FROM p.payload->'binding'
 OR live->>'expires_at' IS DISTINCT FROM p.payload->'lease'->>'expires_at'
 OR to_jsonb(proof) IS DISTINCT FROM p.payload->'proof' OR proof.expires_at<=clock_timestamp()
 OR NOT EXISTS(SELECT 1 FROM assignment_leases.leases WHERE lease_id=d.lease_id
 AND proof_id=proof.proof_id AND state='ACTIVE')
 THEN RAISE EXCEPTION 'ATOMIC_ISSUANCE_LEASE_CHANGED'; END IF;
 -- Dedicated issuer credentials + independently verified GitHub check are the
 -- trust boundary. Authors have no execution grant or read-model table writes.
 INSERT INTO atomic_receipts.receipts(preparation_id,check_id,suite_id,external_id,observation_digest,completed_at,expires_at)
 VALUES(p.preparation_id,check_number,suite_number,external_digest,observation_hash,completed,
 least(d.receipt_expires_at,(p.payload->>'issue_grant_expires_at')::timestamptz,(SELECT expires_at FROM atomic_receipts.product_grants
 WHERE principal=session_user AND product=d.product AND capability='issue'))) RETURNING * INTO result;
 RETURN to_jsonb(result);
END $$;

CREATE FUNCTION atomic_receipts.revoke(receipt_uuid uuid,reason_text text,request_uuid uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE product_name text;actor_oid oid;result atomic_receipts.revocations;
BEGIN
 SELECT p.payload->'binding'->>'product' INTO product_name FROM atomic_receipts.receipts r
 JOIN atomic_receipts.preparations p USING(preparation_id) WHERE r.receipt_id=receipt_uuid;
 IF product_name IS NULL THEN RAISE EXCEPTION 'ATOMIC_RECEIPT_REQUIRED'; END IF;
 actor_oid:=atomic_receipts._permit(product_name,'revoke');
 SELECT * INTO result FROM atomic_receipts.revocations WHERE role_oid=actor_oid AND request_id=request_uuid;
 IF FOUND THEN
  IF result.receipt_id IS DISTINCT FROM receipt_uuid OR result.reason IS DISTINCT FROM reason_text
  THEN RAISE EXCEPTION 'ATOMIC_REQUEST_REUSED'; END IF;
  RETURN to_jsonb(result);
 END IF;
 INSERT INTO atomic_receipts.revocations(receipt_id,principal,role_oid,authentication,reason,request_id)
 VALUES(receipt_uuid,session_user,actor_oid,system_user,reason_text,request_uuid) RETURNING * INTO result;
 RETURN to_jsonb(result);
END $$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA atomic_receipts FROM PUBLIC;
COMMENT ON SCHEMA atomic_receipts IS 'Empty source contract. Sealed historical inclusion is never a current writer lease or evidence of prior publication admission. Normal RELEASED preserves history; explicit binding/receipt revocation invalidates it. Runtime provisioning separately authorized.';
COMMIT;
