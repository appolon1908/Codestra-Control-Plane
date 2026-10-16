-- EMPTY SOURCE ONLY, requires reviewed 011 + 012. No live application, identities,
-- grants, leases, delegation rows or certification effects are authorized here.
-- Only an operator can authenticate an exact first-issuance delegation. Runtime
-- receives SELECT; it must never own, populate or alter this read model.
BEGIN;
CREATE TABLE certifier_authority.pending_bindings (
 binding_hash text PRIMARY KEY CHECK(binding_hash ~ '^[0-9a-f]{64}$'),
 principal name NOT NULL,
 role_oid oid NOT NULL,
 product text NOT NULL REFERENCES public.products(product),
 repository text NOT NULL,
 repository_id bigint NOT NULL CHECK(repository_id>0),
 pr_number bigint NOT NULL CHECK(pr_number>0),
 authority jsonb NOT NULL CHECK(jsonb_typeof(authority)='object'),
 snapshot jsonb NOT NULL CHECK(jsonb_typeof(snapshot)='object'
  AND snapshot ? 'certificate' AND snapshot->'certificate'='null'::jsonb),
 scope_type text NOT NULL CHECK(scope_type IN ('SUBSECTION','SECTION','DEVELOPMENT','TESTING','STAGING','PRODUCTION')),
 scope_name text NOT NULL CHECK(length(trim(scope_name))>0),
 assignment_id uuid NOT NULL,
 lease_id uuid NOT NULL,
 lease_epoch bigint NOT NULL CHECK(lease_epoch>0),
 lease_principal name NOT NULL,
 delegation_ref text NOT NULL CHECK(length(trim(delegation_ref))>0),
 capability_receipt text NOT NULL CHECK(length(trim(capability_receipt))>0),
 dependency_policy jsonb NOT NULL CHECK(jsonb_typeof(dependency_policy)='array' AND jsonb_array_length(dependency_policy)<=100),
 accepted_by text NOT NULL CHECK(accepted_by='Ralph L. Appolon'),
 purpose text NOT NULL CHECK(purpose='FIRST_SCOPE_CERTIFICATION'),
 issued_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL CHECK(expires_at>issued_at AND expires_at<=issued_at+interval '5 minutes'),
 active boolean NOT NULL DEFAULT false,
 FOREIGN KEY(principal,product) REFERENCES certifier_authority.product_grants(principal,product)
);
REVOKE ALL ON certifier_authority.pending_bindings FROM PUBLIC;
COMMENT ON TABLE certifier_authority.pending_bindings IS
 'Operator-owned exact scope first-issuance delegation with complete independently accepted dependency policy. Not an existing certificate or a caller/CI PASS. Empty by default; runtime is restricted to read-only acquisition and current independent online verification.';
COMMIT;
