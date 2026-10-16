-- SOURCE ONLY: an EMPTY operator-owned read model for pre-existing, independently
-- authenticated SCOPE_CERTIFICATION receipts. This is not a first-certification
-- decision procedure, nor authority to provision/apply anything. No roles, grants,
-- credentials, policies, receipts or leases are created. Legacy CERTIFIED/PASS
-- metadata cannot establish the independent receipt's authenticity.
BEGIN;
CREATE SCHEMA certifier_authority;
REVOKE ALL ON SCHEMA certifier_authority FROM PUBLIC;
CREATE TABLE certifier_authority.product_grants (
 principal name NOT NULL,
 role_oid oid NOT NULL,
 product text NOT NULL REFERENCES public.products(product),
 repository text NOT NULL,
 repository_id bigint NOT NULL CHECK(repository_id>0),
 active boolean NOT NULL DEFAULT false,
 expires_at timestamptz NOT NULL,
 PRIMARY KEY(principal,product)
);
CREATE TABLE certifier_authority.existing_receipts (
 binding_hash text PRIMARY KEY CHECK(binding_hash ~ '^[0-9a-f]{64}$'),
 principal name NOT NULL,
 role_oid oid NOT NULL,
 product text NOT NULL REFERENCES public.products(product),
 repository text NOT NULL,
 repository_id bigint NOT NULL CHECK(repository_id>0),
 pr_number bigint NOT NULL CHECK(pr_number>0),
 authority jsonb NOT NULL CHECK(jsonb_typeof(authority)='object'),
 snapshot jsonb NOT NULL CHECK(jsonb_typeof(snapshot)='object'),
 receipt jsonb NOT NULL CHECK(jsonb_typeof(receipt)='object'),
 assignment_id uuid NOT NULL,
 lease_id uuid NOT NULL,
 lease_epoch bigint NOT NULL CHECK(lease_epoch>0),
 existing_receipt_ref text NOT NULL CHECK(length(trim(existing_receipt_ref))>0),
 scope_type text NOT NULL,
 scope_name text NOT NULL,
 accepted_by text NOT NULL CHECK(accepted_by='Ralph L. Appolon'),
 acceptance_ref text NOT NULL CHECK(length(trim(acceptance_ref))>0),
 purpose text NOT NULL CHECK(purpose='SCOPE_CERTIFICATION'),
 origin text NOT NULL CHECK(origin='INDEPENDENTLY_AUTHENTICATED_EXISTING_RECEIPT'),
 active boolean NOT NULL DEFAULT false,
 expires_at timestamptz NOT NULL,
 FOREIGN KEY(principal,product) REFERENCES certifier_authority.product_grants(principal,product)
);
REVOKE ALL ON ALL TABLES IN SCHEMA certifier_authority FROM PUBLIC;
COMMENT ON TABLE certifier_authority.existing_receipts IS
 'Operator-owned acceptance of an independently authenticated existing scope receipt. Empty by default; runtime must never own/write/register receipts. Not legacy PASS, a promotion decision, or new certification issuance.';
COMMIT;
