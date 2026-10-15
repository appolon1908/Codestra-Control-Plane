-- Source contract only. Never executed against the installed database here.
-- Apply as an operator under separately approved provisioning. Runtime receives
-- USAGE + SELECT only; neither roles nor grants are created by this migration.
BEGIN;
CREATE SCHEMA publisher_authority;
REVOKE ALL ON SCHEMA publisher_authority FROM PUBLIC;
CREATE TABLE publisher_authority.bindings (
 binding_hash text PRIMARY KEY CHECK(binding_hash ~ '^[0-9a-f]{64}$'),
 principal name NOT NULL,
 role_oid oid NOT NULL,
 active boolean NOT NULL DEFAULT false,
 expires_at timestamptz NOT NULL,
 authority jsonb NOT NULL CHECK(jsonb_typeof(authority)='object'),
 snapshot jsonb NOT NULL CHECK(jsonb_typeof(snapshot)='object'),
 repository_id bigint NOT NULL CHECK(repository_id>0),
 pr_number bigint NOT NULL CHECK(pr_number>0),
 certificate_check_id bigint NOT NULL CHECK(certificate_check_id>0)
);
REVOKE ALL ON publisher_authority.bindings FROM PUBLIC;
COMMENT ON TABLE publisher_authority.bindings IS
 'Operator-owned exact binding acquisition read model. Not a PASS/certification writer. Runtime must never own or mutate this table. Receipt provenance is independently checked online.';
COMMIT;
