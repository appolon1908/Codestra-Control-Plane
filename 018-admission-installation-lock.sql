-- Separately administered prerequisite, NOT an installer migration. Run under
-- an accepted NOLOGIN owner; no role, profile or privilege grant is seeded.
-- Only that owner needs table-level UPDATE for PostgreSQL's lock permission.
-- It also needs one-way INHERIT membership in the operator/reader roles to
-- inspect their own-backend TLS statistics inside SECURITY DEFINER. Require
-- INHERIT TRUE, SET FALSE, ADMIN FALSE; never grant the reverse membership. The
-- trusted owner consequently inherits their existing rights as well as locks.
-- Callers receive EXECUTE, never membership in the owner or legacy owner roles.
BEGIN;
DO $$
BEGIN
 IF EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=current_user AND
   (rolcanlogin OR rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls))
 THEN RAISE EXCEPTION 'RESTRICTED_NOLOGIN_LOCK_OWNER_REQUIRED'; END IF;
END $$;
CREATE SCHEMA admission_installation_lock;
REVOKE ALL ON SCHEMA admission_installation_lock FROM PUBLIC;
CREATE TABLE admission_installation_lock.profile (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 revision bigint NOT NULL CHECK(revision>0),
 system_identifier text NOT NULL,
 database_oid oid NOT NULL,
 operator name NOT NULL, operator_oid oid NOT NULL,
 verifier name NOT NULL, verifier_oid oid NOT NULL,
 valid_until timestamptz NOT NULL CHECK(isfinite(valid_until)),
 active boolean NOT NULL DEFAULT false,
 relations jsonb NOT NULL CHECK(jsonb_typeof(relations)='array'),
 CHECK(operator<>verifier AND operator_oid<>verifier_oid)
);
REVOKE ALL ON ALL TABLES IN SCHEMA admission_installation_lock FROM PUBLIC;

CREATE FUNCTION admission_installation_lock._profile_revision() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
BEGIN
 IF TG_OP<>'UPDATE' THEN RAISE EXCEPTION 'LOCK_PROFILE_HISTORY_REQUIRED'; END IF;
 NEW.revision:=OLD.revision+1;
 RETURN NEW;
END $$;
CREATE TRIGGER profile_revision BEFORE UPDATE OR DELETE ON admission_installation_lock.profile
FOR EACH ROW EXECUTE FUNCTION admission_installation_lock._profile_revision();
CREATE TRIGGER profile_truncate BEFORE TRUNCATE ON admission_installation_lock.profile
FOR EACH STATEMENT EXECUTE FUNCTION admission_installation_lock._profile_revision();

CREATE FUNCTION admission_installation_lock.describe() RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE p admission_installation_lock.profile; actual jsonb; owner_oid oid; actor_oid oid;
BEGIN
 SELECT oid INTO actor_oid FROM pg_catalog.pg_roles WHERE rolname=session_user;
 SELECT nspowner INTO owner_oid FROM pg_catalog.pg_namespace WHERE nspname='admission_installation_lock';
 IF system_user IS DISTINCT FROM 'scram-sha-256:'||session_user::text
 OR current_setting('role')<>'none' OR pg_is_in_recovery()
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_ssl WHERE pid=pg_backend_pid() AND ssl)
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE oid=owner_oid AND rolname=current_user
   AND NOT (rolcanlogin OR rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls))
 OR pg_has_role(actor_oid,owner_oid,'MEMBER')
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc f JOIN pg_catalog.pg_namespace n ON n.oid=f.pronamespace
   WHERE n.nspname='admission_installation_lock' AND
    (f.prokind<>'f' OR f.provolatile<>'v' OR f.proparallel<>'u' OR f.proretset OR f.proisstrict
     OR f.proleakproof OR f.prosupport<>0 OR f.pronargdefaults<>0 OR f.provariadic<>0))
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='admission_installation_lock' AND c.relname='profile' AND
    (c.relowner<>owner_oid OR c.relkind<>'r' OR c.relrowsecurity OR c.relforcerowsecurity
     OR EXISTS(SELECT 1 FROM pg_catalog.pg_rewrite w WHERE w.ev_class=c.oid)
     OR EXISTS(SELECT 1 FROM pg_catalog.pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid)
     OR (SELECT count(*) FROM pg_catalog.pg_trigger t WHERE t.tgrelid=c.oid AND NOT t.tgisinternal)<>2
     OR (SELECT count(*) FROM pg_catalog.pg_trigger t WHERE t.tgrelid=c.oid AND NOT t.tgisinternal
       AND t.tgfoid='admission_installation_lock._profile_revision()'::regprocedure
       AND t.tgenabled='O' AND t.tgnargs=0 AND t.tgqual IS NULL
       AND NOT t.tgdeferrable AND NOT t.tginitdeferred AND t.tgconstraint=0
       AND t.tgoldtable IS NULL AND t.tgnewtable IS NULL
       AND ((t.tgname='profile_revision' AND t.tgtype=27) OR (t.tgname='profile_truncate' AND t.tgtype=34)))<>2
     OR EXISTS(SELECT 1 FROM pg_catalog.aclexplode(coalesce(c.relacl,pg_catalog.acldefault('r',c.relowner))) a
       WHERE a.grantee<>owner_oid)
     OR EXISTS(SELECT 1 FROM pg_catalog.pg_attribute att CROSS JOIN LATERAL pg_catalog.aclexplode(att.attacl) a
       WHERE att.attrelid=c.oid AND a.grantee<>owner_oid)
     OR EXISTS(SELECT 1 FROM pg_catalog.pg_roles r
      WHERE pg_has_role(actor_oid,r.oid,'MEMBER') AND
       (pg_catalog.has_table_privilege(r.oid,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
        OR pg_catalog.has_any_column_privilege(r.oid,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))))
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n CROSS JOIN LATERAL
   pg_catalog.aclexplode(coalesce(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) a
   WHERE n.nspname='admission_installation_lock' AND a.privilege_type='CREATE' AND a.grantee<>owner_oid)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_roles r WHERE pg_has_role(actor_oid,r.oid,'MEMBER') AND
   (r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls
    OR r.rolname IN ('pg_read_server_files','pg_write_server_files','pg_execute_server_program')))
 THEN RAISE EXCEPTION 'LOCK_AUTHENTICATION_REQUIRED'; END IF;
 SELECT * INTO STRICT p FROM admission_installation_lock.profile WHERE singleton;
 IF NOT p.active OR NOT isfinite(p.valid_until) OR p.valid_until<=clock_timestamp()
 OR p.system_identifier IS DISTINCT FROM (pg_control_system()).system_identifier::text
 OR p.database_oid IS DISTINCT FROM (SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())
 OR NOT ((session_user=p.operator AND actor_oid=p.operator_oid)
      OR (session_user=p.verifier AND actor_oid=p.verifier_oid))
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=p.operator AND oid=p.operator_oid)
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=p.verifier AND oid=p.verifier_oid)
 THEN RAISE EXCEPTION 'LOCK_PROFILE_DENIED'; END IF;
 SELECT jsonb_agg(jsonb_build_object('name',c.relname,'oid',c.oid::bigint,
   'namespace_oid',n.oid::bigint,'owner_oid',c.relowner::bigint,'kind',c.relkind) ORDER BY c.relname)
 INTO actual FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relkind IN ('r','p','f');
 IF actual IS DISTINCT FROM p.relations
 OR (SELECT array_agg(x->>'name' ORDER BY x->>'name') FROM jsonb_array_elements(actual) x)
    IS DISTINCT FROM ARRAY['atomic_tasks','events','family_components','family_programs','products',
     'promotion_attempts','promotion_edges','promotion_evidence','scope_certifications','sections','workstations']
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='public' AND c.relkind IN ('r','p','f') AND
    (c.relkind<>'r' OR c.relispartition OR pg_has_role(actor_oid,c.relowner,'MEMBER')
     OR EXISTS(SELECT 1 FROM pg_catalog.pg_roles r WHERE pg_has_role(actor_oid,r.oid,'MEMBER')
       AND has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER'))
     OR EXISTS(SELECT 1 FROM pg_catalog.pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid)))
 THEN RAISE EXCEPTION 'LOCK_RELATION_VECTOR_CHANGED'; END IF;
 RETURN jsonb_build_object('profile',to_jsonb(p),'profile_sha256',
   encode(sha256(convert_to(to_jsonb(p)::text,'UTF8')),'hex'));
END $$;

CREATE FUNCTION admission_installation_lock.acquire(expected_profile_sha256 text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE before_snapshot jsonb; after_snapshot jsonb; relation_name text;
BEGIN
 before_snapshot:=admission_installation_lock.describe();
 IF expected_profile_sha256 IS DISTINCT FROM before_snapshot->>'profile_sha256'
 OR session_user IS DISTINCT FROM before_snapshot->'profile'->>'operator'
 THEN RAISE EXCEPTION 'LOCK_PROFILE_DENIED'; END IF;
 -- Row lock fences profile edits until the outer transaction ends. Expiry or
 -- revocation cannot release locks already held: this delegates bounded-target
 -- lock capability, including lock-duration denial of service, to the operator.
 PERFORM 1 FROM admission_installation_lock.profile WHERE singleton FOR SHARE;
 IF admission_installation_lock.describe() IS DISTINCT FROM before_snapshot
 THEN RAISE EXCEPTION 'LOCK_PROFILE_CHANGED'; END IF;
 FOR relation_name IN SELECT unnest(ARRAY['atomic_tasks','events','family_components','family_programs','products',
   'promotion_attempts','promotion_edges','promotion_evidence','scope_certifications','sections','workstations']) LOOP
   EXECUTE format('LOCK TABLE ONLY public.%I IN ACCESS EXCLUSIVE MODE',relation_name);
 END LOOP;
 after_snapshot:=admission_installation_lock.describe();
 IF after_snapshot IS DISTINCT FROM before_snapshot THEN RAISE EXCEPTION 'LOCK_PROFILE_CHANGED'; END IF;
 RETURN after_snapshot;
END $$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA admission_installation_lock FROM PUBLIC;
COMMIT;
