-- Separate issuer-cluster source. NEVER part of an installation-target profile.
-- Profiles and three independent restricted identities are external prerequisites.
-- No roles, grants, profiles, credentials, installation or activation are seeded.
BEGIN;
CREATE SCHEMA admission_bootstrap;
REVOKE ALL ON SCHEMA admission_bootstrap FROM PUBLIC;

CREATE FUNCTION admission_bootstrap._quote(value text) RETURNS text LANGUAGE plpgsql IMMUTABLE
SET search_path=pg_catalog,pg_temp AS $$
DECLARE result text:='"';character text;code integer;
BEGIN
 FOREACH character IN ARRAY string_to_array(value,NULL) LOOP
  code:=ascii(character);
  IF code IN (34,92) THEN result:=result||chr(92)||character;
  ELSIF code IN (8,9,10,12,13) THEN result:=result||chr(92)||CASE code WHEN 8 THEN 'b' WHEN 9 THEN 't' WHEN 10 THEN 'n' WHEN 12 THEN 'f' ELSE 'r' END;
  ELSIF code<32 OR code>126 THEN
   IF code>65535 THEN
    result:=result||chr(92)||'u'||lpad(to_hex(55296+(code-65536)/1024),4,'0')||chr(92)||'u'||lpad(to_hex(56320+(code-65536)%1024),4,'0');
   ELSE result:=result||chr(92)||'u'||lpad(to_hex(code),4,'0'); END IF;
  ELSE result:=result||character;
  END IF;
 END LOOP;
 RETURN result||'"';
END $$;
CREATE FUNCTION admission_bootstrap._canonical(value jsonb,depth integer DEFAULT 0) RETURNS text LANGUAGE plpgsql IMMUTABLE
SET search_path=pg_catalog,pg_temp AS $$
DECLARE result text;
BEGIN
 IF depth>32 THEN RAISE EXCEPTION 'AUTHORITY_INVALID_BINDING'; END IF;
 CASE jsonb_typeof(value)
 WHEN 'object' THEN
  SELECT '{'||coalesce(string_agg(admission_bootstrap._quote(key)||':'||admission_bootstrap._canonical(item,depth+1),',' ORDER BY key COLLATE "C"),'')||'}' INTO result FROM jsonb_each(value) entry(key,item);
 WHEN 'array' THEN
  SELECT '['||coalesce(string_agg(admission_bootstrap._canonical(item,depth+1),',' ORDER BY ordinal),'')||']' INTO result FROM jsonb_array_elements(value) WITH ORDINALITY entry(item,ordinal);
 WHEN 'string' THEN result:=admission_bootstrap._quote(value#>>'{}');
 WHEN 'number' THEN
  IF value::text !~ '^-?(0|[1-9][0-9]*)$' THEN RAISE EXCEPTION 'AUTHORITY_INVALID_BINDING'; END IF;
  result:=value::text;
 WHEN 'boolean' THEN result:=value::text;
 WHEN 'null' THEN result:='null';
 ELSE RAISE EXCEPTION 'AUTHORITY_INVALID_BINDING';
 END CASE;
 RETURN result;
END $$;
CREATE FUNCTION admission_bootstrap._binding(value jsonb) RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE target jsonb;own_identifier text;
BEGIN
 IF current_setting('server_encoding')<>'UTF8' OR jsonb_typeof(value) IS DISTINCT FROM 'object' OR pg_column_size(value)>1048576
 OR NOT value ?& ARRAY['attempt_id','plan_sha256','source_commit','manifest_sha256','target','filesystem','configuration_sha256','request_sha256']
 OR value-ARRAY['attempt_id','plan_sha256','source_commit','manifest_sha256','target','filesystem','configuration_sha256','request_sha256']<>'{}'::jsonb
 OR jsonb_typeof(value->'attempt_id') IS DISTINCT FROM 'string'
 OR value->>'attempt_id' IS DISTINCT FROM ((value->>'attempt_id')::uuid)::text
 OR EXISTS(SELECT 1 FROM unnest(ARRAY['plan_sha256','manifest_sha256','configuration_sha256','request_sha256']) key WHERE jsonb_typeof(value->key) IS DISTINCT FROM 'string' OR value->>key !~ '^[0-9a-f]{64}$' OR value->>key=repeat('0',64))
 OR jsonb_typeof(value->'source_commit') IS DISTINCT FROM 'string' OR value->>'source_commit' !~ '^[0-9a-f]{40}$' OR value->>'source_commit'=repeat('0',40)
 OR jsonb_typeof(value->'filesystem') IS DISTINCT FROM 'object'
 OR NOT (value->'filesystem') ?& ARRAY['path','device','inode','uid','gid','mode']
 OR (value->'filesystem')-ARRAY['path','device','inode','uid','gid','mode','runtime']<>'{}'::jsonb
 OR jsonb_typeof(value->'filesystem'->'path') IS DISTINCT FROM 'string'
 OR value->'filesystem'->>'path' !~ '^/' OR right(value->'filesystem'->>'path',1)='/'
 OR position('//' in value->'filesystem'->>'path')>0 OR value->'filesystem'->>'path' ~ '(^|/)\.\.?(/|$)'
 OR value->'filesystem'->>'mode' IS DISTINCT FROM '0o700'
 OR EXISTS(SELECT 1 FROM unnest(ARRAY['device','inode','uid','gid']) key
  WHERE jsonb_typeof(value->'filesystem'->key) IS DISTINCT FROM 'number' OR value->'filesystem'->>key !~ '^(0|[1-9][0-9]*)$')
 OR value->'filesystem'->>'inode'='0'
 OR ((value->'filesystem') ? 'runtime' AND jsonb_typeof(value->'filesystem'->'runtime') IS DISTINCT FROM 'object')
 THEN RETURN false; END IF;
 target:=value->'target';
 IF jsonb_typeof(target) IS DISTINCT FROM 'object' OR NOT target ?& ARRAY['system_identifier','database_oid','database_name','session_user','role_oid']
 OR target-ARRAY['system_identifier','database_oid','database_name','session_user','role_oid']<>'{}'::jsonb
 OR EXISTS(SELECT 1 FROM unnest(ARRAY['system_identifier','database_name','session_user']) key WHERE jsonb_typeof(target->key) IS DISTINCT FROM 'string' OR target->>key='')
 OR target->>'system_identifier' !~ '^[0-9]+$'
 OR EXISTS(SELECT 1 FROM unnest(ARRAY['database_oid','role_oid']) key WHERE jsonb_typeof(target->key) IS DISTINCT FROM 'number' OR target->>key !~ '^[1-9][0-9]*$')
 THEN RETURN false; END IF;
 SELECT system_identifier::text INTO own_identifier FROM pg_control_system();
 RETURN own_identifier IS DISTINCT FROM target->>'system_identifier'
 AND value->>'request_sha256'=encode(sha256(convert_to(admission_bootstrap._canonical(value-'request_sha256'),'UTF8')),'hex');
END $$;

CREATE TABLE admission_bootstrap.profiles (
 profile_id uuid PRIMARY KEY,revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
 operator name NOT NULL,operator_oid oid NOT NULL,verifier name NOT NULL,verifier_oid oid NOT NULL,
 client name NOT NULL,client_oid oid NOT NULL,target_verifier_oid oid NOT NULL CHECK(target_verifier_oid>0),
 binding jsonb NOT NULL,custody_scope text NOT NULL CHECK(custody_scope=btrim(custody_scope) AND length(custody_scope) BETWEEN 1 AND 1024),
 not_before timestamptz NOT NULL,expires_at timestamptz NOT NULL,rollback_expires_at timestamptz NOT NULL,
 active boolean NOT NULL DEFAULT false,
 CHECK(isfinite(not_before) AND isfinite(expires_at) AND isfinite(rollback_expires_at)),
 CHECK(expires_at>not_before AND rollback_expires_at>=expires_at),
 CHECK(operator<>verifier AND operator<>client AND verifier<>client),
 CHECK(operator_oid<>verifier_oid AND operator_oid<>client_oid AND verifier_oid<>client_oid)
);
COMMENT ON COLUMN admission_bootstrap.profiles.custody_scope IS
 'Independently administered host-qualified installation collision domain, accepted with the exact binding; a filesystem path alone does not establish host identity.';
CREATE TABLE admission_bootstrap.requests (
 request_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),profile_id uuid NOT NULL REFERENCES admission_bootstrap.profiles(profile_id),
 operator_oid oid NOT NULL,client_request_id text NOT NULL,request_digest text NOT NULL,profile_snapshot jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(operator_oid,client_request_id)
);
CREATE TABLE admission_bootstrap.acceptances (
 request_id uuid PRIMARY KEY REFERENCES admission_bootstrap.requests(request_id),proof_id uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
 verifier name NOT NULL,verifier_oid oid NOT NULL,authentication text NOT NULL,request_digest text NOT NULL,
 accepted_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE admission_bootstrap.grants (
 grant_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),request_id uuid NOT NULL UNIQUE REFERENCES admission_bootstrap.requests(request_id),
 profile_snapshot jsonb NOT NULL,binding jsonb NOT NULL,issued_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE admission_bootstrap.reservations (
 scope_key text PRIMARY KEY,grant_id uuid NOT NULL REFERENCES admission_bootstrap.grants(grant_id)
);
CREATE TABLE admission_bootstrap.revocations (
 grant_id uuid PRIMARY KEY REFERENCES admission_bootstrap.grants(grant_id),revoked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 reason text NOT NULL,actor name NOT NULL,actor_oid oid NOT NULL,authentication text
);
CREATE TABLE admission_bootstrap.revoke_requests (
 nonce uuid PRIMARY KEY,grant_id uuid NOT NULL REFERENCES admission_bootstrap.grants(grant_id),binding jsonb NOT NULL,response jsonb NOT NULL
);
CREATE TABLE admission_bootstrap.audit (
 audit_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,request_id uuid NOT NULL REFERENCES admission_bootstrap.requests(request_id),
 actor name NOT NULL,actor_oid oid NOT NULL,authentication text NOT NULL,action text NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON ALL TABLES IN SCHEMA admission_bootstrap FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA admission_bootstrap FROM PUBLIC;

CREATE FUNCTION admission_bootstrap._restricted(actor name,actor_oid oid) RETURNS boolean LANGUAGE sql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
 SELECT EXISTS(SELECT 1 FROM pg_roles r WHERE r.rolname=actor AND r.oid=actor_oid AND r.rolcanlogin
  AND (r.rolvaliduntil IS NULL OR r.rolvaliduntil>clock_timestamp()))
 AND NOT EXISTS(SELECT 1 FROM pg_roles r WHERE (r.oid=actor_oid OR pg_has_role(actor_oid,r.oid,'MEMBER')) AND (
 r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls
 OR r.rolname IN ('pg_read_server_files','pg_write_server_files','pg_execute_server_program')
 OR EXISTS(SELECT 1 FROM pg_database d WHERE d.datname=current_database() AND (d.datdba=r.oid OR has_database_privilege(r.oid,d.oid,'CREATE')))
 OR EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema' AND (n.nspowner=r.oid OR has_schema_privilege(r.oid,n.oid,'CREATE')))
 OR EXISTS(SELECT 1 FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema' AND
  (t.relowner=r.oid OR t.relkind IN ('r','p','v','m','f') AND (has_table_privilege(r.oid,t.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(r.oid,t.oid,'INSERT,UPDATE,REFERENCES'))
   OR t.relkind='S' AND has_sequence_privilege(r.oid,t.oid,'USAGE,UPDATE')))
 OR EXISTS(SELECT 1 FROM pg_proc f JOIN pg_namespace n ON n.oid=f.pronamespace WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema' AND f.proowner=r.oid)
 OR EXISTS(SELECT 1 FROM pg_proc f JOIN pg_namespace n ON n.oid=f.pronamespace WHERE n.nspname='pg_catalog'
  AND f.proname IN ('lo_import','lo_export','pg_read_file','pg_read_binary_file','pg_stat_file','pg_ls_dir',
    'pg_ls_logdir','pg_ls_waldir','pg_ls_archive_statusdir','pg_ls_tmpdir','pg_ls_logicalsnapdir','pg_ls_logicalmapdir','pg_ls_replslotdir',
    'pg_backup_start','pg_backup_stop','pg_create_restore_point','pg_switch_wal','pg_log_standby_snapshot','pg_wal_replay_pause','pg_wal_replay_resume',
    'pg_rotate_logfile','pg_reload_conf','pg_promote','pg_log_backend_memory_contexts','pg_stat_reset','pg_stat_reset_shared','pg_stat_reset_slru',
    'pg_stat_reset_single_table_counters','pg_stat_reset_single_function_counters','pg_stat_reset_replication_slot','pg_stat_reset_subscription_stats',
    'pg_replication_origin_advance','pg_replication_origin_create','pg_replication_origin_drop','pg_replication_origin_session_reset',
    'pg_replication_origin_session_setup','pg_replication_origin_xact_reset','pg_replication_origin_xact_setup')
  AND has_function_privilege(r.oid,f.oid,'EXECUTE'))
 ))
$$;
CREATE FUNCTION admission_bootstrap._actor() RETURNS oid LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE actor_oid oid;
BEGIN
 SELECT oid INTO actor_oid FROM pg_roles WHERE rolname=session_user;
 IF current_setting('server_encoding')<>'UTF8'
 OR system_user IS DISTINCT FROM 'scram-sha-256:'||session_user::text OR current_setting('role')<>'none'
 OR current_setting('transaction_isolation')<>'read committed' OR pg_is_in_recovery()
 OR NOT EXISTS(SELECT 1 FROM pg_stat_ssl WHERE pid=pg_backend_pid() AND ssl)
 OR NOT admission_bootstrap._restricted(session_user,actor_oid)
 THEN RAISE EXCEPTION 'AUTHORITY_AUTHENTICATION_REQUIRED'; END IF;
 RETURN actor_oid;
END $$;
CREATE FUNCTION admission_bootstrap._profile(profile_uuid uuid) RETURNS admission_bootstrap.profiles LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE p admission_bootstrap.profiles;
BEGIN
 SELECT * INTO p FROM admission_bootstrap.profiles WHERE profile_id=profile_uuid;
 IF NOT FOUND OR NOT p.active OR p.not_before>clock_timestamp() OR p.expires_at<=clock_timestamp()
 OR NOT admission_bootstrap._restricted(p.operator,p.operator_oid) OR NOT admission_bootstrap._restricted(p.verifier,p.verifier_oid)
 OR NOT admission_bootstrap._restricted(p.client,p.client_oid) THEN RAISE EXCEPTION 'AUTHORITY_PROFILE_DENIED'; END IF;
 RETURN p;
END $$;
CREATE FUNCTION admission_bootstrap._request(request_uuid uuid) RETURNS admission_bootstrap.requests LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE r admission_bootstrap.requests;p admission_bootstrap.profiles;
BEGIN
 SELECT * INTO r FROM admission_bootstrap.requests WHERE request_id=request_uuid;
 IF NOT FOUND THEN RAISE EXCEPTION 'AUTHORITY_REQUEST_NOT_FOUND'; END IF;
 p:=admission_bootstrap._profile(r.profile_id);
 IF to_jsonb(p) IS DISTINCT FROM r.profile_snapshot THEN RAISE EXCEPTION 'AUTHORITY_PROFILE_CHANGED'; END IF;
 RETURN r;
END $$;
CREATE FUNCTION admission_bootstrap._audit(request_uuid uuid,action_name text) RETURNS void LANGUAGE sql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
 INSERT INTO admission_bootstrap.audit(request_id,actor,actor_oid,authentication,action)
 VALUES(request_uuid,session_user,admission_bootstrap._actor(),system_user,action_name)
$$;
CREATE FUNCTION admission_bootstrap._receipt(r admission_bootstrap.requests,state text) RETURNS jsonb LANGUAGE sql
SET search_path=pg_catalog,pg_temp AS $$
 SELECT jsonb_build_object('request_id',r.request_id,'profile_id',r.profile_id,'request_digest',r.request_digest,'state',state,'usable',false)
$$;
CREATE FUNCTION admission_bootstrap.request(profile_uuid uuid,client_request_id text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE p admission_bootstrap.profiles;r admission_bootstrap.requests;actor_oid oid;
BEGIN
 actor_oid:=admission_bootstrap._actor();PERFORM set_config('synchronous_commit','on',true);
 p:=admission_bootstrap._profile(profile_uuid);
 IF p.operator<>session_user OR p.operator_oid<>actor_oid THEN RAISE EXCEPTION 'AUTHORITY_PROFILE_DENIED'; END IF;
 IF client_request_id IS NULL OR client_request_id !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' THEN RAISE EXCEPTION 'AUTHORITY_REQUEST_CONFLICT'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('issuer-request:'||actor_oid::text||':'||client_request_id,1717));
 SELECT * INTO r FROM admission_bootstrap.requests q WHERE q.operator_oid=actor_oid AND q.client_request_id=request.client_request_id;
 IF FOUND THEN
  IF r.profile_id<>profile_uuid OR r.profile_snapshot IS DISTINCT FROM to_jsonb(p) THEN RAISE EXCEPTION 'AUTHORITY_REQUEST_CONFLICT'; END IF;
 ELSE
  INSERT INTO admission_bootstrap.requests(profile_id,operator_oid,client_request_id,request_digest,profile_snapshot)
  VALUES(p.profile_id,actor_oid,client_request_id,encode(sha256(convert_to(admission_bootstrap._canonical(to_jsonb(p)),'UTF8')),'hex'),to_jsonb(p)) RETURNING * INTO r;
  PERFORM admission_bootstrap._audit(r.request_id,'REQUEST');
 END IF;
 RETURN admission_bootstrap._receipt(r,'REQUESTED');
END $$;
CREATE FUNCTION admission_bootstrap.accept(request_uuid uuid) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE r admission_bootstrap.requests;actor_oid oid;a admission_bootstrap.acceptances;
BEGIN
 actor_oid:=admission_bootstrap._actor();PERFORM set_config('synchronous_commit','on',true);r:=admission_bootstrap._request(request_uuid);
 IF r.profile_snapshot->>'verifier'<>session_user::text OR (r.profile_snapshot->>'verifier_oid')::oid<>actor_oid THEN RAISE EXCEPTION 'AUTHORITY_PROFILE_DENIED'; END IF;
 INSERT INTO admission_bootstrap.acceptances(request_id,verifier,verifier_oid,authentication,request_digest)
 VALUES(r.request_id,session_user,actor_oid,system_user,r.request_digest) ON CONFLICT DO NOTHING;
 SELECT * INTO a FROM admission_bootstrap.acceptances WHERE request_id=r.request_id;
 PERFORM admission_bootstrap._audit(r.request_id,'ACCEPT');
 RETURN admission_bootstrap._receipt(r,'ACCEPTED')||jsonb_build_object('proof_id',a.proof_id);
END $$;
CREATE FUNCTION admission_bootstrap._retire(grant_uuid uuid,reason text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 PERFORM set_config('synchronous_commit','on',true);
 INSERT INTO admission_bootstrap.revocations(grant_id,reason,actor,actor_oid,authentication)
 VALUES(grant_uuid,reason,session_user,(SELECT oid FROM pg_roles WHERE rolname=session_user),system_user) ON CONFLICT DO NOTHING;
 DELETE FROM admission_bootstrap.reservations WHERE grant_id=grant_uuid;
END $$;
CREATE FUNCTION admission_bootstrap.issue(request_uuid uuid) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE r admission_bootstrap.requests;actor_oid oid;g admission_bootstrap.grants;scope text;keys text[];lock_key bigint;
BEGIN
 actor_oid:=admission_bootstrap._actor();PERFORM set_config('synchronous_commit','on',true);r:=admission_bootstrap._request(request_uuid);
 IF r.operator_oid<>actor_oid OR r.profile_snapshot->>'operator'<>session_user::text THEN RAISE EXCEPTION 'AUTHORITY_PROFILE_DENIED'; END IF;
 keys:=ARRAY['custody:'||(r.profile_snapshot->>'custody_scope'),
  'target:'||(r.profile_snapshot->'binding'->'target'->>'system_identifier')||':'||(r.profile_snapshot->'binding'->'target'->>'database_oid')];
 FOR lock_key IN SELECT DISTINCT hashtextextended(k,1717) FROM unnest(keys) k ORDER BY 1 LOOP PERFORM pg_advisory_xact_lock(lock_key); END LOOP;
 PERFORM 1 FROM admission_bootstrap.profiles WHERE profile_id=r.profile_id FOR SHARE;
 PERFORM 1 FROM admission_bootstrap.requests WHERE request_id=request_uuid FOR UPDATE;
 r:=admission_bootstrap._request(request_uuid);
 SELECT * INTO g FROM admission_bootstrap.grants WHERE request_id=request_uuid;
 IF FOUND THEN
  IF EXISTS(SELECT 1 FROM admission_bootstrap.revocations WHERE grant_id=g.grant_id) THEN RAISE EXCEPTION 'AUTHORITY_REVOKED'; END IF;
  RETURN admission_bootstrap._receipt(r,'ISSUED')||jsonb_build_object('grant_id',g.grant_id);
 END IF;
 IF NOT EXISTS(SELECT 1 FROM admission_bootstrap.acceptances a WHERE a.request_id=r.request_id AND a.request_digest=r.request_digest
  AND a.verifier::text=r.profile_snapshot->>'verifier' AND a.verifier_oid=(r.profile_snapshot->>'verifier_oid')::oid
  AND a.authentication='scram-sha-256:'||a.verifier::text) THEN RAISE EXCEPTION 'AUTHORITY_ACCEPTANCE_REQUIRED'; END IF;
 IF EXISTS(SELECT 1 FROM admission_bootstrap.reservations WHERE scope_key=ANY(keys)) THEN RAISE EXCEPTION 'AUTHORITY_SCOPE_HELD'; END IF;
 INSERT INTO admission_bootstrap.grants(request_id,profile_snapshot,binding) VALUES(r.request_id,r.profile_snapshot,r.profile_snapshot->'binding') RETURNING * INTO g;
 FOREACH scope IN ARRAY keys LOOP INSERT INTO admission_bootstrap.reservations VALUES(scope,g.grant_id); END LOOP;
 PERFORM admission_bootstrap._audit(r.request_id,'ISSUE');
 RETURN admission_bootstrap._receipt(r,'ISSUED')||jsonb_build_object('grant_id',g.grant_id);
END $$;
CREATE FUNCTION admission_bootstrap.inspect(request_uuid uuid) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE r admission_bootstrap.requests;g admission_bootstrap.grants;actor_oid oid;state text;
BEGIN
 actor_oid:=admission_bootstrap._actor();SELECT * INTO r FROM admission_bootstrap.requests WHERE request_id=request_uuid;
 IF NOT FOUND OR NOT ((r.profile_snapshot->>'operator'=session_user::text AND (r.profile_snapshot->>'operator_oid')::oid=actor_oid)
  OR (r.profile_snapshot->>'verifier'=session_user::text AND (r.profile_snapshot->>'verifier_oid')::oid=actor_oid)) THEN RAISE EXCEPTION 'AUTHORITY_PROFILE_DENIED'; END IF;
 SELECT * INTO g FROM admission_bootstrap.grants WHERE request_id=request_uuid;
 state:=CASE WHEN g.grant_id IS NOT NULL THEN CASE WHEN EXISTS(SELECT 1 FROM admission_bootstrap.revocations WHERE grant_id=g.grant_id) THEN 'REVOKED' ELSE 'ISSUED' END
  WHEN EXISTS(SELECT 1 FROM admission_bootstrap.acceptances WHERE request_id=request_uuid) THEN 'ACCEPTED' ELSE 'REQUESTED' END;
 RETURN admission_bootstrap._receipt(r,state)||jsonb_build_object('grant_id',g.grant_id,'authority','NONE','historical',true);
END $$;
CREATE FUNCTION admission_bootstrap._rpc(grant_uuid uuid,provided jsonb) RETURNS admission_bootstrap.grants LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE g admission_bootstrap.grants;actor_oid oid;
BEGIN
 actor_oid:=admission_bootstrap._actor();SELECT * INTO g FROM admission_bootstrap.grants WHERE grant_id=grant_uuid;
 IF NOT FOUND OR g.profile_snapshot->>'client'<>session_user::text OR (g.profile_snapshot->>'client_oid')::oid<>actor_oid
 THEN RAISE EXCEPTION 'AUTHORITY_PROFILE_DENIED'; END IF;
 IF provided IS NULL THEN RAISE EXCEPTION 'AUTHORITY_BINDING_MISMATCH'; END IF;
 RETURN g;
END $$;
CREATE FUNCTION admission_bootstrap.describe(grant_uuid uuid,operation text,binding jsonb,phase text,nonce uuid) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE g admission_bootstrap.grants;p admission_bootstrap.profiles;expected jsonb;revoked timestamptz;observed timestamptz;expiry timestamptz;
BEGIN
 g:=admission_bootstrap._rpc(grant_uuid,binding);
 IF nonce IS NULL OR NOT coalesce((operation='install' AND phase IN ('preflight','intent','database','database_commit','files','files_commit','configuration','configuration_commit','receipt','receipt_commit','return'))
  OR (operation='verify' AND phase IN ('preflight','return')) OR (operation='rollback' AND phase IN ('revoke','record_revocation','return')),false)
 THEN RAISE EXCEPTION 'AUTHORITY_PHASE_DENIED'; END IF;
 expected:=g.binding;
 IF operation='verify' THEN expected:=expected||jsonb_build_object('verifier_role_oid',(g.profile_snapshot->>'target_verifier_oid')::bigint); END IF;
 IF binding IS DISTINCT FROM expected THEN RAISE EXCEPTION 'AUTHORITY_BINDING_MISMATCH'; END IF;
 SELECT revoked_at INTO revoked FROM admission_bootstrap.revocations WHERE grant_id=grant_uuid;
 observed:=clock_timestamp();expiry:=(g.profile_snapshot->>CASE WHEN operation='rollback' THEN 'rollback_expires_at' ELSE 'expires_at' END)::timestamptz;
 IF observed<(g.profile_snapshot->>'not_before')::timestamptz OR observed>=expiry THEN RAISE EXCEPTION 'AUTHORITY_EXPIRED'; END IF;
 IF operation<>'rollback' THEN
  p:=admission_bootstrap._profile((g.profile_snapshot->>'profile_id')::uuid);
  IF to_jsonb(p) IS DISTINCT FROM g.profile_snapshot THEN RAISE EXCEPTION 'AUTHORITY_PROFILE_CHANGED'; END IF;
  IF revoked IS NOT NULL THEN RAISE EXCEPTION 'AUTHORITY_REVOKED'; END IF;
 ELSIF phase IN ('record_revocation','return') AND revoked IS NULL THEN RAISE EXCEPTION 'AUTHORITY_REVOKED';
 END IF;
 RETURN jsonb_build_object('schema','codestra.admission-authority-response.v1','grant_id',g.grant_id,'operation',operation,'binding',expected,
  'phase',phase,'nonce',nonce,'observed_at',observed,'not_before',g.profile_snapshot->'not_before','expires_at',expiry,'revoked_at',revoked,'decision','ALLOWED');
END $$;
CREATE FUNCTION admission_bootstrap.revoke(grant_uuid uuid,binding jsonb,nonce uuid) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $$
DECLARE g admission_bootstrap.grants;prior admission_bootstrap.revoke_requests;response jsonb;
BEGIN
 PERFORM set_config('synchronous_commit','on',true);g:=admission_bootstrap._rpc(grant_uuid,binding);
 IF binding IS DISTINCT FROM g.binding THEN RAISE EXCEPTION 'AUTHORITY_BINDING_MISMATCH'; END IF;
 IF nonce IS NULL THEN RAISE EXCEPTION 'AUTHORITY_NONCE_CONFLICT'; END IF;
 IF clock_timestamp()<(g.profile_snapshot->>'not_before')::timestamptz OR clock_timestamp()>=(g.profile_snapshot->>'rollback_expires_at')::timestamptz
 THEN RAISE EXCEPTION 'AUTHORITY_EXPIRED'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('issuer-revoke-nonce:'||nonce::text,1717));
 PERFORM 1 FROM admission_bootstrap.grants WHERE grant_id=grant_uuid FOR UPDATE;
 SELECT * INTO prior FROM admission_bootstrap.revoke_requests WHERE revoke_requests.nonce=revoke.nonce;
 IF FOUND THEN
  IF prior.grant_id<>grant_uuid OR prior.binding IS DISTINCT FROM binding THEN RAISE EXCEPTION 'AUTHORITY_NONCE_CONFLICT'; END IF;
  RETURN prior.response;
 END IF;
 PERFORM admission_bootstrap._retire(grant_uuid,'RPC_REVOKE');
 response:=jsonb_build_object('grant_id',g.grant_id,'binding',g.binding,'nonce',nonce,'state','REVOKED');
 INSERT INTO admission_bootstrap.revoke_requests VALUES(nonce,grant_uuid,binding,response);
 PERFORM admission_bootstrap._audit(g.request_id,'REVOKE');RETURN response;
END $$;

CREATE FUNCTION admission_bootstrap._profile_revision() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE g admission_bootstrap.grants;
BEGIN
 PERFORM set_config('synchronous_commit','on',true);
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'AUTHORITY_HISTORY_IMMUTABLE'; END IF;
 IF NOT admission_bootstrap._binding(NEW.binding) OR NEW.target_verifier_oid=(NEW.binding->'target'->>'role_oid')::oid
 THEN RAISE EXCEPTION 'AUTHORITY_INVALID_BINDING'; END IF;
 IF TG_OP='UPDATE' THEN
  IF NEW.profile_id<>OLD.profile_id THEN RAISE EXCEPTION 'AUTHORITY_HISTORY_IMMUTABLE'; END IF;
  NEW.revision:=OLD.revision+1;
  FOR g IN SELECT * FROM admission_bootstrap.grants WHERE profile_snapshot->>'profile_id'=OLD.profile_id::text ORDER BY grant_id LOOP
   PERFORM 1 FROM admission_bootstrap.grants WHERE grant_id=g.grant_id FOR UPDATE;
   PERFORM admission_bootstrap._retire(g.grant_id,'PROFILE_REVISION');
  END LOOP;
 ELSE NEW.revision:=1;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER profile_revision BEFORE INSERT OR UPDATE OR DELETE ON admission_bootstrap.profiles FOR EACH ROW EXECUTE FUNCTION admission_bootstrap._profile_revision();
CREATE FUNCTION admission_bootstrap._immutable() RETURNS trigger LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp AS $$ BEGIN RAISE EXCEPTION 'AUTHORITY_HISTORY_IMMUTABLE'; END $$;
DO $$ DECLARE relation text;BEGIN
 FOREACH relation IN ARRAY ARRAY['requests','acceptances','grants','revocations','revoke_requests','audit'] LOOP
  EXECUTE format('CREATE TRIGGER immutable_history BEFORE UPDATE OR DELETE ON admission_bootstrap.%I FOR EACH ROW EXECUTE FUNCTION admission_bootstrap._immutable()',relation);
  EXECUTE format('CREATE TRIGGER immutable_history_truncate BEFORE TRUNCATE ON admission_bootstrap.%I FOR EACH STATEMENT EXECUTE FUNCTION admission_bootstrap._immutable()',relation);
 END LOOP;
END $$;
CREATE TRIGGER profile_history_truncate BEFORE TRUNCATE ON admission_bootstrap.profiles FOR EACH STATEMENT EXECUTE FUNCTION admission_bootstrap._immutable();
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA admission_bootstrap FROM PUBLIC;
COMMIT;
