"""Real disposable PostgreSQL/TLS tests; all identities/keys are synthetic."""
import concurrent.futures
from datetime import datetime,timezone
import json
from pathlib import Path
import socket
import subprocess
import unittest
import uuid
import psycopg2
from psycopg2.extras import Json
import test_scoped_registration as base

ROOT=Path(__file__).resolve().parents[1]

@unittest.skipUnless((base.PG/'initdb').exists(),'PostgreSQL16 disposable binaries required')
class AssignmentLeaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        base.ScopedRegistrationTests.setUpClass()
        cls.path=base.ScopedRegistrationTests.path
        try:
            cert=cls.path/'fixture.crt';key=cls.path/'fixture.key'
            subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1,DNS:localhost','-keyout',str(key),'-out',str(cert)],check=True,capture_output=True)
            key.chmod(0o600)
            subprocess.run([str(base.PG/'pg_ctl'),'-D',str(base.ScopedRegistrationTests.data),'-m','fast','-w','stop'],check=True,capture_output=True)
            with socket.socket() as listener:listener.bind(('127.0.0.1',0));cls.port=listener.getsockname()[1]
            options=f'-k {cls.path} -p {cls.port} -h 127.0.0.1 -c ssl=on -c ssl_cert_file={cert} -c ssl_key_file={key}'
            subprocess.run([str(base.PG/'pg_ctl'),'-D',str(base.ScopedRegistrationTests.data),'-l',str(cls.path/'postgres.log'),'-o',options,'-w','start'],check=True,capture_output=True)
            with cls.connect('fixture_admin') as c,c.cursor() as cur:
                cur.execute((ROOT/'007-assignment-leases.sql').read_text())
                cur.execute('CREATE ROLE verifier LOGIN;CREATE ROLE operator LOGIN')
                cur.execute('GRANT USAGE ON SCHEMA assignment_leases TO alice,bob,verifier,operator')
                for name,args in [('claim','uuid,uuid,text'),('renew','uuid,bigint,uuid,text'),('release','uuid,bigint,text'),('check_owned','uuid,bigint')]:
                    cur.execute(f'GRANT EXECUTE ON FUNCTION assignment_leases.{name}({args}) TO alice,bob')
                cur.execute('GRANT EXECUTE ON FUNCTION assignment_leases.describe(uuid),assignment_leases.attest(uuid,jsonb) TO verifier')
                cur.execute('GRANT EXECUTE ON FUNCTION assignment_leases.revoke(uuid,text,text) TO operator')
        except BaseException:
            base.ScopedRegistrationTests.tearDownClass();raise
    @classmethod
    def tearDownClass(cls):base.ScopedRegistrationTests.tearDownClass()
    @classmethod
    def connect(cls,user='alice',sslmode='verify-full'):
        return psycopg2.connect(host='127.0.0.1',port=cls.port,dbname='postgres',user=user,sslmode=sslmode,sslrootcert=str(cls.path/'fixture.crt'))
    def setUp(self):
        with self.connect('fixture_admin') as c,c.cursor() as cur:cur.execute('TRUNCATE assignment_leases.audit,assignment_leases.leases,assignment_leases.proofs,assignment_leases.bindings,assignment_leases.permissions,assignment_leases.policies,assignment_leases.slots CASCADE')
        self.fixture=base.ScopedRegistrationTests('test_authentication_grants_and_role_switch');self.fixture.connect=self.connect
        self.fixture.setUp();self.fixture.prepare();self.fixture.register('candidate',self.fixture.candidate(),'candidate')
        self.binding=str(uuid.uuid4())
        with self.connect('fixture_admin') as c,c.cursor() as cur:
            cur.execute("INSERT INTO scoped_registration.principals SELECT rolname,oid,true FROM pg_roles WHERE rolname IN ('verifier','operator')")
            cur.execute("INSERT INTO assignment_leases.permissions VALUES ('verifier','A','attest',true),('operator','A','revoke',true)")
            cur.execute("INSERT INTO assignment_leases.policies VALUES ('A',30,30,120,20,true)")
            cur.execute("""INSERT INTO assignment_leases.bindings(binding_id,product,workstation_id,task_id,principal,principal_oid,repository,repository_id,source_ref,target_ref,head_sha,base_sha,worktree,host,root_path,git_common_dir,worktree_uid,valid_until,active)
              SELECT %s,'A','A-ws','A-task','alice',oid,'appolon1908/A',123,'atomic/sec--sub--task','subsection/sec--sub',%s,%s,'/fixture/A/atomic','fixture-host','/fixture/A','/fixture/A/repo.git',1000,clock_timestamp()+interval '5 minutes',true FROM pg_roles WHERE rolname='alice'""",(self.binding,'a'*40,'b'*40))
    def call(self,name,args,user='alice',role=None,sslmode='verify-full'):
        c=self.connect(user,sslmode)
        try:
            with c.cursor() as cur:
                if role:cur.execute('SET ROLE '+role)
                cur.execute('SELECT assignment_leases.'+name+'('+','.join(['%s']*len(args))+')',args)
                value=cur.fetchone()[0]
            c.commit();return value
        finally:c.close()
    def proof(self,changes=None):
        description=self.call('describe',(self.binding,),user='verifier')
        b=description['binding']
        observed={k:b[k] for k in ('repository','repository_id','source_ref','target_ref','head_sha','base_sha','worktree','host','git_common_dir','worktree_uid')}
        observed.update(directory_device=1,directory_inode=2,observed_at=datetime.now(timezone.utc).isoformat(),dependencies={})
        observed.update(changes or {})
        return self.call('attest',(self.binding,Json(observed)),user='verifier')['proof_id']
    def claim(self,proof=None,request='claim-1',user='alice'):
        return self.call('claim',(self.binding,proof or self.proof(),request),user=user)
    def test_real_authenticated_claim_and_online_owned_check(self):
        lease=self.claim();self.assertEqual(lease['principal'],'alice');self.assertEqual(lease['state'],'ACTIVE')
        self.assertEqual(self.call('check_owned',(lease['lease_id'],lease['epoch']))['lease_id'],lease['lease_id'])
        self.assertEqual(lease['binding']['head_sha'],'a'*40)
    def test_owner_strings_role_switch_and_superuser_are_not_authentication(self):
        proof=self.proof()
        with self.assertRaisesRegex(psycopg2.Error,'LEASE_DENIED'):self.claim(proof,user='bob')
        with self.connect('fixture_admin') as c,c.cursor() as cur:cur.execute('GRANT alice TO bob')
        with self.assertRaisesRegex(psycopg2.Error,'LEASE_DENIED'):self.call('claim',(self.binding,proof,'spoof'),'bob',role='alice')
        with self.assertRaisesRegex(psycopg2.Error,'LEASE_DENIED'):self.claim(proof,user='fixture_admin')
    def test_builder_cannot_attest_or_write_policy_lease_or_audit(self):
        with self.assertRaises(psycopg2.Error):self.call('attest',(self.binding,Json({})))
        for table in ('policies','bindings','proofs','leases','audit','permissions','slots'):
            c=self.connect()
            try:
                with c.cursor() as cur:
                    with self.assertRaises(psycopg2.Error):cur.execute('DELETE FROM assignment_leases.'+table)
            finally:c.close()
    def test_wrong_actual_materialization_binding_denies(self):
        for field,value in (('head_sha','d'*40),('worktree','/another/path'),('host','other-host'),('repository_id',999)):
            with self.subTest(field=field),self.assertRaisesRegex(psycopg2.Error,'MATERIALIZATION_MISMATCH'):self.proof({field:value})
    def test_concurrent_distinct_claims_have_one_winner(self):
        proofs=[self.proof(),self.proof()]
        def attempt(index):
            try:return self.claim(proofs[index],request='claim-'+str(index))
            except psycopg2.Error:return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(attempt,range(2)))
        self.assertEqual(sum(v is not None for v in results),1)
    def test_revoked_assignment_or_candidate_drift_prevents_claim(self):
        proof=self.proof()
        with self.connect('fixture_admin') as c,c.cursor() as cur:cur.execute("UPDATE scoped_registration.task_assignments SET active=false WHERE task_id='A-task'")
        with self.assertRaisesRegex(psycopg2.Error,'ASSIGNMENT_UNAVAILABLE'):self.claim(proof)
    def test_renew_requires_fresh_proof_and_stays_bounded_then_release_invalidates(self):
        proof=self.proof();lease=self.claim(proof)
        with self.assertRaisesRegex(psycopg2.Error,'PROOF_CONSUMED'):self.call('renew',(lease['lease_id'],lease['epoch'],proof,'renew-old'))
        renewed=self.call('renew',(lease['lease_id'],lease['epoch'],self.proof(),'renew-1'))
        self.assertEqual(renewed['epoch'],lease['epoch'])
        self.call('release',(lease['lease_id'],lease['epoch'],'release-1'))
        with self.assertRaisesRegex(psycopg2.Error,'LEASE_NOT_ACTIVE'):self.call('check_owned',(lease['lease_id'],lease['epoch']))
    def test_expired_lease_never_renews_or_silently_recovers(self):
        lease=self.claim()
        with self.connect('fixture_admin') as c,c.cursor() as cur:cur.execute('UPDATE assignment_leases.leases SET expires_at=clock_timestamp()-interval \'1 second\' WHERE lease_id=%s',(lease['lease_id'],))
        with self.assertRaisesRegex(psycopg2.Error,'LEASE_NOT_ACTIVE'):self.call('renew',(lease['lease_id'],lease['epoch'],self.proof(),'late'))
        with self.assertRaisesRegex(psycopg2.Error,'RECOVERY_REQUIRED'):self.claim(request='replace')
    def test_operator_revocation_invalidates_and_preserves_history(self):
        lease=self.claim();self.call('revoke',(self.binding,'operator revocation','revoke-1'),user='operator')
        with self.assertRaises(psycopg2.Error):self.call('check_owned',(lease['lease_id'],lease['epoch']))
        with self.connect('fixture_admin') as c,c.cursor() as cur:
            cur.execute('SELECT state FROM assignment_leases.leases');self.assertEqual(cur.fetchone(),('REVOKED',))
            cur.execute('SELECT count(*) FROM assignment_leases.audit');self.assertGreaterEqual(cur.fetchone()[0],2)
    def test_frozen_or_blocked_lane_and_unencrypted_transport_deny(self):
        with self.connect('fixture_admin') as c,c.cursor() as cur:cur.execute("UPDATE workstations SET lease_state='FROZEN',status='BLOCKED',blocker='STALE_DIRTY_WORKTREE' WHERE workstation_id='A-ws'")
        with self.assertRaisesRegex(psycopg2.Error,'LANE_UNAVAILABLE'):self.proof()
        with self.assertRaisesRegex(psycopg2.Error,'LEASE_DENIED'):self.call('describe',(self.binding,),user='verifier',sslmode='disable')
    def test_attestation_requires_every_actual_observation_field(self):
        description=self.call('describe',(self.binding,),user='verifier');b=description['binding']
        observed={k:b[k] for k in ('repository','repository_id','source_ref','target_ref','head_sha','base_sha','worktree','host','git_common_dir','worktree_uid')}
        observed.update(directory_device=1,observed_at=datetime.now(timezone.utc).isoformat(),dependencies={})
        with self.assertRaisesRegex(psycopg2.Error,'MATERIALIZATION_MISMATCH'):self.call('attest',(self.binding,Json(observed)),user='verifier')
    def test_renewal_cannot_transfer_to_replaced_directory(self):
        lease=self.claim();proof=self.proof({'directory_inode':99})
        with self.assertRaisesRegex(psycopg2.Error,'MATERIALIZATION_REPLACED'):self.call('renew',(lease['lease_id'],lease['epoch'],proof,'renew-replaced'))
    def test_consumer_reads_current_receipt_without_owner_impersonation(self):
        lease=self.claim()
        with self.connect('fixture_admin') as c,c.cursor() as cur:
            cur.execute("INSERT INTO assignment_leases.permissions VALUES('verifier','A','read',true)")
            cur.execute('GRANT EXECUTE ON FUNCTION assignment_leases.inspect_binding(uuid) TO verifier,bob')
        with self.connect('verifier') as c:
            c.set_session(readonly=True)
            with c.cursor() as cur:
                cur.execute('SELECT assignment_leases.inspect_binding(%s)',(self.binding,));receipt=cur.fetchone()[0]
                self.assertEqual(receipt['lease_id'],lease['lease_id'])
        with self.assertRaisesRegex(psycopg2.Error,'LEASE_DENIED'):self.call('inspect_binding',(self.binding,),user='bob')
    def test_legacy_dependency_pass_cannot_authorize_a_lease(self):
        prerequisite={'product':'A','scope_type':'SECTION','scope_name':'sec','sha':'c'*40}
        with self.connect('fixture_admin') as c,c.cursor() as cur:
            cur.execute("UPDATE scoped_registration.candidates SET payload=jsonb_set(payload,'{prerequisites}',%s::jsonb) WHERE task_id='A-task'",(Json([prerequisite]),))
            cur.execute("INSERT INTO scope_certifications VALUES('A','SECTION','sec',%s,'CERTIFIED')",('c'*40,))
        with self.assertRaisesRegex(psycopg2.Error,'DEPENDENCY_UNAVAILABLE'):self.proof()
    def test_revoking_frozen_lane_does_not_recover_or_erase_blocker(self):
        lease=self.claim()
        with self.connect('fixture_admin') as c,c.cursor() as cur:cur.execute("UPDATE workstations SET lease_state='FROZEN',status='BLOCKED',blocker='STALE_DIRTY_WORKTREE' WHERE workstation_id='A-ws'")
        self.call('revoke',(self.binding,'revoke only','frozen-revoke'),user='operator')
        with self.connect('fixture_admin') as c,c.cursor() as cur:
            cur.execute("SELECT lease_state,status,blocker FROM workstations WHERE workstation_id='A-ws'");self.assertEqual(cur.fetchone(),('FROZEN','BLOCKED','STALE_DIRTY_WORKTREE'))
    def test_materialization_expiration_and_verifier_revocation_deny(self):
        proof=self.proof()
        with self.connect('fixture_admin') as c,c.cursor() as cur:cur.execute('UPDATE assignment_leases.proofs SET expires_at=clock_timestamp()-interval \'1 second\' WHERE proof_id=%s',(proof,))
        with self.assertRaisesRegex(psycopg2.Error,'MATERIALIZATION_EXPIRED'):self.claim(proof)
        proof=self.proof()
        with self.connect('fixture_admin') as c,c.cursor() as cur:cur.execute("UPDATE assignment_leases.permissions SET active=false WHERE principal='verifier'")
        with self.assertRaisesRegex(psycopg2.Error,'VERIFIER_REVOKED'):self.claim(proof)
    def test_lost_claim_response_lookup_is_current_and_nonce_cannot_reissue(self):
        lease=self.claim()
        with self.connect('fixture_admin') as c,c.cursor() as cur:cur.execute('GRANT EXECUTE ON FUNCTION assignment_leases.lookup(text) TO alice,bob')
        self.assertEqual(self.call('lookup',('claim-1',))['lease_id'],lease['lease_id'])
        with self.assertRaisesRegex(psycopg2.Error,'REQUEST_NOT_FOUND'):self.call('lookup',('claim-1',),user='bob')
        self.call('release',(lease['lease_id'],lease['epoch'],'release-lookup'))
        with self.assertRaisesRegex(psycopg2.Error,'LEASE_NOT_ACTIVE'):self.call('lookup',('claim-1',))
        with self.assertRaisesRegex(psycopg2.Error,'REQUEST_CONSUMED'):self.claim(request='claim-1')
    def test_renewal_is_bounded_by_total_lifetime(self):
        lease=self.claim()
        with self.connect('fixture_admin') as c,c.cursor() as cur:
            cur.execute("UPDATE assignment_leases.leases SET started_at=clock_timestamp()-interval '115 seconds' WHERE lease_id=%s",(lease['lease_id'],))
        renewed=self.call('renew',(lease['lease_id'],lease['epoch'],self.proof(),'bounded-renew'))
        self.assertLessEqual((datetime.fromisoformat(renewed['expires_at'])-datetime.fromisoformat(renewed['started_at'])).total_seconds(),120)
    def test_same_named_recreated_builder_role_is_not_original_identity(self):
        proof=self.proof()
        with self.connect('fixture_admin') as c,c.cursor() as cur:
            cur.execute('DROP OWNED BY alice;DROP ROLE alice;CREATE ROLE alice LOGIN')
            cur.execute('GRANT USAGE ON SCHEMA assignment_leases TO alice;GRANT EXECUTE ON FUNCTION assignment_leases.claim(uuid,uuid,text) TO alice')
        try:
            with self.assertRaisesRegex(psycopg2.Error,'LEASE_DENIED'):self.claim(proof)
        finally:
            with self.connect('fixture_admin') as c,c.cursor() as cur:
                cur.execute('GRANT registration_runtime TO alice')
                cur.execute('GRANT EXECUTE ON FUNCTION assignment_leases.claim(uuid,uuid,text),assignment_leases.renew(uuid,bigint,uuid,text),assignment_leases.release(uuid,bigint,text),assignment_leases.check_owned(uuid,bigint) TO alice')
    def test_privileged_verifier_membership_revokes_existing_proof(self):
        proof=self.proof()
        with self.connect('fixture_admin') as c,c.cursor() as cur:cur.execute('GRANT fixture_admin TO verifier')
        try:
            with self.assertRaisesRegex(psycopg2.Error,'VERIFIER_REVOKED'):self.claim(proof)
        finally:
            with self.connect('fixture_admin') as c,c.cursor() as cur:cur.execute('REVOKE fixture_admin FROM verifier')
    def test_operator_dependency_binding_is_pinned_and_revocation_invalidates_lease(self):
        from dataclasses import asdict
        from codestra_control.evidence import PromotionRequest
        from codestra_control.lease_materialization import dependency_digest
        prerequisite={'product':'A','scope_type':'SECTION','scope_name':'sec','sha':'c'*40}
        binding=PromotionRequest('appolon1908/A','A','section/sec','development','c'*40,'d'*40)
        with self.connect('fixture_admin') as c,c.cursor() as cur:
            cur.execute("UPDATE scoped_registration.candidates SET payload=jsonb_set(payload,'{prerequisites}',%s::jsonb) WHERE task_id='A-task'",(Json([prerequisite]),))
            cur.execute("""INSERT INTO assignment_leases.dependencies VALUES(%s,'section:sec',%s,'appolon1908/A',123,%s,%s,99,'scope-certification','synthetic-capability','Ralph L. Appolon','SCOPE_CERTIFICATION',10,clock_timestamp()+interval '5 minutes',true)""",(self.binding,Json(prerequisite),Json(asdict(binding)),dependency_digest(binding,prerequisite)))
        description=self.call('describe',(self.binding,),user='verifier')
        dependencies={d['dependency_key']:d for d in description['dependencies']}
        lease=self.claim(self.proof({'dependencies':dependencies}))
        self.assertEqual(lease['state'],'ACTIVE')
        with self.connect('fixture_admin') as c,c.cursor() as cur:cur.execute('UPDATE assignment_leases.dependencies SET active=false WHERE binding_id=%s',(self.binding,))
        with self.assertRaisesRegex(psycopg2.Error,'DEPENDENCY_UNAVAILABLE'):self.call('check_owned',(lease['lease_id'],lease['epoch']))
