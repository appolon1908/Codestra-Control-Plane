"""Real disposable PostgreSQL16/TLS/SCRAM operation admission tests.

Fixture observations originate in a distinct authenticated verifier session.
They exercise SQL authority, not filesystem/Git verification or live admission.
"""
import concurrent.futures
from datetime import datetime, timedelta, timezone
import json
import unittest
import uuid

import psycopg2
from psycopg2.extras import Json
import test_controller_coordinator as coordinator
import test_assignment_leases as leases
import test_scoped_registration as registration


@unittest.skipUnless((registration.PG/'initdb').exists(), 'PostgreSQL16 required')
class ScopedAdmissionTests(unittest.TestCase):
    password_ready = False

    @classmethod
    def connect(cls, user='alice', sslmode='verify-full'):
        return coordinator.CoordinatorTests.connect.__func__(cls, user, sslmode)

    @classmethod
    def reload_hba(cls):
        coordinator.CoordinatorTests.reload_hba.__func__(cls)

    @classmethod
    def setUpClass(cls):
        coordinator.CoordinatorTests.setUpClass.__func__(cls)
        try:
            cls.migration = leases.ROOT/'010-scoped-operation-admission.sql'
            if cls.migration.exists():
                with cls.connect('fixture_admin') as connection, connection.cursor() as cur:
                    cur.execute(cls.migration.read_text())
                    cur.execute('GRANT USAGE ON SCHEMA scoped_admission TO alice,bob,verifier,operator')
                    cur.execute('GRANT EXECUTE ON FUNCTION scoped_admission.request(uuid,uuid,bigint,jsonb,text),scoped_admission.consume(uuid,uuid),scoped_admission.inspect(uuid) TO alice,bob')
                    cur.execute('GRANT EXECUTE ON FUNCTION scoped_admission.describe(uuid),scoped_admission.attest(uuid,jsonb) TO verifier')
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        coordinator.CoordinatorTests.tearDownClass.__func__(cls)

    def setUp(self):
        # Composition reuses setup only; no inherited test methods are rerun.
        self.fixture = coordinator.CoordinatorTests('test_prepare_registers_metadata_without_creating_admission')
        self.fixture.connect = self.baseline_connect
        self.fixture.setUp()
        if self._testMethodName=='test_nonempty_dependency_snapshot_crosses_zones_and_rejects_receipt_drift':
            self.install_fixture_dependency()
        self.fixture.coordinate()
        baseline=self.fixture.call('describe',(self.fixture.binding,),user='verifier')
        dependencies={row['dependency_key']:row for row in baseline['dependencies']}
        self.lease = self.fixture.coordinate('admit', proof=self.fixture.proof({'dependencies':dependencies}))['lease']
        self.binding = self.fixture.binding
        self.grant = str(uuid.uuid4())
        self.l2_grant = str(uuid.uuid4())
        self.paths = ['src/one.py', 'src/two.py']
        if self.migration.exists():
            self.admin("INSERT INTO assignment_leases.permissions VALUES('verifier','A','read',true)")
            self.admin('INSERT INTO scoped_admission.grants(grant_id,binding_id,operation,paths,valid_until,active) VALUES(%s,%s,\'L1\',%s,clock_timestamp()+interval \'5 minutes\',true),(%s,%s,\'L2\',%s,clock_timestamp()+interval \'5 minutes\',true)',
                       (self.grant,self.binding,Json(self.paths),self.l2_grant,self.binding,Json(self.paths)))

    def admin(self, query, values=()):
        with self.connect('fixture_admin') as connection, connection.cursor() as cur:
            cur.execute(query, values)
            return cur.fetchall() if cur.description else None

    def baseline_connect(self, user='alice', sslmode='verify-full'):
        # Deliberately issue the unchanged007/009 baseline outside UTC. New010
        # must accept equivalent instants without rewriting that old snapshot.
        connection=self.connect(user,sslmode)
        try:
            with connection.cursor() as cur:cur.execute("SET TIME ZONE 'America/New_York'")
            connection.commit()
            return connection
        except BaseException:
            connection.close()
            raise

    def install_fixture_dependency(self):
        from dataclasses import asdict
        from codestra_control.evidence import PromotionRequest
        from codestra_control.lease_materialization import dependency_digest
        prerequisite={'product':'A','scope_type':'SECTION','scope_name':'sec','sha':'c'*40}
        promotion=PromotionRequest('appolon1908/A','A','section/sec','development','c'*40,'d'*40)
        self.admin('UPDATE assignment_leases.coordinator_tasks SET prerequisites=%s',(Json([prerequisite]),))
        self.admin("INSERT INTO scope_certifications VALUES('A','SECTION','sec',%s,'CERTIFIED')",('c'*40,))
        self.admin("INSERT INTO assignment_leases.dependencies VALUES(%s,'section:sec',%s,'appolon1908/A',123,%s,%s,99,'scope-certification','synthetic-capability','Ralph L. Appolon','SCOPE_CERTIFICATION',10,clock_timestamp()+interval '5 minutes',true)",
            (self.fixture.binding,Json(prerequisite),Json(asdict(promotion)),dependency_digest(promotion,prerequisite)))

    def call(self, operation, values, user='alice', role=None, commit=True, timezone=None):
        with self.connect(user) as connection, connection.cursor() as cur:
            if timezone:
                cur.execute('SET TIME ZONE %s',(timezone,))
            if role:
                cur.execute('SET ROLE '+role)
            try:
                cur.execute('SELECT scoped_admission.'+operation+'('+','.join(['%s']*len(values))+')', values)
            except (psycopg2.errors.InvalidSchemaName, psycopg2.errors.UndefinedFunction):
                self.fail('Operation-scoped online admission API is missing')
            result = cur.fetchone()[0]
            if commit:
                connection.commit()
            else:
                connection.rollback()
            return result

    def payload(self, operation='L1'):
        if operation == 'L1':
            return {'paths':['src/one.py'], 'mutation_sha256':'e'*64}
        return {'paths':['src/one.py'], 'candidate_sha':'c'*40, 'candidate_tree_sha':'d'*40,
                'expected_remote_sha':'a'*40, 'target_base_sha':'b'*40}

    def request(self, operation='L1', payload=None, request_id='operation-1', **kwargs):
        return self.call('request', (self.grant if operation=='L1' else self.l2_grant,
            self.lease['lease_id'],self.lease['epoch'],Json(self.payload(operation) if payload is None else payload),request_id), **kwargs)

    def observation(self, intent, user='verifier'):
        description = self.call('describe',(intent['intent_id'],),user=user)
        observed = {'intent_id':intent['intent_id'], 'request_digest':description['request_digest'],
            'operation':description['operation'], 'lease_id':self.lease['lease_id'], 'epoch':self.lease['epoch'],
            'head_sha':'c'*40 if description['operation']=='L2' else 'a'*40, 'tree_sha':'d'*40,
            'changed_paths':['src/one.py'], 'directory_device':1, 'directory_inode':2,
            'dependencies':{row['dependency_key']:row for row in description['dependencies']},
            'observed_at':datetime.now(timezone.utc).isoformat()}
        return observed

    def proof(self, intent, changes=None, user='verifier'):
        observed=self.observation(intent,user)
        observed.update(changes or {})
        return self.call('attest',(intent['intent_id'],Json(observed)),user=user)

    def test_l1_consumes_exact_mutation_once_and_inspect_never_reissues(self):
        intent = self.request()
        self.assertFalse(intent['usable'])
        self.assertEqual(intent['state'],'PENDING')
        proof = self.proof(intent)
        result = self.call('consume',(intent['intent_id'],proof['proof_id']))
        self.assertTrue(result['usable'])
        self.assertEqual(result['authority'],'ONLINE_SCOPED_OPERATION_RECEIPT')
        self.assertEqual(result['state'],'CONSUMED')
        self.assertEqual(result['operation'],'L1')
        self.assertEqual(result['payload'],{'paths':['src/one.py'],'mutation_sha256':'e'*64})
        self.assertEqual(result['lease_id'],self.lease['lease_id'])
        self.assertEqual(result['epoch'],1)
        with self.assertRaises(psycopg2.Error):self.call('consume',(intent['intent_id'],proof['proof_id']))
        self.assertFalse(self.call('inspect',(intent['intent_id'],))['usable'])
        with self.assertRaises(psycopg2.Error):self.request()

    def test_l2_is_separate_exact_candidate_authority(self):
        intent = self.request('L2')
        description = self.call('describe',(intent['intent_id'],),user='verifier')
        self.assertEqual(set(description),{'intent_id','operation','request_digest','payload','grant','binding','lease','dependencies'})
        self.assertEqual(description['lease']['directory_inode'],2)
        self.assertEqual(description['grant']['paths'],self.paths)
        result = self.call('consume',(intent['intent_id'],self.proof(intent)['proof_id']))
        self.assertEqual(result['operation'],'L2')
        self.assertEqual(result['payload'],self.payload('L2'))
        with self.assertRaises(psycopg2.Error):self.request(payload=self.payload('L2'),request_id='wrong-stage')

    def test_nonce_reuse_only_resolves_identical_pending_request(self):
        first = self.request()
        self.assertEqual(self.request()['intent_id'],first['intent_id'])
        changed = dict(self.payload(),mutation_sha256='f'*64)
        with self.assertRaises(psycopg2.Error):self.request(payload=changed)

    def test_payloads_reject_out_of_scope_paths_and_substitution(self):
        invalid = [['src/other.py'],[],['src/one.py','src/one.py'],['src/two.py','src/one.py'],['../one'],['src/.git/config'],['/src/one.py'],['src\\one.py'],['src/'],['src/./one.py'],['src/../one.py'],[1],['src/a b.py']]
        for paths in invalid:
            with self.subTest(paths=paths), self.assertRaises(psycopg2.Error):self.request(payload=dict(self.payload(),paths=paths))
        for payload in [dict(self.payload(),approved=True),{'paths':['src/one.py']},dict(self.payload(),mutation_sha256='0'*64),dict(self.payload(),mutation_sha256='E'*64)]:
            with self.subTest(payload=payload), self.assertRaises(psycopg2.Error):self.request(payload=payload)
        for field in ['expected_remote_sha','target_base_sha']:
            with self.subTest(field=field), self.assertRaises(psycopg2.Error):self.request('L2',payload=dict(self.payload('L2'),**{field:'f'*40}))

    def test_grant_updates_invalidate_proofs_even_after_reenable(self):
        intent = self.request();proof = self.proof(intent)
        self.admin('UPDATE scoped_admission.grants SET active=false WHERE grant_id=%s',(self.grant,))
        self.admin('UPDATE scoped_admission.grants SET active=true,revision=1 WHERE grant_id=%s',(self.grant,))
        self.assertEqual(self.admin('SELECT revision FROM scoped_admission.grants WHERE grant_id=%s',(self.grant,))[0][0],3)
        with self.assertRaises(psycopg2.Error):self.call('consume',(intent['intent_id'],proof['proof_id']))
        with self.assertRaises(psycopg2.Error):self.admin('DELETE FROM scoped_admission.grants WHERE grant_id=%s',(self.grant,))

    def test_wrong_owner_privileged_actor_and_self_attestation_deny(self):
        intent = self.request()
        for user in ['bob','fixture_admin']:
            with self.subTest(user=user),self.assertRaises(psycopg2.Error):self.request(user=user)
        with self.assertRaises(psycopg2.Error):self.call('attest',(intent['intent_id'],Json({})))
        self.admin('GRANT alice TO bob')
        try:
            with self.assertRaises(psycopg2.Error):self.request(user='bob',role='alice')
        finally:self.admin('REVOKE alice FROM bob')
        with self.connect() as connection,connection.cursor() as cur:
            with self.assertRaises(psycopg2.Error):cur.execute('UPDATE scoped_admission.grants SET active=true')

    def test_exact_observation_fields_and_directory_identity_are_required(self):
        intent = self.request('L2')
        for changes in [{'approved':True},{'head_sha':'f'*40},{'tree_sha':'f'*40},{'changed_paths':[]},{'changed_paths':['src/two.py']},{'directory_inode':3},{'dependencies':{'fake':'PASS'}},{'epoch':2},{'operation':'L1'},{'intent_id':str(uuid.uuid4())}]:
            with self.subTest(changes=changes),self.assertRaises(psycopg2.Error):self.proof(intent,changes)

    def test_observation_freshness_and_consumption_expiry_deny(self):
        intent = self.request()
        for stamp in [(datetime.now(timezone.utc)-timedelta(minutes=1)).isoformat(),(datetime.now(timezone.utc)+timedelta(minutes=1)).isoformat()]:
            with self.subTest(stamp=stamp),self.assertRaises(psycopg2.Error):self.proof(intent,{'observed_at':stamp})
        proof=self.proof(intent)
        self.admin("UPDATE scoped_admission.proofs SET expires_at=clock_timestamp()-interval '1 second' WHERE proof_id=%s",(proof['proof_id'],))
        with self.assertRaises(psycopg2.Error):self.call('consume',(intent['intent_id'],proof['proof_id']))

    def test_stage_verifier_revocation_after_attestation_denies_consumption(self):
        intent=self.request();proof=self.proof(intent)
        self.admin("UPDATE assignment_leases.permissions SET active=false WHERE principal='verifier' AND capability='read'")
        with self.assertRaises(psycopg2.Error):self.call('consume',(intent['intent_id'],proof['proof_id']))

    def test_current_coordinator_assignment_and_lease_snapshots_are_rechecked(self):
        intent=self.request();proof=self.proof(intent)
        self.admin('UPDATE assignment_leases.coordinator_tasks SET active=false WHERE binding_id=%s',(self.binding,))
        with self.assertRaises(psycopg2.Error):self.call('consume',(intent['intent_id'],proof['proof_id']))
        self.admin('UPDATE assignment_leases.coordinator_tasks SET active=true WHERE binding_id=%s',(self.binding,))
        self.admin('UPDATE assignment_leases.slots SET epoch=epoch+1')
        with self.assertRaises(psycopg2.Error):self.call('consume',(intent['intent_id'],proof['proof_id']))

    def test_lease_host_workstation_and_directory_identity_remain_bound(self):
        # A second valid FK/epoch must not make another workstation this lease's
        # assignment, even while the original legacy ownership row still matches.
        self.admin("INSERT INTO public.workstations(workstation_id,product,section,subsection,branch,parent_branch,worktree,order_index) VALUES('other-ws','A','sec','other','subsection/sec--other','section/sec','/fixture/A/other',2)")
        self.admin("INSERT INTO assignment_leases.slots VALUES('other-ws',%s)",(self.lease['epoch'],))
        changes=[('host','other-host','fixture-host'),('workstation_id','other-ws','A-ws'),
            ('directory_device',-1,1),('directory_inode',0,2),('directory_inode',-1,2)]
        for field,value,original in changes:
            self.admin('UPDATE assignment_leases.leases SET '+field+'=%s WHERE lease_id=%s',(value,self.lease['lease_id']))
            try:
                with self.subTest(field=field,value=value),self.assertRaisesRegex(psycopg2.Error,'OPERATION_LEASE_UNAVAILABLE'):
                    self.request(request_id='lease-substitution-'+field+str(value))
            finally:
                self.admin('UPDATE assignment_leases.leases SET '+field+'=%s WHERE lease_id=%s',(original,self.lease['lease_id']))

    def test_credential_provenance_and_tls_are_required(self):
        intent=self.request()
        try:
            self.hba.write_text(self.trust_hba);self.reload_hba()
            with self.assertRaises(psycopg2.Error):self.request()
            with self.assertRaises(psycopg2.Error):self.call('describe',(intent['intent_id'],),user='verifier')
        finally:
            self.hba.write_text('local all all trust\nhostssl all all 127.0.0.1/32 scram-sha-256\nhostnossl all all 127.0.0.1/32 reject\n');self.reload_hba()

    def test_rollback_preserves_one_use_admission_and_concurrent_consume_has_one_winner(self):
        intent=self.request();proof=self.proof(intent)
        result=self.call('consume',(intent['intent_id'],proof['proof_id']),commit=False)
        self.assertTrue(result['usable'])  # client must mask uncommitted SQL output
        def attempt(_):
            try:return self.call('consume',(intent['intent_id'],proof['proof_id']))
            except psycopg2.Error:return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(attempt,range(2)))
        self.assertEqual(sum(value is not None for value in results),1)
        self.assertEqual(self.admin("SELECT count(*) FROM scoped_admission.audit WHERE action='CONSUME'")[0][0],1)

    def test_historical_consumed_outcome_remains_inspectable_after_revocation_and_expiry(self):
        intent=self.request();proof=self.proof(intent)
        original=self.call('consume',(intent['intent_id'],proof['proof_id']))
        mutations=[('UPDATE scoped_admission.grants SET active=false WHERE grant_id=%s',(self.grant,)),
            ("UPDATE assignment_leases.leases SET expires_at=clock_timestamp()-interval '1 second'",()),
            ("UPDATE scoped_admission.intents SET expires_at=clock_timestamp()-interval '1 second'",()),
            ("UPDATE assignment_leases.leases SET state='REVOKED'; UPDATE assignment_leases.slots SET epoch=epoch+1",())]
        for query,values in mutations:
            self.admin(query,values)
            with self.subTest(query=query):
                historic=self.call('inspect',(intent['intent_id'],))
                self.assertEqual(historic['state'],'CONSUMED')
                self.assertEqual(historic['payload'],original['payload'])
                self.assertFalse(historic['usable'])
                self.assertEqual(historic['authority'],'NONE')
        with self.assertRaises(psycopg2.Error):self.call('inspect',(intent['intent_id'],),user='bob')

    def test_pending_expiry_inspection_does_not_authorize_a_new_request(self):
        intent=self.request()
        self.admin("UPDATE scoped_admission.intents SET expires_at=clock_timestamp()-interval '1 second'")
        result=self.call('inspect',(intent['intent_id'],))
        self.assertEqual(result['state'],'PENDING')
        self.assertFalse(result['usable'])
        self.assertEqual(result['authority'],'NONE')
        with self.assertRaises(psycopg2.Error):self.request()

    def test_server_file_and_program_memberships_deny_builder_and_verifier(self):
        intent=self.request()
        for user in ['alice','verifier']:
            for role in ['pg_read_server_files','pg_write_server_files','pg_execute_server_program']:
                self.admin('GRANT '+role+' TO '+user)
                try:
                    with self.subTest(user=user,role=role),self.assertRaises(psycopg2.Error):
                        if user=='alice':self.request(request_id='unsafe-'+role)
                        else:self.proof(intent)
                finally:self.admin('REVOKE '+role+' FROM '+user)

    def test_authenticated_admin_session_authorization_cannot_spoof_either_actor(self):
        intent=self.request();observed=self.observation(intent)
        for role in ['alice','verifier']:
            with self.connect('fixture_admin') as connection,connection.cursor() as cur:
                cur.execute('SET SESSION AUTHORIZATION '+role)
                with self.subTest(role=role),self.assertRaisesRegex(psycopg2.Error,'OPERATION_AUTHENTICATION_REQUIRED'):
                    if role=='alice':
                        cur.execute('SELECT scoped_admission.request(%s,%s,%s,%s,%s)',
                            (self.grant,self.lease['lease_id'],1,Json(self.payload()),'spoof'))
                    else:cur.execute('SELECT scoped_admission.attest(%s,%s)',(intent['intent_id'],Json(observed)))

    def test_baseline_and_stage_provenance_must_match_authenticating_verifier(self):
        intent=self.request();proof=self.proof(intent)
        self.admin("UPDATE assignment_leases.proofs SET verifier_authentication='scram-sha-256:bob'")
        with self.assertRaises(psycopg2.Error):self.request(request_id='wrong-baseline-provenance')
        self.admin("UPDATE assignment_leases.proofs SET verifier_authentication='scram-sha-256:verifier'")
        self.admin("UPDATE scoped_admission.proofs SET verifier_authentication='scram-sha-256:bob'")
        with self.assertRaises(psycopg2.Error):self.call('consume',(intent['intent_id'],proof['proof_id']))

    def test_baseline_snapshot_comparison_is_timezone_invariant_and_still_complete(self):
        snapshot=self.admin('SELECT binding_snapshot FROM assignment_leases.leases')[0][0]
        self.assertTrue(snapshot['valid_until'].endswith(('-04:00','-05:00')))
        intent=self.request(timezone='Asia/Kolkata')
        proof=self.proof(intent)
        result=self.call('consume',(intent['intent_id'],proof['proof_id']),timezone='Europe/Paris')
        self.assertTrue(result['usable'])
        self.assertEqual(self.admin('SELECT binding_snapshot FROM assignment_leases.leases')[0][0],snapshot)
        self.admin("UPDATE assignment_leases.leases SET binding_snapshot=jsonb_set(binding_snapshot,'{repository_id}','999')")
        with self.assertRaises(psycopg2.Error):self.request(request_id='snapshot-substitution')

    def test_real_client_and_sql_default_rollback_then_committed_consumption(self):
        from codestra_control.scoped_admission import operate
        with self.connect() as connection:
            requested=operate(connection,'request',{'grant':self.grant,'lease':self.lease['lease_id'],
                'epoch':1,'payload':self.payload(),'request_id':'client-1'},apply=True)
        intent=requested['result'];proof=self.proof(intent)
        values={'intent':intent['intent_id'],'proof':proof['proof_id']}
        with self.connect() as connection:
            dry=operate(connection,'consume',values)
            self.assertEqual(dry['authority'],'NONE_DRY_RUN')
            self.assertFalse(dry['usable'])
            self.assertNotIn('result',dry)
            consumed=operate(connection,'consume',values,apply=True)
            self.assertTrue(consumed['usable'])
            self.assertEqual(consumed['result']['authority'],'ONLINE_SCOPED_OPERATION_RECEIPT')
            self.assertEqual(consumed['result']['payload'],self.payload())
            inspected=operate(connection,'inspect',{'intent':intent['intent_id']},apply=True)
            self.assertFalse(inspected['usable'])
            self.assertFalse(inspected['result']['usable'])

    def test_lost_commit_response_can_reconcile_without_reconsuming_after_revocation(self):
        from codestra_control.scoped_admission import operate,AdmissionOutcomeUnknown
        intent=self.request();proof=self.proof(intent)
        class LostCommit:
            def __init__(self,real):self.real=real
            def __getattr__(self,name):return getattr(self.real,name)
            def commit(self):
                self.real.commit()
                raise psycopg2.OperationalError('synthetic lost commit response')
        with self.connect() as connection:
            with self.assertRaises(AdmissionOutcomeUnknown):
                operate(LostCommit(connection),'consume',{'intent':intent['intent_id'],'proof':proof['proof_id']},apply=True)
        self.admin('UPDATE scoped_admission.grants SET active=false')
        with self.connect() as connection:
            inspected=operate(connection,'inspect',{'intent':intent['intent_id']},apply=True)
        self.assertEqual(inspected['result']['state'],'CONSUMED')
        self.assertFalse(inspected['usable'])
        self.assertFalse(inspected['result']['usable'])
        self.assertEqual(self.admin("SELECT count(*) FROM scoped_admission.audit WHERE action='CONSUME'")[0][0],1)

    def test_nonempty_dependency_snapshot_crosses_zones_and_rejects_receipt_drift(self):
        baseline=self.admin('SELECT proof.observations FROM assignment_leases.leases lease JOIN assignment_leases.proofs proof USING(proof_id)')[0][0]
        original=baseline['dependencies']['section:sec']
        self.assertTrue(original['valid_until'].endswith(('-04:00','-05:00')))
        first=self.request(timezone='Asia/Kolkata')
        staged=self.observation(first)
        self.assertTrue(staged['dependencies']['section:sec']['valid_until'].endswith('+00:00'))
        self.assertEqual(staged['dependencies']['section:sec']['check_id'],10)
        proof=self.proof(first)
        self.assertTrue(self.call('consume',(first['intent_id'],proof['proof_id']),timezone='Europe/Paris')['usable'])
        self.assertEqual(self.admin('SELECT proof.observations FROM assignment_leases.leases lease JOIN assignment_leases.proofs proof USING(proof_id)')[0][0],baseline)
        # A fresh, unconsumed intent makes these denials depend on receipt state,
        # rather than merely detecting that the earlier intent was consumed.
        pending=self.request(request_id='dependency-drift');proof=self.proof(pending)
        self.admin('UPDATE assignment_leases.dependencies SET check_id=11')
        with self.assertRaisesRegex(psycopg2.Error,'OPERATION_VERIFIER_REVOKED'):
            self.call('consume',(pending['intent_id'],proof['proof_id']))
        self.admin('UPDATE assignment_leases.dependencies SET check_id=10,active=false')
        with self.assertRaisesRegex(psycopg2.Error,'DEPENDENCY_UNAVAILABLE'):
            self.call('consume',(pending['intent_id'],proof['proof_id']))

    def test_stage_verifier_denies_when_bound_builder_gains_server_capabilities(self):
        intent=self.request()
        for role in ['pg_read_server_files','pg_write_server_files','pg_execute_server_program']:
            self.admin('GRANT '+role+' TO alice')
            try:
                with self.subTest(role=role),self.assertRaises(psycopg2.Error):self.proof(intent)
            finally:self.admin('REVOKE '+role+' FROM alice')

    def test_settable_noninherited_authority_writer_roles_deny_admission(self):
        intent=self.request()
        targets=[('TABLE',table,'UPDATE') for table in
            ['scoped_admission.grants','scoped_admission.intents','scoped_admission.proofs',
             'scoped_admission.audit','assignment_leases.permissions',
             'scoped_registration.principals','public.scope_certifications']]
        targets += [('SCHEMA',schema,'CREATE') for schema in
            ['scoped_admission','assignment_leases','scoped_registration','public']]
        for kind,target,privilege in targets:
            self.admin('CREATE ROLE operation_writer NOLOGIN')
            try:
                self.admin('GRANT '+privilege+' ON '+kind+' '+target+' TO operation_writer')
                if kind=='TABLE':
                    self.admin('GRANT USAGE ON SCHEMA '+target.split('.')[0]+' TO operation_writer')
                    target_oid=self.admin('SELECT %s::regclass::oid',(target,))[0][0]
                else:target_oid=self.admin('SELECT %s::regnamespace::oid',(target,))[0][0]
                for user in ['alice','verifier']:
                    self.admin('GRANT operation_writer TO '+user+' WITH INHERIT FALSE, SET TRUE')
                    try:
                        with self.subTest(kind=kind,target=target,user=user):
                            with self.connect(user) as connection,connection.cursor() as cur:
                                cur.execute('SELECT has_'+kind.lower()+'_privilege(session_user,%s::oid,%s)',(target_oid,privilege))
                                self.assertFalse(cur.fetchone()[0])
                                # Prove SET ROLE is available without mutating authority.
                                cur.execute('SET ROLE operation_writer')
                                cur.execute('SELECT current_user')
                                self.assertEqual(cur.fetchone()[0],'operation_writer')
                                cur.execute('RESET ROLE')
                            with self.assertRaises(psycopg2.Error):
                                if user=='alice':self.request(request_id='noninherited-'+target)
                                else:self.proof(intent)
                    finally:self.admin('REVOKE operation_writer FROM '+user)
            finally:
                self.admin('DROP OWNED BY operation_writer; DROP ROLE operation_writer')


if __name__=='__main__':unittest.main()
