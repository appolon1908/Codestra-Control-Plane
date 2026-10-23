"""Production issuer SQL exercised only in private disposable PostgreSQL16 clusters."""
import concurrent.futures
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
import uuid

import psycopg2
from psycopg2.extras import Json

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
from codestra_control.admission_installation import PostgresTarget, canonical

PG = Path('/usr/lib/postgresql/16/bin')
SOURCE = ROOT / '017-installation-authority.sql'


class ProductionIssuerFixture:
    """Three distinct synthetic SCRAM roles and the actual production SQL source."""
    def __init__(self, path, certificate, key):
        self.path = Path(path)
        self.path.mkdir(mode=0o700)
        self.data = self.path / 'data'
        self.certificate, self.key = Path(certificate), Path(key)
        self.started = False
        self.connections = []
        self.socket_directory = tempfile.TemporaryDirectory(prefix='ia-sock-')
        try:
            subprocess.run([str(PG/'initdb'),'-D',str(self.data),'-A','trust','-U','issuer_owner','-E','UTF8','--no-locale'],check=True,capture_output=True)
            (self.data/'pg_hba.conf').write_text('local all all trust\nhostssl all all 127.0.0.1/32 scram-sha-256\nhostnossl all all 127.0.0.1/32 reject\n')
            with socket.socket() as listener:
                listener.bind(('127.0.0.1',0))
                self.port = listener.getsockname()[1]
            options = f'-k {self.socket_directory.name} -p {self.port} -h 127.0.0.1 -c ssl=on -c ssl_cert_file={self.certificate} -c ssl_key_file={self.key}'
            subprocess.run([str(PG/'pg_ctl'),'-D',str(self.data),'-l',str(self.path/'postgres.log'),'-o',options,'-w','start'],check=True,capture_output=True)
            self.started = True
            self.owner = psycopg2.connect(host=self.socket_directory.name,port=self.port,dbname='postgres',user='issuer_owner')
            self.connections.append(self.owner)
            with self.owner,self.owner.cursor() as cursor:
                for role in ('issuer_operator','issuer_verifier','issuer_client'):
                    cursor.execute('CREATE ROLE '+role+' LOGIN PASSWORD %s',('synthetic-'+role,))
                if SOURCE.exists():
                    cursor.execute(SOURCE.read_text())
                    cursor.execute('GRANT USAGE ON SCHEMA admission_bootstrap TO issuer_operator,issuer_verifier,issuer_client')
                    cursor.execute('GRANT EXECUTE ON FUNCTION admission_bootstrap.request(uuid,text),admission_bootstrap.issue(uuid),admission_bootstrap.inspect(uuid) TO issuer_operator')
                    cursor.execute('GRANT EXECUTE ON FUNCTION admission_bootstrap.accept(uuid),admission_bootstrap.inspect(uuid) TO issuer_verifier')
                    cursor.execute('GRANT EXECUTE ON FUNCTION admission_bootstrap.describe(uuid,text,jsonb,text,uuid),admission_bootstrap.revoke(uuid,jsonb,uuid) TO issuer_client')
                    cursor.execute('GRANT EXECUTE ON FUNCTION pg_control_system() TO issuer_client')
        except BaseException:
            self.close()
            raise

    def connect(self, role):
        connection = psycopg2.connect(host='127.0.0.1',port=self.port,dbname='postgres',user=role,password='synthetic-'+role,
            sslmode='verify-full',sslrootcert=str(self.certificate),connect_timeout=5,
            options='-c statement_timeout=10000 -c lock_timeout=5000')
        self.connections.append(connection)
        return connection

    def call(self, name, values, role='issuer_operator', connection=None):
        connection = connection or self.connect(role)
        with connection,connection.cursor() as cursor:
            cursor.execute('SELECT admission_bootstrap.'+name+'('+','.join(['%s']*len(values))+')',values)
            return cursor.fetchone()[0]

    def profile(self, binding, verifier_oid):
        profile = str(uuid.uuid4())
        with self.owner,self.owner.cursor() as cursor:
            cursor.execute('INSERT INTO admission_bootstrap.profiles(profile_id,operator,operator_oid,verifier,verifier_oid,client,client_oid,target_verifier_oid,binding,custody_scope,not_before,expires_at,rollback_expires_at,active) '
                "SELECT %s,'issuer_operator',o.oid,'issuer_verifier',v.oid,'issuer_client',c.oid,%s,%s,%s,clock_timestamp()-interval '1 minute',clock_timestamp()+interval '5 minutes',clock_timestamp()+interval '10 minutes',true "
                "FROM pg_roles o,pg_roles v,pg_roles c WHERE o.rolname='issuer_operator' AND v.rolname='issuer_verifier' AND c.rolname='issuer_client'",
                (profile,verifier_oid,Json(binding),'synthetic-custody:'+binding['filesystem']['path']))
        return profile

    def create_grant(self, binding, verifier_oid):
        profile = self.profile(binding,verifier_oid)
        request = self.call('request',(profile,'fixture-'+str(uuid.uuid4())))
        self.call('accept',(request['request_id'],),role='issuer_verifier')
        issued = self.call('issue',(request['request_id'],))
        connection = self.connect('issuer_client')
        backend = PostgresTarget(connection)
        with backend.readonly() as cursor:
            identity = backend._identity(cursor)
            catalog = backend._catalog(cursor,('admission_bootstrap','public'))[0]
        selection = dict(identity={key:identity[key] for key in ('system_identifier','database_oid','database_name','session_user','role_oid')},
                         catalog_sha256=catalog,grant_id=issued['grant_id'])
        return connection,selection,self.owner

    def close(self):
        for connection in reversed(getattr(self,'connections',[])):
            connection.close()
        self.connections = []
        if getattr(self,'started',False):
            subprocess.run([str(PG/'pg_ctl'),'-D',str(self.data),'-m','immediate','-w','stop'],check=True,capture_output=True)
            self.started = False
        if hasattr(self,'socket_directory'):
            self.socket_directory.cleanup()


@unittest.skipUnless((PG/'initdb').exists(),'PostgreSQL16 required')
class InstallationAuthorityPostgresTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='cp-production-issuer-')
        cls.path = Path(cls.temporary.name)
        cls.certificate,cls.key = cls.path/'fixture.crt',cls.path/'fixture.key'
        subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost',
            '-addext','subjectAltName=IP:127.0.0.1,DNS:localhost','-keyout',str(cls.key),'-out',str(cls.certificate)],check=True,capture_output=True)
        cls.key.chmod(0o600)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.fixture = ProductionIssuerFixture(self.path/str(uuid.uuid4()),self.certificate,self.key)
        self.addCleanup(self.fixture.close)
        self.binding = dict(attempt_id=str(uuid.uuid4()),plan_sha256='a'*64,source_commit='b'*40,manifest_sha256='c'*64,
            target=dict(system_identifier='123456789',database_oid=123,database_name='synthetic',session_user='target_operator',role_oid=456),
            filesystem=dict(path='/synthetic/journal',device=1,inode=2,uid=1000,gid=1000,mode='0o700'),configuration_sha256='d'*64)
        self.binding['request_sha256'] = hashlib.sha256(canonical(self.binding)).hexdigest()
        if SOURCE.exists():
            self.profile = self.fixture.profile(self.binding,457)

    def request(self, nonce='request-1'):
        try:
            return self.fixture.call('request',(getattr(self,'profile',str(uuid.uuid4())),nonce))
        except (psycopg2.errors.InvalidSchemaName,psycopg2.errors.UndefinedFunction):
            self.fail('Production authenticated installation issuer is missing')

    def issue(self):
        request = self.request()
        self.fixture.call('accept',(request['request_id'],),role='issuer_verifier')
        return self.fixture.call('issue',(request['request_id'],))

    def test_authenticated_producer_requires_independent_acceptance(self):
        request = self.request()
        with self.assertRaisesRegex(psycopg2.Error,'AUTHORITY_ACCEPTANCE_REQUIRED'):
            self.fixture.call('issue',(request['request_id'],))
        with self.assertRaises(psycopg2.Error):
            self.fixture.call('accept',(request['request_id'],))
        self.fixture.call('accept',(request['request_id'],),role='issuer_verifier')
        grant = self.fixture.call('issue',(request['request_id'],))
        self.assertEqual(grant['state'],'ISSUED')
        self.assertFalse(grant['usable'])

    def test_request_accept_issue_and_historical_readback_are_idempotent(self):
        request = self.request()
        self.assertEqual(self.request(),request)
        accepted = self.fixture.call('accept',(request['request_id'],),role='issuer_verifier')
        self.assertEqual(self.fixture.call('accept',(request['request_id'],),role='issuer_verifier'),accepted)
        issued = self.fixture.call('issue',(request['request_id'],))
        self.assertEqual(self.fixture.call('issue',(request['request_id'],)),issued)
        self.assertEqual(self.fixture.call('inspect',(request['request_id'],))['grant_id'],issued['grant_id'])

    def test_describe_is_readonly_and_verifier_binding_is_exact(self):
        issued = self.issue()
        rpc = self.fixture.connect('issuer_client')
        with rpc,rpc.cursor() as cursor:
            cursor.execute('SET TRANSACTION READ ONLY')
            cursor.execute('SELECT admission_bootstrap.describe(%s,%s,%s,%s,%s)',(issued['grant_id'],'verify',Json(dict(self.binding,verifier_role_oid=457)),'preflight',str(uuid.uuid4())))
            response = cursor.fetchone()[0]
            self.assertEqual(set(response),{'schema','grant_id','operation','binding','phase','nonce','observed_at','not_before','expires_at','revoked_at','decision'})
            self.assertEqual(response['decision'],'ALLOWED')
        for operation,phase,binding in [('verify','preflight',dict(self.binding,verifier_role_oid=458)),('install','invalid',self.binding),('install','preflight',dict(self.binding,extra=True))]:
            with self.subTest(operation=operation,phase=phase),self.assertRaises(psycopg2.Error):
                self.fixture.call('describe',(issued['grant_id'],operation,Json(binding),phase,str(uuid.uuid4())),role='issuer_client')

    def test_revoke_is_irreversible_idempotent_and_requires_exact_binding(self):
        issued = self.issue()
        nonce = str(uuid.uuid4())
        wrong = dict(self.binding,plan_sha256='e'*64)
        wrong['request_sha256'] = hashlib.sha256(canonical({k:v for k,v in wrong.items() if k!='request_sha256'})).hexdigest()
        with self.assertRaisesRegex(psycopg2.Error,'AUTHORITY_BINDING_MISMATCH'):
            self.fixture.call('revoke',(issued['grant_id'],Json(wrong),nonce),role='issuer_client')
        with self.fixture.owner,self.fixture.owner.cursor() as cursor:
            cursor.execute('SELECT count(*) FROM admission_bootstrap.revocations')
            self.assertEqual(cursor.fetchone()[0],0)
        values = (issued['grant_id'],Json(self.binding),nonce)
        revoked = self.fixture.call('revoke',values,role='issuer_client')
        self.assertEqual(self.fixture.call('revoke',values,role='issuer_client'),revoked)
        with self.assertRaises(psycopg2.Error):
            self.fixture.call('describe',(issued['grant_id'],'install',Json(self.binding),'preflight',str(uuid.uuid4())),role='issuer_client')
        self.assertEqual(self.fixture.call('describe',(issued['grant_id'],'rollback',Json(self.binding),'return',str(uuid.uuid4())),role='issuer_client')['decision'],'ALLOWED')
        successor = self.request('after-revocation')
        self.fixture.call('accept',(successor['request_id'],),role='issuer_verifier')
        second = self.fixture.call('issue',(successor['request_id'],))
        with self.assertRaisesRegex(psycopg2.Error,'AUTHORITY_NONCE_CONFLICT'):
            self.fixture.call('revoke',(second['grant_id'],Json(self.binding),nonce),role='issuer_client')
        with self.fixture.owner,self.fixture.owner.cursor() as cursor:
            cursor.execute('SELECT count(*) FROM admission_bootstrap.revocations WHERE grant_id=%s',(second['grant_id'],))
            self.assertEqual(cursor.fetchone()[0],0)
        self.assertEqual(self.fixture.call('describe',(second['grant_id'],'install',Json(self.binding),'preflight',str(uuid.uuid4())),role='issuer_client')['decision'],'ALLOWED')

    def test_durable_history_denies_owner_update_delete_and_truncate(self):
        issued = self.issue()
        self.fixture.call('revoke',(issued['grant_id'],Json(self.binding),str(uuid.uuid4())),role='issuer_client')
        for table,column in [('requests','client_request_id'),('acceptances','request_digest'),('grants','binding'),
                             ('revocations','reason'),('revoke_requests','binding'),('audit','action')]:
            with self.fixture.owner,self.fixture.owner.cursor() as cursor:
                cursor.execute('SELECT count(*) FROM admission_bootstrap.'+table)
                before = cursor.fetchone()[0]
                self.assertGreater(before,0)
            for statement in ['UPDATE admission_bootstrap.'+table+' SET '+column+'='+column,
                              'DELETE FROM admission_bootstrap.'+table,'TRUNCATE admission_bootstrap.'+table+' CASCADE']:
                with self.subTest(table=table,statement=statement),self.assertRaisesRegex(psycopg2.Error,'AUTHORITY_HISTORY_IMMUTABLE'):
                    with self.fixture.owner,self.fixture.owner.cursor() as cursor:
                        cursor.execute(statement)
            with self.fixture.owner,self.fixture.owner.cursor() as cursor:
                cursor.execute('SELECT count(*) FROM admission_bootstrap.'+table)
                self.assertEqual(cursor.fetchone()[0],before)

    def test_profile_reenable_never_reactivates_old_grant(self):
        issued = self.issue()
        with self.fixture.owner,self.fixture.owner.cursor() as cursor:
            cursor.execute("SET synchronous_commit='off'")
            cursor.execute('UPDATE admission_bootstrap.profiles SET active=false WHERE profile_id=%s',(self.profile,))
            cursor.execute('SHOW synchronous_commit')
            self.assertEqual(cursor.fetchone()[0],'on')
            cursor.execute('UPDATE admission_bootstrap.profiles SET active=true WHERE profile_id=%s',(self.profile,))
        with self.assertRaises(psycopg2.Error):
            self.fixture.call('describe',(issued['grant_id'],'install',Json(self.binding),'preflight',str(uuid.uuid4())),role='issuer_client')
        self.assertEqual(self.fixture.call('inspect',(issued['request_id'],))['state'],'REVOKED')

    def test_competing_accepted_requests_have_one_custody_scope_winner(self):
        requests = [self.request('race-'+str(index)) for index in range(2)]
        for request in requests:
            self.fixture.call('accept',(request['request_id'],),role='issuer_verifier')
        def attempt(request):
            try:return self.fixture.call('issue',(request['request_id'],))
            except psycopg2.Error as error:return error.diag.message_primary
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(attempt,requests))
        self.assertEqual(sum(isinstance(value,dict) for value in outcomes),1,repr(outcomes))
        self.assertIn('AUTHORITY_SCOPE_HELD',outcomes)

    def test_filesystem_contract_rejects_null_identity_extra_keys_and_unsafe_paths(self):
        for field,value in [('device',None),('inode',0),('uid','1000'),('mode','0o777'),('extra',True),('path','/synthetic/../journal'),('path','/synthetic//journal')]:
            binding = copy.deepcopy(self.binding)
            binding['filesystem'][field] = value
            binding['request_sha256'] = hashlib.sha256(canonical({k:v for k,v in binding.items() if k!='request_sha256'})).hexdigest()
            with self.subTest(field=field,value=value),self.assertRaisesRegex(psycopg2.Error,'AUTHORITY_INVALID_BINDING'):
                self.fixture.profile(binding,457)
        for change in ["not_before='-infinity'","expires_at='infinity',rollback_expires_at='infinity'","rollback_expires_at='infinity'"]:
            with self.subTest(change=change),self.assertRaises(psycopg2.IntegrityError):
                with self.fixture.owner,self.fixture.owner.cursor() as cursor:
                    cursor.execute('UPDATE admission_bootstrap.profiles SET '+change+' WHERE profile_id=%s',(self.profile,))

    def test_canonical_unicode_and_integer_runtime_metadata_match_client(self):
        value = {'z':['é','🙂','a\nb\t\\"',None,True,False,123,-99],'α':{'key':'\x01'}}
        with self.fixture.owner,self.fixture.owner.cursor() as cursor:
            cursor.execute('SHOW server_encoding')
            self.assertEqual(cursor.fetchone()[0],'UTF8')
            cursor.execute('SELECT admission_bootstrap._canonical(%s)',(Json(value),))
            self.assertEqual(cursor.fetchone()[0],canonical(value).decode())
        binding = copy.deepcopy(self.binding)
        binding['filesystem']['runtime'] = {'nested':[True,None,123,'é🙂']}
        binding['request_sha256'] = hashlib.sha256(canonical({k:v for k,v in binding.items() if k!='request_sha256'})).hexdigest()
        self.fixture.profile(binding,457)

    def test_role_switch_trust_and_session_authorization_cannot_impersonate_operator(self):
        with self.assertRaisesRegex(psycopg2.Error,'AUTHORITY_AUTHENTICATION_REQUIRED'):
            self.fixture.call('request',(self.profile,'trust'),connection=self.fixture.owner)
        with self.fixture.owner,self.fixture.owner.cursor() as cursor:
            cursor.execute('SET SESSION AUTHORIZATION issuer_operator')
            with self.assertRaisesRegex(psycopg2.Error,'AUTHORITY_AUTHENTICATION_REQUIRED'):
                cursor.execute('SELECT admission_bootstrap.request(%s,%s)',(self.profile,'impersonate'))
        with self.fixture.owner,self.fixture.owner.cursor() as cursor:
            cursor.execute('GRANT issuer_operator TO issuer_client')
        connection = self.fixture.connect('issuer_client')
        with connection,connection.cursor() as cursor:
            cursor.execute('SET ROLE issuer_operator')
            with self.assertRaisesRegex(psycopg2.Error,'AUTHORITY_AUTHENTICATION_REQUIRED'):
                cursor.execute('SELECT admission_bootstrap.request(%s,%s)',(self.profile,'switched'))

    def test_noninherited_column_writer_and_privileged_builtin_grants_deny(self):
        with self.fixture.owner,self.fixture.owner.cursor() as cursor:
            cursor.execute('CREATE ROLE issuer_holder NOINHERIT; GRANT UPDATE(active) ON admission_bootstrap.profiles TO issuer_holder; GRANT issuer_holder TO issuer_operator WITH INHERIT FALSE, SET TRUE')
        with self.assertRaisesRegex(psycopg2.Error,'AUTHORITY_AUTHENTICATION_REQUIRED'):
            self.request()
        with self.fixture.owner,self.fixture.owner.cursor() as cursor:
            cursor.execute('REVOKE issuer_holder FROM issuer_operator; GRANT EXECUTE ON FUNCTION pg_stat_reset() TO issuer_verifier')
        with self.assertRaisesRegex(psycopg2.Error,'AUTHORITY_PROFILE_DENIED'):
            self.request()

    def test_revoke_forces_synchronous_commit_and_withdrawal_allows_rollback(self):
        issued = self.issue()
        rpc = self.fixture.connect('issuer_client')
        with rpc,rpc.cursor() as cursor:
            cursor.execute("SET synchronous_commit='off'")
            cursor.execute('SELECT admission_bootstrap.revoke(%s,%s,%s)',(issued['grant_id'],Json(self.binding),str(uuid.uuid4())))
            self.assertEqual(cursor.fetchone()[0]['state'],'REVOKED')
            cursor.execute('SHOW synchronous_commit')
            self.assertEqual(cursor.fetchone()[0],'on')
        with self.fixture.owner,self.fixture.owner.cursor() as cursor:
            cursor.execute('UPDATE admission_bootstrap.profiles SET active=false WHERE profile_id=%s',(self.profile,))
        response = self.fixture.call('describe',(issued['grant_id'],'rollback',Json(self.binding),'record_revocation',str(uuid.uuid4())),role='issuer_client')
        self.assertEqual(response['decision'],'ALLOWED')

    def test_real_operator_client_requests_accepts_issues_and_inspects(self):
        from codestra_control.installation_authority import operate
        operator = self.fixture.connect('issuer_operator')
        request = operate(operator,'request',{'profile_id':self.profile,'request_id':'client-real'},apply=True)['result']
        verifier = self.fixture.connect('issuer_verifier')
        operate(verifier,'accept',{'operation_id':request['request_id']},apply=True)
        issued = operate(operator,'issue',{'operation_id':request['request_id']},apply=True)['result']
        self.assertEqual(issued['state'],'ISSUED')
        self.assertEqual(operate(operator,'inspect',{'operation_id':request['request_id']},apply=True)['result']['grant_id'],issued['grant_id'])
