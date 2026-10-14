"""Real SQL authorization tests in a disposable socket-only PostgreSQL cluster."""
import concurrent.futures
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import psycopg2
from psycopg2.extras import Json
from psycopg2 import sql

ROOT = Path(__file__).resolve().parents[1]
PG = Path('/usr/lib/postgresql/16/bin')


@unittest.skipUnless((PG / 'initdb').exists(), 'PostgreSQL 16 disposable test binaries required')
class ScopedRegistrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='cp-registration-test-')
        cls.path = Path(cls.tmp.name)
        cls.data = cls.path / 'data'
        cls.started = False
        try:
            subprocess.run([str(PG / 'initdb'), '-D', str(cls.data), '-A', 'trust', '-U', 'fixture_admin', '--no-locale'], check=True, capture_output=True)
            subprocess.run([str(PG / 'pg_ctl'), '-D', str(cls.data), '-l', str(cls.path / 'postgres.log'), '-o', f"-k {cls.path} -p 6543 -c listen_addresses=''", '-w', 'start'], check=True, capture_output=True)
            cls.started = True
            with cls.connect('fixture_admin') as c:
                with c.cursor() as cur:
                    cur.execute((ROOT / 'schema.sql').read_text())
                    cur.execute((ROOT / '002-hierarchy-promotion.sql').read_text())
                    cur.execute("CREATE TABLE scope_certifications(product text,scope_type text,scope_name text,sha text,status text,PRIMARY KEY(product,scope_type,scope_name))")
                    cur.execute("CREATE ROLE registration_runtime NOLOGIN; CREATE ROLE alice LOGIN; CREATE ROLE bob LOGIN; CREATE ROLE mallory LOGIN; GRANT registration_runtime TO alice,bob,mallory")
                    # A legacy row must survive forward migration unchanged.
                    cur.execute("INSERT INTO products(product,repository) VALUES('legacy','appolon1908/legacy')")
                    cur.execute((ROOT / '005-scoped-registration.sql').read_text())
                    cur.execute('GRANT USAGE ON SCHEMA scoped_registration TO registration_runtime')
                    cur.execute('GRANT EXECUTE ON FUNCTION scoped_registration.register(text,jsonb,text,text) TO registration_runtime')
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        if cls.started:
            subprocess.run([str(PG / 'pg_ctl'), '-D', str(cls.data), '-m', 'immediate', '-w', 'stop'], check=True, capture_output=True)
        cls.tmp.cleanup()

    @classmethod
    def connect(cls, user='alice'):
        # Never accepts a caller/environment DSN or connects to the installed DB.
        return psycopg2.connect(host=str(cls.path), port=6543, dbname='postgres', user=user)

    def setUp(self):
        with self.connect('fixture_admin') as c, c.cursor() as cur:
            cur.execute('TRUNCATE scoped_registration.audit,scoped_registration.candidates,scoped_registration.task_assignments,scoped_registration.workstations,scoped_registration.products,scoped_registration.grants,scoped_registration.principals CASCADE')
            cur.execute("DELETE FROM atomic_tasks; DELETE FROM sections; DELETE FROM workstations; DELETE FROM products WHERE product<>'legacy'; DELETE FROM scope_certifications")
            cur.execute("INSERT INTO scoped_registration.principals(principal,role_oid) SELECT rolname,oid FROM pg_roles WHERE rolname IN ('alice','bob','mallory')")
            for product in ('A', 'B'):
                for capability in ('product', 'workstation', 'candidate'):
                    cur.execute('INSERT INTO scoped_registration.grants VALUES(%s,%s,%s,%s)', ('alice', product, capability, 'appolon1908/' + product))

    def product(self, name='A'):
        return dict(product=name, repository='appolon1908/' + name, test_branch='testing', promotion_chain=['development','testing','staging','production'])

    def workstation(self, name='A', wid=None):
        return dict(product=name, workstation_id=wid or name+'-ws', section='sec', subsection='sub', branch='subsection/sec--sub', parent_branch='section/sec', worktree='/fixture/'+name+'/subsection', order_index=1)

    def candidate(self, name='A', task=None):
        return dict(product=name, workstation_id=name+'-ws', task_id=task or name+'-task', title='fixture task', branch='atomic/sec--sub--task', target_branch='subsection/sec--sub', worktree='/fixture/'+name+'/atomic', head_sha='a'*40, base_sha='b'*40, prerequisites=[])

    def register(self, kind, payload, request='request', user='alice', dry=False, role=None):
        c = self.connect(user)
        try:
            with c.cursor() as cur:
                if role:
                    cur.execute(sql.SQL('SET ROLE {}').format(sql.Identifier('registration_runtime' if role is True else role)))
                cur.execute('SELECT scoped_registration.register(%s,%s,%s,%s)', (kind, Json(payload), request, 'c'*64))
                result = cur.fetchone()[0]
            c.rollback() if dry else c.commit()
            return result
        finally:
            c.close()

    def prepare(self, name='A'):
        self.register('product', self.product(name), name+'-product')
        with self.connect('fixture_admin') as c, c.cursor() as cur:
            cur.execute('INSERT INTO sections(section_id,product,section_key,branch,order_index) VALUES(%s,%s,%s,%s,1)', (name+'-sec',name,'sec','section/sec'))
        self.register('workstation', self.workstation(name), name+'-ws')
        with self.connect('fixture_admin') as c, c.cursor() as cur:
            cur.execute('INSERT INTO scoped_registration.task_assignments(product,workstation_id,task_id,principal) VALUES(%s,%s,%s,%s)', (name,name+'-ws',name+'-task','alice'))

    def denied(self, kind, payload, code, **kwargs):
        with self.assertRaisesRegex(psycopg2.Error, code):
            self.register(kind, payload, **kwargs)

    def count(self, table):
        with self.connect('fixture_admin') as c, c.cursor() as cur:
            cur.execute('SELECT count(*) FROM scoped_registration.'+table)
            return cur.fetchone()[0]

    def test_authentication_grants_and_role_switch(self):
        self.denied('product', self.product(), 'REGISTRATION_DENIED', user='mallory')
        self.denied('product', self.product(), 'REGISTRATION_DENIED', user='fixture_admin')
        self.denied('product', self.product(), 'REGISTRATION_DENIED', user='mallory', role=True)
        with self.connect('fixture_admin') as c, c.cursor() as cur:
            cur.execute('GRANT alice TO mallory')
        self.denied('product',self.product(),'REGISTRATION_DENIED',user='mallory',role='alice')
        result = self.register('product', self.product(), role=True)
        self.assertEqual(result['principal'], 'alice')
        self.assertFalse(result['authority'])
        self.assertFalse(result['ready'])

    def test_wrong_product_repository_revoked_grant_and_spoofed_owner(self):
        self.denied('product', self.product('C'), 'REGISTRATION_DENIED')
        self.denied('product', dict(self.product(),repository='appolon1908/B'), 'REGISTRATION_DENIED')
        self.denied('product', dict(self.product(),owner='alice'), 'INVALID_PAYLOAD')
        with self.connect('fixture_admin') as c, c.cursor() as cur:
            cur.execute("DELETE FROM scoped_registration.grants WHERE principal='alice' AND product='A'")
        self.denied('product', self.product(), 'REGISTRATION_DENIED')

    def test_dropped_recreated_login_does_not_inherit_old_authority(self):
        with self.connect('fixture_admin') as c, c.cursor() as cur:
            cur.execute("INSERT INTO scoped_registration.grants VALUES('mallory','A','product','appolon1908/A')")
            cur.execute("DROP ROLE mallory; CREATE ROLE mallory LOGIN; GRANT registration_runtime TO mallory")
        self.denied('product',self.product(),'REGISTRATION_DENIED',user='mallory')

    def test_runtime_cannot_write_grants_assignments_or_audit(self):
        for table in ('grants','task_assignments','audit','products','workstations','candidates','lanes','principals'):
            with self.subTest(table=table), self.connect() as c, c.cursor() as cur:
                with self.assertRaisesRegex(psycopg2.Error, 'permission denied'):
                    cur.execute('DELETE FROM scoped_registration.'+table)

    def test_runtime_cannot_mutate_legacy_authority_tables(self):
        for table in ('products','workstations','atomic_tasks','scope_certifications'):
            with self.subTest(table=table), self.connect() as c, c.cursor() as cur:
                with self.assertRaisesRegex(psycopg2.Error,'permission denied'):
                    cur.execute('DELETE FROM public.'+table)

    def test_candidate_separates_subsection_lane_and_binds_principal(self):
        self.prepare()
        result = self.register('candidate', self.candidate())
        self.assertEqual(result['principal'], 'alice')
        self.assertFalse(result['authority'])
        with self.connect('fixture_admin') as c, c.cursor() as cur:
            cur.execute("SELECT w.branch,c.branch,c.principal,a.owner FROM scoped_registration.workstations w JOIN scoped_registration.candidates c USING(product,workstation_id) JOIN atomic_tasks a ON a.task_id=c.task_id")
            self.assertEqual(cur.fetchone(), ('subsection/sec--sub','atomic/sec--sub--task','alice','alice'))
        self.denied('candidate', dict(self.candidate(),worktree='/fixture/A/subsection'), 'INVALID_CANDIDATE_LANE', request='other')
        self.denied('candidate', dict(self.candidate(),target_branch='subsection/other'), 'INVALID_CANDIDATE_LANE', request='other')

    def test_cross_product_workstation_task_prerequisite_and_owner_denial(self):
        self.prepare('A'); self.prepare('B')
        self.denied('candidate', dict(self.candidate('A'),workstation_id='B-ws'), 'ASSIGNMENT_REQUIRED')
        self.denied('candidate', dict(self.candidate('A'),task_id='B-task'), 'ASSIGNMENT_REQUIRED')
        self.denied('candidate', dict(self.candidate(),prerequisites=[dict(product='B',scope_type='SECTION',scope_name='sec',sha='d'*40)]), 'INVALID_PREREQUISITE')
        with self.connect('fixture_admin') as c, c.cursor() as cur:
            cur.execute("INSERT INTO scoped_registration.grants VALUES('bob','A','candidate','appolon1908/A')")
        self.denied('candidate', self.candidate(), 'ASSIGNMENT_REQUIRED', user='bob')

    def test_prerequisites_require_exact_certificate_without_conferring_authority(self):
        self.prepare()
        p=dict(product='A',scope_type='SECTION',scope_name='sec',sha='d'*40)
        value=dict(self.candidate(),prerequisites=[p])
        self.denied('candidate', value, 'PREREQUISITE_NOT_CERTIFIED')
        with self.connect('fixture_admin') as c, c.cursor() as cur:
            cur.execute("INSERT INTO scope_certifications VALUES('A','SECTION','sec',%s,'CERTIFIED')", ('e'*40,))
        self.denied('candidate', value, 'PREREQUISITE_NOT_CERTIFIED')
        with self.connect('fixture_admin') as c, c.cursor() as cur:
            cur.execute("UPDATE scope_certifications SET sha=%s", ('d'*40,))
        self.assertFalse(self.register('candidate', value)['authority'])

    def test_idempotent_retry_conflict_and_provenance(self):
        first=self.register('product',self.product())
        self.assertEqual(first,self.register('product',self.product()))
        self.assertEqual(self.count('audit'),1)
        self.denied('product',dict(self.product(),test_branch='test',promotion_chain=['development','test','staging','production']), 'REQUEST_CONFLICT')
        self.denied('product',dict(self.product(),test_branch='test',promotion_chain=['development','test','staging','production']), 'BINDING_CONFLICT',request='different')
        with self.connect('fixture_admin') as c, c.cursor() as cur:
            cur.execute('SELECT principal,manifest_sha256,payload FROM scoped_registration.audit')
            principal,digest,payload=cur.fetchone()
            self.assertEqual((principal,digest,payload),('alice','c'*64,self.product()))

    def test_dry_run_and_failed_candidate_leave_no_partial_rows(self):
        self.register('product',self.product(),dry=True)
        self.assertEqual(self.count('products'),0); self.assertEqual(self.count('audit'),0)
        self.prepare()
        self.denied('candidate',dict(self.candidate(),head_sha='0'*40),'INVALID_PAYLOAD')
        self.assertEqual(self.count('candidates'),0)
        with self.connect('fixture_admin') as c, c.cursor() as cur:
            cur.execute('SELECT count(*) FROM atomic_tasks'); self.assertEqual(cur.fetchone()[0],0)

    def test_concurrent_duplicate_has_one_audit_and_cross_product_isolation(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results=list(pool.map(lambda _: self.register('product',self.product()), range(4)))
        self.assertTrue(all(r==results[0] for r in results)); self.assertEqual(self.count('audit'),1)
        self.prepare('A'); self.prepare('B')
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(lambda n:self.register('candidate',self.candidate(n),request='same-request'),('A','B')))
        self.assertEqual({r['product'] for r in results},{'A','B'})
        self.assertEqual(self.count('candidates'),2)

    def test_duplicate_physical_lane_is_rejected_without_orphan_task(self):
        self.prepare('A')
        self.register('candidate', self.candidate())
        with self.connect('fixture_admin') as c, c.cursor() as cur:
            cur.execute("INSERT INTO scoped_registration.task_assignments VALUES('A','A-ws','second-task','alice')")
        self.denied('candidate', dict(self.candidate(),task_id='second-task'), 'BINDING_CONFLICT',request='second')
        self.assertEqual(self.count('candidates'),1)
        with self.connect('fixture_admin') as c, c.cursor() as cur:
            cur.execute("SELECT count(*) FROM atomic_tasks WHERE task_id='second-task'")
            self.assertEqual(cur.fetchone()[0],0)

    def test_migration_repeat_and_legacy_metadata_survive_rollback(self):
        with self.connect('fixture_admin') as c, c.cursor() as cur:
            cur.execute((ROOT/'005-scoped-registration.sql').read_text())
            cur.execute("SELECT repository FROM products WHERE product='legacy'")
            self.assertEqual(cur.fetchone()[0],'appolon1908/legacy')
        self.register('product',self.product(),dry=True)
        with self.connect('fixture_admin') as c, c.cursor() as cur:
            cur.execute("SELECT repository FROM products WHERE product='legacy'")
            self.assertEqual(cur.fetchone()[0],'appolon1908/legacy')

    def test_legacy_test_ref_and_chain_are_preserved(self):
        payload=dict(self.product(),test_branch='test')
        with self.connect('fixture_admin') as c, c.cursor() as cur:
            cur.execute("INSERT INTO products(product,repository,test_branch,promotion_chain) VALUES('A','appolon1908/A','test',%s)", (Json(payload['promotion_chain']),))
        self.register('product',payload)
        with self.connect('fixture_admin') as c, c.cursor() as cur:
            cur.execute("SELECT test_branch,promotion_chain FROM products WHERE product='A'")
            self.assertEqual(cur.fetchone(),('test',['development','testing','staging','production']))

    def test_concurrent_candidates_and_cross_product_physical_worktree_conflict(self):
        self.prepare('A'); self.prepare('B')
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            results=list(pool.map(lambda _: self.register('candidate',self.candidate(),request='candidate-retry'),range(3)))
        self.assertEqual(results[0],results[1]); self.assertEqual(self.count('candidates'),1)
        self.denied('candidate',dict(self.candidate('B'),worktree='/fixture/A/atomic'),'BINDING_CONFLICT',request='other-product')
        self.assertEqual(self.count('candidates'),1)

    def test_retry_rechecks_revoked_grants_and_legacy_workstation_drift(self):
        self.prepare()
        self.register('candidate',self.candidate())
        with self.connect('fixture_admin') as c, c.cursor() as cur:
            cur.execute("DELETE FROM scoped_registration.grants WHERE product='A' AND capability='candidate'")
        self.denied('candidate',self.candidate(),'REGISTRATION_DENIED')
        with self.connect('fixture_admin') as c, c.cursor() as cur:
            cur.execute("INSERT INTO scoped_registration.grants VALUES('alice','A','candidate','appolon1908/A')")
            cur.execute("UPDATE workstations SET section='other' WHERE workstation_id='A-ws'")
        self.denied('candidate',self.candidate(),'BINDING_CONFLICT',request='new')

    def test_task_assignment_can_be_revoked_without_deleting_history(self):
        self.prepare()
        self.register('candidate',self.candidate())
        with self.connect('fixture_admin') as c, c.cursor() as cur:
            cur.execute("UPDATE scoped_registration.task_assignments SET active=false WHERE task_id='A-task'")
        self.denied('candidate',self.candidate(),'ASSIGNMENT_REQUIRED')
        self.assertEqual(self.count('candidates'),1)

    def test_unadopted_legacy_worktrees_cannot_be_reused(self):
        self.prepare()
        with self.connect('fixture_admin') as c, c.cursor() as cur:
            for kind in ('candidate','workstation'):
                cur.execute("INSERT INTO workstations(workstation_id,product,section,subsection,branch,parent_branch,worktree,order_index) VALUES(%s,'legacy','sec',%s,%s,'section/sec',%s,1)",('legacy-'+kind,kind,'subsection/sec--'+kind,'/fixture/legacy-'+kind))
        values=[('candidate',dict(self.candidate(),worktree='/fixture/legacy-candidate')),
                ('workstation',dict(self.workstation(),workstation_id='other-ws',subsection='other',branch='subsection/sec--other',worktree='/fixture/legacy-workstation'))]
        for kind,payload in values:
            with self.subTest(kind=kind):
                self.denied(kind,payload,'INVALID_CANDIDATE_LANE|BINDING_CONFLICT',request='legacy-'+kind)

    def test_cli_dry_run_apply_and_owner_label_rejection(self):
        manifest=self.path/'manifest.json'
        manifest.write_text(json.dumps(self.product()))
        env=dict(os.environ,CODESTRA_REGISTRATION_DSN=f'host={self.path} port=6543 dbname=postgres user=alice')
        command=[sys.executable,str(ROOT/'bin/codestra-register'),'product','--manifest',str(manifest),'--request-id','cli-request']
        result=subprocess.run(command,env=env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['mode'],'dry-run')
        self.assertEqual(self.count('products'),0)
        result=subprocess.run(command+['--apply'],env=env,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.count('products'),1)
        self.assertEqual(subprocess.run(command+['--owner','alice'],env=env,capture_output=True).returncode,2)
        manifest.write_text('{"product":"A","product":"B"}')
        result=subprocess.run(command,env=env,capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.count('audit'),1)

    def test_foreign_keys_and_legacy_conflicts(self):
        with self.connect('fixture_admin') as c, c.cursor() as cur:
            with self.assertRaises(psycopg2.IntegrityError):
                cur.execute("INSERT INTO scoped_registration.task_assignments VALUES('A','missing','task','alice')")
        with self.connect('fixture_admin') as c, c.cursor() as cur:
            cur.execute("INSERT INTO products(product,repository) VALUES('A','appolon1908/wrong')")
        self.denied('product', self.product(), 'BINDING_CONFLICT')
        self.assertEqual(self.count('audit'),0)


if __name__ == '__main__':
    unittest.main()
