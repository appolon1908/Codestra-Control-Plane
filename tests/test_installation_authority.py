"""Protected producer transactions and distinct offline package boundaries."""
import contextlib
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys
import tempfile
import zipfile
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
REQUEST='11111111-1111-4111-8111-111111111111'
PROFILE='22222222-2222-4222-8222-222222222222'
PROOF='33333333-3333-4333-8333-333333333333'
GRANT='44444444-4444-4444-8444-444444444444'


class Transport:
    autocommit=False
    def __init__(self, fail_commit=False):
        self.pending=0; self.committed=0; self.calls=[]; self.fail_commit=fail_commit; self.closed=False
    def get_transaction_status(self): return 0
    def cursor(self): return self
    def __enter__(self): return self
    def __exit__(self,*args): return False
    def execute(self,query,values):
        self.calls.append((query,values)); self.pending+=int('inspect(' not in query)
        self.response={'request_id':REQUEST,'profile_id':PROFILE,'request_digest':'a'*64,
                       'state':'REQUESTED','usable':False}
        if 'accept(' in query:self.response.update(state='ACCEPTED',proof_id=PROOF)
        if 'issue(' in query:self.response.update(state='ISSUED',grant_id=GRANT)
    def fetchone(self): return (self.response,)
    def commit(self):
        self.committed+=self.pending;self.pending=0
        if self.fail_commit:raise RuntimeError('password=private SQL COMMIT loss')
    def rollback(self):self.pending=0
    def close(self):self.closed=True


class InstallationAuthorityTests(unittest.TestCase):
    def api(self):
        try:return importlib.import_module('codestra_control.installation_authority')
        except ImportError:self.fail('Installation authority producer source is missing')
    def test_mutations_rollback_without_disclosing_uncommitted_receipts(self):
        connection=Transport()
        result=self.api().operate(connection,'issue',{'operation_id':REQUEST})
        self.assertEqual((connection.pending,connection.committed),(0,0))
        self.assertFalse(result['committed']);self.assertNotIn('result',result)
        self.assertNotIn(GRANT,json.dumps(result))
    def test_each_committed_operation_uses_only_fixed_sql_signature(self):
        for operation,values,sql in [('request',{'profile_id':PROFILE,'request_id':'one'},'SELECT admission_bootstrap.request(%s,%s)'),
              ('accept',{'operation_id':REQUEST},'SELECT admission_bootstrap.accept(%s)'),
              ('issue',{'operation_id':REQUEST},'SELECT admission_bootstrap.issue(%s)'),
              ('inspect',{'operation_id':REQUEST},'SELECT admission_bootstrap.inspect(%s)')]:
            connection=Transport();result=self.api().operate(connection,operation,values,apply=True)
            self.assertEqual(connection.calls[0][0],sql)
            self.assertTrue(result['committed']);self.assertFalse(result['usable'])
            self.assertFalse(result['certified']);self.assertFalse(result['publication_authorized'])
    def test_lost_issuance_commit_response_exposes_no_success_and_never_retries(self):
        api=self.api();connection=Transport(True)
        with self.assertRaisesRegex(api.OutcomeUnknown,'INSPECT'):
            api.operate(connection,'issue',{'operation_id':REQUEST},apply=True)
        self.assertEqual(connection.committed,1);self.assertEqual(len(connection.calls),1)
    def test_invalid_ids_raw_payloads_and_existing_transactions_deny_before_sql(self):
        api=self.api()
        for operation,values in [('request',{'profile_id':PROFILE,'request_id':'one','binding':{}}),
                                  ('issue',{'operation_id':'../bad'}),('enroll',{})]:
            connection=Transport()
            with self.assertRaises(ValueError):api.operate(connection,operation,values,apply=True)
            self.assertEqual(connection.calls,[])
        connection=Transport();connection.autocommit=True
        with self.assertRaises(ValueError):api.operate(connection,'inspect',{'operation_id':REQUEST})
    def test_wrong_response_binding_or_missing_acceptance_cannot_be_committed(self):
        api=self.api();connection=Transport();original=connection.execute
        def execute(query,values):original(query,values);connection.response['request_id']=PROOF
        connection.execute=execute
        with self.assertRaises(ValueError):api.operate(connection,'issue',{'operation_id':REQUEST},apply=True)
        self.assertEqual(connection.committed,0)
    def test_accept_uses_separate_fixed_verifier_custody_and_sanitizes_opaque_errors(self):
        api=self.api();selected=[];connection=Transport();output=io.StringIO()
        with mock.patch.object(api,'connect_protected',side_effect=lambda path:selected.append(path) or connection),contextlib.redirect_stdout(output):
            self.assertEqual(api.main(['accept','--request',REQUEST,'--apply']),0)
        self.assertEqual(selected,[Path('/etc/codestra/control-plane/installation-authority-verifier.dsn')])
        self.assertTrue(connection.closed)
        output=io.StringIO()
        with mock.patch.object(api,'connect_protected',side_effect=RuntimeError('password=private')),contextlib.redirect_stdout(output):
            self.assertEqual(api.main(['issue','--request',REQUEST]),1)
        self.assertNotIn('private',output.getvalue())
    def test_no_caller_dsn_profile_enrollment_or_raw_receipt_route(self):
        api=self.api()
        for flag in ('--dsn','--receipt','--binding'):
            with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(api.main(['issue','--request',REQUEST,flag,'private']),1)
    def test_allowlisted_database_errors_are_actionable_without_sql_leakage(self):
        api=self.api();connection=Transport();error=RuntimeError('private SQL')
        error.pgcode='P0001';error.diag=mock.Mock(message_primary='AUTHORITY_ACCEPTANCE_REQUIRED')
        connection.execute=mock.Mock(side_effect=error)
        with self.assertRaisesRegex(ValueError,'AUTHORITY_ACCEPTANCE_REQUIRED'):
            api.operate(connection,'issue',{'operation_id':REQUEST},apply=True)
    def test_ambient_postgresql_settings_are_rejected_before_connection(self):
        api=self.api()
        with mock.patch.dict(os.environ,{'PGHOST':'private'}),self.assertRaises(ValueError):
            api.connection_parameters(b'host=example.invalid')
    def test_root_entrypoint_cannot_import_project_code(self):
        import builtins
        real=builtins.__import__
        def guarded(name,*args,**kwargs):
            if name.startswith('codestra_control'):raise AssertionError('project imported before custody')
            return real(name,*args,**kwargs)
        with mock.patch('os.getuid',return_value=0),mock.patch('os.geteuid',return_value=0),mock.patch('builtins.__import__',side_effect=guarded),contextlib.redirect_stdout(io.StringIO()),self.assertRaises(SystemExit) as stopped:
            runpy.run_path(str(Path(__file__).resolve().parents[1]/'bin/codestra-installation-authority'),run_name='__main__')
        self.assertEqual(stopped.exception.code,1)

    def package_fixture(self):
        api=self.api();temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        root=Path(temporary.name);source=root/'source';source.mkdir()
        repository=Path(__file__).resolve().parents[1]
        for name in api.FILES:
            path=source/name;path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes((repository/name).read_bytes() if name!=api.SQL else b'-- source fixture\n')
            path.chmod(0o755 if name.startswith('bin/') else 0o644)
        wheel=root/'synthetic-wheel.whl'
        with zipfile.ZipFile(wheel,'w') as archive:
            entry=zipfile.ZipInfo('psycopg2/__init__.py');entry.external_attr=0o100644<<16
            archive.writestr(entry,b'# Synthetic packaging bytes only; never imported.\n')
        wheel_hash=hashlib.sha256(wheel.read_bytes()).hexdigest()
        (source/'requirements-publisher.txt').write_text('psycopg2-binary==2.9.10 --hash=sha256:'+wheel_hash+'\n')
        def git(*args):return subprocess.check_output(['/usr/bin/git','-C',str(source),*args],stderr=subprocess.DEVNULL,text=True).strip()
        git('init');git('config','user.name','Source Fixture');git('config','user.email','fixture@example.invalid');git('add','.');git('commit','-m','fixture')
        commit=git('rev-parse','HEAD');original=(source/'lib/codestra_control/installation_authority.py').read_bytes()
        (source/'lib/codestra_control/installation_authority.py').write_text('raise RuntimeError("uncommitted")\n')
        output=root/'candidate';manifest=api.prepare_source(source,commit,output,wheel)
        return output,manifest,original

    def test_package_reads_exact_commit_and_stays_distinct_from_installer_authority(self):
        api=self.api();output,manifest,original=self.package_fixture()
        self.assertEqual((output/'lib/codestra_control/installation_authority.py').read_bytes(),original)
        self.assertTrue(manifest['source_only']);self.assertIsNone(manifest['installation_profile'])
        self.assertFalse(manifest['install_allowed']);self.assertFalse(manifest['authority_provisioning_approved'])
        self.assertFalse((output/'controller-release-manifest.json').exists())
        self.assertEqual({entry['path'] for entry in manifest['files']},set(api.FILES)|{api.WHEEL})

    def test_guard_checks_actual_fixture_bytes_and_rejects_tampering_and_unlisted_cache(self):
        api=self.api();output,manifest,_=self.package_fixture()
        guard=runpy.run_path(str(Path(__file__).resolve().parents[1]/'bin/codestra-installation-authority'))['validate_source']
        digest=hashlib.sha256((output/api.MANIFEST).read_bytes()).hexdigest()
        self.assertEqual(guard(output,digest,owner=os.getuid()),output)
        module=output/'lib/codestra_control/installation_authority.py';original=module.read_bytes();module.write_bytes(original+b'\n# tamper\n')
        with self.assertRaises(ValueError):guard(output,digest,owner=os.getuid())
        module.write_bytes(original)
        cache=module.parent/'__pycache__';cache.mkdir();(cache/'unlisted.pyc').write_bytes(b'fake')
        with self.assertRaises(ValueError):guard(output,digest,owner=os.getuid())

    def test_driver_host_cache_and_tampered_payload_deny_before_any_driver_import(self):
        api=self.api()
        with mock.patch.dict(sys.modules,{'psycopg2':object()}),self.assertRaisesRegex(ValueError,'DRIVER_UNPROVISIONED'):
            api._driver()
        archive=io.BytesIO()
        with zipfile.ZipFile(archive,'w') as wheel:
            entry=zipfile.ZipInfo('psycopg2/__init__.py');entry.external_attr=(0o100644<<16);wheel.writestr(entry,b'pass\n')
        wheel=archive.getvalue();metadata=json.dumps({'driver':{'sha256':hashlib.sha256(wheel).hexdigest()}}).encode()
        observed=[]
        def read(path,**kwargs):
            if str(path).endswith(api.MANIFEST):return metadata
            if str(path).endswith('.whl'):return wheel
            observed.append(path)
            return b'tampered\n'
        with mock.patch.dict(sys.modules):
            for name in list(sys.modules):
                if name=='psycopg2' or name.startswith('psycopg2.'):sys.modules.pop(name)
            with mock.patch.object(api,'protected_read',side_effect=read),mock.patch.object(api.importlib,'import_module',side_effect=AssertionError('driver imported before validation')):
                with self.assertRaisesRegex(ValueError,'DRIVER_UNPROVISIONED'):api._driver()
            self.assertEqual(observed,[api.DRIVER_ROOT/'psycopg2/__init__.py'])
            def valid_read(path,**kwargs):
                if str(path).endswith(api.MANIFEST):return metadata
                if str(path).endswith('.whl'):return wheel
                return b'pass\n'
            layout=[(str(api.DRIVER_ROOT),['psycopg2'],[]),
                    (str(api.DRIVER_ROOT/'psycopg2'),[],['__init__.py'])]
            with mock.patch.object(api,'protected_read',side_effect=valid_read), \
                 mock.patch.object(api.os,'walk',return_value=layout), \
                 mock.patch.object(Path,'lstat',return_value=SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_uid=0)), \
                 mock.patch.object(api.sys,'path',list(sys.path)), \
                 mock.patch.object(api.importlib,'import_module',return_value=SimpleNamespace(__file__='/untrusted/psycopg2.py')) as imported:
                with self.assertRaisesRegex(ValueError,'DRIVER_UNPROVISIONED'):api._driver()
            imported.assert_called_once_with('psycopg2')


if __name__=='__main__':unittest.main()
