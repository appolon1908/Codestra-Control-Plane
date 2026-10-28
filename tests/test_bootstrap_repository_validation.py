"""Exercise the real entry point with a non-network GitHub transport."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class BootstrapRepositoryValidationTests(unittest.TestCase):
    def test_rollout_never_self_certifies_installation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport = root / 'sudo'
            transport.write_text("#!/usr/bin/env python3\nimport json,os,sys\nwith open(os.environ['TRANSPORT_LOG'],'a') as f:f.write(json.dumps(sys.argv[1:])+'\\n')\nprint('{}')\n")
            transport.chmod(0o700)
            git = root / 'git'
            git.write_text('#!/bin/sh\nprintf "%040d\\n" 1\n')
            git.chmod(0o700)
            log = root / 'calls.jsonl'
            # Bash functions can replace the exact hardcoded installer path.
            # The real rollout shell is sourced unchanged; no installer runs.
            command = 'function /srv/codestra/dev-platform/control-plane/bin/codestra-install-family-governance() { return 0; }; source "$1"'
            result = subprocess.run(['bash','--noprofile','--norc','-c',command,'fixture',
                str(ROOT/'bin/codestra-rollout-standalone-governance')],
                env={**os.environ,'PATH':str(root)+':/usr/bin:/bin','TRANSPORT_LOG':str(log)},
                capture_output=True,text=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr)
            calls=[json.loads(line) for line in log.read_text().splitlines()]
            writes=[call for call in calls if '--method' in call and call[call.index('--method')+1]!='GET']
            self.assertEqual(writes,[], 'Installing source files must not certify a bootstrap')

    def test_validation_never_publishes_controller_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport = root / 'sudo'
            transport.write_text('''#!/usr/bin/env python3
import base64,json,os,sys
from pathlib import Path
a=sys.argv[sys.argv.index('gh')+1:] if 'gh' in sys.argv else sys.argv[1:]
with open(os.environ['TRANSPORT_LOG'],'a') as f:f.write(json.dumps(a)+'\\n')
if a[:2] in (['pr','list'], ['pr','view']):
 p={'number':1,'headRefOid':'a'*40,'url':'https://github.com/appolon1908/Codestra-Connect/pull/1','headRefName':'workstation/standalone-v3-20261007','baseRefName':'development','baseRefOid':'b'*40,'state':'OPEN','isCrossRepository':False}
 print(json.dumps(p if '--jq' in a or a[1]=='view' else [p]))
elif a and a[0]=='api':
 if '--method' in a and a[a.index('--method')+1]!='GET':print('{}');sys.exit(0)
 if '/pulls' in ' '.join(a):
  p={'number':1,'state':'open','head':{'ref':'workstation/standalone-v3-20261007','sha':'a'*40,'repo':{'full_name':'appolon1908/Codestra-Connect'}},'base':{'ref':'development','sha':'b'*40,'repo':{'full_name':'appolon1908/Codestra-Connect'}},'html_url':'https://github.com/appolon1908/Codestra-Connect/pull/1'}
  print(json.dumps([p] if '?' in a[-1] else p));sys.exit(0)
 if 'policy.json' in ' '.join(a):
  raw=json.dumps({'schema_version':'codestra.governance.v3','repository':'appolon1908/Codestra-Connect','required_status':'codestra-control-plane','promotion_chain':['subsection','section','development','testing','staging','production'],'production':{'PRODUCTION_GO':'NO','LIVE_CAPABILITIES_ENABLED':'NO','EXTERNAL_EFFECTS':'false'},'force_push':False,'direct_protected_branch_writes':False}).encode()
 elif 'workstations.json' in ' '.join(a):raw=b'{"workstations":[{"id":"fixture"}]}'
 else:raw=b'# Development contract\\n'
 content=base64.b64encode(raw).decode()
 print(content if '--jq' in a else json.dumps({'type':'file','encoding':'base64','content':content,'size':len(raw)}))
else:sys.exit(2)
''')
            transport.chmod(0o700)
            (root / 'gh').symlink_to(transport)
            log = root / 'calls.jsonl'
            result = subprocess.run([str(ROOT / 'bin/codestra-validate-v3-bootstrap-prs'), '--repo', 'appolon1908/Codestra-Connect'],
                env={**os.environ, 'PATH':str(root)+':/usr/bin:/bin','TRANSPORT_LOG':str(log)},
                capture_output=True,text=True,timeout=30)
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            writes = [call for call in calls if '--method' in call and call[call.index('--method')+1] != 'GET']
            self.assertEqual(writes, [], 'Source validation must not publish authenticated controller success')
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertNotIn('BOOTSTRAP=PASS',result.stdout)


# The real inspector runs against a transport fixture, never a product remote.
import base64
import copy
import sys
from unittest import mock
sys.path.insert(0, str(ROOT / 'lib'))
from codestra_control import bootstrap_repository_validation as api

REPO = 'appolon1908/Codestra-Connect'
CANDIDATE = {'number':21,'state':'OPEN','headRefName':'workstation/standalone-v3-r2-20261007',
             'headRefOid':'a'*40,'baseRefName':'development','baseRefOid':'b'*40,
             'isCrossRepository':False,'url':'https://github.com/appolon1908/Codestra-Connect/pull/21'}
POLICY = {'schema_version':'codestra.governance.v3','repository':'appolon1908/Codestra-Connect','required_status':'codestra-control-plane',
          'promotion_chain':['subsection','section','development','testing','staging','production'],
          'production':{'PRODUCTION_GO':'NO','LIVE_CAPABILITIES_ENABLED':'NO','EXTERNAL_EFFECTS':'false'},
          'force_push':False,'direct_protected_branch_writes':False}

class SourceReader:
    def __init__(self):
        self.rows = [copy.deepcopy(CANDIDATE)]
        self.current = copy.deepcopy(CANDIDATE)
        self.files = {'.codestra/governance/policy.json':json.dumps(POLICY).encode(),
                      '.codestra/governance/workstations.json':b'{"workstations":[{"id":"fixture"}]}',
                      'AGENTS.md':b'# Fixture development contract\n'}
        self.reads = []
    def candidates(self, repository):return copy.deepcopy(self.rows)
    def candidate(self, repository, number):return copy.deepcopy(self.current)
    def content(self, repository, sha, path):
        self.reads.append((repository,sha,path))
        raw=self.files[path]
        return {'type':'file','encoding':'base64','content':base64.b64encode(raw).decode(),'size':len(raw)}

class InspectorTests(unittest.TestCase):
    def test_replacement_branch_is_inspected_at_exact_sha_without_admission(self):
        reader=SourceReader();result=api.inspect_repository(reader,REPO)
        self.assertTrue(result['source_validated'])
        self.assertEqual(result['authority'],'NONE')
        self.assertFalse(result['certified']);self.assertFalse(result['publication_authorized'])
        self.assertEqual(reader.reads,[(REPO,'a'*40,p) for p in [
            '.codestra/governance/policy.json','.codestra/governance/workstations.json','AGENTS.md']])
    def test_old_and_replacement_candidates_require_explicit_selection(self):
        reader=SourceReader();old=copy.deepcopy(CANDIDATE);old.update(number=18,headRefName='workstation/standalone-v3-20261007')
        reader.rows.append(old)
        result=api.inspect_repository(reader,REPO)
        self.assertEqual(result['reason'],'AMBIGUOUS_BOOTSTRAP_CANDIDATES');self.assertEqual(reader.reads,[])
        self.assertTrue(api.inspect_repository(reader,REPO,CANDIDATE['headRefName'])['source_validated'])
    def test_different_head_base_or_route_after_reads_never_validates(self):
        for field,value in [('headRefOid','c'*40),('baseRefOid','c'*40),('baseRefName','main'),('state','CLOSED')]:
            with self.subTest(field=field):
                reader=SourceReader();reader.current[field]=value
                self.assertFalse(api.inspect_repository(reader,REPO)['source_validated'])
    def test_fork_and_wrong_repository_url_deny_before_content_reads(self):
        for field,value in [('isCrossRepository',True),('url','https://github.com/appolon1908/Other/pull/21')]:
            with self.subTest(field=field):
                reader=SourceReader();reader.rows[0][field]=value
                self.assertFalse(api.inspect_repository(reader,REPO)['source_validated']);self.assertEqual(reader.reads,[])
    def test_missing_candidate_and_saturated_listing_fail_closed(self):
        for rows,reason in [([], 'PR_MISSING'),([CANDIDATE]*100,'INCOMPLETE_CANDIDATE_LIST')]:
            reader=SourceReader();reader.rows=rows
            self.assertEqual(api.inspect_repository(reader,REPO)['reason'],reason)
    def test_weakened_policy_and_bool_coercion_rejected(self):
        for field,value in [('repository','appolon1908/Unrelated'),('required_status','ordinary-ci'),('force_push',True),('force_push',0),('direct_protected_branch_writes',0),('promotion_chain',['development','production'])]:
            with self.subTest(field=field,value=value):
                reader=SourceReader();policy=copy.deepcopy(POLICY);policy[field]=value
                reader.files['.codestra/governance/policy.json']=json.dumps(policy).encode()
                self.assertEqual(api.inspect_repository(reader,REPO)['reason'],'POLICY_INVALID')
    def test_live_production_settings_rejected(self):
        for field in ('PRODUCTION_GO','LIVE_CAPABILITIES_ENABLED','EXTERNAL_EFFECTS'):
            reader=SourceReader();policy=copy.deepcopy(POLICY);policy['production'][field]='true'
            reader.files['.codestra/governance/policy.json']=json.dumps(policy).encode()
            self.assertFalse(api.inspect_repository(reader,REPO)['source_validated'])
    def test_duplicate_keys_and_nonfinite_numbers_rejected(self):
        for raw,reason in [(b'{"x":1,"x":2}','DUPLICATE_JSON_KEY'),(b'{"x":NaN}','NONFINITE_JSON'),(b'{"x":1e999}','NONFINITE_JSON')]:
            reader=SourceReader();reader.files['.codestra/governance/policy.json']=raw
            self.assertEqual(api.inspect_repository(reader,REPO)['reason'],reason)
    def test_invalid_companion_files_are_not_treated_as_present(self):
        for path,raw in [('.codestra/governance/workstations.json',b'[]'),('.codestra/governance/workstations.json',b'{}'),('AGENTS.md',b'   '),('AGENTS.md',b'\xff')]:
            reader=SourceReader();reader.files[path]=raw
            self.assertFalse(api.inspect_repository(reader,REPO)['source_validated'])
    def test_file_envelope_rejects_symlinks_and_size_mismatch(self):
        for value in [{'type':'symlink'}, {'type':'file','encoding':'base64','size':3,'content':'YQ=='},
                      {'type':'file','encoding':'base64','size':1,'content':'???'},
                      {'type':'file','encoding':'base64','size':True,'content':'YQ=='}]:
            reader=SourceReader();reader.content=lambda *args:value
            self.assertEqual(api.inspect_repository(reader,REPO)['reason'],'INVALID_SOURCE_FILE')
    def test_unavailable_repo_does_not_prevent_remaining_inspections(self):
        import contextlib,io
        class Reader(SourceReader):
            def candidates(self, repository):
                if repository.endswith('/Missing'):raise api.InvalidSource('GITHUB_READ_UNAVAILABLE')
                return super().candidates(repository)
        output=io.StringIO()
        with mock.patch.object(api,'GitHubReader',Reader),contextlib.redirect_stdout(output):
            status=api.main(['--repo','appolon1908/Missing','--repo',REPO])
        self.assertEqual(status,1);results=json.loads(output.getvalue())['results']
        self.assertFalse(results[0]['source_validated']);self.assertTrue(results[1]['source_validated'])
    def test_transport_failures_redact_private_error_text(self):
        for effect in [OSError('private-token'),subprocess.TimeoutExpired('private-token',30)]:
            with mock.patch.object(api.subprocess,'run',side_effect=effect):
                result=api.inspect_repository(api.GitHubReader(),REPO)
            self.assertEqual(result['reason'],'GITHUB_READ_UNAVAILABLE');self.assertNotIn('private-token',json.dumps(result))
    def test_invalid_repository_never_reaches_transport(self):
        reader=SourceReader()
        with mock.patch.object(reader,'candidates',side_effect=AssertionError('unexpected transport')):
            for repository in ['other-owner/repo','appolon1908/a?ref=main','appolon1908/a/../b']:
                self.assertEqual(api.inspect_repository(reader,repository)['reason'],'INVALID_REPOSITORY')

    def test_reader_uses_rest_base_sha_instead_of_version_specific_gh_fields(self):
        raw={'number':21,'state':'open','head':{'ref':'workstation/standalone-v3-r2-20261007','sha':'a'*40,'repo':{'full_name':REPO}},
             'base':{'ref':'development','sha':'b'*40,'repo':{'full_name':REPO}},'html_url':CANDIDATE['url']}
        calls=[]
        def transport(command,**kwargs):
            calls.append(command)
            if command[:4] != ['gh','api','--method','GET']:
                return subprocess.CompletedProcess(command,1,b'',b'Unknown JSON field: baseRefOid')
            return subprocess.CompletedProcess(command,0,json.dumps([raw] if '?' in command[-1] else raw).encode(),b'')
        with mock.patch.object(api.subprocess,'run',side_effect=transport):
            reader=api.GitHubReader()
            self.assertEqual(reader.candidates(REPO),[CANDIDATE])
            self.assertEqual(reader.candidate(REPO,21),CANDIDATE)
        self.assertEqual(calls,[['gh','api','--method','GET','repos/appolon1908/Codestra-Connect/pulls?state=open&base=development&per_page=100'],['gh','api','--method','GET','repos/appolon1908/Codestra-Connect/pulls/21']])

if __name__ == '__main__':unittest.main()
