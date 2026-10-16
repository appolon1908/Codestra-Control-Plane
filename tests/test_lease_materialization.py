"""Real temporary Git checkout checks; observers are explicitly synthetic."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
from codestra_control.lease_materialization import GitMaterializer,MaterializationDenied

class Observer:
    def __init__(self,binding):self.binding=binding
    def repository(self,name):return self.binding['repository_id']
    def ref(self,name,ref):return self.binding['head_sha'] if ref==self.binding['source_ref'] else self.binding['base_sha']
    def dependency(self,value):raise AssertionError('no dependencies in fixture')

class MaterializationTests(unittest.TestCase):
    def setUp(self):
        patch=mock.patch('codestra_control.lease_materialization.verify_system_tools');patch.start();self.addCleanup(patch.stop)
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.repo=self.root/'atomic';self.repo.mkdir(mode=0o700)
        self.git('init');self.git('config','user.name','Synthetic Fixture');self.git('config','user.email','fixture@example.invalid')
        (self.repo/'source.txt').write_text('fixture\n');self.git('add','.');self.git('commit','-m','fixture')
        (self.repo/'.git').chmod(0o700)
        self.git('checkout','-b','atomic/sec--sub--task');self.git('remote','add','origin','https://github.com/appolon1908/A.git')
        sha=self.git('rev-parse','HEAD')
        self.binding={'repository':'appolon1908/A','repository_id':123,'source_ref':'atomic/sec--sub--task','target_ref':'subsection/sec--sub','head_sha':sha,'base_sha':sha,'worktree':str(self.repo),'host':'fixture-host','root_path':str(self.root),'git_common_dir':str(self.repo/'.git'),'worktree_uid':os.geteuid()}
        self.observer=Observer(self.binding)
        self.materializer=GitMaterializer(self.observer,host=lambda:'fixture-host',filesystem_anchor=self.root)
    def git(self,*args):return subprocess.check_output(['git','-C',str(self.repo),*args],stderr=subprocess.DEVNULL,text=True).strip()
    def test_real_checkout_identity_and_remote_binding_are_observed(self):
        result=self.materializer.inspect({'binding':self.binding,'dependencies':[]})
        self.assertEqual(result['head_sha'],self.binding['head_sha']);self.assertEqual(result['directory_inode'],self.repo.stat().st_ino)
    def test_dirty_checkout_wrong_remote_detached_head_or_host_deny(self):
        (self.repo/'source.txt').write_text('dirty\n')
        with self.assertRaises(MaterializationDenied):self.materializer.inspect({'binding':self.binding,'dependencies':[]})
        self.git('checkout','--','source.txt');self.git('remote','set-url','origin','https://github.com/other/A.git')
        with self.assertRaises(MaterializationDenied):self.materializer.inspect({'binding':self.binding,'dependencies':[]})
        self.git('remote','set-url','origin','https://github.com/appolon1908/A.git');self.git('checkout','--detach')
        with self.assertRaises(MaterializationDenied):self.materializer.inspect({'binding':self.binding,'dependencies':[]})
    def test_symlink_path_or_wrong_materialization_owner_deny(self):
        alias=self.root/'alias';alias.symlink_to(self.repo,target_is_directory=True)
        changed=dict(self.binding,worktree=str(alias))
        with self.assertRaises(MaterializationDenied):self.materializer.inspect({'binding':changed,'dependencies':[]})
        changed=dict(self.binding,worktree_uid=os.geteuid()+1)
        with self.assertRaises(MaterializationDenied):self.materializer.inspect({'binding':changed,'dependencies':[]})
    def test_moving_remote_target_or_wrong_numeric_repository_denies(self):
        self.observer.ref=lambda *_:'d'*40
        with self.assertRaises(MaterializationDenied):self.materializer.inspect({'binding':self.binding,'dependencies':[]})
        self.observer.ref=Observer(self.binding).ref;self.observer.repository=lambda *_:999
        with self.assertRaises(MaterializationDenied):self.materializer.inspect({'binding':self.binding,'dependencies':[]})
    def test_missing_dependency_verification_does_not_upgrade_pass_rows(self):
        class Missing(Observer):
            def dependency(self,value):raise MaterializationDenied('DEPENDENCY_UNAVAILABLE')
        verifier=GitMaterializer(Missing(self.binding),host=lambda:'fixture-host',filesystem_anchor=self.root)
        with self.assertRaises(MaterializationDenied):verifier.inspect({'binding':self.binding,'dependencies':[{'dependency_key':'legacy-pass'}]})
    def test_repository_filters_and_fsmonitor_never_execute(self):
        marker=self.root/'executed'
        self.git('config','core.fsmonitor','touch '+str(marker))
        self.git('config','filter.malicious.clean','touch '+str(marker))
        with self.assertRaises(MaterializationDenied):self.materializer.inspect({'binding':self.binding,'dependencies':[]})
        self.assertFalse(marker.exists())
    def test_staged_changes_ignored_files_and_executable_mode_drift_deny(self):
        (self.repo/'source.txt').write_text('staged\n');self.git('add','source.txt')
        with self.assertRaises(MaterializationDenied):self.materializer.inspect({'binding':self.binding,'dependencies':[]})
        self.git('reset','--hard','HEAD');(self.repo/'.git'/'info'/'exclude').write_text('ignored\n');(self.repo/'ignored').write_text('untracked')
        with self.assertRaises(MaterializationDenied):self.materializer.inspect({'binding':self.binding,'dependencies':[]})
        (self.repo/'ignored').unlink();(self.repo/'source.txt').chmod(0o755)
        with self.assertRaises(MaterializationDenied):self.materializer.inspect({'binding':self.binding,'dependencies':[]})

class DependencyObserverTests(unittest.TestCase):
    def setUp(self):
        from codestra_control.lease_materialization import GitHubLeaseObserver,dependency_digest
        from codestra_control.evidence import PromotionRequest
        from dataclasses import asdict
        self.client=mock.Mock();self.binding=PromotionRequest('appolon1908/A','A','section/sec','development','a'*40,'b'*40)
        prerequisite={'product':'A','scope_type':'SECTION','scope_name':'sec','sha':'a'*40}
        digest=dependency_digest(self.binding,prerequisite)
        self.value={'dependency_key':'section:sec','repository':'appolon1908/A','repository_id':123,'binding':asdict(self.binding),'prerequisite':prerequisite,'binding_hash':digest,'issuer_app_id':99,'issuer_name':'scope-certification','capability_receipt':'synthetic','approved_by':'Ralph L. Appolon','purpose':'SCOPE_CERTIFICATION','check_id':10}
        self.receipt={'id':10,'app':{'id':99},'name':'scope-certification','external_id':digest,'head_sha':'a'*40,'status':'completed','conclusion':'success'}
        self.refs={'section/sec':'a'*40,'development':'b'*40}
        self.client.get.side_effect=self.response
        self.observer=GitHubLeaseObserver(self.client,7,8)
    def response(self,path):
        from urllib.parse import unquote
        if path=='/repos/appolon1908/A':
            return {'id':123,'full_name':'appolon1908/A'}
        prefix='/repos/appolon1908/A/git/ref/heads/'
        if path.startswith(prefix):
            ref=unquote(path[len(prefix):])
            return {'ref':'refs/heads/'+ref,'object':{'type':'commit','sha':self.refs[ref]}}
        if path=='/repos/appolon1908/A/check-runs/10':
            return dict(self.receipt)
        raise AssertionError('Unexpected synthetic dependency request: '+path)
    def test_online_exact_issuer_receipt_is_observed(self):
        self.assertEqual(self.observer.dependency(self.value),self.value)
        self.client.authorize_readonly.assert_called_once()
        self.assertEqual([call.args[0] for call in self.client.get.call_args_list],[
            '/repos/appolon1908/A',
            '/repos/appolon1908/A/git/ref/heads/section%2Fsec',
            '/repos/appolon1908/A/git/ref/heads/development',
            '/repos/appolon1908/A/check-runs/10',
            '/repos/appolon1908/A/git/ref/heads/section%2Fsec',
            '/repos/appolon1908/A/git/ref/heads/development'])
    def test_old_successful_certificate_denies_when_either_remote_ref_has_moved(self):
        for ref in ('section/sec','development'):
            self.refs={'section/sec':'a'*40,'development':'b'*40}
            self.refs[ref]='c'*40
            self.client.reset_mock()
            with self.subTest(ref=ref),self.assertRaisesRegex(MaterializationDenied,'DEPENDENCY_REF_MOVED'):
                self.observer.dependency(self.value)
            self.assertFalse(any('/check-runs/' in call.args[0] for call in self.client.get.call_args_list))
    def test_remote_ref_movement_during_successful_receipt_observation_denies(self):
        for ref in ('section/sec','development'):
            self.refs={'section/sec':'a'*40,'development':'b'*40}
            self.client.reset_mock()
            def response(path):
                value=self.response(path)
                if path=='/repos/appolon1908/A/check-runs/10':
                    self.refs[ref]='c'*40
                return value
            self.client.get.side_effect=response
            with self.subTest(ref=ref),self.assertRaisesRegex(MaterializationDenied,'DEPENDENCY_REF_MOVED'):
                self.observer.dependency(self.value)
    def test_wrong_scope_ci_issuer_or_forged_receipt_denies(self):
        for change in ({'issuer_app_id':15368},{'issuer_app_id':7},{'issuer_name':'codestra-control-plane'},{'prerequisite':dict(self.value['prerequisite'],scope_name='other')}):
            with self.subTest(change=change),self.assertRaises(MaterializationDenied):self.observer.dependency(dict(self.value,**change))
        for key,value in (('external_id','forged'),('head_sha','c'*40),('conclusion','failure'),('app',{'id':15368})):
            self.receipt[key]=value
            with self.subTest(key=key),self.assertRaises(MaterializationDenied):self.observer.dependency(self.value)
