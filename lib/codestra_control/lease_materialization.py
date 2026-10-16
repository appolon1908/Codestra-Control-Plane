"""Independent Linux checkout observations, not caller-controlled attestations.

Only the separately authenticated verifier submits these observations. Filesystem,
Git and remote refs are re-read; proof age is bounded by server operator policy.
This does not make filesystem reads and a later database commit atomic.
"""
from datetime import datetime,timezone
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import hashlib
import json
from dataclasses import asdict
import selectors
import time
from .publisher_startup import verify_system_tools,protected_read
from .evidence import PromotionRequest
from .policy import valid_ref

class MaterializationDenied(RuntimeError):pass

def require(condition,reason):
    if not condition:raise MaterializationDenied(reason)

def machine_identity():
    machine=protected_read('/etc/machine-id',allow_public=True).decode().strip()
    require(bool(re.fullmatch('[0-9a-f]{32}',machine)),'HOST_IDENTITY_UNAVAILABLE')
    return socket.gethostname()+':'+machine

class GitMaterializer:
    def __init__(self,observer,*,host=machine_identity,filesystem_anchor=None):
        self.observer,self.host,self.fixture_anchor=observer,host,filesystem_anchor
    def _path(self,path,uid,*,leaf_owner=False):
        path=Path(path)
        require(path.is_absolute() and str(path.resolve(strict=True))==str(path),'NONCANONICAL_MATERIALIZATION_PATH')
        for item in (path,*path.parents):
            info=item.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0,uid) and not info.st_mode&0o022,'UNTRUSTED_MATERIALIZATION_DIRECTORY')
            if item==path and leaf_owner:require(info.st_uid==uid,'MATERIALIZATION_OWNER_MISMATCH')
            if self.fixture_anchor is not None and item==self.fixture_anchor:break
        return path
    def _git(self,path,*args,allowed=(0,)):
        env={'PATH':os.defpath,'LC_ALL':'C','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':os.devnull,'GIT_OPTIONAL_LOCKS':'0','GIT_NO_REPLACE_OBJECTS':'1','GIT_TERMINAL_PROMPT':'0','GIT_ATTR_NOSYSTEM':'1','GIT_ALLOW_PROTOCOL':'','GIT_NO_LAZY_FETCH':'1'}
        process=subprocess.Popen(['/usr/bin/git','-C',str(path),'-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false','-c','core.untrackedCache=false','-c','core.commitGraph=false','-c','submodule.recurse=false','--no-pager',*args],env=env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        output=bytearray();deadline=time.monotonic()+10
        try:
            os.set_blocking(process.stdout.fileno(),False)
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout,selectors.EVENT_READ)
                while selector.get_map():
                    remaining=deadline-time.monotonic();require(remaining>0,'GIT_OBSERVATION_TIMEOUT')
                    for key,_ in selector.select(remaining):
                        chunk=os.read(key.fd,65536)
                        if not chunk:selector.unregister(key.fileobj)
                        else:
                            output.extend(chunk);require(len(output)<=4*1024*1024,'GIT_OBSERVATION_TOO_LARGE')
            process.wait(timeout=max(0.01,deadline-time.monotonic()))
            require(process.returncode in allowed,'GIT_OBSERVATION_FAILED')
            return output.decode().strip()
        finally:
            if process.poll() is None:process.kill();process.wait(timeout=5)
            process.stdout.close()
    def _repository_safety(self,path):
        # Lazy-fetch suppression is not supported by every Git version. Transport
        # denial applies even before this check; partial stores cannot establish
        # full object integrity because fsck treats promised objects as optional.
        require(not self._git(path,'config','--get-regexp','^(extensions\\.partialclone|remote\\..*\\.promisor)$',allowed=(0,1)),
                'UNSUPPORTED_PROMISOR_MATERIALIZATION')
        objects=Path(self._git(path,'rev-parse','--path-format=absolute','--git-path','objects'))
        require(objects.is_dir() and str(objects.resolve(strict=True))==str(objects)
                and not os.path.lexists(objects/'info'/'alternates'),'UNSUPPORTED_OBJECT_STORE')
        pack=objects/'pack'
        require(pack.is_dir() and str(pack.resolve(strict=True))==str(pack),'UNSUPPORTED_OBJECT_STORE')
        deadline=time.monotonic()+10
        with os.scandir(pack) as entries:
            for count,entry in enumerate(entries):
                require(count<4096 and time.monotonic()<deadline,'MATERIALIZATION_LIMIT')
                require(not entry.name.endswith('.promisor'),'UNSUPPORTED_PROMISOR_MATERIALIZATION')
    def _integrity(self,path,*roots):
        require(roots and all(isinstance(oid,str) and re.fullmatch('[0-9a-f]{40}',oid)
                and oid!='0'*40 for oid in roots),'INVALID_MATERIALIZATION_BINDING')
        # Full fsck recomputes object IDs, rather than trusting loose filenames or
        # pack metadata. Corrupt objects are not skip-listable. Override repository
        # skip lists and retain the shared process deadline/output bounds.
        self._git(path,'-c','fsck.skipList=/dev/null','fsck','--full','--strict',
                  '--no-reflogs','--no-dangling','--no-progress',*dict.fromkeys(roots))
    def _local(self,b,path):
        self._repository_safety(path)
        require(self._git(path,'rev-parse','--show-toplevel')==str(path),'WORKTREE_ROOT_MISMATCH')
        require(self._git(path,'rev-parse','HEAD')==b['head_sha'],'HEAD_MISMATCH')
        require(self._git(path,'symbolic-ref','--short','HEAD')==b['source_ref'],'BRANCH_MISMATCH')
        common=Path(self._git(path,'rev-parse','--path-format=absolute','--git-common-dir'))
        require(str(common)==b['git_common_dir'],'COMMON_GIT_DIRECTORY_MISMATCH')
        self._path(common,b['worktree_uid'])
        origin=self._git(path,'remote','get-url','origin')
        require(origin in ('https://github.com/'+b['repository']+'.git','git@github.com:'+b['repository']+'.git'),'ORIGIN_REPOSITORY_MISMATCH')
        # A privileged observer never runs repository-configured filters, hooks,
        # fsmonitor commands, submodule programs or network transports.
        require(not self._git(path,'config','--get-regexp','^filter\\.',allowed=(0,1)),'UNSUPPORTED_REPOSITORY_FILTER')
        self._integrity(path,b['head_sha'])
        require(not any(line.startswith('160000 ') for line in self._git(path,'ls-files','--stage').splitlines()),'UNSUPPORTED_SUBMODULE_MATERIALIZATION')
        self._clean(path)
    def _clean(self,path):
        # Never invoke status/working-tree diff: repository attributes can select
        # executable clean filters. Compare raw index blobs and regular files.
        require(not self._git(path,'diff-index','--cached','--raw','--no-ext-diff','--no-textconv','HEAD','--'),'STAGED_MATERIALIZATION')
        tracked={};total=0;deadline=time.monotonic()+10
        for entry in self._git(path,'ls-files','--stage','-z').split('\0'):
            if not entry:continue
            header,name=entry.split('\t',1);mode,sha,stage=header.split()
            relative=Path(name)
            require(stage=='0' and mode in ('100644','100755') and not relative.is_absolute()
                    and all(part not in ('.','..','.git') for part in relative.parts),'UNSUPPORTED_MATERIALIZATION_ENTRY')
            item=path/relative
            for parent in relative.parents:
                require(not (path/parent).is_symlink(),'SYMLINK_MATERIALIZATION')
            info=item.lstat();require(stat.S_ISREG(info.st_mode),'UNSUPPORTED_MATERIALIZATION_ENTRY')
            require(bool(info.st_mode&0o111)==(mode=='100755'),'MATERIALIZATION_MODE_DRIFT')
            total+=info.st_size;require(total<=200*1024*1024 and time.monotonic()<deadline,'MATERIALIZATION_LIMIT')
            digest=hashlib.sha1(('blob '+str(info.st_size)+'\0').encode())
            descriptor=os.open(item,os.O_RDONLY|os.O_NOFOLLOW)
            with os.fdopen(descriptor,'rb') as source:
                opened=os.fstat(source.fileno())
                require((opened.st_dev,opened.st_ino,opened.st_size)==(info.st_dev,info.st_ino,info.st_size),'MATERIALIZATION_REPLACED')
                while chunk:=source.read(65536):
                    digest.update(chunk);require(time.monotonic()<deadline,'MATERIALIZATION_LIMIT')
                after=os.fstat(source.fileno())
                require((after.st_size,after.st_mtime_ns,after.st_ctime_ns)==(opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns),'MATERIALIZATION_CHANGED')
            require(digest.hexdigest()==sha,'DIRTY_MATERIALIZATION');tracked[name]=True
        for directory,dirs,files in os.walk(path,followlinks=False):
            require(time.monotonic()<deadline,'MATERIALIZATION_LIMIT')
            if Path(directory)==path:
                dirs[:]=[name for name in dirs if name!='.git'];files=[name for name in files if name!='.git']
            require(not any((Path(directory)/name).is_symlink() for name in dirs),'SYMLINK_MATERIALIZATION')
            for name in files:
                require(str((Path(directory)/name).relative_to(path)) in tracked,'UNTRACKED_MATERIALIZATION')
    def _remote(self,b):
        require(self.observer.repository(b['repository'])==b['repository_id'],'REMOTE_REPOSITORY_ID_MISMATCH')
        require(self.observer.ref(b['repository'],b['source_ref'])==b['head_sha'],'REMOTE_HEAD_MISMATCH')
        require(self.observer.ref(b['repository'],b['target_ref'])==b['base_sha'],'REMOTE_TARGET_MISMATCH')
    def inspect(self,description):
        try:
            verify_system_tools()
            b=description['binding'];uid=b['worktree_uid']
            require(type(uid) is int and uid>=0 and type(b['repository_id']) is int and b['repository_id']>0,'INVALID_MATERIALIZATION_BINDING')
            require(bool(re.fullmatch('[A-Za-z0-9-]+/[A-Za-z0-9_.-]+',b['repository'])) and all(valid_ref(b[k]) for k in ('source_ref','target_ref')),'INVALID_MATERIALIZATION_BINDING')
            require(all(re.fullmatch('[0-9a-f]{40}',b[k]) and b[k]!='0'*40 for k in ('head_sha','base_sha')),'INVALID_MATERIALIZATION_BINDING')
            require(self.host()==b['host'],'MATERIALIZATION_HOST_MISMATCH')
            root=self._path(b['root_path'],uid);path=self._path(b['worktree'],uid,leaf_owner=True)
            require(root in path.parents,'MATERIALIZATION_OUTSIDE_ASSIGNED_ROOT')
            initial=path.lstat()
            git_entry=path/'.git';info=git_entry.lstat()
            require(not stat.S_ISLNK(info.st_mode) and info.st_uid in (0,uid) and not info.st_mode&0o022,'UNTRUSTED_GIT_ENTRY')
            if hasattr(self.observer,'bind'):self.observer.bind(b)
            self._local(b,path);self._remote(b)
            dependencies={}
            for dependency in description['dependencies']:
                require(dependency['dependency_key'] not in dependencies,'DUPLICATE_DEPENDENCY')
                dependencies[dependency['dependency_key']]=self.observer.dependency(dependency)
            if hasattr(self.observer,'bind'):self.observer.bind(b)
            self._local(b,path);self._remote(b)
            final=path.lstat();require((initial.st_dev,initial.st_ino)==(final.st_dev,final.st_ino),'MATERIALIZATION_REPLACED')
            observed={k:b[k] for k in ('repository','repository_id','source_ref','target_ref','head_sha','base_sha','worktree','host','git_common_dir','worktree_uid')}
            observed.update(directory_device=final.st_dev,directory_inode=final.st_ino,observed_at=datetime.now(timezone.utc).isoformat(),dependencies=dependencies)
            return observed
        except MaterializationDenied:raise
        except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
            raise MaterializationDenied('MATERIALIZATION_UNAVAILABLE') from None


def dependency_digest(binding,prerequisite):
    require(set(prerequisite)=={'product','scope_type','scope_name','sha'} and prerequisite['scope_type'] in ('SUBSECTION','SECTION','DEVELOPMENT','TESTING','STAGING','PRODUCTION'),'INVALID_DEPENDENCY_SCOPE')
    payload={'schema':'codestra.lease-dependency.v1','promotion':asdict(binding),'scope_type':prerequisite['scope_type'],'scope_name':prerequisite['scope_name']}
    return hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).hexdigest()

class GitHubLeaseObserver:
    """Concrete read-only API observer; caller supplies administered App client."""
    def __init__(self,client,app_id,installation_id,*,clock=lambda:datetime.now(timezone.utc)):
        self.client,self.app_id,self.installation_id,self.clock=client,app_id,installation_id,clock
        self.current=None
    def _authorize(self,repository,repository_id):
        self.client.authorize_readonly(self.app_id,self.installation_id,repository_id,self.clock())
        actual=self.client.get('/repos/'+repository)
        require(actual['id']==repository_id and actual['full_name']==repository,'REMOTE_REPOSITORY_ID_MISMATCH')
        self.current=(repository,repository_id)
    def repository(self,name):
        # Expected ID comes from the authenticated server binding, not the author.
        require(self.current is not None and self.current[0]==name,'REMOTE_SCOPE_UNAVAILABLE')
        value=self.client.get('/repos/'+name)
        return value['id']
    def bind(self,binding):self._authorize(binding['repository'],binding['repository_id'])
    def ref(self,name,ref):
        from urllib.parse import quote
        require(self.current is not None and self.current[0]==name,'REMOTE_SCOPE_UNAVAILABLE')
        value=self.client.get('/repos/'+name+'/git/ref/heads/'+quote(ref,safe=''))
        require(value['ref']=='refs/heads/'+ref and value['object']['type']=='commit','REMOTE_REF_UNAVAILABLE')
        return value['object']['sha']
    def dependency(self,value):
        self._authorize(value['repository'],value['repository_id'])
        binding=PromotionRequest(**value['binding'])
        prerequisite=value['prerequisite']
        require(binding.repository==value['repository'] and binding.product==prerequisite['product'] and binding.source_sha==prerequisite['sha']
                and value['binding_hash']==dependency_digest(binding,prerequisite),'DEPENDENCY_BINDING_MISMATCH')
        require(value['approved_by']=='Ralph L. Appolon' and value['purpose']=='SCOPE_CERTIFICATION' and bool(value['capability_receipt']),'DEPENDENCY_CAPABILITY_UNAVAILABLE')
        require(value['issuer_app_id'] not in (15368,self.app_id) and value['issuer_name'] not in ('codestra-control-plane','codestra/control-plane','promotion-gate'),'DEPENDENCY_ISSUER_UNAVAILABLE')
        receipt=self.client.get('/repos/'+value['repository']+'/check-runs/'+str(value['check_id']))
        require(receipt['id']==value['check_id'] and receipt['app']['id']==value['issuer_app_id'] and receipt['name']==value['issuer_name']
                and receipt['external_id']==value['binding_hash'] and receipt['head_sha']==binding.source_sha
                and receipt['status']=='completed' and receipt['conclusion']=='success','DEPENDENCY_RECEIPT_UNAVAILABLE')
        return dict(value)
