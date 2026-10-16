"""Concrete source startup; fixed operator config, no caller JSON or enable flag.

No configuration, keys, connection secrets or service state are provisioned here.
The designated service must own the local lock before any credential is read.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time
import tomllib
from .publisher_ownership import PublisherUnavailable,publisher_session

CONFIG=Path('/etc/codestra/control-plane/authenticated-publisher.toml')


def protected_read(path,*,expected_owner=0,allow_public=False):
    """Root-owned, nonreplaceable parent and private regular file; never create."""
    path=Path(path)
    if not path.is_absolute():raise PublisherUnavailable('OPERATOR_PATH_MUST_BE_ABSOLUTE')
    parent_fd=fd=None
    try:
        if expected_owner==0:
            for ancestor in (path.parent,*path.parent.parents):
                info=ancestor.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:
                    raise PublisherUnavailable('UNTRUSTED_OPERATOR_ANCESTOR')
        parent_fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        parent=os.fstat(parent_fd)
        if parent.st_uid!=expected_owner or parent.st_mode&0o022:
            raise PublisherUnavailable('UNTRUSTED_OPERATOR_DIRECTORY')
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent_fd)
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=expected_owner or info.st_mode&(0o022 if allow_public else 0o027):
            raise PublisherUnavailable('UNTRUSTED_OPERATOR_FILE')
        with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(1024*1024+1)
        if len(raw)>1024*1024:raise PublisherUnavailable('OPERATOR_FILE_TOO_LARGE')
        return raw
    except OSError:
        raise PublisherUnavailable('AUTHENTICATED_PUBLICATION_ADAPTER_UNAVAILABLE') from None
    finally:
        if fd is not None:os.close(fd)
        if parent_fd is not None:os.close(parent_fd)



def verify_system_tools():
    requirements=json.loads((Path(__file__).resolve().parents[2]/'runtime-publisher-tools.json').read_text())
    if requirements['schema']!='codestra.publisher-system-tools.v1':raise PublisherUnavailable('INVALID_SYSTEM_TOOL_REQUIREMENTS')
    for path,digest in requirements['files'].items():
        fd=None
        try:
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise PublisherUnavailable('UNTRUSTED_SYSTEM_TOOL')
            value=hashlib.sha256()
            with os.fdopen(fd,'rb',closefd=False) as stream:
                while chunk:=stream.read(1024*1024):value.update(chunk)
            if value.hexdigest()!=digest:raise PublisherUnavailable('SYSTEM_TOOL_DIGEST_MISMATCH')
        except OSError:raise PublisherUnavailable('SYSTEM_TOOL_UNAVAILABLE') from None
        finally:
            if fd is not None:os.close(fd)

class AppJWT:
    """Local single-host key custodian. Key bytes stay private/in-memory.

    This optional concrete custodian requires separate acceptance/provisioning of
    exclusive local root-owned key custody. It is not a remote signing service.
    """
    def __init__(self,key_path,app_id,*,clock=time.time,expected_owner=0):
        self.key_path,self.app_id,self.clock,self.expected_owner=key_path,app_id,clock,expected_owner
    def __call__(self):
        if type(self.app_id) is not int or self.app_id<=0:raise PublisherUnavailable('INVALID_APP_ID')
        verify_system_tools()
        key=protected_read(self.key_path,expected_owner=self.expected_owner)
        encode=lambda raw:base64.urlsafe_b64encode(raw).rstrip(b'=')
        now=int(self.clock())
        header=encode(json.dumps({'alg':'RS256','typ':'JWT'},separators=(',',':')).encode())
        claims=encode(json.dumps({'iat':now-60,'exp':now+540,'iss':str(self.app_id)},separators=(',',':')).encode())
        message=header+b'.'+claims
        # Feed the private key on an inherited anonymous pipe; never place it in
        # argv, environment, disk scratch files or diagnostic output.
        read_fd,write_fd=os.pipe()
        try:
            # Typical RSA PEM is small; reject oversized keys before pipe writes.
            if len(key)>4096:raise PublisherUnavailable('APP_KEY_TOO_LARGE')
            os.write(write_fd,key);os.close(write_fd);write_fd=None
            result=subprocess.run(['/usr/bin/openssl','dgst','-sha256','-sign',f'/proc/self/fd/{read_fd}'],
                                  input=message,capture_output=True,pass_fds=(read_fd,),timeout=10,check=False,
                                  env={'PATH':os.defpath,'LC_ALL':'C','OPENSSL_CONF':os.devnull})
            if result.returncode!=0:raise PublisherUnavailable('APP_SIGNING_UNAVAILABLE')
            return (message+b'.'+encode(result.stdout)).decode('ascii')
        except (OSError,subprocess.TimeoutExpired):
            raise PublisherUnavailable('APP_SIGNING_UNAVAILABLE') from None
        finally:
            os.close(read_fd)
            if write_fd is not None:os.close(write_fd)



def verify_code_custody():
    root=Path(__file__).resolve().parents[2]
    paths=[root/'bin/codestra-github-statusd',root/'runtime-publisher-tools.json',*root.joinpath('lib').rglob('*.py')]
    if (root/'bin/codestra-lease').exists():paths.append(root/'bin/codestra-lease')
    if (root/'bin/codestra-coordinate').exists():paths.append(root/'bin/codestra-coordinate')
    for path in paths:
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=0 or info.st_mode&0o022:
            raise PublisherUnavailable('UNTRUSTED_RUNTIME_CODE')
        for parent in (path.parent,*path.parent.parents):
            info=parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:
                raise PublisherUnavailable('UNTRUSTED_RUNTIME_CODE_PATH')

def run_configured_cycle():
    """Only the already-locked source entrypoint invokes this composition root."""
    from .publisher_adapter import build_publisher_service
    connection=None
    try:
        config=tomllib.loads(protected_read(CONFIG).decode())
        verify_code_custody()
        fields={'app_id','installation_id','app_key_file','database_dsn_file','certificate_name','certificate_app_id','ledger_file'}
        if set(config)!=fields or any(type(config[k]) is not int or config[k]<=0 for k in ('app_id','installation_id','certificate_app_id')):
            raise PublisherUnavailable('INVALID_OPERATOR_CONFIGURATION')
        if any(type(config[k]) is not str or not config[k] for k in fields-{'app_id','installation_id','certificate_app_id'}):
            raise PublisherUnavailable('INVALID_OPERATOR_CONFIGURATION')
        # Load secrets only after designated-service ownership has been checked.
        dsn=protected_read(config['database_dsn_file']).decode().strip()
        import psycopg2
        from psycopg2.extensions import parse_dsn
        params=parse_dsn(dsn)
        if not {'host','dbname','user','sslmode','sslrootcert'}<=set(params) or params['sslmode']!='verify-full':
            raise PublisherUnavailable('VERIFIED_DATABASE_CONFIGURATION_REQUIRED')
        protected_read(params['sslrootcert'],allow_public=True)
        connection=psycopg2.connect(**params)
        service=build_publisher_service(connection,AppJWT(config['app_key_file'],config['app_id']),config['ledger_file'],
                                        certificate_name=config['certificate_name'],certificate_app_id=config['certificate_app_id'])
        publisher=service._publisher
        return reconcile_inventory(publisher,config['app_id'],config['installation_id'])
    except PublisherUnavailable:raise
    except Exception:
        # DSNs, keys, connection errors and API bodies never enter diagnostics.
        raise PublisherUnavailable('AUTHENTICATED_PUBLISHER_CYCLE_REFUSED') from None
    finally:
        if connection is not None:connection.close()



def reconcile_inventory(publisher,app_id,installation_id):
    from .publisher_scope import APPROVED_REPOSITORIES
    from .publisher_adapter import PublicationDenied,require
    bindings=publisher.store.bindings()
    require(len(set(bindings))==len(bindings),'DUPLICATE_AUTHORITY_BINDINGS')
    # Complete all approved-repository pages before any status effect.
    inventory=publisher.github.api.inventory(app_id,installation_id,APPROVED_REPOSITORIES)
    by_key={(b.repository,b.source_ref,b.target_ref,b.source_sha,b.target_base_sha):b for b in bindings}
    outcomes=[] if bindings else ['UNAVAILABLE_NO_ACTIVE_BINDINGS']
    seen=set()
    for pr in inventory:
        binding=by_key.get(pr.key)
        state='UNAVAILABLE_MISSING_BINDING'
        if binding is not None:
            seen.add(binding)
            try:
                acquired=publisher.store.acquire(binding)
                require(acquired.repository_id==pr.repository_id and acquired.pr_number==pr.number,'INVENTORY_AUTHORITY_ID_MISMATCH')
                state=publisher.publish(binding).state
            except PublicationDenied:state='UNAVAILABLE_AUTHORITY_OR_EVIDENCE'
        outcomes.append(state)
        print(f'AUTHENTICATED_PR repo={pr.repository} pr={pr.number} outcome={state}')
    if any(binding not in seen for binding in bindings):outcomes.append('UNAVAILABLE_STALE_BINDING')
    if not outcomes:outcomes.append('UNAVAILABLE_NO_ACTIVE_BINDINGS')
    return tuple(outcomes)

def run_operator_cycle():
    with publisher_session():return run_configured_cycle()
