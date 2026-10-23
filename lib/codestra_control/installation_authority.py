"""Standalone installation-authority producer SOURCE, never provisioning.

An independent administrator provisions exact profiles, three distinct issuer
roles, verifier observation delegation and protected driver/credential custody.
This client cannot enroll a profile, choose arbitrary binding JSON, install its
SQL/driver, or grant target/source/publication authority through a local receipt.
"""
import argparse
import hashlib
import importlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import sysconfig
import uuid
import zipfile

MANIFEST='installation-authority-source-manifest.json'
SQL='017-installation-authority.sql'
FILES=(SQL,'lib/codestra_control/installation_authority.py',
       'bin/codestra-installation-authority','lib/codestra_control/__init__.py','requirements-publisher.txt')
DIRECTORY=Path('/etc/codestra/control-plane')
DRIVER_ROOT=Path('/opt/codestra-control-plane/installation-authority-driver')
WHEEL='vendor/psycopg2_binary-2.9.10-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl'
REASONS=frozenset(('AUTHORITY_AUTHENTICATION_REQUIRED','AUTHORITY_PROFILE_DENIED','AUTHORITY_PROFILE_CHANGED',
    'AUTHORITY_REQUEST_CONFLICT','AUTHORITY_REQUEST_NOT_FOUND','AUTHORITY_ACCEPTANCE_REQUIRED',
    'AUTHORITY_SCOPE_HELD','AUTHORITY_REVOKED','AUTHORITY_EXPIRED','AUTHORITY_BINDING_MISMATCH',
    'AUTHORITY_PHASE_DENIED','AUTHORITY_NONCE_CONFLICT','AUTHORITY_HISTORY_IMMUTABLE','AUTHORITY_INVALID_BINDING'))
LOCAL=frozenset(('INSTALLATION_AUTHORITY_INVALID_REQUEST','INSTALLATION_AUTHORITY_INVALID_RESPONSE',
    'INSTALLATION_AUTHORITY_IDLE_TRANSACTION_REQUIRED','INSTALLATION_AUTHORITY_UNAVAILABLE',
    'INSTALLATION_AUTHORITY_CUSTODY_UNAVAILABLE','INSTALLATION_AUTHORITY_DRIVER_UNPROVISIONED',
    'INSTALLATION_AUTHORITY_SESSION_UNAVAILABLE','INSTALLATION_AUTHORITY_CLOSE_UNCONFIRMED',
    'INSTALLATION_AUTHORITY_AMBIENT_DATABASE_SETTINGS_FORBIDDEN','INSTALLATION_AUTHORITY_CONNECTION_DENIED'))


class Denied(ValueError): pass
class OutcomeUnknown(RuntimeError): pass


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def _uuid(value):
    try:
        if type(value) is str and str(uuid.UUID(value))==value:return value
    except (ValueError,TypeError,AttributeError):pass
    raise Denied('INSTALLATION_AUTHORITY_INVALID_REQUEST')


def _safe(error):
    if isinstance(error,Denied) and len(error.args)==1 and type(error.args[0]) is str and error.args[0] in LOCAL|REASONS:
        return error.args[0]
    reason=getattr(getattr(error,'diag',None),'message_primary',None)
    if getattr(error,'pgcode',None)=='P0001' and type(reason) is str and reason in REASONS:return reason
    return 'INSTALLATION_AUTHORITY_UNAVAILABLE'


def protected_read(path,*,owner=0,mode=None,limit=16*1024*1024):
    """Descriptor-relative nofollow traversal; never create or repair custody."""
    path=Path(path)
    if not path.is_absolute() or any(p in ('.','..') for p in path.parts):raise Denied('INSTALLATION_AUTHORITY_CUSTODY_UNAVAILABLE')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
            info=os.fstat(fd)
            if info.st_uid!=owner or info.st_mode&0o022:raise Denied('INSTALLATION_AUTHORITY_CUSTODY_UNAVAILABLE')
        source=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
        with os.fdopen(source,'rb') as stream:
            before=os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_uid!=owner
                    or before.st_mode&0o022 or mode is not None and stat.S_IMODE(before.st_mode)!=mode
                    or before.st_size>limit):raise Denied('INSTALLATION_AUTHORITY_CUSTODY_UNAVAILABLE')
            data=stream.read(limit+1);after=os.fstat(stream.fileno())
            keys=('st_dev','st_ino','st_size','st_mode','st_uid','st_gid','st_nlink','st_mtime_ns','st_ctime_ns')
            if len(data)>limit or any(getattr(before,k)!=getattr(after,k) for k in keys):raise Denied('INSTALLATION_AUTHORITY_CUSTODY_UNAVAILABLE')
            return data
    finally:os.close(fd)


def _driver():
    """Verify complete separately provisioned wheel payload before importing it."""
    try:
        if any(name=='psycopg2' or name.startswith('psycopg2.') for name in sys.modules):raise ValueError
        root=Path(__file__).resolve().parents[2]
        manifest=json.loads(protected_read(root/MANIFEST,mode=0o644))
        wheel=protected_read(root/WHEEL,mode=0o644)
        if hashlib.sha256(wheel).hexdigest()!=manifest['driver']['sha256']:raise ValueError
        import io
        expected=set()
        with zipfile.ZipFile(io.BytesIO(wheel)) as archive:
            for entry in archive.infolist():
                if entry.is_dir():continue
                name=entry.filename
                if name.startswith('/') or any(p in ('','.','..') for p in name.split('/')) or name in expected:raise ValueError
                expected.add(name);mode=(entry.external_attr>>16)&0o777
                if mode not in (0o644,0o755):raise ValueError
                if protected_read(DRIVER_ROOT/name,mode=mode)!=archive.read(entry):raise ValueError
        actual=set()
        def failed(error):raise error
        for directory,dirs,files in os.walk(DRIVER_ROOT,followlinks=False,onerror=failed):
            for name in dirs:
                path=Path(directory)/name;info=path.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise ValueError
                if not any(p.startswith(str(path.relative_to(DRIVER_ROOT))+'/') for p in expected):raise ValueError
            actual.update(str((Path(directory)/name).relative_to(DRIVER_ROOT)) for name in files)
        if actual!=expected:raise ValueError
        standard=Path(sysconfig.get_paths()['stdlib'])
        sys.path[:]=[str(DRIVER_ROOT),str(standard),str(standard/'lib-dynload')]
        module=importlib.import_module('psycopg2')
        if Path(module.__file__)!=DRIVER_ROOT/'psycopg2/__init__.py':raise ValueError
        return module
    except Exception:raise Denied('INSTALLATION_AUTHORITY_DRIVER_UNPROVISIONED') from None


def connection_parameters(raw):
    if any(k.startswith('PG') for k in os.environ):raise Denied('INSTALLATION_AUTHORITY_AMBIENT_DATABASE_SETTINGS_FORBIDDEN')
    # No driver import is needed to reject ambient routes. The deferred driver
    # was already pinned/custodied by connect_protected before parsing a DSN.
    from psycopg2.extensions import parse_dsn,libpq_version
    params=parse_dsn(raw.decode().strip())
    required={'host','port','dbname','user','password','sslmode','sslrootcert'}
    if (libpq_version()<160000 or not required<=set(params) or not set(params)<=required|{'hostaddr','connect_timeout'}
            or any(not params[k] for k in required) or params['sslmode']!='verify-full'
            or not params['port'].isdigit() or not 1<=int(params['port'])<=65535
            or not params['sslrootcert'].startswith(str(DIRECTORY)+'/')):raise Denied('INSTALLATION_AUTHORITY_CONNECTION_DENIED')
    try:ipaddress.ip_address(params['host'])
    except ValueError:
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}',params['host']):raise Denied('INSTALLATION_AUTHORITY_CONNECTION_DENIED') from None
    if 'hostaddr' in params:
        try:ipaddress.ip_address(params['hostaddr'])
        except ValueError:raise Denied('INSTALLATION_AUTHORITY_CONNECTION_DENIED') from None
    params.update(connect_timeout='10',options='-csearch_path=pg_catalog,pg_temp',require_auth='scram-sha-256',
        channel_binding='require',sslcertmode='disable',sslcert='/dev/null',sslkey='/dev/null',passfile='/dev/null',
        target_session_attrs='read-write',gssencmode='disable',ssl_min_protocol_version='TLSv1.2')
    return params


def connect_protected(path):
    if any(k.startswith('PG') for k in os.environ):raise Denied('INSTALLATION_AUTHORITY_AMBIENT_DATABASE_SETTINGS_FORBIDDEN')
    raw=protected_read(path,mode=0o640)
    module=_driver();params=connection_parameters(raw)
    protected_read(params['sslrootcert'],mode=0o644)
    return module.connect(**params)


def operate(connection,operation,values,*,apply=False):
    signatures={'request':('profile_id','request_id'),'accept':('operation_id',),'issue':('operation_id',),'inspect':('operation_id',)}
    if type(operation) is not str or operation not in signatures or type(values) is not dict or set(values)!=set(signatures[operation]):raise Denied('INSTALLATION_AUTHORITY_INVALID_REQUEST')
    if operation=='request':
        _uuid(values['profile_id'])
        if type(values['request_id']) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',values['request_id']):raise Denied('INSTALLATION_AUTHORITY_INVALID_REQUEST')
    else:_uuid(values['operation_id'])
    if type(apply) is not bool or connection.autocommit or connection.get_transaction_status()!=0:raise Denied('INSTALLATION_AUTHORITY_IDLE_TRANSACTION_REQUIRED')
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT admission_bootstrap.'+operation+'('+','.join(['%s']*len(signatures[operation]))+')',tuple(values[k] for k in signatures[operation]))
            row=cursor.fetchone()
        result=row[0] if row else None
        if type(result) is not dict:raise Denied('INSTALLATION_AUTHORITY_INVALID_RESPONSE')
        _uuid(result.get('request_id'));_uuid(result.get('profile_id'))
        if (type(result.get('request_digest')) is not str or not re.fullmatch('[0-9a-f]{64}',result['request_digest'])
                or operation!='request' and result['request_id']!=values['operation_id']
                or operation=='request' and result['profile_id']!=values['profile_id']
                or result.get('state') not in ({'REQUESTED','ACCEPTED','ISSUED','REVOKED'} if operation=='inspect' else {dict(request='REQUESTED',accept='ACCEPTED',issue='ISSUED')[operation]})):
            raise Denied('INSTALLATION_AUTHORITY_INVALID_RESPONSE')
        if operation=='accept':_uuid(result.get('proof_id'))
        if operation=='issue':_uuid(result.get('grant_id'))
        if not apply:
            connection.rollback();return dict(operation=operation,committed=False,authority='NONE_DRY_RUN',usable=False,certified=False,publication_authorized=False)
        try:connection.commit()
        except Exception:raise OutcomeUnknown('INSTALLATION_AUTHORITY_COMMIT_UNKNOWN_USE_INSPECT_SAME_REQUEST') from None
        result=dict(result,authority='NONE' if operation=='inspect' else 'SOURCE_ISSUER_RECORD',usable=False)
        return dict(operation=operation,committed=True,usable=False,certified=False,source_authorized=False,publication_authorized=False,result=result)
    except Exception as error:
        try:connection.rollback()
        except Exception:pass
        if isinstance(error,OutcomeUnknown):raise
        raise Denied(_safe(error)) from None


class Parser(argparse.ArgumentParser):
    def error(self,message):raise Denied('INSTALLATION_AUTHORITY_INVALID_REQUEST')


def main(argv=None):
    connection=None
    try:
        parser=Parser(description='Source installation authority producer; rollback unless --apply. No profile enrollment or target installation.')
        parser.add_argument('--manifest-sha256')
        commands=parser.add_subparsers(dest='operation',required=True)
        for operation in ('request','accept','issue','inspect'):
            command=commands.add_parser(operation)
            if operation=='request':command.add_argument('--profile',required=True);command.add_argument('--request-id',required=True)
            else:command.add_argument('--request',required=True)
            command.add_argument('--apply',action='store_true')
        args=parser.parse_args(argv)
        values={'profile_id':args.profile,'request_id':args.request_id} if args.operation=='request' else {'operation_id':args.request}
        role='verifier' if args.operation=='accept' else 'operator'
        connection=connect_protected(DIRECTORY/('installation-authority-'+role+'.dsn'))
        result=operate(connection,args.operation,values,apply=args.apply)
        connection.close();connection=None
        print(json.dumps(result,sort_keys=True));return 0
    except OutcomeUnknown:print('INSTALLATION_AUTHORITY_COMMIT_UNKNOWN_USE_INSPECT_SAME_REQUEST');return 1
    except Exception as error:print(_safe(error));return 1
    finally:
        if connection is not None:
            try:connection.close()
            except Exception:pass


def prepare_source(root,source_sha,output,driver_wheel):
    """Offline exact committed source only; no installer profile or live authority."""
    if type(source_sha) is not str or not re.fullmatch('[0-9a-f]{40}',source_sha) or source_sha=='0'*40:raise ValueError('EXACT_SOURCE_COMMIT_REQUIRED')
    def git(*args):return subprocess.run(['/usr/bin/git','--no-replace-objects','-C',str(root),*args],check=True,capture_output=True).stdout
    if git('rev-parse',source_sha+'^{commit}').decode().strip()!=source_sha:raise ValueError('EXACT_SOURCE_COMMIT_REQUIRED')
    payload={};records=[]
    for path in FILES:
        row=git('ls-tree','-z',source_sha,'--',path)
        if not row:raise ValueError('INCOMPLETE_AUTHORITY_SOURCE')
        metadata,name=row.rstrip(b'\0').split(b'\t');mode,kind,oid=metadata.decode().split()
        expected='100755' if path.startswith('bin/') else '100644'
        if name.decode()!=path or kind!='blob' or mode!=expected:raise ValueError('UNSAFE_AUTHORITY_SOURCE')
        data=git('cat-file','blob',oid);payload[path]=(data,int(mode[-3:],8))
    wheel=Path(driver_wheel).read_bytes();wheel_hash=hashlib.sha256(wheel).hexdigest()
    lines=[line for line in payload['requirements-publisher.txt'][0].decode().splitlines() if line and not line.startswith('#')]
    if lines!=['psycopg2-binary==2.9.10 --hash=sha256:'+wheel_hash]:raise ValueError('AUTHORITY_DRIVER_DIGEST_MISMATCH')
    payload[WHEEL]=(wheel,0o644)
    for path,(data,mode) in sorted(payload.items()):records.append(dict(path=path,sha256=hashlib.sha256(data).hexdigest(),size=len(data),mode=oct(mode)))
    manifest=dict(schema='codestra.installation-authority-source.v1',source_commit=source_sha,source_only=True,
        install_allowed=False,activation_allowed=False,authority_provisioning_approved=False,installation_profile=None,
        files=records,driver=dict(path=WHEEL,sha256=wheel_hash,size=len(wheel)))
    output=Path(output);output.mkdir(mode=0o700)
    for path,(data,mode) in payload.items():
        destination=output/path;destination.parent.mkdir(parents=True,exist_ok=True)
        for parent in (destination.parent,*destination.parent.parents):
            if parent==output:break
            parent.chmod(0o755)
        with destination.open('xb') as stream:stream.write(data)
        destination.chmod(mode)
    (output/MANIFEST).write_bytes(canonical(manifest)+b'\n');(output/MANIFEST).chmod(0o644)
    return manifest
