"""Source lease CLI composition. Fixed protected credentials; rollback default.

No DSN/agent identity comes from arguments or environment. Different commands
require independently provisioned builder/verifier/operator credential custody.
"""
import argparse
import json
from pathlib import Path
import tomllib
import uuid
from .publisher_startup import protected_read,verify_code_custody,AppJWT
from .publisher_github import GitHubAppClient
from .lease_materialization import GitMaterializer,GitHubLeaseObserver

DIRECTORY=Path('/etc/codestra/control-plane')


def connect_protected(path):
    import psycopg2
    from psycopg2.extensions import parse_dsn
    params=parse_dsn(protected_read(path).decode().strip())
    if not {'host','dbname','user','sslmode','sslrootcert'}<=set(params) or params['sslmode']!='verify-full' or params['host'].startswith('/'):
        raise ValueError('VERIFIED_LEASE_CONNECTION_REQUIRED')
    protected_read(params['sslrootcert'],allow_public=True)
    return psycopg2.connect(**params)


def attest_materialization(connection,binding_id,observer):
    from psycopg2.extras import Json
    with connection.cursor() as cur:
        cur.execute('SELECT assignment_leases.describe(%s)',(binding_id,));description=cur.fetchone()[0]
    # Never hold authority-row locks while inspecting Git or doing HTTP reads.
    connection.commit()
    observed=GitMaterializer(observer).inspect(description)
    with connection.cursor() as cur:
        cur.execute('SELECT assignment_leases.attest(%s,%s)',(binding_id,Json(observed)))
        return cur.fetchone()[0]


def perform(connection,operation,values):
    signatures={'claim':('binding','proof','request_id'),'renew':('lease','epoch','proof','request_id'),
                'release':('lease','epoch','request_id'),'check':('lease','epoch'),
                'lookup':('request_id',),'revoke':('binding','reason','request_id')}
    names={'check':'check_owned'}
    fields=signatures[operation]
    with connection.cursor() as cur:
        cur.execute('SELECT assignment_leases.'+names.get(operation,operation)+'('+','.join(['%s']*len(fields))+')',tuple(values[name] for name in fields))
        return cur.fetchone()[0]


def main(argv=None):
    parser=argparse.ArgumentParser(description='Authenticated assignment lease API; rollback unless --apply. No installation or credential provisioning.')
    sub=parser.add_subparsers(dest='operation',required=True)
    for operation,fields in {'claim':('binding','proof','request-id'),'renew':('lease','epoch','proof','request-id'),
                             'release':('lease','epoch','request-id'),'check':('lease','epoch'),
                             'lookup':('request-id',),'revoke':('binding','reason','request-id'),'verify':('binding',)}.items():
        command=sub.add_parser(operation)
        for name in fields:command.add_argument('--'+name,required=True,type=int if name=='epoch' else str)
        command.add_argument('--apply',action='store_true')
    args=parser.parse_args(argv);values=vars(args);connection=None
    try:
        for name in ('binding','proof','lease'):
            if name in values:values[name]=str(uuid.UUID(values[name]))
        if 'epoch' in values and values['epoch']<=0:raise ValueError('INVALID_FENCE')
        verify_code_custody()
        if args.operation=='verify':
            config=tomllib.loads(protected_read(DIRECTORY/'lease-verifier.toml').decode())
            if set(config)!={'database_dsn_file','app_id','installation_id','app_key_file'} or any(type(config[k]) is not int or config[k]<=0 for k in ('app_id','installation_id')):raise ValueError('INVALID_VERIFIER_CONFIG')
            connection=connect_protected(config['database_dsn_file'])
            observer=GitHubLeaseObserver(GitHubAppClient(AppJWT(config['app_key_file'],config['app_id'])),config['app_id'],config['installation_id'])
            result=attest_materialization(connection,args.binding,observer)
        else:
            role='operator' if args.operation=='revoke' else 'builder'
            connection=connect_protected(DIRECTORY/('lease-'+role+'.dsn'))
            result=perform(connection,args.operation,values)
        if args.apply:connection.commit()
        else:
            connection.rollback()
            result=dict(result,authority='NONE_DRY_RUN',usable=False)
        print(json.dumps({'mode':'apply' if args.apply else 'dry-run','committed':args.apply,'certified':False,'result':result},sort_keys=True))
        return 0
    except Exception:
        if connection is not None:connection.rollback()
        print('LEASE_OPERATION_UNAVAILABLE')
        return 1
    finally:
        if connection is not None:connection.close()
