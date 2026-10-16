"""Protected recovery client; source only, independent observation, rollback default."""
import argparse
import json
from pathlib import Path
import re
import tomllib
import uuid

from .lease_interface import connect_protected
from .lease_materialization import GitMaterializer, GitHubLeaseObserver
from .publisher_github import GitHubAppClient
from .publisher_startup import AppJWT, protected_read, verify_code_custody as publisher_code_custody

DIRECTORY = Path('/etc/codestra/control-plane')
SIGNATURES = {
    'authorize': ('workstation', 'checkout', 'executor', 'reviewer', 'verifier', 'request_id'),
    'review': ('grant', 'digest'),
    'execute': ('grant', 'proof', 'digest', 'request_id'),
    'revoke': ('grant', 'digest', 'reason', 'request_id'),
    'lookup': ('request_id',),
}
ROLES = {'authorize': 'operator', 'review': 'reviewer', 'execute': 'executor',
         'revoke': 'operator', 'lookup': 'executor'}


def verify_code_custody():
    publisher_code_custody()
    protected_read(Path(__file__).resolve().parents[2] / 'bin' / 'codestra-frozen-recovery',
                   allow_public=True)


def attest_repair(connection, grant_id, digest, observer):
    """Inspect the exact authenticated server grant before submitting any proof."""
    from psycopg2.extras import Json
    with connection.cursor() as cursor:
        cursor.execute('SELECT frozen_recovery.describe(%s)', (grant_id,))
        description = cursor.fetchone()[0]
    if (description.get('schema') != 'codestra.frozen-recovery.v2'
            or description.get('action') != 'RELEASE_STALE_WORKTREE_TO_FREE'
            or description.get('grant_id') != grant_id
            or description.get('request_digest') != digest
            or description.get('dependencies') != []):
        raise ValueError('RECOVERY_REQUEST_CHANGED')
    # Describe is read-only. Release database row/advisory locks before Git/HTTP.
    connection.commit()
    observed = GitMaterializer(observer).inspect(description)
    with connection.cursor() as cursor:
        cursor.execute('SELECT frozen_recovery.attest(%s,%s,%s)',
                       (grant_id, digest, Json(observed)))
        return cursor.fetchone()[0]


def perform(connection, operation, values):
    from psycopg2.extras import Json
    fields = SIGNATURES[operation]
    arguments = tuple(Json(values[name]) if name == 'checkout' else values[name]
                      for name in fields)
    with connection.cursor() as cursor:
        cursor.execute('SELECT frozen_recovery.' + operation + '('
                       + ','.join(['%s'] * len(fields)) + ')', arguments)
        return cursor.fetchone()[0]


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Source recovery client. Protected role credentials; rollback unless --apply.')
    sub = parser.add_subparsers(dest='operation', required=True)
    for operation, fields in {
        'authorize': ('workstation', 'checkout-file', 'executor', 'reviewer', 'verifier', 'request-id'),
        'review': ('grant', 'digest'),
        'verify': ('grant', 'digest'),
        'execute': ('grant', 'proof', 'digest', 'request-id'),
        'revoke': ('grant', 'digest', 'reason', 'request-id'),
        'lookup': ('request-id',),
    }.items():
        command = sub.add_parser(operation)
        for field in fields:
            command.add_argument('--' + field, required=True)
        command.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    values = vars(args)
    connection = None
    try:
        for field in ('grant', 'proof'):
            if field in values:
                values[field] = str(uuid.UUID(values[field]))
        if 'digest' in values and (
                not re.fullmatch('[0-9a-f]{64}', values['digest'])
                or values['digest'] == '0' * 64):
            raise ValueError('INVALID_RECOVERY_DIGEST')
        verify_code_custody()
        if args.operation == 'verify':
            config = tomllib.loads(protected_read(DIRECTORY / 'recovery-verifier.toml').decode())
            if (set(config) != {'database_dsn_file', 'app_id', 'installation_id', 'app_key_file'}
                    or any(type(config[k]) is not int or config[k] <= 0
                           for k in ('app_id', 'installation_id'))):
                raise ValueError('INVALID_RECOVERY_VERIFIER_CONFIG')
            connection = connect_protected(config['database_dsn_file'])
            observer = GitHubLeaseObserver(
                GitHubAppClient(AppJWT(config['app_key_file'], config['app_id'])),
                config['app_id'], config['installation_id'])
            result = attest_repair(connection, values['grant'], values['digest'], observer)
        else:
            if args.operation == 'authorize':
                values['checkout'] = json.loads(protected_read(values['checkout_file']).decode())
                if type(values['checkout']) is not dict:
                    raise ValueError('INVALID_RECOVERY_CHECKOUT')
            connection = connect_protected(
                DIRECTORY / ('recovery-' + ROLES[args.operation] + '.dsn'))
            result = perform(connection, args.operation, values)
        if args.apply:
            connection.commit()
        else:
            connection.rollback()
            result = dict(result, authority='NONE_DRY_RUN', usable=False,
                          released=False, lease_granted=False, certified=False)
        print(json.dumps({'mode': 'apply' if args.apply else 'dry-run',
                          'committed': args.apply, 'certified': False,
                          'result': result}, sort_keys=True))
        return 0
    except Exception:
        if connection is not None:
            try:
                connection.rollback()
            except Exception:
                pass
        print('RECOVERY_OPERATION_UNAVAILABLE')
        return 1
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
