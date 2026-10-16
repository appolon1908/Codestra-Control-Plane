"""Protected source client for staged online L1/L2 authorization.

The SQL issuer decides authority. This client never provisions grants, writes a
product file, pushes a branch or treats a historical receipt as a new permission.
"""
import argparse
import json
import os
import re
import stat
import tomllib
import uuid

from .lease_interface import DIRECTORY, connect_protected
from .publisher_startup import AppJWT, protected_read, verify_code_custody
from .publisher_github import GitHubAppClient
from .lease_materialization import GitHubLeaseObserver


class AdmissionOutcomeUnknown(RuntimeError):
    """Consumption may have committed; inspect the same intent, never retry it."""


def _call(connection, function, values):
    with connection.cursor() as cursor:
        cursor.execute('SELECT scoped_admission.'+function+'('
                       +','.join(['%s']*len(values))+')', values)
        result = cursor.fetchone()[0]
    if not isinstance(result, dict):
        raise ValueError('INVALID_ADMISSION_RESPONSE')
    return result


def _values(operation, values):
    signatures = {'request': ('grant', 'lease', 'epoch', 'payload', 'request_id'),
                  'verify': ('intent',), 'consume': ('intent', 'proof'),
                  'inspect': ('intent',)}
    if operation not in signatures or not isinstance(values, dict) or set(values) != set(signatures[operation]):
        raise ValueError('INVALID_ADMISSION_OPERATION')
    parsed = dict(values)
    for field in ('grant', 'lease', 'intent', 'proof'):
        if field in parsed:
            parsed[field] = str(uuid.UUID(parsed[field]))
    if 'epoch' in parsed and (type(parsed['epoch']) is not int or parsed['epoch'] <= 0):
        raise ValueError('INVALID_ADMISSION_EPOCH')
    if 'payload' in parsed and not isinstance(parsed['payload'], dict):
        raise ValueError('INVALID_ADMISSION_PAYLOAD')
    if 'request_id' in parsed and (not isinstance(parsed['request_id'], str)
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', parsed['request_id'])):
        raise ValueError('INVALID_ADMISSION_REQUEST')
    return parsed


def operate(connection, operation, values, *, observer=None, apply=False):
    """Own an idle transaction; expose consumption authority only after commit.

    verify runs only in independent verifier custody. The caller supplies a
    trusted observer, never raw observation JSON. Dry runs disclose no issuer
    receipt or proof, and inspect never grants permission to repeat an effect.
    """
    from psycopg2.extensions import TRANSACTION_STATUS_IDLE
    from psycopg2.extras import Json

    values = _values(operation, values)
    if type(apply) is not bool or connection.autocommit or connection.get_transaction_status() != TRANSACTION_STATUS_IDLE:
        raise ValueError('IDLE_TRANSACTIONAL_ADMISSION_CONNECTION_REQUIRED')
    consumption_started = False
    try:
        if operation == 'request':
            result = _call(connection, 'request', (values['grant'], values['lease'],
                           values['epoch'], Json(values['payload']), values['request_id']))
        elif operation == 'verify':
            if observer is None:
                raise ValueError('INDEPENDENT_STAGE_OBSERVER_REQUIRED')
            from .admission_materialization import StageMaterializer
            description = _call(connection, 'describe', (values['intent'],))
            # Release all authority-row locks before filesystem or HTTP reads.
            connection.commit()
            observed = StageMaterializer(observer).inspect(description)
            result = _call(connection, 'attest', (values['intent'], Json(observed)))
        else:
            consumption_started = operation == 'consume'
            fields = (values['intent'], values['proof']) if consumption_started else (values['intent'],)
            result = _call(connection, operation, fields)
            if consumption_started and (result.get('intent_id') != values['intent']
                    or result.get('operation') not in ('L1', 'L2')
                    or result.get('state') != 'CONSUMED'
                    or result.get('authority') != 'ONLINE_SCOPED_OPERATION_RECEIPT'
                    or result.get('usable') is not True):
                raise ValueError('INVALID_OPERATION_RECEIPT')
        if not apply:
            connection.rollback()
            return {'operation': operation, 'mode': 'dry-run', 'committed': False,
                    'authority': 'NONE_DRY_RUN', 'usable': False,
                    'certified': False, 'promotion_authorized': False}
        try:
            connection.commit()
        except Exception:
            if consumption_started:
                raise AdmissionOutcomeUnknown('ADMISSION_OUTCOME_UNKNOWN_USE_INSPECT') from None
            raise
        result = dict(result)
        if not consumption_started:
            result['usable'] = False
        if operation == 'inspect':
            result['authority'] = 'NONE'
        return {'operation': operation, 'mode': 'apply', 'committed': True,
                'usable': consumption_started, 'certified': False,
                'promotion_authorized': False, 'result': result}
    except Exception:
        try:
            connection.rollback()
        except Exception:
            pass
        raise


def read_manifest(path):
    """Read bounded untrusted request data, never credential or authority data."""
    def unique_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('DUPLICATE_MANIFEST_FIELD')
            value[key] = item
        return value

    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > 65536:
            raise ValueError('INVALID_MANIFEST_FILE')
        raw = source.read(65537)
        after = os.fstat(source.fileno())
        if len(raw) > 65536 or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('MANIFEST_CHANGED')
    value = json.loads(raw, object_pairs_hook=unique_pairs)
    if not isinstance(value, dict):
        raise ValueError('INVALID_MANIFEST')
    return value


def _verifier():
    config = tomllib.loads(protected_read(DIRECTORY/'lease-verifier.toml').decode())
    if set(config) != {'database_dsn_file', 'app_id', 'installation_id', 'app_key_file'} or any(
            type(config[key]) is not int or config[key] <= 0 for key in ('app_id', 'installation_id')):
        raise ValueError('INVALID_ADMISSION_VERIFIER_CONFIGURATION')
    client = GitHubAppClient(AppJWT(config['app_key_file'], config['app_id']))
    return connect_protected(config['database_dsn_file']), GitHubLeaseObserver(
        client, config['app_id'], config['installation_id'])


def main(argv=None):
    parser = argparse.ArgumentParser(description='Source scoped L1/L2 admission; rollback unless --apply; no product effects or provisioning.')
    commands = parser.add_subparsers(dest='operation', required=True)
    for operation, fields in {'request': ('grant', 'lease', 'epoch', 'manifest', 'request-id'),
                              'verify': ('intent',), 'consume': ('intent', 'proof'),
                              'inspect': ('intent',)}.items():
        command = commands.add_parser(operation)
        for field in fields:
            command.add_argument('--'+field, required=True, type=int if field == 'epoch' else str)
        command.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    values = {key: value for key, value in vars(args).items() if key not in ('operation', 'apply')}
    connection = None
    try:
        if 'manifest' in values:
            values['payload'] = read_manifest(values.pop('manifest'))
        values = _values(args.operation, values)
        verify_code_custody()
        if args.operation == 'verify':
            connection, observer = _verifier()
        else:
            connection, observer = connect_protected(DIRECTORY/'lease-builder.dsn'), None
        result = operate(connection, args.operation, values, observer=observer, apply=args.apply)
        print(json.dumps(result, sort_keys=True))
        return 0
    except AdmissionOutcomeUnknown:
        print('ADMISSION_OUTCOME_UNKNOWN_USE_INSPECT')
        return 1
    except Exception:
        print('SCOPED_ADMISSION_UNAVAILABLE')
        return 1
    finally:
        if connection is not None:
            connection.close()
