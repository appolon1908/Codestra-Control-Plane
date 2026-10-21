"""Protected client for operator-delegated task bootstrap, inactive until provisioned.

Bootstrap records an exact mapping and grants. A separate current assignment
lease and actual L1/L2 operation receipts remain necessary for source/publication.
No caller DSN, credential profile, raw observation or ACK body is accepted.
"""
import argparse
import json
import re
import tomllib
import uuid

from .lease_interface import DIRECTORY, connect_protected
from .lease_materialization import GitMaterializer, GitHubLeaseObserver
from .admission_materialization import StageMaterializer
from .publisher_github import GitHubAppClient
from .publisher_startup import AppJWT, protected_read, verify_code_custody
from .scoped_admission import read_manifest


class BootstrapDenied(ValueError):
    """A fixed, nonsecret diagnostic; never an arbitrary SQL/transport message."""


class BootstrapOutcomeUnknown(RuntimeError):
    """Inspect the original operation; never retry an uncertain issuance."""


_SIGNATURES = {
    'request': ('payload', 'request_id'), 'describe': ('operation_id',),
    'verify': ('operation_id',), 'acknowledge': ('operation_id',),
    'verify-stage': ('operation_id',), 'verify-lease': ('operation_id',),
    'issue': ('operation_id', 'proof_id'), 'inspect': ('operation_id',),
    'revoke': ('operation_id',),
}
_SERVER_REASONS = frozenset({
    'BOOTSTRAP_PROFILE_DENIED', 'BOOTSTRAP_SESSION_DENIED',
    'BOOTSTRAP_ROUTE_DENIED', 'BOOTSTRAP_CUSTODY_MISMATCH',
    'BOOTSTRAP_ACK_REQUIRED', 'BOOTSTRAP_PROOF_REQUIRED',
    'BOOTSTRAP_AUTHORITY_REQUIRED', 'BOOTSTRAP_OVERLAP',
    'BOOTSTRAP_CAS_MISMATCH', 'BOOTSTRAP_REQUEST_CONFLICT',
    'BOOTSTRAP_REVOKED', 'BOOTSTRAP_AUTHENTICATION_REQUIRED',
    'BOOTSTRAP_VERIFIER_REQUIRED', 'BOOTSTRAP_AUTHORITY_CHANGED',
    'BOOTSTRAP_INVALID_REQUEST', 'BOOTSTRAP_INVALID_BINDING',
    'BOOTSTRAP_INVALID_REQUEST_ID', 'BOOTSTRAP_REQUEST_NOT_FOUND',
    'BOOTSTRAP_REGISTRY_DRIFT', 'BOOTSTRAP_POLICY_REQUIRED',
    'BOOTSTRAP_DEPENDENCY_DENIED', 'BOOTSTRAP_OBSERVATION_MISMATCH',
    'BOOTSTRAP_PROOF_EXPIRED', 'BOOTSTRAP_TASK_HISTORY_CONFLICT',
    'BOOTSTRAP_EXECUTOR_UNSUPPORTED', 'BOOTSTRAP_EXECUTOR_MALFORMED',
})
_CLIENT_REASONS = frozenset({
    'TASK_BOOTSTRAP_INVALID_IDENTIFIER', 'TASK_BOOTSTRAP_INVALID_OPERATION',
    'TASK_BOOTSTRAP_INVALID_REQUEST', 'TASK_BOOTSTRAP_INVALID_RESPONSE',
    'TASK_BOOTSTRAP_RESPONSE_BINDING_MISMATCH', 'TASK_BOOTSTRAP_IDLE_TRANSACTION_REQUIRED',
    'TASK_BOOTSTRAP_INDEPENDENT_OBSERVER_REQUIRED', 'TASK_BOOTSTRAP_INVALID_ISSUANCE_RECEIPT',
    'TASK_BOOTSTRAP_COMMIT_UNCONFIRMED_USE_SAME_REQUEST', 'TASK_BOOTSTRAP_UNAVAILABLE',
    'TASK_BOOTSTRAP_OPERATOR_CUSTODY_UNAVAILABLE', 'TASK_BOOTSTRAP_VERIFIER_CUSTODY_UNAVAILABLE',
    'TASK_BOOTSTRAP_VERIFIER_SESSION_UNAVAILABLE', 'TASK_BOOTSTRAP_INVALID_ARGUMENTS',
    'TASK_BOOTSTRAP_CODE_CUSTODY_UNAVAILABLE', 'TASK_BOOTSTRAP_RECEIVING_SESSION_UNAVAILABLE',
    'TASK_BOOTSTRAP_OPERATOR_SESSION_UNAVAILABLE', 'TASK_BOOTSTRAP_CLOSE_UNCONFIRMED_USE_INSPECT',
    'TASK_BOOTSTRAP_STAGE_COMMIT_UNCONFIRMED_INSPECT_INTENT',
    'TASK_BOOTSTRAP_LEASE_COMMIT_UNCONFIRMED_INSPECT_BINDING',
})
_MISSING_AUTHORITY = ['ACTIVE_ASSIGNMENT_LEASE_REQUIRED',
                      'L1_OPERATION_RECEIPT_REQUIRED', 'L2_OPERATION_RECEIPT_REQUIRED']


def _uuid(value):
    try:
        if type(value) is str and str(uuid.UUID(value)) == value:
            return value
    except (ValueError, TypeError, AttributeError):
        pass
    raise BootstrapDenied('TASK_BOOTSTRAP_INVALID_IDENTIFIER')


def _values(operation, values):
    if type(operation) is not str or operation not in _SIGNATURES or type(values) is not dict or set(values) != set(_SIGNATURES[operation]):
        raise BootstrapDenied('TASK_BOOTSTRAP_INVALID_OPERATION')
    result = dict(values)
    for field in ('operation_id', 'proof_id'):
        if field in result: result[field] = _uuid(result[field])
    if operation == 'request':
        if type(result['request_id']) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', result['request_id']):
            raise BootstrapDenied('TASK_BOOTSTRAP_INVALID_REQUEST')
        try:
            if type(result['payload']) is not dict or len(json.dumps(result['payload'], allow_nan=False).encode()) > 65536:
                raise ValueError
        except (ValueError, TypeError, RecursionError):
            raise BootstrapDenied('TASK_BOOTSTRAP_INVALID_REQUEST') from None
    return result


def _call(connection, function, values):
    if function not in {'request', 'describe', 'attest', 'issue', 'inspect', 'revoke', 'acknowledge',
                        'stage_description', 'stage_attest', 'lease_description', 'lease_attest'}:
        raise BootstrapDenied('TASK_BOOTSTRAP_INVALID_OPERATION')
    with connection.cursor() as cursor:
        cursor.execute('SELECT task_bootstrap.' + function + '(' + ','.join(['%s'] * len(values)) + ')', values)
        row = cursor.fetchone()
    if row is None or type(row[0]) is not dict:
        raise BootstrapDenied('TASK_BOOTSTRAP_INVALID_RESPONSE')
    return row[0]


def _response(result, request=None):
    if (type(result) is not dict or type(result.get('request_digest')) is not str
            or re.fullmatch('[0-9a-f]{64}', result['request_digest']) is None):
        raise BootstrapDenied('TASK_BOOTSTRAP_INVALID_RESPONSE')
    _uuid(result.get('request_id'))
    if request is not None and result['request_id'] != request:
        raise BootstrapDenied('TASK_BOOTSTRAP_RESPONSE_BINDING_MISMATCH')
    return result


def _safe_reason(error):
    if isinstance(error, BootstrapDenied) and len(error.args) == 1:
        reason = error.args[0]
        if type(reason) is str and reason in _CLIENT_REASONS | _SERVER_REASONS: return reason
    if getattr(error, 'pgcode', None) == 'P0001':
        reason = getattr(getattr(error, 'diag', None), 'message_primary', None)
        if type(reason) is str and reason in _SERVER_REASONS: return reason
    return 'TASK_BOOTSTRAP_UNAVAILABLE'


class BootstrapMaterializer(GitMaterializer):
    """Bind the exact accepted origin URL on both hardened local observations."""
    def _local(self, binding, path):
        super()._local(binding, path)
        if self._git(path, 'remote', 'get-url', 'origin') != self._permitted_remote:
            raise BootstrapDenied('BOOTSTRAP_ROUTE_DENIED')

    def inspect(self, description):
        try:
            repository = description['binding']['repository']
            remote = description['permitted_remote']
            if type(remote) is not str or remote not in (
                    'https://github.com/' + repository + '.git', 'git@github.com:' + repository + '.git'):
                raise ValueError
        except (KeyError, TypeError, ValueError):
            raise BootstrapDenied('BOOTSTRAP_ROUTE_DENIED') from None
        self._permitted_remote = remote
        result = super().inspect(description)
        return dict(result, permitted_remote=remote)


def _nested_description(envelope, kind):
    """Check the two server bindings before any independent observation."""
    _response(envelope)
    _response({'request_id': envelope.get('bootstrap_request_id'),
               'request_digest': envelope.get('bootstrap_request_digest')})
    description = envelope.get('description')
    if type(description) is not dict:
        raise BootstrapDenied('TASK_BOOTSTRAP_RESPONSE_BINDING_MISMATCH')
    if kind == 'stage':
        if (description.get('intent_id') != envelope['request_id']
                or description.get('request_digest') != envelope['request_digest']):
            raise BootstrapDenied('TASK_BOOTSTRAP_RESPONSE_BINDING_MISMATCH')
    elif (type(description.get('binding')) is not dict
            or description['binding'].get('binding_id') != envelope['request_id']
            or envelope['request_digest'] != envelope['bootstrap_request_digest']):
        raise BootstrapDenied('TASK_BOOTSTRAP_RESPONSE_BINDING_MISMATCH')
    return dict(description, permitted_remote=envelope.get('permitted_remote'))


class BootstrapStageMaterializer(StageMaterializer):
    """Seal the exact accepted origin during both actual L1/L2 snapshots."""
    def _identity(self, binding, path):
        super()._identity(binding, path)
        if self._git(path, 'remote', 'get-url', 'origin') != self._permitted_remote:
            raise BootstrapDenied('BOOTSTRAP_ROUTE_DENIED')

    def inspect(self, envelope):
        description = _nested_description(envelope, 'stage')
        try:
            repository = description['binding']['repository']
            remote = description['permitted_remote']
            if type(remote) is not str or remote not in (
                    'https://github.com/' + repository + '.git', 'git@github.com:' + repository + '.git'):
                raise ValueError
        except (KeyError, TypeError, ValueError):
            raise BootstrapDenied('BOOTSTRAP_ROUTE_DENIED') from None
        self._permitted_remote = remote
        return dict(super().inspect(description), permitted_remote=remote)


def operate(connection, operation, values, *, observer=None, apply=False):
    """Own an idle transaction and expose receipts only after successful commit.

    observer is a privileged in-process port. The CLI constructs it from fixed
    verifier custody; users cannot supply observations or select that identity.
    Read locks are released before the independent filesystem/GitHub observation.
    SQL revalidates current authority when accepting its attestation and issuing.
    """
    from psycopg2.extensions import TRANSACTION_STATUS_IDLE
    from psycopg2.extras import Json

    values = _values(operation, values)
    if type(apply) is not bool or connection.autocommit or connection.get_transaction_status() != TRANSACTION_STATUS_IDLE:
        raise BootstrapDenied('TASK_BOOTSTRAP_IDLE_TRANSACTION_REQUIRED')
    proof_operations = {'verify': ('describe', 'attest'),
                        'verify-stage': ('stage_description', 'stage_attest'),
                        'verify-lease': ('lease_description', 'lease_attest')}
    if operation in proof_operations and observer is None:
        raise BootstrapDenied('TASK_BOOTSTRAP_INDEPENDENT_OBSERVER_REQUIRED')
    issue_started = False
    try:
        if operation == 'request':
            result = _call(connection, 'request', (Json(values['payload']), values['request_id']))
        elif operation in proof_operations:
            describe, attest = proof_operations[operation]
            description = _response(_call(connection, describe, (values['operation_id'],)), values['operation_id'])
            connection.rollback()
            if operation == 'verify-stage':
                materialization = BootstrapStageMaterializer(observer).inspect(description)
            else:
                materialization = BootstrapMaterializer(observer).inspect(
                    _nested_description(description, 'lease') if operation == 'verify-lease' else description)
            observed = {'request_digest': description['request_digest'], 'materialization': materialization}
            result = _call(connection, attest, (values['operation_id'], Json(observed)))
        else:
            issue_started = operation == 'issue'
            fields = (values['operation_id'], values['proof_id']) if issue_started else (values['operation_id'],)
            result = _call(connection, operation, fields)
        _response(result, values.get('operation_id'))
        if operation in proof_operations:
            _uuid(result.get('proof_id'))
            if result['request_digest'] != description['request_digest']:
                raise BootstrapDenied('TASK_BOOTSTRAP_RESPONSE_BINDING_MISMATCH')
        if issue_started and (result.get('state') != 'ISSUED'
                or result.get('authority') != 'ONLINE_TASK_BOOTSTRAP_BINDING'
                or result.get('ready_for_admission') is not True
                or any(result.get(key) is not False for key in ('usable', 'source_authorized', 'publication_authorized', 'certified'))):
            raise BootstrapDenied('TASK_BOOTSTRAP_INVALID_ISSUANCE_RECEIPT')
        if not apply:
            connection.rollback()
            return {'operation': operation, 'mode': 'dry-run', 'committed': False,
                    'authority': 'NONE_DRY_RUN', 'usable': False, 'certified': False,
                    'promotion_authorized': False, 'lease_granted': False,
                    'source_authorized': False, 'publication_authorized': False}
        try:
            connection.commit()
        except Exception:
            if issue_started:
                raise BootstrapOutcomeUnknown('TASK_BOOTSTRAP_OUTCOME_UNKNOWN_USE_INSPECT') from None
            if operation == 'verify-stage':
                raise BootstrapDenied('TASK_BOOTSTRAP_STAGE_COMMIT_UNCONFIRMED_INSPECT_INTENT') from None
            if operation == 'verify-lease':
                raise BootstrapDenied('TASK_BOOTSTRAP_LEASE_COMMIT_UNCONFIRMED_INSPECT_BINDING') from None
            raise BootstrapDenied('TASK_BOOTSTRAP_COMMIT_UNCONFIRMED_USE_SAME_REQUEST') from None
        result = dict(result, usable=False, source_authorized=False, publication_authorized=False,
                      certified=False, promotion_authorized=False, lease_granted=False)
        if operation in ('inspect', 'describe'): result['authority'] = 'NONE'
        if operation in ('inspect', 'issue'): result['missing_authority'] = list(_MISSING_AUTHORITY)
        return {'operation': operation, 'mode': 'apply', 'committed': True,
                'usable': False, 'certified': False, 'promotion_authorized': False,
                'lease_granted': False, 'source_authorized': False,
                'publication_authorized': False, 'result': result}
    except Exception as error:
        try: connection.rollback()
        except Exception: pass
        if isinstance(error, BootstrapOutcomeUnknown): raise
        raise BootstrapDenied(_safe_reason(error)) from None


def _operator_config():
    try:
        config = tomllib.loads(protected_read(DIRECTORY / 'task-bootstrap-operator.toml').decode())
        if set(config) != {'database_dsn_file', 'profile_id'} or type(config['database_dsn_file']) is not str:
            raise ValueError
        _uuid(config['profile_id'])
        return config
    except Exception:
        raise BootstrapDenied('TASK_BOOTSTRAP_OPERATOR_CUSTODY_UNAVAILABLE') from None


def _verifier():
    try:
        config = tomllib.loads(protected_read(DIRECTORY / 'task-bootstrap-verifier.toml').decode())
        if set(config) != {'database_dsn_file', 'app_id', 'installation_id', 'app_key_file'} or any(
                type(config[key]) is not int or config[key] <= 0 for key in ('app_id', 'installation_id')):
            raise ValueError
        client = GitHubAppClient(AppJWT(config['app_key_file'], config['app_id']))
    except Exception:
        raise BootstrapDenied('TASK_BOOTSTRAP_VERIFIER_CUSTODY_UNAVAILABLE') from None
    try: connection = connect_protected(config['database_dsn_file'])
    except Exception:
        raise BootstrapDenied('TASK_BOOTSTRAP_VERIFIER_SESSION_UNAVAILABLE') from None
    return connection, GitHubLeaseObserver(client, config['app_id'], config['installation_id'])


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise BootstrapDenied('TASK_BOOTSTRAP_INVALID_ARGUMENTS')


def main(argv=None):
    connection = None
    try:
        parser = _Parser(description='Protected task bootstrap source client; rollback unless --apply. No lease or L1/L2 admission.')
        commands = parser.add_subparsers(dest='operation', required=True)
        for operation, fields in _SIGNATURES.items():
            command = commands.add_parser(operation)
            for field in fields:
                command.add_argument('--' + ('manifest' if field == 'payload' else field.replace('_', '-')), required=True)
            command.add_argument('--apply', action='store_true')
        args = parser.parse_args(argv)
        values = {key: value for key, value in vars(args).items() if key not in ('operation', 'apply')}
        if 'manifest' in values: values['payload'] = read_manifest(values.pop('manifest'))
        values = _values(args.operation, values)
        try: verify_code_custody()
        except Exception:
            raise BootstrapDenied('TASK_BOOTSTRAP_CODE_CUSTODY_UNAVAILABLE') from None
        observer = None
        if args.operation in ('verify', 'describe', 'verify-stage', 'verify-lease'):
            connection, observer = _verifier()
        elif args.operation == 'acknowledge':
            try: connection = connect_protected(DIRECTORY / 'lease-builder.dsn')
            except Exception:
                raise BootstrapDenied('TASK_BOOTSTRAP_RECEIVING_SESSION_UNAVAILABLE') from None
        else:
            config = _operator_config()
            if args.operation == 'request':
                payload = dict(values['payload'])
                if 'profile_id' in payload and payload['profile_id'] != config['profile_id']:
                    raise BootstrapDenied('BOOTSTRAP_PROFILE_DENIED')
                payload['profile_id'] = config['profile_id']; values['payload'] = payload
            try: connection = connect_protected(config['database_dsn_file'])
            except Exception:
                raise BootstrapDenied('TASK_BOOTSTRAP_OPERATOR_SESSION_UNAVAILABLE') from None
        result = operate(connection, args.operation, values, observer=observer, apply=args.apply)
        try: connection.close()
        except Exception:
            raise BootstrapDenied('TASK_BOOTSTRAP_CLOSE_UNCONFIRMED_USE_INSPECT') from None
        connection = None
        print(json.dumps(result, sort_keys=True))
        return 0
    except BootstrapOutcomeUnknown:
        print('TASK_BOOTSTRAP_OUTCOME_UNKNOWN_USE_INSPECT')
        return 1
    except Exception as error:
        print(_safe_reason(error))
        return 1
    finally:
        if connection is not None:
            try: connection.close()
            except Exception: pass
