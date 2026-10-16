"""Builder coordinator for approved registration and real assignment admission.

Owns transactions on an idle builder connection. The verifier runs independently
and supplies only a committed proof identifier; this module never loads its
credentials, accepts observations or creates authority records.
"""
import argparse
import hashlib
import json
import re
import uuid

from .lease_interface import DIRECTORY, connect_protected
from .publisher_startup import verify_code_custody


class AdmissionOutcomeUnknown(RuntimeError):
    """A claim commit may have succeeded. Recover the same request, never retry it blindly."""


def _call(connection, function, values):
    # Function names are internal constants, never caller-controlled SQL.
    with connection.cursor() as cursor:
        cursor.execute('SELECT '+function+'('+','.join(['%s']*len(values))+')', values)
        return cursor.fetchone()[0]


def _not_found(error):
    return (getattr(error, 'pgcode', None) == 'P0001'
            and error.diag.message_primary == 'REQUEST_NOT_FOUND')


def coordinate(connection, operation, task, repository, request_id, *, proof_id=None, apply=False):
    """Prepare, admit or recover; rollback and return no usable receipt by default.

    prepare commits approved candidate metadata only. An independently deployed
    verifier then describes/observes/attests that binding and commits its proof.
    admit consumes it through the existing epoch-bound issuer. recover performs
    only a current, exact-mapping lookup of the original request.
    """
    from psycopg2.extras import Json
    from psycopg2.extensions import TRANSACTION_STATUS_IDLE

    if operation not in ('prepare', 'admit', 'recover') or type(apply) is not bool:
        raise ValueError('INVALID_COORDINATOR_OPERATION')
    if not isinstance(request_id, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', request_id):
        raise ValueError('INVALID_COORDINATOR_REQUEST')
    if connection.autocommit or connection.get_transaction_status() != TRANSACTION_STATUS_IDLE:
        raise ValueError('IDLE_TRANSACTIONAL_BUILDER_CONNECTION_REQUIRED')
    if proof_id is not None:
        proof_id = str(uuid.UUID(proof_id))
    result = {'authority': 'NONE', 'usable': False, 'certified': False, 'promotion_authorized': False}
    claim_attempted = False
    try:
        if operation == 'prepare':
            mapping = _call(connection, 'assignment_leases.resolve_task', (task, repository))
            candidate = mapping['candidate']
            encoded = json.dumps(candidate, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
            registration_request = 'coordinator.register.'+hashlib.sha256(request_id.encode()).hexdigest()
            _call(connection, 'scoped_registration.register',
                  ('candidate', Json(candidate), registration_request, hashlib.sha256(encoded).hexdigest()))
            result.update(state='AWAITING_VERIFICATION', binding_id=mapping['binding']['binding_id'])
        else:
            try:
                receipt = _call(connection, 'assignment_leases.lookup_task', (task, repository, request_id))
            except Exception as error:
                if operation != 'admit' or not _not_found(error):
                    raise
                connection.rollback()
                if proof_id is None:
                    raise ValueError('COMMITTED_INDEPENDENT_PROOF_REQUIRED') from None
                claim_attempted = True
                receipt = _call(connection, 'assignment_leases.admit_task', (task, repository, request_id, proof_id))
            result.update(state='ADMITTED', authority='ONLINE_DATABASE_RECEIPT', usable=True, lease=receipt)
        if not apply:
            connection.rollback()
            result.pop('lease', None)
            result.update(state='DRY_RUN', authority='NONE_DRY_RUN', usable=False)
        else:
            try:
                connection.commit()
            except Exception:
                if claim_attempted:
                    raise AdmissionOutcomeUnknown('ADMISSION_OUTCOME_UNKNOWN_USE_RECOVER') from None
                raise
        return result
    except Exception:
        try:
            connection.rollback()
        except Exception:
            pass
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description='Source coordinator: approved metadata and independent-proof admission; no provisioning.')
    parser.add_argument('operation', choices=('prepare', 'admit', 'recover'))
    parser.add_argument('--task', required=True)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--request-id', required=True)
    parser.add_argument('--proof')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    connection = None
    try:
        verify_code_custody()
        connection = connect_protected(DIRECTORY/'lease-builder.dsn')
        result = coordinate(connection, args.operation, args.task, args.repository,
                            args.request_id, proof_id=args.proof, apply=args.apply)
        print(json.dumps(result, sort_keys=True))
        return 0
    except AdmissionOutcomeUnknown:
        print('ADMISSION_OUTCOME_UNKNOWN_USE_RECOVER')
        return 1
    except Exception:
        print('COORDINATOR_OPERATION_UNAVAILABLE')
        return 1
    finally:
        if connection is not None:
            connection.close()
