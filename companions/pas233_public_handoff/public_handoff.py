"""Offline public candidate consistency checks; NEVER an authority decision.

This companion does not import the runtime, read trust files, authenticate a
signature, contact an endpoint, generate keys, create grants, or issue leases.
A review reference is another untrusted input: agreement proves consistency
only. Owner acceptance of this helper envelope and operational verification
remain external. The runtime remains the sole implementation of its gates.
"""
import hashlib
import ipaddress
import json
from pathlib import PurePosixPath
import re
from urllib.parse import urlsplit

MAX_INPUT_BYTES = 32768
CHANNEL_SCHEMA = 'codestra.source-unit-issuer-channel.v2'
CHANNEL_DIRECTORY = '/etc/codestra/control-plane/unit-issuer'
CHANNEL_FIELDS = ('schema', 'issuer', 'public_key_path', 'public_key_sha256',
                  'status_url', 'status_address', 'ca_sha256', 'openssl_sha256')
ACTORS = ('issuer', 'executor', 'reviewer', 'source_owner')
BINDING_HASHES = ('action_sha256', 'manifest_sha256', 'archive_sha256',
                  'machine_sha256', 'boot_sha256', 'command_sha256',
                  'review_sha256', 'approval_sha256', 'admission_sha256',
                  'issuer_channel_sha256')
BINDING_FIELDS = ACTORS + ('attempt_id',) + BINDING_HASHES
EVIDENCE_FIELDS = ('actor', 'evidence_url', 'evidence_sha256')
PROVISIONING_FIELDS = EVIDENCE_FIELDS + ('scope', 'issuer',
                                       'issuer_channel_sha256', 'public_key_sha256')
CANDIDATE_FIELDS = ('schema', 'scope', 'channel', 'binding', 'status_source', 'provenance')
STATUS_FIELDS = ('schema', 'status_schema', 'purpose', 'issuer',
                 'issuer_channel_sha256', 'status_url')
# Informational unresolved obligations, never a handshake implementation or input schema.
REMAINING_GATES = ('OWNER_SCHEMA_ACK_REQUIRED', 'OWNER_HANDSHAKE_INTEGRATION_REQUIRED',
                   'INDEPENDENT_OPERATIONAL_TRUST_REQUIRED',
                   'CURRENT_AUTHENTICATED_GRANT_AND_STATUS_REQUIRED',
                   'EXACT_PACKAGE_AND_ACTION_REVIEW_REQUIRED',
                   'EXISTING_RUNTIME_ADMISSION_AND_CONTAINMENT_GATES_REQUIRED')


def _canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       allow_nan=False) + '\n').encode()


def _pin(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def _actor(value):
    return type(value) is str and 0 < len(value) <= 128


def _public_url(value, *, evidence=False):
    if type(value) is not str or not 0 < len(value) <= 2048 or not value.isascii():
        return False
    if re.search(r'[\x00-\x20\x7f\\]', value) or '?' in value or (not evidence and '#' in value):
        return False
    if re.search(r'%(?![0-9A-Fa-f]{2})', value):
        return False
    try:
        parsed = urlsplit(value)
        host, port = parsed.hostname, parsed.port
        if not host or len(host) > 253 or '%' in host:
            return False
        if ':' in host or parsed.netloc.startswith('['):
            ipaddress.IPv6Address(host)
        else:
            labels = (host[:-1] if host.endswith('.') else host).split('.')
            if any(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                   is None for label in labels):
                return False
        return (parsed.scheme == 'https'
                and parsed.username is None and parsed.password is None
                and (port is None or 0 < port < 65536) and parsed.path.startswith('/'))
    except ValueError:
        return False


def _key_reference(value):
    if type(value) is not str or len(value) > 256:
        return False
    path = PurePosixPath(value)
    return (str(path) == value and str(path.parent) == CHANNEL_DIRECTORY
            and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}[.]pub', path.name) is not None)


def _numeric_address(value):
    if type(value) is not str or '%' in value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _load(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_INPUT_BYTES:
        raise ValueError

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    def reject_constant(_):
        raise ValueError

    row = json.loads(raw, object_pairs_hook=unique, parse_constant=reject_constant,
                     parse_float=reject_constant)
    if type(row) is not dict:
        raise ValueError
    return row


class _Check:
    def __init__(self):
        self.issues = []

    def issue(self, code, path):
        # Every caller supplies literal schema paths, never caller-provided keys.
        item = {'code': code, 'field': path}
        if item not in self.issues:
            self.issues.append(item)

    def exact(self, row, fields, path):
        if type(row) is not dict:
            self.issue('INVALID_OBJECT', path)
            row = {}
        for name in fields:
            if name not in row:
                self.issue('MISSING_FIELD', path + '.' + name)
        if set(row) - set(fields):
            self.issue('UNEXPECTED_FIELD', path)
        return row

    def check_channel(self, row, path):
        row = self.exact(row, CHANNEL_FIELDS, path)
        if row.get('schema') != CHANNEL_SCHEMA:
            self.issue('UNSUPPORTED_SCHEMA', path + '.schema')
        issuer = row.get('issuer')
        if type(issuer) is not str or re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}', issuer) is None:
            self.issue('INVALID_ISSUER', path + '.issuer')
        for field in ('public_key_sha256', 'ca_sha256', 'openssl_sha256'):
            if not _pin(row.get(field)):
                self.issue('INVALID_DIGEST', path + '.' + field)
        if not _key_reference(row.get('public_key_path')):
            self.issue('INVALID_PUBLIC_KEY_REFERENCE', path + '.public_key_path')
        if not _public_url(row.get('status_url')):
            self.issue('INVALID_PUBLIC_ENDPOINT', path + '.status_url')
        if not _numeric_address(row.get('status_address')):
            self.issue('INVALID_STATUS_ADDRESS', path + '.status_address')
        return row

    def check_binding(self, row, path):
        row = self.exact(row, BINDING_FIELDS, path)
        actors_ok = all(_actor(row.get(field)) for field in ACTORS)
        attempt = row.get('attempt_id')
        if (not actors_ok or row.get('source_owner') in (row.get('issuer'), row.get('reviewer'))
                or row.get('reviewer') == row.get('executor')
                or type(attempt) is not str or re.fullmatch('[0-9a-f]{32}', attempt) is None):
            self.issue('INVALID_BINDING', path)
        for field in BINDING_HASHES:
            if not _pin(row.get(field)):
                self.issue('INVALID_DIGEST', path + '.' + field)
        return row

    def check_provenance(self, row, binding, path):
        # Helper-only metadata pending owner ACK; does not provision runtime trust.
        row = self.exact(row, ('custody', 'provisioning'), path)
        for kind, fields in (('custody', EVIDENCE_FIELDS), ('provisioning', PROVISIONING_FIELDS)):
            section = self.exact(row.get(kind), fields, path + '.' + kind)
            if not _actor(section.get('actor')):
                self.issue('INVALID_PROVENANCE_ACTOR', path + '.' + kind + '.actor')
            if section.get('actor') == binding.get('source_owner'):
                self.issue('INDEPENDENT_PROVENANCE_REQUIRED', path + '.' + kind + '.actor')
            if not _public_url(section.get('evidence_url'), evidence=True):
                self.issue('INVALID_PUBLIC_EVIDENCE_REFERENCE', path + '.' + kind + '.evidence_url')
            for field in fields:
                if field.endswith('sha256') and not _pin(section.get(field)):
                    self.issue('INVALID_DIGEST', path + '.' + kind + '.' + field)
        return row

    def report(self):
        return {'schema': 'pas233.public-handoff-result.v1', 'disposition': 'NONEXECUTING',
                'candidate_consistency': 'REJECTED' if self.issues else 'CONSISTENT',
                'execution_authorized': False, 'operational_trust_verified': False,
                'owner_schema_acknowledged': False, 'issues': self.issues,
                'remaining_gates': list(REMAINING_GATES)}


def validate(candidate_raw, review_reference_raw=None):
    """Compare bounded JSON public candidates with separately supplied review facts.

    CONSISTENT never means trusted, approved, authenticated, installed or usable
    for execution. No supplied input can turn any authority flag true. Output
    includes only fixed strings/schema paths; input values and keys are omitted.
    """
    check = _Check()
    try:
        candidate = _load(candidate_raw)
        review = _load(review_reference_raw) if review_reference_raw is not None else {}
    except (ValueError, TypeError, UnicodeError, RecursionError):
        check.issue('INVALID_INPUT', 'input')
        return check.report()
    if review_reference_raw is None:
        check.issue('REVIEW_REFERENCE_REQUIRED', 'review_reference')
    if 'staging_receipt' in candidate:
        check.issue('STAGING_NOT_EXECUTION_AUTHORITY', 'candidate')
    if 'installation_roles' in candidate:
        check.issue('INSTALLATION_ROLE_NOT_EXECUTION_SCOPE', 'candidate')
    candidate = check.exact(candidate, CANDIDATE_FIELDS, 'candidate')
    review = check.exact(review, ('scope', 'channel_sha256', 'binding', 'provenance'), 'review_reference')
    if candidate.get('schema') != 'pas233.public-handoff-candidate.v1':
        check.issue('UNSUPPORTED_SCHEMA', 'candidate.schema')
    for row, path in ((candidate, 'candidate'), (review, 'review_reference')):
        if row.get('scope') == 'PG':
            check.issue('PG_CONTRACT_UNCONFIRMED', path + '.scope')
        elif row.get('scope') != 'UNIT':
            check.issue('UNIT_SCOPE_REQUIRED', path + '.scope')
    channel = check.check_channel(candidate.get('channel'), 'candidate.channel')
    binding = check.check_binding(candidate.get('binding'), 'candidate.binding')
    expected_binding = check.check_binding(review.get('binding'), 'review_reference.binding')
    provenance = check.check_provenance(candidate.get('provenance'), binding, 'candidate.provenance')
    expected_provenance = check.check_provenance(review.get('provenance'), expected_binding,
                                                'review_reference.provenance')
    if not _pin(review.get('channel_sha256')):
        check.issue('INVALID_DIGEST', 'review_reference.channel_sha256')
    try:
        channel_sha = hashlib.sha256(_canonical(channel)).hexdigest()
    except (ValueError, TypeError, UnicodeError, RecursionError):
        check.issue('INVALID_INPUT', 'input')
        return check.report()
    if (channel_sha != review.get('channel_sha256') or binding != expected_binding
            or provenance != expected_provenance or candidate.get('scope') != review.get('scope')):
        check.issue('REVIEW_REFERENCE_MISMATCH', 'candidate')
    if channel.get('issuer') != binding.get('issuer') or channel_sha != binding.get('issuer_channel_sha256'):
        check.issue('CHANNEL_BINDING_MISMATCH', 'candidate.channel')
    status = check.exact(candidate.get('status_source'), STATUS_FIELDS, 'candidate.status_source')
    expected_status = {'schema': 'codestra.source-unit-status-envelope.v1',
                       'status_schema': 'codestra.source-unit-lease-status.v1',
                       'purpose': 'source-unit-status-v1', 'issuer': binding.get('issuer'),
                       'issuer_channel_sha256': channel_sha, 'status_url': channel.get('status_url')}
    if status != expected_status:
        check.issue('STATUS_SOURCE_MISMATCH', 'candidate.status_source')
    provisioning = provenance.get('provisioning')
    if type(provisioning) is not dict or any(provisioning.get(key) != value for key, value in (
            ('scope', 'UNIT'), ('issuer', binding.get('issuer')),
            ('issuer_channel_sha256', channel_sha), ('public_key_sha256', channel.get('public_key_sha256')))):
        check.issue('PROVENANCE_BINDING_MISMATCH', 'candidate.provenance.provisioning')
    return check.report()


def missing_input_handoff():
    """Names missing real bindings without fabricating identities, hashes or routes."""
    return {'schema': 'pas233.missing-public-bindings.v1', 'disposition': 'NONEXECUTING',
            'execution_authorized': False, 'operational_trust_verified': False,
            'owner_schema_acknowledged': False,
            'unit_channel_schema': CHANNEL_SCHEMA,
            'missing_unit_channel_fields': list(CHANNEL_FIELDS[1:]),
            'missing_reviewed_binding_fields': list(BINDING_FIELDS),
            'missing_provenance': ['independent_custody_evidence',
                                   'independent_provisioning_evidence',
                                   'explicit_UNIT_scope_acceptance',
                                   'issuer_key_status_channel_linkage'],
            'status_requirement': 'INDEPENDENTLY_AUTHENTICATED_SIGNED_CURRENT_STATUS_AND_REVOCATION',
            'historical_staging_status': 'CRM_ISOLATED_PRINCIPAL_AND_INDEPENDENT_PKI_STAGED_NOT_TRUSTED_OR_ENABLED',
            'historical_staging_is_active_authority': False,
            'installation_roles_imply_execution_scope': False,
            'pg_status': 'SEPARATE_ACCEPTED_CONTRACT_REQUIRED',
            'remaining_gates': list(REMAINING_GATES)}
