"""Bounded installer with fixed-custody, separately authenticated composition.

Trusted adapters are code-custody dependencies, not request JSON or owner strings.
No function here provisions identities, credentials, grants, leases or activation.
"""
from abc import ABC, abstractmethod
import argparse
import ast
import base64
import csv
from contextlib import contextmanager, ExitStack
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ctypes
import errno
import fcntl
import json
import io
import ipaddress
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tomllib
import time
from types import MappingProxyType
import uuid
import zipfile

from .controller_release import (SCHEMA_PREREQUISITES, SCHEMA_SOURCES,
    CONTROLLER_ENTRYPOINTS, REQUIRED_LIBRARIES, CONFIGURATION_SOURCES, CONTRACT_SOURCES, _proposal)
from .publisher_release import ENTRYPOINTS

LEDGER_SOURCE = '015-admission-installation-state.sql'
# Packaging is broader than this accepted bootstrap's execution authority.
# No recovery, publisher, readiness or certifier DDL is selected implicitly.
MIGRATIONS = ('schema.sql', '002-hierarchy-promotion.sql', '005-scoped-registration.sql',
    '007-assignment-leases.sql', '009-atomic-inspection.sql', '009-controller-coordinator.sql',
    '010-controller-coordinator-integration.sql', '010-scoped-operation-admission.sql', LEDGER_SOURCE)
GRAPH = {name: SCHEMA_PREREQUISITES[name] for name in MIGRATIONS}
TASK_BOOTSTRAP_SOURCE = '016-authenticated-task-bootstrap.sql'
LOCK_SOURCE = '018-admission-installation-lock.sql'
RESTRICTED_PROFILE = 'task-bootstrap-restricted-v1'


def migration_sources(profile='admission-v1'):
    """Select source DDL explicitly; packaging a new API never opts it in."""
    if profile == 'admission-v1':
        return MIGRATIONS
    if profile in ('task-bootstrap-v1', RESTRICTED_PROFILE):
        return MIGRATIONS + (TASK_BOOTSTRAP_SOURCE,)
    raise ValueError('UNSUPPORTED_MIGRATION_PROFILE')


MANIFEST = 'controller-release-manifest.json'
SHA256 = re.compile(r'[0-9a-f]{64}')
SHA1 = re.compile(r'[0-9a-f]{40}')
# PostgreSQL16 initdb revokes these builtins from PUBLIC instead of checking
# superuser internally. Explicit function grants can bypass server-file roles.
PRIVILEGED_BUILTINS = (
    'lo_import', 'lo_export', 'pg_read_file', 'pg_read_binary_file', 'pg_stat_file', 'pg_ls_dir',
    'pg_ls_logdir', 'pg_ls_waldir', 'pg_ls_archive_statusdir', 'pg_ls_tmpdir',
    'pg_ls_logicalsnapdir', 'pg_ls_logicalmapdir', 'pg_ls_replslotdir',
    'pg_backup_start', 'pg_backup_stop', 'pg_create_restore_point', 'pg_switch_wal',
    'pg_log_standby_snapshot', 'pg_wal_replay_pause', 'pg_wal_replay_resume',
    'pg_rotate_logfile', 'pg_reload_conf', 'pg_promote', 'pg_log_backend_memory_contexts',
    'pg_stat_reset', 'pg_stat_reset_shared', 'pg_stat_reset_slru',
    'pg_stat_reset_single_table_counters', 'pg_stat_reset_single_function_counters',
    'pg_stat_reset_replication_slot', 'pg_stat_reset_subscription_stats',
    'pg_replication_origin_advance', 'pg_replication_origin_create', 'pg_replication_origin_drop',
    'pg_replication_origin_session_reset', 'pg_replication_origin_session_setup',
    'pg_replication_origin_xact_reset', 'pg_replication_origin_xact_setup',
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('DUPLICATE_INSTALLATION_FIELD')
        value[key] = item
    return value


def _path(value):
    if (not isinstance(value, str) or not value or len(value) > 512
            or value.startswith('/') or '\\' in value
            or any(part in ('', '.', '..', '.git') for part in value.split('/'))
            or not re.fullmatch(r'[A-Za-z0-9_./-]+', value)):
        raise ValueError('UNSAFE_CANDIDATE_PATH')
    return PurePosixPath(value).parts


@contextmanager
def _directory(path):
    """Resolve every absolute component without following directory symlinks."""
    path = Path(path).absolute()
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            if part in ('.', '..'):
                raise ValueError('UNSAFE_CANDIDATE_DIRECTORY')
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def _read(directory, name, limit=16 * 1024 * 1024):
    parts = _path(name)
    fd = os.dup(directory)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=fd)
            os.close(fd)
            fd = child
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             dir_fd=fd)
        with os.fdopen(descriptor, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
                raise ValueError('UNSAFE_CANDIDATE_FILE')
            raw = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_uid', 'st_gid', 'st_nlink')
            if len(raw) > limit or any(getattr(before, k) != getattr(after, k) for k in fields):
                raise ValueError('CANDIDATE_CHANGED_DURING_READ')
            return raw, before
    finally:
        os.close(fd)


def _imports(files):
    modules = {}
    for path in files:
        if path.startswith('lib/') and path.endswith('.py'):
            module = path[4:-3].replace('/', '.')
            if module.endswith('.__init__'):
                module = module[:-9]
            modules[module] = path
    for path, data in files.items():
        if not (path.startswith('lib/') and path.endswith('.py') or path.startswith('bin/')):
            continue
        module = next((key for key, value in modules.items() if value == path), '')
        try:
            tree = ast.parse(data, filename=path)
        except (SyntaxError, UnicodeError):
            raise ValueError('INVALID_CANDIDATE_PYTHON') from None
        for node in ast.walk(tree):
            targets = []
            if isinstance(node, ast.Import):
                targets = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    package = module.split('.') if path.endswith('/__init__.py') else module.split('.')[:-1]
                    prefix = package[:len(package) - node.level + 1]
                    target = '.'.join(prefix + ([node.module] if node.module else []))
                    targets = [target] if node.module else [target + '.' + alias.name for alias in node.names]
                elif node.module:
                    targets = [node.module]
                    if node.module == 'codestra_control':
                        targets += [node.module + '.' + alias.name for alias in node.names]
            if any((target == 'codestra_control' or target.startswith('codestra_control.')) and target not in modules for target in targets):
                raise ValueError('INCOMPLETE_CANDIDATE_IMPORT_CLOSURE')


@dataclass(frozen=True)
class SourceCandidate:
    root: Path
    manifest_sha256: str
    source_commit: str
    files: object
    modes: object
    manifest_bytes: bytes

    @classmethod
    def load(cls, directory, manifest_sha256):
        if not isinstance(manifest_sha256, str) or not SHA256.fullmatch(manifest_sha256):
            raise ValueError('EXACT_MANIFEST_DIGEST_REQUIRED')
        try:
            with _directory(directory) as fd:
                raw, _ = _read(fd, MANIFEST, 1024 * 1024)
                if digest(raw) != manifest_sha256:
                    raise ValueError('MANIFEST_DIGEST_MISMATCH')
                value = json.loads(raw, object_pairs_hook=_unique)
                if (not isinstance(value, dict) or value.get('schema') != 'codestra.controller-candidate.v1'
                        or not isinstance(value.get('source_commit'), str)
                        or not SHA1.fullmatch(value['source_commit'])
                        or value['source_commit'] == '0' * 40
                        or value.get('install_allowed') is not False
                        or value.get('activation_allowed') is not False
                        or any(value.get(key) is not False for key in ('release_approved', 'database_setup_approved', 'authority_provisioning_approved'))
                        or value.get('schema_sources') != list(SCHEMA_SOURCES)
                        or not isinstance(value.get('files'), list) or len(value['files']) > 512):
                    raise ValueError('INVALID_CANDIDATE_MANIFEST')
                runtime_root = '/opt/codestra-control-plane/releases/' + value['source_commit']
                if value.get('proposed_runtime_root') != runtime_root:
                    raise ValueError('INVALID_CANDIDATE_RUNTIME_TARGET')
                files, modes = {}, {}
                entries = {}
                for entry in value['files']:
                    name = entry['source_path']
                    _path(name)
                    if name in files or name == MANIFEST:
                        raise ValueError('DUPLICATE_CANDIDATE_PATH')
                    target = (None if name in CONFIGURATION_SOURCES else
                        '/opt/codestra-dev/control-plane/bin/github-status-sync' if name == 'legacy/bin/github-status-sync'
                        else runtime_root + '/' + name)
                    if entry.get('proposed_target') != target:
                        raise ValueError('INVALID_CANDIDATE_FILE_TARGET')
                    mode = int(entry['mode'], 8)
                    if (mode not in (0o644, 0o755) or name.startswith(('bin/', 'legacy/bin/')) and mode != 0o755
                            or type(entry['size']) is not int
                            or entry['size'] < 0 or not SHA256.fullmatch(entry['sha256'])):
                        raise ValueError('INVALID_CANDIDATE_ENTRY')
                    data, metadata = _read(fd, name)
                    if (len(data) != entry['size'] or digest(data) != entry['sha256']
                            or stat.S_IMODE(metadata.st_mode) != mode):
                        raise ValueError('CANDIDATE_FILE_MISMATCH')
                    files[name], modes[name] = data, mode
                    entries[name] = entry
                    if sum(map(len, files.values())) > 64 * 1024 * 1024:
                        raise ValueError('CANDIDATE_TOO_LARGE')
                    if name in CONFIGURATION_SOURCES or name == 'config/examples/admission-installation.proposal.json':
                        _proposal(name, data)
                required = (set(SCHEMA_SOURCES + CONTROLLER_ENTRYPOINTS + ENTRYPOINTS + REQUIRED_LIBRARIES
                                + CONFIGURATION_SOURCES + CONTRACT_SOURCES)
                            | {'bin/codestra-install-admission', 'lib/codestra_control/admission_installation.py',
                               'config/examples/admission-installation.proposal.json', 'docs/admission-installation.md'})
                if not required <= files.keys() or modes['bin/codestra-install-admission'] != 0o755:
                    raise ValueError('INCOMPLETE_CANDIDATE')
                wheel = value['driver_artifact']
                name = wheel['path']
                _path(name)
                if name in files or not name.startswith('vendor/') or not name.endswith('.whl'):
                    raise ValueError('INVALID_CANDIDATE_DRIVER')
                data, metadata = _read(fd, name)
                if (type(wheel['size']) is not int or len(data) != wheel['size']
                        or digest(data) != wheel['sha256'] or stat.S_IMODE(metadata.st_mode) != 0o644):
                    raise ValueError('CANDIDATE_DRIVER_MISMATCH')
                lines = [line for line in files['requirements-publisher.txt'].decode().splitlines() if line and not line.startswith('#')]
                if lines != ['psycopg2-binary==2.9.10 --hash=sha256:' + digest(data)]:
                    raise ValueError('CANDIDATE_DRIVER_REQUIREMENT_MISMATCH')
                files[name], modes[name] = data, 0o644
                component_name = value['publisher_component_manifest']
                if component_name != 'release-manifest.json' or component_name in files:
                    raise ValueError('INVALID_COMPONENT_MANIFEST')
                component_bytes, component_stat = _read(fd, component_name, 1024 * 1024)
                if (digest(component_bytes) != value['publisher_component_manifest_sha256']
                        or stat.S_IMODE(component_stat.st_mode) != 0o644):
                    raise ValueError('COMPONENT_MANIFEST_MISMATCH')
                component = json.loads(component_bytes, object_pairs_hook=_unique)
                if (component.get('schema') != 'codestra.publisher-candidate.v1'
                        or component.get('source_commit') != value['source_commit']
                        or component.get('proposed_runtime_root') != runtime_root
                        or any(component.get(key) is not False for key in ('release_approved', 'install_allowed', 'activation_allowed'))
                        or component.get('driver_artifact') != value['driver_artifact']
                        or component.get('runtime') != value.get('runtime')):
                    raise ValueError('COMPONENT_MANIFEST_BINDING_CONFLICT')
                names = set()
                for entry in component['files']:
                    name = entry['source_path']
                    if (name in names or name not in entries or any(entry.get(key) != entries[name].get(key)
                            for key in ('sha256', 'size', 'mode', 'proposed_target'))):
                        raise ValueError('COMPONENT_FILE_BINDING_CONFLICT')
                    names.add(name)
                if not set(ENTRYPOINTS) <= names:
                    raise ValueError('INCOMPLETE_COMPONENT_MANIFEST')
                files[component_name], modes[component_name] = component_bytes, 0o644
                _imports(files)
                return cls(Path(directory).absolute(), manifest_sha256, value['source_commit'],
                           MappingProxyType(files), MappingProxyType(modes), raw)
        except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
            raise ValueError('INVALID_CANDIDATE') from None

    def revalidate(self):
        current = type(self).load(self.root, self.manifest_sha256)
        if (current.files != self.files or current.modes != self.modes
                or current.source_commit != self.source_commit or current.manifest_bytes != self.manifest_bytes):
            raise ValueError('CANDIDATE_REPLACED')


def migration_order(graph):
    """Topological order, with explicit rejection of missing/cyclic prerequisites."""
    pending = {name: set(dependencies) for name, dependencies in graph.items()}
    if any(not prerequisites <= pending.keys() for prerequisites in pending.values()):
        raise ValueError('MISSING_MIGRATION_DEPENDENCY')
    ordered = []
    while pending:
        ready = sorted(name for name, dependencies in pending.items() if not dependencies)
        if not ready:
            raise ValueError('CYCLIC_MIGRATION_DEPENDENCY')
        for name in ready:
            ordered.append(name)
            del pending[name]
        for dependencies in pending.values():
            dependencies.difference_update(ready)
    return tuple(ordered)


class Authority(ABC):
    """Trusted online operator adapter, supplied only by separately accepted code.

    authorize must bind operation, exact request/target/custody, fresh expiry and
    authoritative revocation. It must raise on unavailable or denied authority.
    revoke must durably revoke before returning. Neither accepts caller PASS data.
    """
    @abstractmethod
    def authorize(self, operation, binding, phase):
        raise NotImplementedError

    @abstractmethod
    def revoke(self, binding):
        raise NotImplementedError


class DeniedAuthority(Authority):
    def authorize(self, operation, binding, phase):
        raise ValueError('INSTALLATION_AUTHORITY_NOT_CONFIGURED')

    def revoke(self, binding):
        raise ValueError('INSTALLATION_AUTHORITY_NOT_CONFIGURED')


def require_authority(authority):
    if not isinstance(authority, Authority):
        raise ValueError('TRUSTED_INSTALLATION_AUTHORITY_REQUIRED')
    return authority


LEGACY_CONTRACT = {
    'public.products': ({'product': 'text', 'repository': 'text', 'promotion_chain': 'jsonb',
                         'production_go': 'boolean', 'live_capabilities_enabled': 'boolean',
                         'external_effects_enabled': 'boolean'}, ('product',)),
    'public.workstations': ({'workstation_id': 'text', 'product': 'text', 'section': 'text',
                             'subsection': 'text', 'branch': 'text', 'worktree': 'text',
                             'lease_state': 'text', 'exact_sha_certified': 'text'}, ('workstation_id',)),
    'public.sections': ({'section_id': 'text', 'product': 'text', 'section_key': 'text',
                        'branch': 'text'}, ('section_id',)),
    'public.atomic_tasks': ({'task_id': 'text', 'workstation_id': 'text', 'owner': 'text',
                            'exact_sha': 'text', 'evidence': 'jsonb'}, ('task_id',)),
    'public.scope_certifications': ({'product': 'text', 'scope_type': 'text', 'scope_name': 'text',
                                   'sha': 'text', 'status': 'text'},
                                  ('product', 'scope_type', 'scope_name')),
}
MARKERS = {
    'schema.sql': 'relation:public.workstations',
    '002-hierarchy-promotion.sql': 'relation:public.products',
    '003-readiness-views.sql': 'relation:public.section_readiness',
    '004-family-programs.sql': 'relation:public.family_programs',
    '005-scoped-registration.sql': 'relation:scoped_registration.principals',
    '006-publisher-authority-read-model.sql': 'relation:publisher_authority.bindings',
    '007-assignment-leases.sql': 'relation:assignment_leases.bindings',
    '008-frozen-recovery.sql': 'relation:frozen_recovery.grants',
    '009-atomic-inspection.sql': 'schema:atomic_inspection',
    '009-controller-coordinator.sql': 'relation:assignment_leases.coordinator_tasks',
    '010-scoped-operation-admission.sql': 'relation:scoped_admission.grants',
    '011-certifier-authority.sql': 'relation:certifier_authority.product_grants',
    '012-scope-assignment-leases.sql': 'relation:scope_assignment_leases.principals',
    '013-first-certification-pending.sql': 'relation:certifier_authority.pending_bindings',
    '014-atomic-inclusion-receipts.sql': 'relation:atomic_receipts.receipts',
    TASK_BOOTSTRAP_SOURCE: 'schema:task_bootstrap',
}
NAMESPACES = ('public', 'scoped_registration', 'publisher_authority', 'assignment_leases',
              'frozen_recovery', 'atomic_inspection', 'scoped_admission',
              'certifier_authority', 'scope_assignment_leases', 'atomic_receipts', 'task_bootstrap',
              'admission_installation_lock')


def _coordinator_contracts(candidate, source):
    """Version the five replaced functions by exact body, signature and settings.

    A shared function name is not evidence of migration 010. These reviewed
    sources use unquoted, non-overloaded names and dollar-quoted bodies only.
    Reject unsupported syntax rather than guessing a migration's presence.
    """
    pattern = re.compile(r'CREATE (?:OR REPLACE )?FUNCTION (assignment_leases\.[a-z_]+)'
        r'\(([^)]*)\)(.*?)\bAS (\$[A-Za-z_]*\$)(.*?)\4;', re.S)
    contracts = {}
    for match in pattern.finditer(candidate.files[source].decode()):
        name, arguments, header, _, body = match.groups()
        settings = re.findall(r"SET ([A-Za-z_]+)\s*=\s*('?)([A-Za-z_]+)\2", header)
        language = re.search(r'LANGUAGE ([a-z]+)', header)
        if name in contracts or language is None:
            raise ValueError('UNSUPPORTED_COORDINATOR_SOURCE_CONTRACT')
        contracts[name] = dict(arguments=re.sub(r'\s+', ' ', arguments.strip()).replace(', ', ','),
            body_sha256=digest(body.encode()), language=language[1],
            security_definer='SECURITY DEFINER' in header,
            settings=sorted(key.lower() + '=' + value for key, _, value in settings))
    if len(contracts) != 5:
        raise ValueError('INCOMPLETE_COORDINATOR_SOURCE_CONTRACT')
    return contracts


def _coordinator_adoption(candidate, observed, accepted):
    old = '009-controller-coordinator.sql'
    new = '010-controller-coordinator-integration.sql'
    actual = observed['function_contracts']
    old_contract, new_contract = (_coordinator_contracts(candidate, name) for name in (old, new))
    if old not in accepted:
        return
    expected = new_contract if new in accepted else old_contract
    if any(actual.get(name) != [contract] for name, contract in expected.items()):
        if new not in accepted and all(actual.get(name) == [contract] for name, contract in new_contract.items()):
            raise ValueError('UNTRACKED_EXISTING_COMPONENT: ' + new)
        raise ValueError('INCOMPATIBLE_LEGACY_COORDINATOR_CONTRACT')


@dataclass(frozen=True)
class InstallationPlan:
    encoded: bytes

    @property
    def digest(self):
        return digest(self.encoded)

    @property
    def value(self):
        return json.loads(self.encoded, object_pairs_hook=_unique)


def build_plan(candidate, observed, *, adopted_sources, filesystem_binding, configuration_sha256,
               migration_profile='admission-v1'):
    """Prepare a non-authorizing exact migration plan from a read-only snapshot."""
    selected = migration_sources(migration_profile)
    graph = {name: SCHEMA_PREREQUISITES[name] for name in selected}
    candidate.revalidate()
    if observed.get('postgres_major') != 16:
        raise ValueError('POSTGRESQL_16_COMPATIBILITY_REQUIRED')
    for name, (columns, primary_key) in LEGACY_CONTRACT.items():
        table = observed['tables'].get(name, {})
        if (any(table.get('columns', {}).get(k) != v for k, v in columns.items())
                or tuple(table.get('primary_key', ())) != primary_key
                or table.get('kind') != 'r' or table.get('primary_key_validated') is not True
                or table.get('primary_key_deferrable') is not False):
            raise ValueError('INCOMPATIBLE_LEGACY_CONTRACT: ' + name)
    adopted = tuple(adopted_sources)
    if (len(set(adopted)) != len(adopted) or not {'schema.sql', '002-hierarchy-promotion.sql'} <= set(adopted)
            or not set(adopted) <= set(selected) - {LEDGER_SOURCE, TASK_BOOTSTRAP_SOURCE}):
        raise ValueError('INVALID_LEGACY_ADOPTION')
    versions = observed['migration_versions']
    checksums = {name: digest(candidate.files[name]) for name in selected}
    if any(row['sha256'] != checksums[name] for name, row in versions.items() if name in checksums):
        raise ValueError('MIGRATION_CHECKSUM_CONFLICT')
    components = set(observed['components'])
    for name, marker in MARKERS.items():
        if name not in selected:
            continue
        if marker in components and name not in adopted and name not in versions:
            raise ValueError('UNTRACKED_EXISTING_COMPONENT: ' + name)
        if name in adopted and marker not in components:
            raise ValueError('MISSING_LEGACY_COMPONENT: ' + name)
    for name in adopted:
        if not set(graph[name]) <= set(adopted) | versions.keys():
            raise ValueError('INCOMPLETE_LEGACY_DEPENDENCY_ADOPTION')
    _coordinator_adoption(candidate, observed, set(adopted) | versions.keys())
    if (not isinstance(configuration_sha256, str) or not SHA256.fullmatch(configuration_sha256)
            or set(filesystem_binding) not in ({'path', 'device', 'inode', 'uid', 'gid', 'mode'},
                {'path', 'device', 'inode', 'uid', 'gid', 'mode', 'runtime'})):
        raise ValueError('INVALID_INSTALLATION_CUSTODY_BINDING')
    order = migration_order(graph)
    if set(order) != set(selected):
        raise ValueError('INCOMPLETE_MIGRATION_DEPENDENCY_GRAPH')
    target = observed['identity']
    value = {
        'schema': 'codestra.admission-installation-plan.v1',
        'source_commit': candidate.source_commit, 'manifest_sha256': candidate.manifest_sha256,
        'target': {k: target[k] for k in ('system_identifier', 'database_oid', 'database_name',
                                         'session_user', 'role_oid')},
        'catalog_before': observed['catalog_sha256'], 'sources': checksums,
        'ledger_catalog_before': observed['ledger_catalog_sha256'],
        # Complete observed constraints/nullability are explicit review inputs;
        # no invented CHECK/NOT NULL requirement for historical certification rows.
        'accepted_legacy_contracts': {name: observed['tables'][name] for name in LEGACY_CONTRACT},
        'existing_versions': versions,
        'preserved_versions': {name: row for name, row in versions.items() if name not in checksums},
        'adopted_sources': sorted(adopted),
        'pending_sources': [name for name in order if name not in adopted and name not in versions and name != LEDGER_SOURCE],
        'filesystem': dict(filesystem_binding), 'configuration_sha256': configuration_sha256,
        'authority': 'NONE_SOURCE_PLAN', 'install_allowed': False, 'activation_allowed': False,
    }
    if migration_profile != 'admission-v1':
        value['migration_profile'] = migration_profile
    if migration_profile == RESTRICTED_PROFILE:
        if LOCK_SOURCE not in candidate.files or not observed.get('lock_capability') or not observed.get('installation_reader'):
            raise ValueError('RESTRICTED_INSTALLATION_CAPABILITIES_REQUIRED')
        if LEDGER_SOURCE in versions:
            raise ValueError('EXISTING_LEDGER_REQUIRES_FORWARD_ADOPTION')
        value['lock_capability'] = observed['lock_capability']
        value['installation_reader'] = observed['installation_reader']
    return InstallationPlan(canonical(value))


class InstallationOutcomeUnknown(RuntimeError):
    """A write commit may have succeeded; inspect the same attempt on a fresh connection."""


class PostgresTarget:
    """Own an idle explicit connection; never discover DSNs from the environment."""
    def __init__(self, connection, *, lock_selection=None, reader=None):
        self.connection = connection
        self.lock_selection = lock_selection
        self.reader = reader
        self._idle()

    def restricted_observation(self, candidate, observed=None):
        """Observe protected broker and independently authenticated reader, not request JSON."""
        observed = dict(observed or self.describe())
        with self.readonly() as cursor:
            observed['lock_capability'] = _lock_capability(cursor, candidate, self.lock_selection)
        if self.reader is None:
            raise ValueError('AUTHENTICATED_INSTALLATION_READER_REQUIRED')
        identity = _restricted_verifier(self.reader, observed['identity'], exact_reads=True)
        with self.reader.readonly() as cursor:
            if _lock_capability(cursor, candidate, self.lock_selection) != observed['lock_capability']:
                raise ValueError('INSTALLATION_READER_BROKER_CONFLICT')
        observed['installation_reader'] = {k: identity[k] for k in
            ('system_identifier', 'database_oid', 'database_name', 'session_user', 'role_oid')}
        profile = observed['lock_capability']['snapshot']['profile']
        if (profile['verifier'] != identity['session_user'] or int(profile['verifier_oid']) != identity['role_oid']
                or profile['operator'] != observed['identity']['session_user']
                or int(profile['operator_oid']) != observed['identity']['role_oid']):
            raise ValueError('INSTALLATION_READER_PROFILE_CONFLICT')
        return observed

    def _idle(self):
        from psycopg2.extensions import TRANSACTION_STATUS_IDLE
        if self.connection.autocommit or self.connection.get_transaction_status() != TRANSACTION_STATUS_IDLE:
            raise ValueError('IDLE_TRANSACTIONAL_INSTALLATION_CONNECTION_REQUIRED')

    @contextmanager
    def readonly(self):
        self._idle()
        self.connection.set_session(readonly=True)
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("SET LOCAL search_path=pg_catalog,pg_temp; SET LOCAL timezone='UTC'")
                yield cursor
            self.connection.rollback()
        except BaseException:
            self.connection.rollback()
            raise
        finally:
            self.connection.set_session(readonly=False)

    @contextmanager
    def transaction(self):
        self._idle()
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("SET LOCAL search_path=pg_catalog,pg_temp; SET LOCAL timezone='UTC'; SET LOCAL lock_timeout='5s'; SET LOCAL statement_timeout='60s'")
                yield cursor
        except BaseException:
            self.connection.rollback()
            raise
        try:
            self.connection.commit()
        except Exception:
            try:
                self.connection.rollback()
            except Exception:
                pass
            raise InstallationOutcomeUnknown('INSTALLATION_COMMIT_UNKNOWN_INSPECT_SAME_ATTEMPT') from None

    def _identity(self, cursor):
        cursor.execute("""SELECT (pg_control_system()).system_identifier::text,
          d.oid,d.datname,session_user::text,current_user::text,r.oid,system_user,
          current_setting('role'),coalesce(s.ssl,false),r.rolsuper,r.rolcreaterole,r.rolcreatedb,r.rolbypassrls,
          current_setting('server_version_num')::int/10000
          FROM pg_database d JOIN pg_roles r ON r.rolname=session_user
          LEFT JOIN pg_stat_ssl s ON s.pid=pg_backend_pid() WHERE d.datname=current_database()""")
        row = cursor.fetchone()
        keys = ('system_identifier', 'database_oid', 'database_name', 'session_user', 'current_user',
                'role_oid', 'authentication', 'set_role', 'ssl', 'superuser', 'createrole', 'createdb', 'bypassrls', 'postgres_major')
        value = dict(zip(keys, row))
        value['client_sslmode'] = self.connection.get_dsn_parameters().get('sslmode')
        return value

    def _catalog(self, cursor, namespaces=NAMESPACES):
        cursor.execute("SELECT nspname,nspowner::regrole::text,nspacl::text FROM pg_namespace WHERE nspname=ANY(%s) ORDER BY 1", (list(namespaces),))
        schemas = cursor.fetchall()
        cursor.execute("""SELECT n.nspname,c.relname,c.relkind,c.relowner::regrole::text,c.relacl::text,
          a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,pg_get_expr(d.adbin,d.adrelid),
          a.attacl::text,a.attidentity,a.attgenerated,c.relrowsecurity,c.relforcerowsecurity,c.reloptions
          FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
          LEFT JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
          LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
          WHERE n.nspname=ANY(%s) AND c.relkind IN ('r','p','v','m','S','f') ORDER BY n.nspname,c.relname,a.attnum""", (list(namespaces),))
        relations = cursor.fetchall()
        cursor.execute("""SELECT n.nspname,c.relname,x.contype,pg_get_constraintdef(x.oid),
          CASE WHEN x.contype='p' THEN ARRAY(SELECT a.attname FROM unnest(x.conkey) WITH ORDINALITY k(num,ord)
            JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=k.num ORDER BY k.ord) ELSE NULL END,
          x.conname,x.convalidated,x.condeferrable,x.condeferred
          FROM pg_constraint x JOIN pg_class c ON c.oid=x.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname=ANY(%s) ORDER BY 1,2,3,4""", (list(namespaces),))
        constraints = cursor.fetchall()
        cursor.execute("""SELECT n.nspname,p.proname,pg_get_function_identity_arguments(p.oid),
          pg_get_functiondef(p.oid),p.proowner::regrole::text,p.proacl::text
          FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
          WHERE n.nspname=ANY(%s) AND p.prokind IN ('f','p') ORDER BY 1,2,3""", (list(namespaces),))
        functions = cursor.fetchall()
        cursor.execute('SELECT schemaname,tablename,indexname,indexdef FROM pg_indexes WHERE schemaname=ANY(%s) ORDER BY 1,2,3', (list(namespaces),))
        indexes = cursor.fetchall()
        cursor.execute('SELECT extname,extversion FROM pg_extension ORDER BY extname')
        extensions = cursor.fetchall()
        cursor.execute("""SELECT n.nspname,c.relname,t.tgname,t.tgenabled,t.tgisinternal,
          pg_get_triggerdef(t.oid),t.tgconstraint FROM pg_trigger t
          JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname=ANY(%s) ORDER BY 1,2,3""", (list(namespaces),))
        triggers = cursor.fetchall()
        cursor.execute("""SELECT n.nspname,c.relname,pg_get_viewdef(c.oid,true)
          FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname=ANY(%s) AND c.relkind IN ('v','m') ORDER BY 1,2""", (list(namespaces),))
        views = cursor.fetchall()
        cursor.execute("""SELECT n.nspname,c.relname,p.polname,p.polcmd,p.polpermissive,
          ARRAY(SELECT x FROM unnest(p.polroles) x ORDER BY x),
          pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)
          FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname=ANY(%s) ORDER BY 1,2,3""", (list(namespaces),))
        policies = cursor.fetchall()
        cursor.execute("""WITH objects(kind,name,object_oid,owner_oid,subobject,acl) AS (
          SELECT 'schema',nspname,oid,nspowner,'',nspacl FROM pg_namespace WHERE nspname=ANY(%s)
          UNION ALL SELECT 'relation',n.nspname||'.'||c.relname,c.oid,c.relowner,'',c.relacl
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=ANY(%s)
          UNION ALL SELECT 'column',n.nspname||'.'||c.relname,c.oid,c.relowner,a.attnum::text,a.attacl
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped WHERE n.nspname=ANY(%s)
          UNION ALL SELECT 'function',n.nspname||'.'||p.proname||'('||pg_get_function_identity_arguments(p.oid)||')',
            p.oid,p.proowner,'',p.proacl FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=ANY(%s))
          SELECT o.kind,o.name,o.object_oid::bigint,o.owner_oid::bigint,o.subobject,
            a.grantor::bigint,a.grantee::bigint,a.privilege_type,a.is_grantable
          FROM objects o LEFT JOIN LATERAL aclexplode(o.acl) a ON true
          ORDER BY 1,2,3,4,5,6,7,8,9""", (list(namespaces),) * 4)
        object_identities = cursor.fetchall()
        cursor.execute("""SELECT d.oid::bigint,d.defaclrole::bigint,d.defaclnamespace::bigint,d.defaclobjtype,
          a.grantor::bigint,a.grantee::bigint,a.privilege_type,a.is_grantable
          FROM pg_default_acl d LEFT JOIN LATERAL aclexplode(d.defaclacl) a ON true
          WHERE d.defaclnamespace=0 OR d.defaclnamespace IN (SELECT oid FROM pg_namespace WHERE nspname=ANY(%s))
          ORDER BY 1,2,3,4,5,6,7,8""", (list(namespaces),))
        default_acls = cursor.fetchall()
        catalog = dict(schemas=schemas, relations=relations, constraints=constraints,
                       functions=functions, indexes=indexes, extensions=extensions,
                       triggers=triggers, views=views, policies=policies,
                       object_identities=object_identities, default_acls=default_acls)
        tables = {}
        components = {'schema:' + row[0] for row in schemas}
        for schema, name, kind, owner, acl, column, datatype, notnull, default, column_acl, identity, generated, rls, force_rls, options in relations:
            key = schema + '.' + name
            components.add('relation:' + key)
            table = tables.setdefault(key, {'kind': kind, 'columns': {}, 'column_contracts': {}, 'primary_key': [], 'constraints': []})
            if column:
                table['columns'][column] = datatype
                table['column_contracts'][column] = dict(type=datatype, not_null=notnull,
                    default=default, acl=column_acl, identity=identity, generated=generated)
        for schema, name, kind, definition, primary_key, constraint_name, validated, deferrable, deferred in constraints:
            table = tables[schema + '.' + name]
            table['constraints'].append(dict(name=constraint_name, kind=kind, definition=definition,
                validated=validated, deferrable=deferrable, deferred=deferred))
            if kind == 'p':
                table.update(primary_key=primary_key, primary_key_validated=validated,
                             primary_key_deferrable=deferrable)
        components.update('function:' + schema + '.' + name for schema, name, *_ in functions)
        return digest(canonical(catalog)), tables, sorted(components)

    def _function_contracts(self, cursor):
        cursor.execute("""SELECT n.nspname||'.'||p.proname,pg_get_function_identity_arguments(p.oid),
          p.prosrc,l.lanname,p.prosecdef,p.proconfig FROM pg_proc p
          JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang
          WHERE n.nspname='assignment_leases' ORDER BY 1,2""")
        contracts = {}
        for name, arguments, body, language, security_definer, settings in cursor.fetchall():
            contracts.setdefault(name, []).append(dict(arguments=arguments.replace(', ', ','),
                body_sha256=digest(body.encode()), language=language, security_definer=security_definer,
                settings=sorted(key.lower() + '=' + value for key, value in
                    (item.split('=', 1) for item in settings or []))))
        return contracts

    def _versions(self, cursor):
        cursor.execute("SELECT to_regclass('admission_installation.migrations')")
        if cursor.fetchone()[0] is None:
            cursor.execute("SELECT to_regnamespace('admission_installation')")
            if cursor.fetchone()[0] is not None:
                raise ValueError('UNTRACKED_INSTALLATION_LEDGER')
            return {}
        cursor.execute('SELECT source_path,sha256,disposition FROM admission_installation.migrations ORDER BY source_path')
        return {name: {'sha256': checksum, 'disposition': disposition} for name, checksum, disposition in cursor.fetchall()}

    def describe(self):
        with self.readonly() as cursor:
            identity = self._identity(cursor)
            checksum, tables, components = self._catalog(cursor)
            versions = self._versions(cursor)
            function_contracts = self._function_contracts(cursor)
            cursor.execute("SELECT to_regnamespace('admission_installation')")
            ledger_catalog = self._catalog(cursor, ('admission_installation',))[0] if cursor.fetchone()[0] is not None else None
        return dict(identity=identity, postgres_major=identity['postgres_major'], catalog_sha256=checksum,
                    tables=tables, components=components, migration_versions=versions,
                    function_contracts=function_contracts, ledger_catalog_sha256=ledger_catalog)

    @staticmethod
    def authenticated(identity):
        if (identity['postgres_major'] != 16 or not identity['ssl'] or identity['client_sslmode'] != 'verify-full'
                or identity['authentication'] != 'scram-sha-256:' + identity['session_user']
                or identity['current_user'] != identity['session_user'] or identity['set_role'] != 'none'):
            raise ValueError('AUTHENTICATED_INSTALLATION_OPERATOR_REQUIRED')

    @contextmanager
    def fence(self):
        with self.readonly() as cursor:
            self.authenticated(self._identity(cursor))
            cursor.execute('SELECT pg_try_advisory_lock(73491, 15001)')
            acquired = cursor.fetchone()[0]
        if not acquired:
            raise ValueError('INSTALLATION_BUSY')
        try:
            yield
        finally:
            if not self.connection.closed:
                self.connection.rollback()
                with self.connection.cursor() as cursor:
                    cursor.execute('SELECT pg_advisory_unlock(73491, 15001)')
                self.connection.commit()

    def attempt(self, attempt_id):
        with self.readonly() as cursor:
            cursor.execute("SELECT to_regclass('admission_installation.attempts')")
            if cursor.fetchone()[0] is None:
                return None
            # PostgreSQL renders the OID type as a JSON string. Bind and compare
            # its numeric identity consistently with the typed catalog read.
            cursor.execute("""SELECT to_jsonb(a)||jsonb_build_object(
              'operator_oid',a.operator_oid::bigint,'database_oid',a.database_oid::bigint)
              FROM admission_installation.attempts a WHERE attempt_id=%s""", (attempt_id,))
            row = cursor.fetchone()
            return row[0] if row else None


def _migration_body(data):
    text = data.decode('utf-8')
    starts = list(re.finditer(r'(?m)^BEGIN;[ \t]*$', text))
    if not starts:
        return text
    if len(starts) != 1 or not text.rstrip().endswith('COMMIT;'):
        raise ValueError('UNSUPPORTED_MIGRATION_TRANSACTION_BOUNDARY')
    text = text[:starts[0].start()] + text[starts[0].end():]
    return text[:text.rfind('COMMIT;')]


class InstallationRevokedRecordingFailed(ValueError):
    """Issuer revocation was confirmed; target/journal recording remains separate."""
    def __init__(self, error):
        super().__init__('INSTALLATION_REVOKED_RECORDING_INCOMPLETE')
        self.recording_outcome = 'UNKNOWN' if isinstance(error, InstallationOutcomeUnknown) else 'INCOMPLETE'


class FileCustody:
    """Descriptor-relative immutable artifacts under an explicitly bound private root.

    The trusted action-time authority must accept this root's complete custody
    and owner. Constructor parameters do not establish an operational approval.
    Interrupted staging directories are preserved, never silently cleaned up.
    """
    directory_mode = 0o700
    def __init__(self, root, *, owner_uid):
        self.root = Path(root).absolute()
        self.owner_uid = owner_uid
        with _directory(self.root) as fd:
            metadata = os.fstat(fd)
            if (metadata.st_uid != owner_uid or owner_uid != os.geteuid()
                    or metadata.st_gid != os.getegid() or stat.S_IMODE(metadata.st_mode) != 0o700):
                raise ValueError('UNSAFE_INSTALLATION_CUSTODY')
            self._binding = dict(path=str(self.root), device=metadata.st_dev, inode=metadata.st_ino,
                                 uid=metadata.st_uid, gid=metadata.st_gid, mode='0o700')

    @property
    def binding(self):
        return dict(self._binding)

    @contextmanager
    def _root(self):
        try:
            with _directory(self.root) as fd:
                metadata = os.fstat(fd)
                actual = dict(path=str(self.root), device=metadata.st_dev, inode=metadata.st_ino,
                              uid=metadata.st_uid, gid=metadata.st_gid, mode=oct(stat.S_IMODE(metadata.st_mode)))
                if actual != self._binding:
                    raise ValueError('INSTALLATION_CUSTODY_REPLACED')
                yield fd
        except OSError:
            raise ValueError('INSTALLATION_CUSTODY_UNAVAILABLE') from None

    def _metadata(self, metadata, mode):
        if (metadata.st_uid != self.owner_uid or metadata.st_gid != self._binding['gid']
                or stat.S_IMODE(metadata.st_mode) != mode):
            raise ValueError('UNSAFE_INSTALLED_ARTIFACT_CUSTODY')

    @contextmanager
    def fence(self):
        with self._root() as root:
            descriptor = os.open('.installation.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 0o600, dir_fd=root)
            try:
                metadata = os.fstat(descriptor)
                self._metadata(metadata, 0o600)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise ValueError('UNSAFE_INSTALLATION_FENCE')
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise ValueError('INSTALLATION_FILESYSTEM_BUSY') from None
                os.fsync(root)
                yield
            finally:
                os.close(descriptor)

    def _child(self, parent, name, *, create=False):
        if create:
            try:
                return self._make_directory(parent, name)
            except FileExistsError:
                pass
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=parent)
        try:
            self._metadata(os.fstat(descriptor), self.directory_mode)
            if create:
                # Also complete a mkdir barrier lost by a previous exact retry.
                os.fsync(parent)
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    def _make_directory(self, parent, name):
        os.mkdir(name, self.directory_mode, dir_fd=parent)
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=parent)
        try:
            metadata = os.fstat(descriptor)
            if metadata.st_uid != self.owner_uid or metadata.st_gid != self._binding['gid']:
                raise ValueError('UNSAFE_NEW_INSTALLATION_DIRECTORY')
            os.fchmod(descriptor, self.directory_mode)
            os.fsync(descriptor)
            os.fsync(parent)
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _verify(self, descriptor, files, modes):
        expected = set(files)
        observed = set()
        def walk(fd, prefix=''):
            for name in os.listdir(fd):
                relative = prefix + name
                metadata = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(metadata.st_mode):
                    if not any(item.startswith(relative + '/') for item in expected):
                        raise ValueError('UNEXPECTED_INSTALLED_DIRECTORY')
                    child = self._child(fd, name)
                    try:
                        walk(child, relative + '/')
                    finally:
                        os.close(child)
                else:
                    if relative not in expected:
                        raise ValueError('UNEXPECTED_INSTALLED_FILE')
                    raw, checked = _read(fd, name)
                    self._metadata(checked, modes[relative])
                    if raw != files[relative]:
                        raise ValueError('INSTALLED_ARTIFACT_MISMATCH')
                    observed.add(relative)
        walk(descriptor)
        if observed != expected:
            raise ValueError('INCOMPLETE_INSTALLED_ARTIFACT')

    @staticmethod
    def _rename_exclusive(parent, source, target):
        # Linux single-host contract. No overwrite-capable rename fallback.
        libc = ctypes.CDLL(None, use_errno=True)
        operation = getattr(libc, 'renameat2', None)
        if operation is None:
            raise ValueError('EXCLUSIVE_INSTALLATION_RENAME_UNAVAILABLE')
        operation.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        operation.restype = ctypes.c_int
        if operation(parent, os.fsencode(source), parent, os.fsencode(target), 1):
            value = ctypes.get_errno()
            if value == errno.EEXIST:
                raise FileExistsError(value, 'installation artifact already exists')
            raise OSError(value, 'exclusive installation rename failed')

    def _tree(self, category, name, files, modes, *, install=False):
        _path(category)
        if not re.fullmatch(r'[a-z0-9-]{1,80}', name):
            raise ValueError('INVALID_INSTALLATION_ARTIFACT_ID')
        for path in files:
            _path(path)
        try:
            with self._root() as root:
                parent = self._child(root, category, create=install)
                try:
                    try:
                        existing = self._child(parent, name)
                    except FileNotFoundError:
                        if not install:
                            raise ValueError('INSTALLATION_ARTIFACT_MISSING') from None
                    else:
                        try:
                            self._verify(existing, files, modes)
                            if install:
                                os.fsync(existing)
                                os.fsync(parent)
                        finally:
                            os.close(existing)
                        return
                    temporary = '.staging-' + uuid.uuid4().hex
                    staging = self._make_directory(parent, temporary)
                    try:
                        for path, data in sorted(files.items()):
                            directory = os.dup(staging)
                            try:
                                parts = _path(path)
                                for part in parts[:-1]:
                                    child = self._child(directory, part, create=True)
                                    os.close(directory)
                                    directory = child
                                descriptor = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                                     modes[path], dir_fd=directory)
                                with os.fdopen(descriptor, 'wb') as stream:
                                    os.fchmod(stream.fileno(), modes[path])
                                    stream.write(data)
                                    stream.flush()
                                    os.fsync(stream.fileno())
                                os.fsync(directory)
                            finally:
                                os.close(directory)
                        self._verify(staging, files, modes)
                        os.fsync(staging)
                        self._rename_exclusive(parent, temporary, name)
                        os.fsync(parent)
                    finally:
                        os.close(staging)
                finally:
                    os.close(parent)
        except OSError:
            raise ValueError('INSTALLATION_ARTIFACT_UNAVAILABLE') from None

    def _release(self, candidate):
        files, modes = dict(candidate.files), dict(candidate.modes)
        files[MANIFEST], modes[MANIFEST] = candidate.manifest_bytes, 0o644
        return files, modes

    def install_release(self, candidate, attempt_id):
        uuid.UUID(attempt_id)
        candidate.revalidate()
        files, modes = self._release(candidate)
        self._tree('releases', candidate.manifest_sha256, files, modes, install=True)

    def verify_release(self, candidate):
        files, modes = self._release(candidate)
        self._tree('releases', candidate.manifest_sha256, files, modes)

    def install_configuration(self, data, attempt_id, expected_sha256):
        if digest(data) != expected_sha256:
            raise ValueError('CONFIGURATION_DIGEST_MISMATCH')
        self._tree('configurations', str(uuid.UUID(attempt_id)), {'configuration': data},
                   {'configuration': 0o600}, install=True)

    def verify_configuration(self, attempt_id, expected_sha256):
        with self._root() as root:
            parent = self._child(root, 'configurations')
            try:
                directory = self._child(parent, str(uuid.UUID(attempt_id)))
                try:
                    data, _ = _read(directory, 'configuration')
                    if digest(data) != expected_sha256:
                        raise ValueError('CONFIGURATION_DIGEST_MISMATCH')
                    self._verify(directory, {'configuration': data}, {'configuration': 0o600})
                finally:
                    os.close(directory)
            finally:
                os.close(parent)

    def receipt(self, attempt_id, value, *, revoked=False):
        self._tree('revocations' if revoked else 'receipts', str(uuid.UUID(attempt_id)),
                   {'receipt.json': canonical(value) + b'\n'}, {'receipt.json': 0o600}, install=True)

    def verify_receipt(self, attempt_id, value):
        self._tree('receipts', str(uuid.UUID(attempt_id)),
                   {'receipt.json': canonical(value) + b'\n'}, {'receipt.json': 0o600})

    def preflight(self, candidate, configuration, expected_sha256):
        candidate.revalidate()
        if (not isinstance(configuration, bytes) or len(configuration) > 1024 * 1024
                or digest(configuration) != expected_sha256):
            raise ValueError('CONFIGURATION_DIGEST_MISMATCH')
        with self._root():
            pass


@dataclass(frozen=True, init=False, eq=False)
class RuntimeNamespace:
    """A real host requires native UID0; prefixed namespaces are always fixtures.

    No chroot, privilege elevation, ownership repair or environment discovery.
    All runtime parents must already exist under independently accepted custody.
    """
    def __init__(self, root='/'):
        path = Path(root).absolute()
        if str(path).startswith('//') or str(path) != os.path.normpath(str(path)):
            raise ValueError('NONCANONICAL_RUNTIME_NAMESPACE')
        object.__setattr__(self, '_root_path', path)
        if self.is_host and (os.getuid() != 0 or os.geteuid() != 0):
            raise ValueError('RUNTIME_INSTALLATION_REQUIRES_NATIVE_ROOT')
        object.__setattr__(self, '_owner_uid', 0 if self.is_host else os.geteuid())
        with _directory(self.root) as fd:
            metadata = os.fstat(fd)
            host = os.stat('/')
            if not self.is_host and (metadata.st_dev, metadata.st_ino) == (host.st_dev, host.st_ino):
                raise ValueError('HOST_RUNTIME_NAMESPACE_ALIAS')
            self._safe(metadata, directory=True)
            object.__setattr__(self, '_identity', MappingProxyType(self._binding('/', metadata)))

    @property
    def root(self):
        return self._root_path

    @property
    def is_host(self):
        return self._root_path == Path('/')

    @property
    def owner_uid(self):
        return self._owner_uid

    @property
    def identity(self):
        return dict(self._identity)

    def _binding(self, path, metadata):
        return dict(path=path, device=metadata.st_dev, inode=metadata.st_ino,
                    uid=metadata.st_uid, gid=metadata.st_gid, mode=oct(stat.S_IMODE(metadata.st_mode)))

    def _safe(self, metadata, *, directory=False):
        kind = stat.S_ISDIR if directory else stat.S_ISREG
        if (not kind(metadata.st_mode) or metadata.st_uid != self.owner_uid
                or metadata.st_mode & 0o022 or not directory and metadata.st_nlink != 1):
            raise ValueError('UNSAFE_PROTECTED_RUNTIME_CUSTODY')

    @contextmanager
    def parent(self, absolute, *, collect=None):
        if not isinstance(absolute, str) or not absolute.startswith('/'):
            raise ValueError('ABSOLUTE_RUNTIME_TARGET_REQUIRED')
        parts = _path(absolute[1:])
        with _directory(self.root) as namespace:
            if self._binding('/', os.fstat(namespace)) != self.identity:
                raise ValueError('RUNTIME_NAMESPACE_REPLACED')
            fd = os.dup(namespace)
            try:
                prefix = ''
                for part in parts[:-1]:
                    prefix += '/' + part
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                    os.close(fd)
                    fd = child
                    metadata = os.fstat(fd)
                    self._safe(metadata, directory=True)
                    if collect is not None:
                        collect[prefix] = self._binding(prefix, metadata)
                yield fd, parts[-1]
            finally:
                os.close(fd)

    def parent_bindings(self, paths):
        bindings = {'/': self.identity}
        for path in sorted(paths):
            with self.parent(path, collect=bindings):
                pass
        return bindings

    def read(self, absolute, *, mode=None, gid=None):
        with self.parent(absolute) as (parent, name):
            data, metadata = _read(parent, name, 64 * 1024 * 1024)
            self._safe(metadata)
            if (mode is not None and stat.S_IMODE(metadata.st_mode) != mode
                    or gid is not None and metadata.st_gid != gid):
                raise ValueError('PROTECTED_RUNTIME_FILE_METADATA_CONFLICT')
            return data

    def snapshot(self, absolute):
        """Non-authorizing import-root fingerprint, including bytecode custody."""
        records, total = {}, 0
        def walk(fd, prefix=''):
            nonlocal total
            for name in sorted(os.listdir(fd)):
                relative = prefix + name
                metadata = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(metadata.st_mode):
                    self._safe(metadata, directory=True)
                    records[relative + '/'] = self._binding(relative + '/', metadata)
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                    try:
                        walk(child, relative + '/')
                    finally:
                        os.close(child)
                else:
                    self._safe(metadata)
                    data, checked = _read(fd, name, 64 * 1024 * 1024)
                    records[relative] = dict(self._binding(relative, checked), sha256=digest(data))
                    total += len(data)
                if len(records) > 30000 or total > 512 * 1024 * 1024:
                    raise ValueError('RUNTIME_IMPORT_CUSTODY_LIMIT')
        with self.parent(absolute) as (parent, name):
            try:
                metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return None
            if stat.S_ISDIR(metadata.st_mode):
                self._safe(metadata, directory=True)
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                try:
                    records['/'] = self._binding('/', os.fstat(child))
                    walk(child)
                finally:
                    os.close(child)
            else:
                self._safe(metadata)
                data, checked = _read(parent, name, 64 * 1024 * 1024)
                records['file'] = dict(self._binding('file', checked), sha256=digest(data))
        return digest(canonical(records))

    def publish(self, absolute, data, mode, gid):
        """Exclusive create or exact reuse; never replace differing private data."""
        if gid != os.getegid() and os.geteuid() != 0:
            raise ValueError('UNSUPPORTED_RUNTIME_CREATION_GROUP')
        with self.parent(absolute) as (parent, name):
            try:
                existing = self.read(absolute, mode=mode, gid=gid)
            except FileNotFoundError:
                pass
            else:
                if existing != data:
                    raise ValueError('EXISTING_RUNTIME_FILE_DIFFERS')
                os.fsync(parent)
                return
            temporary = '.installation-' + uuid.uuid4().hex
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=parent)
            with os.fdopen(fd, 'wb') as stream:
                os.fchown(stream.fileno(), self.owner_uid, gid)
                os.fchmod(stream.fileno(), mode)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            FileCustody._rename_exclusive(parent, temporary, name)
            os.fsync(parent)


def _wheel_contents(candidate):
    """The pinned archive, never installed RECORD metadata, defines provenance."""
    manifest = json.loads(candidate.manifest_bytes)
    data = candidate.files[manifest['driver_artifact']['path']]
    if digest(data) != manifest['driver_artifact']['sha256']:
        raise ValueError('PINNED_DRIVER_ARTIFACT_DIGEST_MISMATCH')
    record_name = 'psycopg2_binary-2.9.10.dist-info/RECORD'
    expected, total = {}, 0
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for entry in archive.infolist():
                _path(entry.filename.rstrip('/'))
                if entry.is_dir():
                    continue
                if (entry.filename in expected or stat.S_ISLNK(entry.external_attr >> 16)
                        or entry.file_size > 64 * 1024 * 1024
                        or not entry.filename.startswith(('psycopg2/', 'psycopg2_binary.libs/', 'psycopg2_binary-2.9.10.dist-info/'))):
                    raise ValueError('UNSAFE_PINNED_DRIVER_ARCHIVE')
                total += entry.file_size
                if total > 128 * 1024 * 1024 or len(expected) > 5000:
                    raise ValueError('PINNED_DRIVER_ARCHIVE_LIMIT')
                expected[entry.filename] = archive.read(entry)
        metadata = expected['psycopg2_binary-2.9.10.dist-info/METADATA'].decode()
        if 'Name: psycopg2-binary\n' not in metadata or 'Version: 2.9.10\n' not in metadata:
            raise ValueError('PINNED_DRIVER_METADATA_CONFLICT')
        seen = set()
        for name, checksum, size in csv.reader(io.StringIO(expected[record_name].decode())):
            if name in seen or name not in expected:
                raise ValueError('PINNED_DRIVER_RECORD_CONFLICT')
            seen.add(name)
            if name == record_name and checksum == size == '':
                continue
            encoded = base64.urlsafe_b64encode(hashlib.sha256(expected[name]).digest()).rstrip(b'=').decode()
            if checksum != 'sha256=' + encoded or size != str(len(expected[name])):
                raise ValueError('PINNED_DRIVER_RECORD_CONFLICT')
        if seen != expected.keys() or 'psycopg2/__init__.py' not in seen or not any(name.startswith('psycopg2/_psycopg.') and name.endswith('.so') for name in seen):
            raise ValueError('INCOMPLETE_PINNED_DRIVER_ARCHIVE')
        return expected
    except (OSError, KeyError, UnicodeError, zipfile.BadZipFile, csv.Error):
        raise ValueError('INVALID_PINNED_DRIVER_ARCHIVE') from None


class _RuntimeCodeTree(FileCustody):
    directory_mode = 0o755

    def __init__(self, namespace):
        self.root = namespace.root / 'opt/codestra-control-plane'
        self.owner_uid = namespace.owner_uid
        with _directory(self.root) as fd:
            metadata = os.fstat(fd)
            namespace._safe(metadata, directory=True)
            if stat.S_IMODE(metadata.st_mode) != 0o755 or metadata.st_gid != os.getegid():
                raise ValueError('UNSUPPORTED_RUNTIME_CODE_ROOT')
            self._binding = dict(path=str(self.root), device=metadata.st_dev, inode=metadata.st_ino,
                                 uid=metadata.st_uid, gid=metadata.st_gid, mode='0o755')


CONFIGURATION_TARGET = '/etc/codestra/control-plane/lease-verifier.toml'
CREDENTIAL_TARGETS = ('/etc/codestra/control-plane/credentials/lease-verifier.dsn',
                      '/etc/codestra/control-plane/credentials/lease-verifier-app.pem')
TASK_CONFIGURATION_TARGET = '/etc/codestra/control-plane/task-bootstrap-verifier.toml'


def _runtime_layout(spec):
    if spec.get('schema') == 'codestra.admission-runtime-selection.v1':
        return CONFIGURATION_TARGET, CREDENTIAL_TARGETS, 'ADMISSION_AND_LEGACY'
    if (spec.get('schema') != 'codestra.admission-runtime-selection.v2'
            or spec.get('publication_mode') != 'TASK_BOOTSTRAP_CLI_ONLY'):
        raise ValueError('INVALID_RUNTIME_PUBLICATION_SELECTION')
    paths = spec.get('verifier_credentials')
    if not isinstance(paths, dict) or set(paths) != {'database_dsn_file', 'app_key_file'}:
        raise ValueError('EXPLICIT_PRIVATE_RUNTIME_CREDENTIAL_SELECTION_REQUIRED')
    dsn, key = paths['database_dsn_file'], paths['app_key_file']
    parent_pattern = r'/etc/codestra/control-plane/credentials/[a-z0-9][a-z0-9-]{0,63}'
    if (not isinstance(dsn, str) or not isinstance(key, str)
            or not re.fullmatch(parent_pattern + r'/connection\.dsn', dsn)
            or not re.fullmatch(parent_pattern + r'/app\.pem', key)
            or Path(dsn).parent != Path(key).parent
            or Path(dsn).parent.name.startswith('pas233-admission-')):
        raise ValueError('DISTINCT_PRIVATE_RUNTIME_CREDENTIAL_SELECTION_REQUIRED')
    return TASK_CONFIGURATION_TARGET, (dsn, key), 'TASK_BOOTSTRAP_CLI_ONLY'


def _runtime_specification(specification, namespace):
    if not isinstance(namespace, RuntimeNamespace):
        raise ValueError('EXACT_RUNTIME_NAMESPACE_REQUIRED')
    if not isinstance(specification, dict):
        raise ValueError('COMPLETE_RUNTIME_SELECTIONS_REQUIRED')
    encoded = canonical(specification)
    spec = json.loads(encoded)
    required = {'schema', 'interpreter_sha256', 'machine_id_sha256', 'writer_exclusion_reference',
                'recovery_reference', 'driver_directory', 'import_roots', 'import_path_order', 'credential_files', 'configuration'}
    if spec.get('schema') == 'codestra.admission-runtime-selection.v2':
        required |= {'publication_mode', 'verifier_credentials'}
    if (set(spec) != required or any(not isinstance(spec[key], dict) for key in ('import_roots', 'credential_files', 'configuration'))
            or any(not isinstance(spec[key], str) for key in ('interpreter_sha256', 'machine_id_sha256'))
            or type(spec['import_path_order']) is not list or any(not isinstance(path, str) for path in spec['import_path_order'])):
        raise ValueError('COMPLETE_RUNTIME_SELECTIONS_REQUIRED')
    configuration_target, credential_targets, _ = _runtime_layout(spec)
    if (set(spec) != required
            or not SHA256.fullmatch(spec['interpreter_sha256'])
            or not SHA256.fullmatch(spec['machine_id_sha256'])
            or any(not isinstance(spec[key], str) or not 1 <= len(spec[key]) <= 512
                   for key in ('writer_exclusion_reference', 'recovery_reference'))
            or spec['driver_directory'] not in ('/usr/lib/python3/dist-packages', '/usr/local/lib/python3.12/dist-packages')
            or set(spec['configuration']) != {configuration_target}
            or set(spec['credential_files']) != set(credential_targets)
            or not {'/usr/lib/python3.12', spec['driver_directory']} <= spec['import_roots'].keys()
            or any(path not in ('/usr/lib/python312.zip', '/usr/lib/python3.12', '/usr/lib/python3.12/lib-dynload',
                '/usr/lib/python3/dist-packages', '/usr/local/lib/python3.12/dist-packages') for path in spec['import_roots'])
            or type(spec['import_path_order']) is not list or len(spec['import_path_order']) != len(spec['import_roots'])
            or set(spec['import_path_order']) != spec['import_roots'].keys()
            or any(value is not None and (not isinstance(value, str) or not SHA256.fullmatch(value)) for value in spec['import_roots'].values())
            or any(not isinstance(value, str) or not SHA256.fullmatch(value) for value in spec['credential_files'].values())):
        raise ValueError('COMPLETE_RUNTIME_SELECTIONS_REQUIRED')
    config = spec['configuration'][configuration_target]
    if (not isinstance(config, dict) or set(config) != {'sha256', 'gid', 'mode'}
            or not isinstance(config['sha256'], str) or not SHA256.fullmatch(config['sha256'])
            or config['mode'] != '0o600' or type(config['gid']) is not int or config['gid'] < 0
            or config['gid'] != (0 if namespace.is_host else os.getegid())):
        raise ValueError('INVALID_PROTECTED_CONFIGURATION_SELECTION')
    return encoded


class RuntimeExecution:
    """Trusted executing client custody, independent of installed targets.

    Recovery must use an accepted intact client. A damaged executing interpreter,
    import tree or native driver is never waived to reach the issuer.
    """
    def __init__(self, candidate, specification, namespace):
        self.candidate, self.namespace = candidate, namespace
        self._specification = _runtime_specification(specification, namespace)
        spec = self.specification
        self._paths = ['/usr/bin/python3', '/etc/machine-id',
            '/usr/lib/x86_64-linux-gnu/libcrypto.so.3',
            '/usr/lib/x86_64-linux-gnu/libssl.so.3', spec['driver_directory'] + '/entry',
            *spec['import_roots']]
        self._parents = namespace.parent_bindings(self._paths)
        self.verify()

    @property
    def specification(self):
        return json.loads(self._specification)

    def verify(self):
        if self.namespace.is_host:
            self.verify_process()
        if self.namespace.parent_bindings(self._paths) != self._parents:
            raise ValueError('RUNTIME_EXECUTION_PARENT_CHANGED')
        spec = self.specification
        if digest(self.namespace.read('/etc/machine-id')) != spec['machine_id_sha256']:
            raise ValueError('RUNTIME_PREREQUISITE_MACHINE_ID_MISMATCH')
        if digest(self.namespace.read('/usr/bin/python3.12', mode=0o755)) != spec['interpreter_sha256']:
            raise ValueError('RUNTIME_INTERPRETER_DIGEST_MISMATCH')
        with self.namespace.parent('/usr/bin/python3') as (parent, name):
            if os.readlink(name, dir_fd=parent) != 'python3.12':
                raise ValueError('RUNTIME_INTERPRETER_LINK_MISMATCH')
        for path, checksum in spec['import_roots'].items():
            if self.namespace.snapshot(path) != checksum:
                raise ValueError('RUNTIME_PREREQUISITE_IMPORT_DRIFT')
        self._verify_tools(executables=False)
        for path, data in _wheel_contents(self.candidate).items():
            # pip may rewrite installed RECORD. Its text never supplies trust;
            # every original payload byte is compared against the pinned wheel.
            if path.endswith('.dist-info/RECORD'):
                continue
            if self.namespace.read(spec['driver_directory'] + '/' + path) != data:
                raise ValueError('PINNED_DRIVER_INSTALLED_CONTENT_MISMATCH')
        if self.namespace.is_host:
            self._probe(spec)

    def verify_process(self, *, require_driver=False):
        """Bind the process that opens credentials/connections, not just a child."""
        spec = self.specification
        if (not sys.flags.isolated or not sys.dont_write_bytecode
                or sys.implementation.name != 'cpython' or tuple(sys.version_info[:2]) != (3, 12)
                or sys.platform != 'linux' or os.uname().machine != 'x86_64'
                or os.path.realpath(sys.executable) != '/usr/bin/python3.12'
                or sys.prefix != sys.base_prefix or sys.exec_prefix != sys.base_exec_prefix
                or sys.path != [str(self.candidate.root / 'lib'), *spec['import_path_order']]):
            raise ValueError('RUNNING_CLIENT_INTERPRETER_OR_IMPORT_ENVIRONMENT_MISMATCH')
        try:
            actual, selected = os.stat('/proc/self/exe'), os.stat('/usr/bin/python3.12')
            if (os.readlink('/proc/self/exe') != '/usr/bin/python3.12'
                    or (actual.st_dev, actual.st_ino) != (selected.st_dev, selected.st_ino)):
                raise ValueError('RUNNING_CLIENT_INTERPRETER_IMAGE_MISMATCH')
        except OSError:
            raise ValueError('RUNNING_CLIENT_INTERPRETER_IMAGE_UNAVAILABLE') from None
        payload = _wheel_contents(self.candidate)
        driver = spec['driver_directory']
        allowed = {}
        for name in payload:
            if not name.startswith('psycopg2/'):
                continue
            if name.endswith('.py'):
                module = name[:-3].replace('/', '.')
                if module.endswith('.__init__'):
                    module = module[:-9]
                allowed[module] = driver + '/' + name
            elif name.startswith('psycopg2/_psycopg.') and name.endswith('.so'):
                if 'psycopg2._psycopg' in allowed:
                    raise ValueError('RUNNING_CLIENT_AMBIGUOUS_NATIVE_DRIVER')
                allowed['psycopg2._psycopg'] = driver + '/' + name
        loaded = {name: module for name, module in tuple(sys.modules.items())
                  if name == 'psycopg2' or name.startswith('psycopg2.')}
        for name, module in loaded.items():
            origin = allowed.get(name)
            if (origin is None or getattr(module, '__file__', None) != origin
                    or getattr(getattr(module, '__spec__', None), 'origin', None) != origin):
                raise ValueError('RUNNING_CLIENT_DRIVER_ORIGIN_MISMATCH')
        if 'psycopg2' in loaded:
            package = loaded['psycopg2']
            if (list(getattr(package, '__path__', ())) != [driver + '/psycopg2']
                    or getattr(package, '__version__', '').split()[0:1] != ['2.9.10']):
                raise ValueError('RUNNING_CLIENT_DRIVER_PACKAGE_MISMATCH')
        if require_driver and not {'psycopg2', 'psycopg2._psycopg'} <= loaded.keys():
            raise ValueError('RUNNING_CLIENT_PINNED_DRIVER_NOT_LOADED')

    def _verify_tools(self, *, executables):
        tools = json.loads(self.candidate.files['runtime-publisher-tools.json'], object_pairs_hook=_unique)
        allowed = {'/usr/bin/git', '/usr/bin/openssl', '/usr/lib/x86_64-linux-gnu/libcrypto.so.3',
                   '/usr/lib/x86_64-linux-gnu/libssl.so.3'}
        if (tools.get('schema') != 'codestra.publisher-system-tools.v1'
                or tools.get('target_verified') is not False or tools.get('provisioning_approved') is not False
                or not isinstance(tools.get('files'), dict) or set(tools['files']) != allowed):
            raise ValueError('INVALID_RUNTIME_SYSTEM_TOOL_CONTRACT')
        for path, checksum in tools['files'].items():
            if not isinstance(checksum, str) or not SHA256.fullmatch(checksum):
                raise ValueError('RUNTIME_SYSTEM_TOOL_DIGEST_MISMATCH')
            if not executables and path.startswith('/usr/bin/'):
                continue
            if digest(self.namespace.read(path, mode=0o755 if path.startswith('/usr/bin/') else 0o644)) != checksum:
                raise ValueError('RUNTIME_SYSTEM_TOOL_DIGEST_MISMATCH')

    def _probe(self, spec):
        extensions = [spec['driver_directory'] + '/' + name for name in _wheel_contents(self.candidate)
                      if name.startswith('psycopg2/_psycopg.') and name.endswith('.so')]
        script = "import json,sys,os,platform,psycopg2,psycopg2._psycopg; print(json.dumps(dict(python=list(sys.version_info[:2]),platform=sys.platform,machine=platform.machine(),executable=os.path.realpath(sys.executable),paths=sys.path,driver=psycopg2.__file__,extension=psycopg2._psycopg.__file__,version=psycopg2.__version__.split()[0])))"
        try:
            result = subprocess.run(['/usr/bin/python3', '-I', '-B', '-c', script], capture_output=True,
                timeout=15, env={'PATH': os.defpath, 'LC_ALL': 'C'}, cwd='/', check=False)
            if result.returncode or len(result.stdout) > 65536:
                raise ValueError('RUNTIME_PREREQUISITE_PROBE_FAILED')
            value = json.loads(result.stdout, object_pairs_hook=_unique)
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            raise ValueError('RUNTIME_PREREQUISITE_PROBE_FAILED') from None
        if (value.get('python') != [3, 12] or value.get('platform') != 'linux' or value.get('machine') != 'x86_64'
                or value.get('executable') != '/usr/bin/python3.12' or value.get('paths') != spec['import_path_order']
                or value.get('driver') != spec['driver_directory'] + '/psycopg2/__init__.py'
                or len(extensions) != 1 or value.get('extension') != extensions[0] or value.get('version') != '2.9.10'):
            raise ValueError('RUNTIME_PREREQUISITE_IMPORT_RESOLUTION_MISMATCH')


class RuntimeRevocationCustody(FileCustody):
    """Only the accepted journal is needed to record a confirmed revocation."""
    def __init__(self, journal, plan, namespace):
        super().__init__(journal.root, owner_uid=journal.owner_uid)
        self.namespace = namespace
        self.validate(plan)

    def validate(self, plan):
        expected = plan.value['filesystem']
        if self.binding != {key: expected[key] for key in self.binding}:
            raise ValueError('REVOCATION_JOURNAL_BINDING_CONFLICT')
        runtime = expected.get('runtime')
        if runtime is None or not isinstance(self.namespace, RuntimeNamespace):
            raise ValueError('EXACT_RUNTIME_REVOCATION_JOURNAL_REQUIRED')
        namespace = self.namespace
        if (runtime['namespace_kind'] != ('HOST' if namespace.is_host else 'DISPOSABLE_FIXTURE')
                or runtime['namespace_root'] != str(namespace.root)
                or runtime['namespace_identity'] != namespace.identity
                or namespace.is_host and self.root != Path('/var/lib/codestra-control-plane/admission-installation')):
            raise ValueError('REVOCATION_NAMESPACE_BINDING_CONFLICT')
        journal_namespace = namespace if namespace.is_host else RuntimeNamespace(self.root.parent)
        target = (str(self.root) if namespace.is_host else '/' + self.root.name) + '/.installation.lock'
        if (runtime['journal_namespace_root'] != str(journal_namespace.root)
                or runtime['journal_namespace_identity'] != journal_namespace.identity
                or runtime['journal_parent_bindings'] != journal_namespace.parent_bindings([target])):
            raise ValueError('REVOCATION_JOURNAL_PARENT_CHANGED')


class RuntimeCustody(FileCustody):
    """Admission code/config installation, with preinstalled runtime prerequisites.

    Selection data describes expected state; only the separate Authority admits
    an operation. This API provisions no driver, credential, identity or service.
    Existing differing targets require a separately reviewed recovery/cutover.
    """
    configuration_target = '/etc/codestra/control-plane/lease-verifier.toml'
    credential_targets = ('/etc/codestra/control-plane/credentials/lease-verifier.dsn',
                          '/etc/codestra/control-plane/credentials/lease-verifier-app.pem')

    def __init__(self, journal, candidate, specification, namespace):
        super().__init__(journal.root, owner_uid=journal.owner_uid)
        if not isinstance(namespace, RuntimeNamespace):
            raise ValueError('EXACT_RUNTIME_NAMESPACE_REQUIRED')
        self.namespace, self.candidate = namespace, candidate
        if namespace.is_host and self.root != Path('/var/lib/codestra-control-plane/admission-installation'):
            raise ValueError('FIXED_HOST_INSTALLATION_JOURNAL_REQUIRED')
        self._execution = RuntimeExecution(candidate, specification, namespace)
        self._specification = self._execution._specification
        spec = self.specification
        self.configuration_target, self.credential_targets, self.publication_mode = _runtime_layout(spec)
        self._parent_paths = [self.configuration_target, *self.credential_targets, '/usr/bin/python3',
            '/etc/machine-id',
            '/opt/codestra-control-plane/releases/entry',
            spec['driver_directory'] + '/entry', *spec['import_roots']]
        if self.publication_mode == 'ADMISSION_AND_LEGACY':
            self._parent_paths.append('/opt/codestra-dev/control-plane/bin/github-status-sync')
        self._parents = namespace.parent_bindings(self._parent_paths)
        # Fixtures have their own private journal namespace; actual host custody
        # walks every ancestor from /. Bind the path as well as the final inode.
        self._journal_namespace = namespace if namespace.is_host else RuntimeNamespace(self.root.parent)
        self._journal_target = (str(self.root) if namespace.is_host else '/' + self.root.name) + '/.installation.lock'
        self._journal_parents = self._journal_namespace.parent_bindings([self._journal_target])
        self._code = _RuntimeCodeTree(namespace)
        self._release_verified = self._configuration_verified = False
        self.verify_prerequisites()
        self._existing_configuration()
        self._existing_release()
        self._existing_legacy()

    @property
    def specification(self):
        return json.loads(self._specification)

    @property
    def binding(self):
        value = super().binding
        value['runtime'] = dict(selection_sha256=digest(self._specification),
            source_commit=self.candidate.source_commit, manifest_sha256=self.candidate.manifest_sha256,
            namespace_kind='HOST' if self.namespace.is_host else 'DISPOSABLE_FIXTURE',
            namespace_root=str(self.namespace.root), namespace_identity=self.namespace.identity,
            journal_namespace_root=str(self._journal_namespace.root),
            journal_namespace_identity=self._journal_namespace.identity,
            journal_parent_bindings=self._journal_parents,
            parent_bindings=self._parents, publication_mode=self.publication_mode,
            installation_scope='ADMISSION_CODE_AND_VERIFIER_CONFIGURATION')
        return value

    @property
    def runtime_installed(self):
        return self.namespace.is_host and self._release_verified and self._configuration_verified

    def verify_prerequisites(self):
        spec = self.specification
        if self._journal_namespace.parent_bindings([self._journal_target]) != self._journal_parents:
            raise ValueError('INSTALLATION_JOURNAL_PARENT_CHANGED')
        if self.namespace.parent_bindings(self._parent_paths) != self._parents:
            raise ValueError('RUNTIME_PREREQUISITE_PARENT_CHANGED')
        self._execution.verify()
        self._execution._verify_tools(executables=True)
        for path, checksum in spec['credential_files'].items():
            if self.publication_mode == 'TASK_BOOTSTRAP_CLI_ONLY':
                with self.namespace.parent(path) as (parent, _):
                    metadata = os.fstat(parent)
                    if stat.S_IMODE(metadata.st_mode) != 0o700 or metadata.st_gid != (0 if self.namespace.is_host else os.getegid()):
                        raise ValueError('PRIVATE_RUNTIME_CREDENTIAL_PARENT_REQUIRED')
            if digest(self.namespace.read(path, mode=0o600, gid=0 if self.namespace.is_host else os.getegid())) != checksum:
                raise ValueError('RUNTIME_PREREQUISITE_CREDENTIAL_DRIFT')

    def _probe(self, spec):
        self._execution._probe(spec)

    def _existing_configuration(self):
        config = self.specification['configuration'][self.configuration_target]
        try:
            data = self.namespace.read(self.configuration_target, mode=0o600, gid=config['gid'])
        except FileNotFoundError:
            return
        if digest(data) != config['sha256']:
            raise ValueError('EXISTING_PROTECTED_CONFIGURATION_DIFFERS')

    def _existing_release(self):
        target = '/opt/codestra-control-plane/releases/' + self.candidate.source_commit
        with self.namespace.parent(target) as (parent, name):
            try:
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return
        files, modes = self._release(self.candidate)
        self._code._tree('releases', self.candidate.source_commit, files, modes)

    def _existing_legacy(self):
        if self.publication_mode == 'TASK_BOOTSTRAP_CLI_ONLY':
            return
        try:
            data = self.namespace.read('/opt/codestra-dev/control-plane/bin/github-status-sync', mode=0o755)
        except FileNotFoundError:
            return
        if data != self.candidate.files['legacy/bin/github-status-sync']:
            raise ValueError('EXISTING_RUNTIME_LEGACY_TARGET_DIFFERS')

    def _record(self, attempt_id, target, phase):
        event = dict(attempt_id=str(uuid.UUID(attempt_id)), target=target, phase=phase,
            source_commit=self.candidate.source_commit, manifest_sha256=self.candidate.manifest_sha256,
            runtime_selection_sha256=digest(self._specification), recovery='EXCLUSIVE_CREATE_OR_IDENTICAL_REUSE_ONLY')
        self._tree('runtime-history', digest(canonical(event)), {'event.json': canonical(event) + b'\n'},
                   {'event.json': 0o600}, install=True)

    def _candidate(self, candidate):
        candidate.revalidate()
        if (candidate.manifest_sha256 != self.candidate.manifest_sha256
                or candidate.source_commit != self.candidate.source_commit):
            raise ValueError('RUNTIME_CANDIDATE_CONFLICT')

    def _release(self, candidate):
        self._candidate(candidate)
        root = '/opt/codestra-control-plane/releases/' + candidate.source_commit
        entries = json.loads(candidate.manifest_bytes)['files']
        names = [entry['source_path'] for entry in entries
                 if entry['proposed_target'] == root + '/' + entry['source_path']]
        files = {name: candidate.files[name] for name in names}
        modes = {name: candidate.modes[name] for name in names}
        # Explicit administrative provenance metadata, not executable artifacts.
        files[MANIFEST], modes[MANIFEST] = candidate.manifest_bytes, 0o644
        files['release-manifest.json'], modes['release-manifest.json'] = candidate.files['release-manifest.json'], 0o644
        return files, modes

    def preflight(self, candidate, configuration, expected_sha256):
        super().preflight(candidate, configuration, expected_sha256)
        self._candidate(candidate)
        self._configuration(configuration)
        self.verify_prerequisites()
        self._existing_configuration()
        self._existing_release()
        self._existing_legacy()

    def install_release(self, candidate, attempt_id):
        self._candidate(candidate)
        self.verify_prerequisites()
        self._existing_configuration()
        self._existing_release()
        self._existing_legacy()
        target = '/opt/codestra-control-plane/releases/' + candidate.source_commit
        self._record(attempt_id, target, 'INTENT')
        files, modes = self._release(candidate)
        self._code._tree('releases', candidate.source_commit, files, modes, install=True)
        self._record(attempt_id, target, 'DURABLE')
        if self.publication_mode == 'ADMISSION_AND_LEGACY':
            target = '/opt/codestra-dev/control-plane/bin/github-status-sync'
            self._record(attempt_id, target, 'INTENT')
            self.namespace.publish(target, candidate.files['legacy/bin/github-status-sync'], 0o755, os.getegid())
            self._record(attempt_id, target, 'DURABLE')
        self.verify_release(candidate)

    def verify_release(self, candidate):
        self._candidate(candidate)
        self.verify_prerequisites()
        files, modes = self._release(candidate)
        self._code._tree('releases', candidate.source_commit, files, modes)
        if (self.publication_mode == 'ADMISSION_AND_LEGACY'
                and self.namespace.read('/opt/codestra-dev/control-plane/bin/github-status-sync', mode=0o755) != candidate.files['legacy/bin/github-status-sync']):
            raise ValueError('RUNTIME_LEGACY_TARGET_MISMATCH')
        self._release_verified = True

    def _configuration(self, data):
        if not isinstance(data, bytes) or len(data) > 1024 * 1024:
            raise ValueError('INVALID_RUNTIME_CONFIGURATION')
        try:
            bundle = json.loads(data, object_pairs_hook=_unique)
            if not isinstance(bundle, dict) or set(bundle) != {self.configuration_target}:
                raise ValueError('INVALID_RUNTIME_CONFIGURATION_TARGETS')
            raw = base64.b64decode(bundle[self.configuration_target], validate=True)
            config = tomllib.loads(raw.decode())
        except (UnicodeError, json.JSONDecodeError, tomllib.TOMLDecodeError, TypeError, base64.binascii.Error):
            raise ValueError('INVALID_RUNTIME_CONFIGURATION') from None
        if (not isinstance(config, dict) or set(config) != {'database_dsn_file', 'app_id', 'installation_id', 'app_key_file'}
                or any(type(config[key]) is not int or config[key] <= 0 for key in ('app_id', 'installation_id'))
                or config['database_dsn_file'] != self.credential_targets[0] or config['app_key_file'] != self.credential_targets[1]
                or digest(raw) != self.specification['configuration'][self.configuration_target]['sha256']):
            raise ValueError('INVALID_RUNTIME_CONFIGURATION')
        return raw

    def install_configuration(self, data, attempt_id, expected_sha256):
        if digest(data) != expected_sha256:
            raise ValueError('CONFIGURATION_DIGEST_MISMATCH')
        raw = self._configuration(data)
        self.verify_prerequisites()
        self._record(attempt_id, self.configuration_target, 'INTENT')
        self.namespace.publish(self.configuration_target, raw, 0o600,
                               self.specification['configuration'][self.configuration_target]['gid'])
        self._record(attempt_id, self.configuration_target, 'DURABLE')
        super().install_configuration(data, attempt_id, expected_sha256)
        self.verify_configuration(attempt_id, expected_sha256)

    def verify_configuration(self, attempt_id, expected_sha256):
        super().verify_configuration(attempt_id, expected_sha256)
        self.verify_prerequisites()
        with self._root() as root:
            bundle, _ = _read(root, 'configurations/' + str(uuid.UUID(attempt_id)) + '/configuration')
        raw = self._configuration(bundle)
        if self.namespace.read(self.configuration_target, mode=0o600,
                gid=self.specification['configuration'][self.configuration_target]['gid']) != raw:
            raise ValueError('PROTECTED_RUNTIME_CONFIGURATION_MISMATCH')
        self._configuration_verified = True


def _plan_binding(plan, attempt_id):
    if not isinstance(plan, InstallationPlan):
        raise ValueError('EXACT_INSTALLATION_PLAN_REQUIRED')
    value = plan.value
    attempt_id = str(uuid.UUID(attempt_id))
    if (value.get('schema') != 'codestra.admission-installation-plan.v1'
            or not SHA1.fullmatch(value['source_commit'])
            or not SHA256.fullmatch(value['manifest_sha256'])
            or not SHA256.fullmatch(value['configuration_sha256'])):
        raise ValueError('INVALID_INSTALLATION_REVOCATION_BINDING')
    binding = dict(attempt_id=attempt_id, plan_sha256=plan.digest,
                   source_commit=value['source_commit'], manifest_sha256=value['manifest_sha256'],
                   target=value['target'], filesystem=value['filesystem'],
                   configuration_sha256=value['configuration_sha256'])
    binding['request_sha256'] = digest(canonical(binding))
    return value, binding


def _context(candidate, plan, store, attempt_id):
    if not isinstance(plan, InstallationPlan) or not isinstance(store, FileCustody):
        raise ValueError('EXACT_INSTALLATION_PLAN_REQUIRED')
    if isinstance(store, RuntimeCustody):
        store._candidate(candidate)
    attempt_id = str(uuid.UUID(attempt_id))
    value = plan.value
    selected = migration_sources(value.get('migration_profile', 'admission-v1'))
    graph = {name: SCHEMA_PREREQUISITES[name] for name in selected}
    if (value['source_commit'] != candidate.source_commit or value['manifest_sha256'] != candidate.manifest_sha256
            or value['filesystem'] != store.binding or set(value['sources']) != set(selected)
            or any(value['sources'][name] != digest(candidate.files[name]) for name in selected)):
        raise ValueError('INSTALLATION_PLAN_BINDING_CONFLICT')
    expected_pending = [name for name in migration_order(graph)
                        if name not in value['adopted_sources'] and name not in value['existing_versions'] and name != LEDGER_SOURCE]
    if value['pending_sources'] != expected_pending:
        raise ValueError('INSTALLATION_DEPENDENCY_PLAN_CONFLICT')
    return _plan_binding(plan, attempt_id)


def _authorize(authority, operation, binding, phase):
    # A trusted adapter must raise on denial; boolean/PASS-style returns are bugs.
    if require_authority(authority).authorize(operation, dict(binding), phase) is not None:
        raise ValueError('INVALID_INSTALLATION_AUTHORITY_RESPONSE')


def _target(identity, expected, *, independent=False):
    PostgresTarget.authenticated(identity)
    fields = ('system_identifier', 'database_oid', 'database_name')
    if not independent:
        fields += ('session_user', 'role_oid')
    if any(identity[key] != expected[key] for key in fields):
        raise ValueError('INSTALLATION_TARGET_IDENTITY_CONFLICT')


def _versions(observed, expected, *, complete=False, preserved=None):
    actual = observed['migration_versions']
    if (any(row['sha256'] != expected[name] for name, row in actual.items() if name in expected)
            or {name: row for name, row in actual.items() if name not in expected} != (preserved or {})):
        raise ValueError('INSTALLATION_VERSION_CHECKSUM_CONFLICT')
    if complete and set(actual) != set(expected) | (preserved or {}).keys():
        raise ValueError('INCOMPLETE_INSTALLATION_VERSIONS')


def _progress(callback, phase):
    if callback is not None:
        callback(phase)


def _lock_capability(cursor, candidate, selection):
    """Validate executable source before calling a pre-existing definer API."""
    if (type(selection) is not dict or set(selection) != {'profile_sha256'}
            or not isinstance(selection['profile_sha256'], str)
            or not SHA256.fullmatch(selection['profile_sha256']) or LOCK_SOURCE not in candidate.files):
        raise ValueError('PROTECTED_LOCK_SELECTION_REQUIRED')
    pattern = re.compile(r'CREATE FUNCTION admission_installation_lock\.([a-z_]+)'
        r'\(([^)]*)\) RETURNS (jsonb|trigger) LANGUAGE plpgsql SECURITY DEFINER\n'
        r"SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS \$\$(.*?)\$\$;", re.S)
    expected = {name: (args, body, returns) for name, args, returns, body in pattern.findall(candidate.files[LOCK_SOURCE].decode())}
    if set(expected) != {'describe', 'acquire', '_profile_revision'}:
        raise ValueError('INVALID_LOCK_SOURCE_CONTRACT')
    cursor.execute("""SELECT p.oid,p.proname,pg_get_function_identity_arguments(p.oid),p.prosrc,
      p.prosecdef,l.lanname,p.proconfig,p.proowner,n.oid,n.nspowner,r.rolcanlogin,
      r.rolsuper,r.rolcreaterole,r.rolcreatedb,r.rolreplication,r.rolbypassrls,
      pg_has_role(session_user,r.oid,'MEMBER'),
      EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE'),
      has_schema_privilege(session_user,n.oid,'CREATE'),p.prorettype::regtype::text,
      p.prokind,p.provolatile,p.proparallel,p.proretset,p.proisstrict,p.proleakproof,
      p.prosupport::oid,p.pronargdefaults,p.provariadic
      FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
      JOIN pg_roles r ON r.oid=p.proowner JOIN pg_language l ON l.oid=p.prolang
      WHERE n.nspname='admission_installation_lock' ORDER BY p.proname,p.oid""")
    rows = cursor.fetchall()
    if len(rows) != 3:
        raise ValueError('LOCK_BROKER_CONTRACT_CHANGED')
    pins = []
    for row in rows:
        oid, name, arguments, body, definer, language, settings, owner, namespace, schema_owner, *tail = row
        unsafe, returns, flags = tail[:9], tail[9], tuple(tail[10:])
        if (name not in expected or (arguments, body, returns) != expected[name]
                or not definer or language != 'plpgsql'
                or sorted(item.lower() for item in settings or []) != ['search_path=pg_catalog, pg_temp', 'timezone=utc']
                or owner != schema_owner or any(unsafe)
                or flags != ('f', 'v', 'u', False, False, False, 0, 0, 0)):
            raise ValueError('LOCK_BROKER_CONTRACT_CHANGED')
        pins.append(dict(oid=oid, name=name, owner_oid=owner, namespace_oid=namespace))
    if len({pin['owner_oid'] for pin in pins}) != 1:
        raise ValueError('LOCK_BROKER_CONTRACT_CHANGED')
    cursor.execute("""SELECT c.oid,c.relowner,c.relkind,
      (EXISTS(SELECT 1 FROM aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE a.grantee<>c.relowner)
       OR EXISTS(SELECT 1 FROM pg_attribute att CROSS JOIN LATERAL aclexplode(att.attacl) a
         WHERE att.attrelid=c.oid AND a.grantee<>c.relowner)),
      EXISTS(SELECT 1 FROM pg_roles r WHERE pg_has_role(session_user,r.oid,'MEMBER') AND
        (has_table_privilege(r.oid,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
         OR has_any_column_privilege(r.oid,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
      FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='admission_installation_lock' AND c.relname='profile'""")
    table = cursor.fetchone()
    if not table or table[1] != pins[0]['owner_oid'] or table[2:] != ('r', False, False):
        raise ValueError('LOCK_BROKER_PROFILE_NOT_PROTECTED')
    helper_oid = next(pin['oid'] for pin in pins if pin['name'] == '_profile_revision')
    cursor.execute("""SELECT tgname,tgfoid,tgtype,tgenabled,tgnargs,tgqual IS NULL,
      tgdeferrable,tginitdeferred,tgconstraint,tgoldtable,tgnewtable
      FROM pg_trigger WHERE tgrelid=%s AND NOT tgisinternal ORDER BY tgname""", (table[0],))
    if cursor.fetchall() != [
            ('profile_revision', helper_oid, 27, 'O', 0, True, False, False, 0, None, None),
            ('profile_truncate', helper_oid, 34, 'O', 0, True, False, False, 0, None, None)]:
        raise ValueError('LOCK_PROFILE_GUARDS_CHANGED')
    cursor.execute('SELECT admission_installation_lock.describe()')
    snapshot = cursor.fetchone()[0]
    if snapshot.get('profile_sha256') != selection['profile_sha256']:
        raise ValueError('LOCK_PROFILE_CHANGED')
    return dict(snapshot=snapshot, functions=pins, profile_oid=table[0], source_sha256=digest(candidate.files[LOCK_SOURCE]))


def _lock_tables(cursor, *, backend=None, candidate=None, plan=None):
    from psycopg2 import sql
    restricted = plan is not None and plan.get('migration_profile') == RESTRICTED_PROFILE
    if restricted:
        actual = _lock_capability(cursor, candidate, backend.lock_selection)
        if actual != plan['lock_capability']:
            raise ValueError('LOCK_CAPABILITY_CHANGED')
    cursor.execute("""SELECT n.nspname,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname=ANY(%s) AND c.relkind IN ('r','p') ORDER BY n.nspname,c.relname""", (list(NAMESPACES) + ['admission_installation'],))
    public_locked = False
    for namespace, table in cursor.fetchall():
        if namespace == 'admission_installation_lock':
            continue
        if restricted and namespace == 'public':
            if not public_locked:
                cursor.execute('SELECT admission_installation_lock.acquire(%s)',
                    (plan['lock_capability']['snapshot']['profile_sha256'],))
                if cursor.fetchone()[0] != plan['lock_capability']['snapshot']:
                    raise ValueError('LOCK_CAPABILITY_CHANGED')
                public_locked = True
            continue
        cursor.execute(sql.SQL('LOCK TABLE {} IN ACCESS EXCLUSIVE MODE').format(sql.Identifier(namespace, table)))


def _event(cursor, attempt_id, stage):
    cursor.execute('INSERT INTO admission_installation.events(attempt_id,stage) VALUES(%s,%s)', (attempt_id, stage))


def _transition(cursor, binding, previous, stage, *, catalog_after=None, receipt=None):
    from psycopg2.extras import Json
    cursor.execute("""UPDATE admission_installation.attempts SET stage=%s,
      catalog_after=coalesce(%s,catalog_after),receipt=coalesce(%s,receipt),updated_at=clock_timestamp()
      WHERE attempt_id=%s AND request_sha256=%s AND stage=%s""",
      (stage, catalog_after, Json(receipt) if receipt is not None else None,
       binding['attempt_id'], binding['request_sha256'], previous))
    if cursor.rowcount != 1:
        raise ValueError('INSTALLATION_ATTEMPT_STATE_CONFLICT')
    _event(cursor, binding['attempt_id'], stage)


def _receipt(binding, state):
    return dict(schema='codestra.admission-installation-observation.v1',
                attempt_id=binding['attempt_id'], request_sha256=binding['request_sha256'],
                source_commit=binding['source_commit'], manifest_sha256=binding['manifest_sha256'],
                plan_sha256=binding['plan_sha256'], state=state,
                authority='NONE_INSTALLATION_OBSERVATION', usable=False, certified=False,
                runtime_installed=False, activation_allowed=False, production_go=False, external_effects=False)


def _installation_receipt(binding, store, prior):
    catalog = dict(catalog_after=prior['catalog_after'], ledger_catalog_sha256=prior['ledger_catalog_sha256'])
    if isinstance(store, RuntimeCustody):
        receipt = _receipt(binding, 'ADMISSION_RUNTIME_FILES_INSTALLED_UNVERIFIED' if store.namespace.is_host
                           else 'DATABASE_APPLIED_RUNTIME_FIXTURE_MATERIALIZED')
        receipt.update(**catalog, runtime_installed=store.namespace.is_host,
            namespace_kind='HOST' if store.namespace.is_host else 'DISPOSABLE_FIXTURE',
            installation_scope='ADMISSION_CODE_AND_VERIFIER_CONFIGURATION')
        return receipt
    return dict(_receipt(binding, 'DATABASE_APPLIED_ARTIFACTS_STAGED'), **catalog)


def install(backend, candidate, plan, store, configuration, attempt_id, authority, *, progress=None):
    """Apply a separately admitted exact attempt; never activate any consumer."""
    require_authority(authority)
    candidate.revalidate()
    value, binding = _context(candidate, plan, store, attempt_id)
    if not isinstance(configuration, bytes) or digest(configuration) != value['configuration_sha256']:
        raise ValueError('CONFIGURATION_DIGEST_MISMATCH')
    store.preflight(candidate, configuration, value['configuration_sha256'])
    observed = backend.describe()
    _target(observed['identity'], value['target'])
    _authorize(authority, 'install', binding, 'preflight')
    restricted = value.get('migration_profile') == RESTRICTED_PROFILE
    if restricted:
        observed = backend.restricted_observation(candidate, observed)
        if any(observed[key] != value[key] for key in ('lock_capability', 'installation_reader')):
            raise ValueError('RESTRICTED_INSTALLATION_CAPABILITY_CHANGED')
        _authorize(authority, 'verify', dict(binding, verifier_role_oid=value['installation_reader']['role_oid']), 'preflight')
    with backend.fence(), store.fence():
        store.preflight(candidate, configuration, value['configuration_sha256'])
        observed = backend.describe()
        if restricted:
            observed = backend.restricted_observation(candidate, observed)
        _target(observed['identity'], value['target'])
        _versions(observed, value['sources'], preserved=value['preserved_versions'])
        prior = backend.attempt(binding['attempt_id'])
        if prior is None:
            if (observed['catalog_sha256'] != value['catalog_before']
                    or observed['ledger_catalog_sha256'] != value['ledger_catalog_before']
                    or observed['migration_versions'] != value['existing_versions']):
                raise ValueError('INSTALLATION_CATALOG_CHANGED')
            rebuilt = build_plan(candidate, observed, adopted_sources=value['adopted_sources'],
                filesystem_binding=store.binding, configuration_sha256=value['configuration_sha256'],
                migration_profile=value.get('migration_profile', 'admission-v1'))
            if rebuilt.encoded != plan.encoded:
                raise ValueError('INSTALLATION_PLAN_SEMANTICS_CHANGED')
            _authorize(authority, 'install', binding, 'intent')
            with backend.transaction() as cursor:
                _lock_tables(cursor, backend=backend, candidate=candidate, plan=value)
                if backend._catalog(cursor)[0] != value['catalog_before']:
                    raise ValueError('INSTALLATION_CATALOG_CHANGED')
                cursor.execute("SELECT to_regnamespace('admission_installation')")
                ledger = backend._catalog(cursor, ('admission_installation',))[0] if cursor.fetchone()[0] is not None else None
                if ledger != value['ledger_catalog_before']:
                    raise ValueError('INSTALLATION_LEDGER_CATALOG_CHANGED')
                versions = backend._versions(cursor)
                if not versions:
                    cursor.execute(_migration_body(candidate.files[LEDGER_SOURCE]))
                    if restricted:
                        _grant_installation_reader(cursor, value['installation_reader'])
                elif versions.get(LEDGER_SOURCE, {}).get('sha256') != value['sources'][LEDGER_SOURCE]:
                    raise ValueError('INSTALLATION_LEDGER_VERSION_CONFLICT')
                cursor.execute("SELECT 1 FROM admission_installation.attempts WHERE stage<>'REVOKED' LIMIT 1")
                if cursor.fetchone():
                    raise ValueError('COMPETING_INSTALLATION_ATTEMPT')
                cursor.execute("""INSERT INTO admission_installation.attempts(attempt_id,request_sha256,source_commit,
                  manifest_sha256,plan_sha256,operator_oid,system_identifier,database_oid,catalog_before,ledger_catalog_sha256,stage)
                  VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'INTENT')""",
                  (binding['attempt_id'], binding['request_sha256'], candidate.source_commit, candidate.manifest_sha256,
                   plan.digest, value['target']['role_oid'], value['target']['system_identifier'],
                   value['target']['database_oid'], value['catalog_before'],
                   backend._catalog(cursor, ('admission_installation',))[0]))
                for name in value['adopted_sources'] + [LEDGER_SOURCE]:
                    cursor.execute("""INSERT INTO admission_installation.migrations(source_path,sha256,attempt_id,disposition)
                      VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
                      (name, value['sources'][name], binding['attempt_id'], 'APPLIED' if name == LEDGER_SOURCE else 'ADOPTED'))
                _event(cursor, binding['attempt_id'], 'INTENT')
                _progress(progress, 'before_intent_commit')
            _progress(progress, 'after_intent_commit')
            prior = backend.attempt(binding['attempt_id'])
        if prior['request_sha256'] != binding['request_sha256'] or prior['operator_oid'] != value['target']['role_oid']:
            raise ValueError('INSTALLATION_ATTEMPT_BINDING_CONFLICT')
        if prior['stage'] == 'REVOKED':
            raise ValueError('INSTALLATION_REVOKED')
        with backend.readonly() as cursor:
            if backend._catalog(cursor, ('admission_installation',))[0] != prior['ledger_catalog_sha256']:
                raise ValueError('INSTALLATION_LEDGER_CATALOG_CHANGED')
        if prior['stage'] == 'INTENT':
            candidate.revalidate()
            _authorize(authority, 'install', binding, 'database')
            with backend.transaction() as cursor:
                _lock_tables(cursor, backend=backend, candidate=candidate, plan=value)
                if backend._catalog(cursor)[0] != value['catalog_before']:
                    raise ValueError('INSTALLATION_CATALOG_CHANGED')
                for name in value['pending_sources']:
                    cursor.execute(_migration_body(candidate.files[name]))
                    cursor.execute("""INSERT INTO admission_installation.migrations(source_path,sha256,attempt_id,disposition)
                      VALUES(%s,%s,%s,'APPLIED')""", (name, value['sources'][name], binding['attempt_id']))
                after = backend._catalog(cursor)[0]
                _authorize(authority, 'install', binding, 'database_commit')
                _transition(cursor, binding, 'INTENT', 'DATABASE_APPLIED', catalog_after=after)
                _progress(progress, 'before_database_commit')
            _progress(progress, 'after_database_commit')
            prior = backend.attempt(binding['attempt_id'])
        observed = backend.describe()
        _versions(observed, value['sources'], complete=True, preserved=value['preserved_versions'])
        if observed['catalog_sha256'] != prior['catalog_after']:
            raise ValueError('INSTALLED_CATALOG_CHANGED')
        if prior['stage'] == 'DATABASE_APPLIED':
            _authorize(authority, 'install', binding, 'files')
            _progress(progress, 'before_files_install')
            store.install_release(candidate, binding['attempt_id'])
            _progress(progress, 'after_files_install')
            _authorize(authority, 'install', binding, 'files_commit')
            with backend.transaction() as cursor:
                _transition(cursor, binding, 'DATABASE_APPLIED', 'FILES_DURABLE')
            _progress(progress, 'after_files_commit')
            prior = backend.attempt(binding['attempt_id'])
        if prior['stage'] == 'FILES_DURABLE':
            candidate.revalidate()
            store.verify_release(candidate)
            _authorize(authority, 'install', binding, 'configuration')
            store.install_configuration(configuration, binding['attempt_id'], value['configuration_sha256'])
            _progress(progress, 'after_configuration_install')
            _authorize(authority, 'install', binding, 'configuration_commit')
            receipt = _installation_receipt(binding, store, prior)
            with backend.transaction() as cursor:
                _transition(cursor, binding, 'FILES_DURABLE', 'CONFIGURATION_DURABLE', receipt=receipt)
            _progress(progress, 'after_configuration_commit')
            prior = backend.attempt(binding['attempt_id'])
        if (prior['stage'] not in ('CONFIGURATION_DURABLE', 'RECEIPTED')
                or prior['receipt'] != _installation_receipt(binding, store, prior)):
            raise ValueError('INVALID_INSTALLATION_RECEIPT')
        candidate.revalidate()
        store.verify_release(candidate)
        store.verify_configuration(binding['attempt_id'], value['configuration_sha256'])
        _authorize(authority, 'install', binding, 'receipt')
        store.receipt(binding['attempt_id'], prior['receipt'])
        _progress(progress, 'after_receipt_install')
        if prior['stage'] == 'CONFIGURATION_DURABLE':
            _authorize(authority, 'install', binding, 'receipt_commit')
            with backend.transaction() as cursor:
                _transition(cursor, binding, 'CONFIGURATION_DURABLE', 'RECEIPTED')
            _progress(progress, 'after_receipt_commit')
        _authorize(authority, 'install', binding, 'return')
        fresh = backend.describe()
        if restricted:
            fresh = backend.restricted_observation(candidate, fresh)
            if any(fresh[key] != value[key] for key in ('lock_capability', 'installation_reader')):
                raise ValueError('RESTRICTED_INSTALLATION_CAPABILITY_CHANGED')
        _target(fresh['identity'], value['target'])
        _versions(fresh, value['sources'], complete=True, preserved=value['preserved_versions'])
        completed = backend.attempt(binding['attempt_id'])
        if (fresh['catalog_sha256'] != prior['catalog_after'] or fresh['ledger_catalog_sha256'] != prior['ledger_catalog_sha256']
                or completed['stage'] != 'RECEIPTED'
                or completed['request_sha256'] != binding['request_sha256'] or completed['receipt'] != prior['receipt']):
            raise ValueError('INSTALLATION_CHANGED_BEFORE_RETURN')
        store.verify_release(candidate)
        store.verify_configuration(binding['attempt_id'], value['configuration_sha256'])
        store.verify_receipt(binding['attempt_id'], prior['receipt'])
        return prior['receipt']


def _has_writer_capability(cursor, namespaces):
    """Include attainable NOINHERIT roles, object owners and database owners."""
    cursor.execute("""SELECT EXISTS(SELECT 1 FROM pg_roles reachable
          WHERE pg_has_role(session_user,reachable.oid,'MEMBER') AND
          (reachable.rolsuper OR reachable.rolcreaterole OR reachable.rolcreatedb
          OR reachable.rolreplication OR reachable.rolbypassrls
          OR reachable.rolname IN ('pg_read_server_files','pg_write_server_files','pg_execute_server_program',
             'pg_signal_backend','pg_checkpoint','pg_create_subscription','pg_use_reserved_connections')
          OR EXISTS(SELECT 1 FROM pg_database d WHERE d.datname=current_database()
            AND (d.datdba=reachable.oid OR has_database_privilege(reachable.oid,d.oid,'CREATE')))
          OR EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
            WHERE n.nspname='pg_catalog' AND p.proname=ANY(%s)
              AND has_function_privilege(reachable.oid,p.oid,'EXECUTE'))
          OR EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
            WHERE n.nspname=ANY(%s) AND p.proowner=reachable.oid)
          OR EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname=ANY(%s)
            AND (n.nspowner=reachable.oid OR has_schema_privilege(reachable.oid,n.oid,'CREATE')))
          OR EXISTS(SELECT 1 FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace
            WHERE n.nspname=ANY(%s) AND t.relkind IN ('r','p','v','m','f','S') AND
            (t.relowner=reachable.oid
            OR CASE WHEN t.relkind='S' THEN has_sequence_privilege(reachable.oid,t.oid,'USAGE,UPDATE')
               ELSE has_table_privilege(reachable.oid,t.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                 OR has_any_column_privilege(reachable.oid,t.oid,'INSERT,UPDATE,REFERENCES') END))))""",
          (list(PRIVILEGED_BUILTINS),) + (list(namespaces),) * 3)
    return cursor.fetchone()[0]


def _restricted_verifier(backend, expected, *, exact_reads=False):
    """Check all attainable roles, including NOINHERIT/SET ROLE capabilities."""
    with backend.readonly() as cursor:
        identity = backend._identity(cursor)
        _target(identity, expected, independent=True)
        namespaces = (*NAMESPACES, 'admission_installation')
        if exact_reads:
            cursor.execute("SELECT nspname FROM pg_namespace WHERE left(nspname,3)<>'pg_' AND nspname<>'information_schema'")
            namespaces = tuple(row[0] for row in cursor.fetchall())
        if (identity['role_oid'] == expected['role_oid']
                or _has_writer_capability(cursor, namespaces)):
            raise ValueError('INDEPENDENT_RESTRICTED_VERIFIER_REQUIRED')
        if exact_reads:
            # The installation observer has no application RPC, sequence or
            # future default-read authority. Existing broader profiles retain
            # their historical contract; this is an explicit new profile.
            cursor.execute("""WITH reachable AS (SELECT oid FROM pg_roles WHERE pg_has_role(session_user,oid,'MEMBER'))
              SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN reachable r
              WHERE left(n.nspname,3)<>'pg_' AND n.nspname<>'information_schema' AND
              ((c.relkind IN ('r','p','v','m','f') AND
                (has_table_privilege(r.oid,c.oid,'SELECT') OR has_any_column_privilege(r.oid,c.oid,'SELECT'))
                AND (n.nspname<>'admission_installation' OR c.relname NOT IN ('attempts','migrations')))
               OR c.relkind='S' AND has_sequence_privilege(r.oid,c.oid,'SELECT,USAGE,UPDATE')))
              OR EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace CROSS JOIN reachable r
                WHERE left(n.nspname,3)<>'pg_' AND n.nspname<>'information_schema'
                AND has_function_privilege(r.oid,p.oid,'EXECUTE')
                AND NOT (n.nspname='admission_installation_lock' AND p.proname='describe' AND p.pronargs=0))
              OR EXISTS(SELECT 1 FROM pg_default_acl d CROSS JOIN LATERAL aclexplode(d.defaclacl) a
                WHERE a.grantee=0 OR a.grantee IN (SELECT oid FROM pg_roles WHERE pg_has_role(session_user,oid,'MEMBER')))""")
            if cursor.fetchone()[0]:
                raise ValueError('EXACT_INSTALLATION_READER_REQUIRED')
        return identity


def _grant_installation_reader(cursor, reader):
    """Fixed objects only, inside fresh-015 intent before ledger hashing."""
    from psycopg2 import sql
    cursor.execute('SELECT oid FROM pg_roles WHERE rolname=%s', (reader['session_user'],))
    if cursor.fetchone() != (reader['role_oid'],):
        raise ValueError('INSTALLATION_READER_IDENTITY_CHANGED')
    grantee = sql.Identifier(reader['session_user'])
    cursor.execute(sql.SQL('GRANT USAGE ON SCHEMA admission_installation TO {}').format(grantee))
    cursor.execute(sql.SQL('GRANT SELECT ON admission_installation.attempts,admission_installation.migrations TO {}').format(grantee))
    cursor.execute("""SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      CROSS JOIN LATERAL aclexplode(c.relacl) a WHERE n.nspname='admission_installation'
      AND c.relname IN ('attempts','migrations') AND a.grantee=%s AND a.privilege_type='SELECT'
      AND NOT a.is_grantable""", (reader['role_oid'],))
    if cursor.fetchone()[0] != 2:
        raise ValueError('INSTALLATION_READER_GRANT_CONFLICT')


def verify(backend, candidate, plan, store, attempt_id, authority):
    """Independent read-only observation; no database or assignment state writes."""
    require_authority(authority)
    candidate.revalidate()
    value, binding = _context(candidate, plan, store, attempt_id)
    observed = backend.describe()
    restricted = value.get('migration_profile') == RESTRICTED_PROFILE
    identity = _restricted_verifier(backend, value['target'], exact_reads=restricted)
    if restricted and any(identity[k] != v for k, v in value['installation_reader'].items()):
        raise ValueError('INSTALLATION_READER_IDENTITY_CHANGED')
    if restricted:
        with backend.readonly() as cursor:
            if _lock_capability(cursor, candidate, backend.lock_selection) != value['lock_capability']:
                raise ValueError('LOCK_CAPABILITY_CHANGED')
    binding['verifier_role_oid'] = identity['role_oid']
    _authorize(authority, 'verify', binding, 'preflight')
    prior = backend.attempt(binding['attempt_id'])
    if (prior is None or prior['request_sha256'] != binding['request_sha256'] or prior['stage'] != 'RECEIPTED'
            or prior['receipt'] != _installation_receipt(binding, store, prior)
            or observed['ledger_catalog_sha256'] != prior['ledger_catalog_sha256']
            or observed['catalog_sha256'] != prior['catalog_after']):
        raise ValueError('INSTALLATION_NOT_INDEPENDENTLY_VERIFIABLE')
    _versions(observed, value['sources'], complete=True, preserved=value['preserved_versions'])
    store.verify_release(candidate)
    store.verify_configuration(binding['attempt_id'], value['configuration_sha256'])
    store.verify_receipt(binding['attempt_id'], prior['receipt'])
    _authorize(authority, 'verify', binding, 'return')
    store.verify_release(candidate)
    store.verify_configuration(binding['attempt_id'], value['configuration_sha256'])
    store.verify_receipt(binding['attempt_id'], prior['receipt'])
    fresh = backend.describe()
    fresh_identity = _restricted_verifier(backend, value['target'], exact_reads=restricted)
    if restricted:
        with backend.readonly() as cursor:
            if _lock_capability(cursor, candidate, backend.lock_selection) != value['lock_capability']:
                raise ValueError('LOCK_CAPABILITY_CHANGED')
    if fresh_identity['role_oid'] != identity['role_oid'] or fresh['identity']['role_oid'] != identity['role_oid']:
        raise ValueError('INDEPENDENT_VERIFIER_IDENTITY_CHANGED')
    if (fresh['catalog_sha256'] != observed['catalog_sha256']
            or fresh['ledger_catalog_sha256'] != observed['ledger_catalog_sha256']
            or backend.attempt(binding['attempt_id']) != prior):
        raise ValueError('INSTALLATION_CHANGED_DURING_VERIFICATION')
    receipt = _receipt(binding, 'INDEPENDENTLY_OBSERVED')
    receipt['verifier_role_oid'] = identity['role_oid']
    receipt['runtime_installed'] = prior['receipt']['runtime_installed']
    if isinstance(store, RuntimeCustody):
        receipt.update(namespace_kind=prior['receipt']['namespace_kind'], installation_scope=prior['receipt']['installation_scope'])
    return receipt


def rollback(backend, candidate, plan, store, attempt_id, authority, *, progress=None):
    """Revoke before acquiring any target resources, then record if possible.

    Trusted composition may supply factories for the target connection/journal.
    Request data never supplies executable adapters. Damaged installation targets
    are not dependencies of revocation or journal-only audit recording.
    """
    require_authority(authority)
    value, binding = _plan_binding(plan, attempt_id)
    _authorize(authority, 'rollback', binding, 'revoke')
    if authority.revoke(dict(binding)) is not None:
        raise ValueError('INVALID_INSTALLATION_REVOCATION_RESPONSE')
    try:
        _progress(progress, 'after_revocation')
        backend = backend() if callable(backend) else backend
        store = store() if callable(store) else store
        if isinstance(store, RuntimeCustody):
            store = RuntimeRevocationCustody(store, plan, store.namespace)
        if (not isinstance(store, FileCustody)
                or value['source_commit'] != candidate.source_commit
                or value['manifest_sha256'] != candidate.manifest_sha256):
            raise ValueError('REVOCATION_RECORDING_BINDING_CONFLICT')

        def journal_check():
            with store._root():
                pass
            if isinstance(store, RuntimeRevocationCustody):
                store.validate(plan)
            elif store.binding != value['filesystem']:
                raise ValueError('REVOCATION_JOURNAL_BINDING_CONFLICT')

        journal_check()
        observed = backend.describe()
        _target(observed['identity'], value['target'])
        with backend.fence(), store.fence():
            journal_check()
            prior = backend.attempt(binding['attempt_id'])
            if prior is None or prior['request_sha256'] != binding['request_sha256']:
                raise ValueError('INSTALLATION_ATTEMPT_BINDING_CONFLICT')
            if backend.describe()['ledger_catalog_sha256'] != prior['ledger_catalog_sha256']:
                raise ValueError('REVOCATION_LEDGER_CATALOG_CHANGED')
            _authorize(authority, 'rollback', binding, 'record_revocation')
            if prior['stage'] != 'REVOKED':
                with backend.transaction() as cursor:
                    _lock_tables(cursor, backend=backend, candidate=candidate, plan=value)
                    if backend._catalog(cursor, ('admission_installation',))[0] != prior['ledger_catalog_sha256']:
                        raise ValueError('REVOCATION_LEDGER_CATALOG_CHANGED')
                    _transition(cursor, binding, prior['stage'], 'REVOKED')
            receipt = _receipt(binding, 'REVOKED')
            journal_check()
            store.receipt(binding['attempt_id'], receipt, revoked=True)
            _authorize(authority, 'rollback', binding, 'return')
            journal_check()
            return receipt
    except Exception as error:
        raise InstallationRevokedRecordingFailed(error) from None


class OnlinePostgresAuthority(Authority):
    """Client for a separately administered, pre-existing issuer contract.

    This client never creates issuer schemas, records, roles or grants. Protected
    operator configuration pins its identity and complete user-schema catalog.
    Target installation credentials cannot be used to reach the issuer cluster.
    """
    def __init__(self, connection, selection, *, custody_check=lambda: None):
        if (type(selection) is not dict or set(selection) != {'identity', 'catalog_sha256', 'grant_id'}
                or type(selection['identity']) is not dict
                or set(selection['identity']) != {'system_identifier', 'database_oid', 'database_name', 'session_user', 'role_oid'}
                or not isinstance(selection['catalog_sha256'], str)
                or not SHA256.fullmatch(selection['catalog_sha256'])):
            raise ValueError('EXACT_INSTALLATION_ISSUER_REQUIRED')
        uuid.UUID(selection['grant_id'])
        identity = selection['identity']
        if (any(type(identity[k]) is not str or not identity[k] for k in ('system_identifier', 'database_name', 'session_user'))
                or not identity['system_identifier'].isdigit()
                or any(type(identity[k]) is not int or identity[k] <= 0 for k in ('database_oid', 'role_oid'))):
            raise ValueError('EXACT_INSTALLATION_ISSUER_REQUIRED')
        self._selection = canonical(selection)
        self.backend = PostgresTarget(connection)
        self.custody_check = custody_check

    @property
    def selection(self):
        return json.loads(self._selection)

    def _check(self, cursor, binding):
        self.custody_check()
        selection = self.selection
        identity = self.backend._identity(cursor)
        _target(identity, selection['identity'])
        cursor.execute('SELECT pg_is_in_recovery()')
        if cursor.fetchone()[0] is not False:
            raise ValueError('INSTALLATION_ISSUER_STANDBY_FORBIDDEN')
        if identity['system_identifier'] == binding['target']['system_identifier']:
            raise ValueError('INDEPENDENT_INSTALLATION_ISSUER_CLUSTER_REQUIRED')
        cursor.execute("SELECT nspname FROM pg_namespace WHERE nspname NOT LIKE 'pg\\_%' ESCAPE '\\' AND nspname<>'information_schema' ORDER BY nspname")
        namespaces = [row[0] for row in cursor.fetchall()]
        if ('admission_bootstrap' not in namespaces or _has_writer_capability(cursor, namespaces)
                or self.backend._catalog(cursor, namespaces)[0] != selection['catalog_sha256']):
            raise ValueError('INSTALLATION_ISSUER_CUSTODY_CHANGED')

    @staticmethod
    def _timestamp(value):
        if type(value) is not str:
            raise ValueError('INVALID_INSTALLATION_ISSUER_TIME')
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if result.tzinfo is None:
            raise ValueError('INVALID_INSTALLATION_ISSUER_TIME')
        return result

    def _describe(self, operation, binding, phase, *, revoked=False):
        from psycopg2.extras import Json
        if (operation not in ('install', 'verify', 'rollback') or type(binding) is not dict
                or type(phase) is not str or not 1 <= len(phase) <= 64):
            raise ValueError('INVALID_INSTALLATION_AUTHORITY_REQUEST')
        nonce = str(uuid.uuid4())
        started = time.monotonic()
        with self.backend.readonly() as cursor:
            cursor.execute("SET LOCAL statement_timeout='10s'")
            self._check(cursor, binding)
            cursor.execute('SELECT admission_bootstrap.describe(%s,%s,%s,%s,%s),clock_timestamp()',
                (self.selection['grant_id'], operation, Json(binding), phase, nonce))
            response, observed_at = cursor.fetchone()
            required = {'schema', 'grant_id', 'operation', 'binding', 'phase', 'nonce',
                        'observed_at', 'not_before', 'expires_at', 'revoked_at', 'decision'}
            if (type(response) is not dict or set(response) != required
                    or response['schema'] != 'codestra.admission-authority-response.v1'
                    or response['grant_id'] != self.selection['grant_id']
                    or response['operation'] != operation or response['binding'] != binding
                    or response['phase'] != phase or response['nonce'] != nonce
                    or response['decision'] != 'ALLOWED'
                    or not isinstance(observed_at, datetime) or observed_at.tzinfo is None
                    or abs((self._timestamp(response['observed_at']) - observed_at).total_seconds()) > 5
                    or self._timestamp(response['not_before']) > observed_at
                    or self._timestamp(response['expires_at']) <= observed_at
                    or time.monotonic() - started > 10
                    or operation != 'rollback' and response['revoked_at'] is not None
                    or revoked and response['revoked_at'] is None):
                raise ValueError('INSTALLATION_AUTHORITY_DENIED')
            if response['revoked_at'] is not None and self._timestamp(response['revoked_at']) > observed_at:
                raise ValueError('INVALID_INSTALLATION_REVOCATION')
            self._check(cursor, binding)
            cursor.execute('SELECT clock_timestamp()')
            if (self._timestamp(response['expires_at']) <= cursor.fetchone()[0]
                    or time.monotonic() - started > 10):
                raise ValueError('INSTALLATION_AUTHORITY_EXPIRED_DURING_OBSERVATION')

    def authorize(self, operation, binding, phase):
        self._describe(operation, binding, phase,
            revoked=operation == 'rollback' and phase in ('record_revocation', 'return'))

    def revoke(self, binding):
        from psycopg2.extras import Json
        self._describe('rollback', binding, 'revoke')
        nonce = str(uuid.uuid4())
        with self.backend.transaction() as cursor:
            self._check(cursor, binding)
            cursor.execute('SELECT admission_bootstrap.revoke(%s,%s,%s)',
                (self.selection['grant_id'], Json(binding), nonce))
            response = cursor.fetchone()[0]
            if response != dict(grant_id=self.selection['grant_id'], binding=binding, nonce=nonce, state='REVOKED'):
                raise ValueError('INSTALLATION_REVOCATION_DENIED')
            self._check(cursor, binding)
        # Only a fresh transaction after successful COMMIT can establish this.
        self._describe('rollback', binding, 'record_revocation', revoked=True)


def _request_plan(operation, request, candidate):
    common = {'schema', 'candidate', 'manifest_sha256', 'runtime_selection', 'adopted_sources', 'configuration_sha256'}
    required = common if operation == 'plan' else common | {'plan', 'plan_sha256', 'attempt_id'}
    if (operation not in ('plan', 'install', 'verify', 'rollback') or type(request) is not dict
            or set(request) not in (required, required | {'migration_profile'})
            or request['schema'] != 'codestra.admission-installation-request.v1'
            or request['candidate'] != str(candidate.root)
            or request['manifest_sha256'] != candidate.manifest_sha256
            or type(request['adopted_sources']) is not list
            or type(request['runtime_selection']) is not dict
            or not isinstance(request['configuration_sha256'], str)
            or not SHA256.fullmatch(request['configuration_sha256'])):
        raise ValueError('INVALID_INSTALLATION_REQUEST')
    profile = request.get('migration_profile', 'admission-v1')
    migration_sources(profile)
    if (request['runtime_selection'].get('schema') == 'codestra.admission-runtime-selection.v2'
            and profile != RESTRICTED_PROFILE):
        raise ValueError('CLI_ONLY_REQUIRES_RESTRICTED_TASK_BOOTSTRAP_PROFILE')
    if operation == 'plan':
        return None
    plan = InstallationPlan(canonical(request['plan']))
    if (plan.digest != request['plan_sha256'] or plan.value['adopted_sources'] != sorted(request['adopted_sources'])
            or plan.value.get('migration_profile', 'admission-v1') != profile
            or plan.value['configuration_sha256'] != request['configuration_sha256']
            or plan.value['filesystem'].get('runtime', {}).get('selection_sha256') != digest(canonical(request['runtime_selection']))):
        raise ValueError('INSTALLATION_REQUEST_PLAN_CONFLICT')
    _plan_binding(plan, request['attempt_id'])
    return plan


def dispatch_request(operation, request, candidate, backend, store, *, authority=None, configuration=None):
    """Validated command dispatch; a plan or request never supplies authority."""
    plan = _request_plan(operation, request, candidate)
    if not isinstance(store, RuntimeCustody) or request['runtime_selection'] != store.specification:
        raise ValueError('INVALID_INSTALLATION_REQUEST')
    if operation == 'plan':
        observed = backend.describe()
        PostgresTarget.authenticated(observed['identity'])
        if request.get('migration_profile') == RESTRICTED_PROFILE:
            observed = backend.restricted_observation(candidate, observed)
        plan = build_plan(candidate, observed, adopted_sources=request['adopted_sources'],
            filesystem_binding=store.binding, configuration_sha256=request['configuration_sha256'],
            migration_profile=request.get('migration_profile', 'admission-v1'))
        return dict(state='PLANNED_NOT_AUTHORIZED', plan=plan.value, plan_sha256=plan.digest,
            usable=False, certified=False, install_allowed=False, activation_allowed=False)
    if operation == 'install':
        return install(backend, candidate, plan, store, configuration, request['attempt_id'], authority)
    if operation == 'verify':
        return verify(backend, candidate, plan, store, request['attempt_id'], authority)
    return rollback(backend, candidate, plan, store, request['attempt_id'], authority)


INSTALLER_CONFIG = '/etc/codestra/control-plane/admission-installer.toml'
INSTALLER_CREDENTIALS = {
    'operator': '/etc/codestra/control-plane/credentials/admission-operator.dsn',
    'verifier': '/etc/codestra/control-plane/credentials/lease-verifier.dsn',
    'installation_verifier': '/etc/codestra/control-plane/credentials/admission-verifier.dsn',
    'issuer': '/etc/codestra/control-plane/credentials/admission-issuer.dsn',
}
PRIVATE_INSTALLER_CREDENTIALS = dict(INSTALLER_CREDENTIALS,
    operator='/etc/codestra/control-plane/credentials/pas233-admission-install-20261028-v1/connection.dsn',
    installation_verifier='/etc/codestra/control-plane/credentials/pas233-admission-verify-20261028-v1/connection.dsn')
CONFIGURATION_INPUT = '/etc/codestra/control-plane/admission-configuration.json'


def installer_credential_paths(config, *, restricted):
    """Explicit profile; legacy defaults and publisher custody stay unchanged."""
    if not isinstance(config, dict):
        raise ValueError('INVALID_INSTALLATION_CONFIGURATION')
    private = config.get('schema') == 'codestra.admission-installer-config.v3'
    expected = {'schema', 'issuer'}
    if restricted:
        expected.add('lock_selection')
    if private:
        expected.add('credential_profile')
    if (set(config) != expected or type(config['issuer']) is not dict
            or config['schema'] != 'codestra.admission-installer-config.' + ('v3' if private else 'v2' if restricted else 'v1')
            or private and (not restricted or config['credential_profile'] != 'pas233-private-v1')):
        raise ValueError('INVALID_INSTALLATION_CONFIGURATION')
    return dict(PRIVATE_INSTALLER_CREDENTIALS if private else INSTALLER_CREDENTIALS)


def _protected_input(namespace, path, *, public=False):
    with namespace.parent(path) as (parent, name):
        raw, metadata = _read(parent, name)
        namespace._safe(metadata)
        if stat.S_IMODE(metadata.st_mode) not in ((0o600, 0o644) if public else (0o600,)) or metadata.st_gid != 0:
            raise ValueError('UNTRUSTED_INSTALLATION_INPUT')
        return raw


def connection_parameters(raw):
    """Validate transport before connecting; no ambient libpq identity inputs."""
    from psycopg2.extensions import parse_dsn, libpq_version
    if any(name.startswith('PG') for name in os.environ):
        raise ValueError('INHERITED_POSTGRESQL_ENVIRONMENT_FORBIDDEN')
    if libpq_version() < 160000:
        raise ValueError('EXPLICIT_CLIENT_CERTIFICATE_POLICY_REQUIRES_LIBPQ_16')
    params = parse_dsn(raw.decode().strip())
    allowed = {'host', 'hostaddr', 'port', 'dbname', 'user', 'password', 'sslmode', 'sslrootcert', 'connect_timeout'}
    required = {'host', 'port', 'dbname', 'user', 'password', 'sslmode', 'sslrootcert'}
    if (not required <= set(params) or not set(params) <= allowed or params['sslmode'] != 'verify-full'
            or any(not params[k] for k in required)
            or not params['port'].isdigit() or not 1 <= int(params['port']) <= 65535
            or any(not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]{0,62}', params[k]) for k in ('dbname', 'user'))
            or not params['sslrootcert'].startswith('/etc/codestra/control-plane/')):
        raise ValueError('EXPLICIT_AUTHENTICATED_INSTALLATION_CONNECTION_REQUIRED')
    try:
        ipaddress.ip_address(params['host'])
    except ValueError:
        if not re.fullmatch(r'(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', params['host']):
            raise ValueError('TCP_INSTALLATION_CONNECTION_REQUIRED') from None
    if 'hostaddr' in params:
        try:
            ipaddress.ip_address(params['hostaddr'])
        except ValueError:
            raise ValueError('TCP_INSTALLATION_CONNECTION_REQUIRED') from None
    params.update(connect_timeout='10', options='-csearch_path=pg_catalog,pg_temp',
        application_name='codestra-admission-installer', sslcertmode='disable',
        require_auth='scram-sha-256', channel_binding='require', ssl_min_protocol_version='TLSv1.2',
        sslcert='/dev/null', sslkey='/dev/null', passfile='/dev/null',
        target_session_attrs='read-write', gssencmode='disable')
    return params


def run_configured(operation, request):
    """Fixed host composition, unavailable until separately provisioned/accepted.

    No arguments or environment variables select credentials or load code.
    Restricted-profile plans also authenticate the dedicated installation reader.
    """
    if not sys.flags.isolated or not sys.dont_write_bytecode:
        raise ValueError('ISOLATED_NON_BYTECODE_INSTALLER_REQUIRED')
    namespace = RuntimeNamespace('/')
    config_raw = _protected_input(namespace, INSTALLER_CONFIG)
    config = tomllib.loads(config_raw.decode())
    restricted = request.get('migration_profile') == RESTRICTED_PROFILE
    installer_credential_paths(config, restricted=restricted)
    candidate = SourceCandidate.load(request['candidate'], request['manifest_sha256'])
    # The code being executed is part of the same accepted candidate. Verifying
    # candidate bytes alone cannot make a different executing module trusted.
    if Path(__file__).resolve() != candidate.root / 'lib/codestra_control/admission_installation.py':
        raise ValueError('EXECUTING_INSTALLER_CANDIDATE_CONFLICT')
    for name, mode in candidate.modes.items():
        namespace.read(str(candidate.root / name), mode=mode, gid=0)
    namespace.read(str(candidate.root / MANIFEST), mode=0o644, gid=0)
    return _configured_connections(operation, request, candidate, namespace, config_raw, config)


def _installation_journal():
    return FileCustody('/var/lib/codestra-control-plane/admission-installation', owner_uid=0)


def _configured_connections(operation, request, candidate, namespace, config_raw, config):
    """Compose protected resources after the native host/source guard.

    Fixed-path I/O is kept separate from host identity validation so disposable
    fixtures can exercise ordering without weakening the operational guard.
    """
    plan = _request_plan(operation, request, candidate)
    restricted = request.get('migration_profile') == RESTRICTED_PROFILE
    credential_paths = installer_credential_paths(config, restricted=restricted)
    if (config['schema'] == 'codestra.admission-installer-config.v3'
            and request['runtime_selection'].get('schema') != 'codestra.admission-runtime-selection.v2'):
        raise ValueError('PRIVATE_INSTALLER_REQUIRES_EXPLICIT_CLI_ONLY_RUNTIME_SELECTION')
    execution = RuntimeExecution(candidate, request['runtime_selection'], namespace)
    snapshots = {INSTALLER_CONFIG: config_raw}

    def custody_check():
        candidate.revalidate()
        execution.verify()
        for path, raw in snapshots.items():
            if _protected_input(namespace, path, public=path not in (INSTALLER_CONFIG, CONFIGURATION_INPUT, *credential_paths.values())) != raw:
                raise ValueError('INSTALLATION_CONNECTION_CUSTODY_CHANGED')

    def connection(role, stack):
        if namespace.is_host:
            execution.verify_process()
        import psycopg2
        if namespace.is_host:
            execution.verify_process(require_driver=True)
        path = credential_paths[role]
        if path != INSTALLER_CREDENTIALS[role]:
            with namespace.parent(path) as (parent, _):
                metadata = os.fstat(parent)
                if stat.S_IMODE(metadata.st_mode) != 0o700 or metadata.st_gid != (0 if namespace.is_host else os.getegid()):
                    raise ValueError('PRIVATE_INSTALLER_CREDENTIAL_PARENT_REQUIRED')
        raw = _protected_input(namespace, path)
        snapshots[path] = raw
        params = connection_parameters(raw)
        if namespace.is_host:
            execution.verify_process(require_driver=True)
        snapshots[params['sslrootcert']] = _protected_input(namespace, params['sslrootcert'], public=True)
        result = psycopg2.connect(**params)
        stack.callback(result.close)
        return result

    with ExitStack() as stack:
        if operation == 'rollback':
            authority = OnlinePostgresAuthority(connection('issuer', stack), config['issuer'], custody_check=custody_check)
            custody_check()

            def target():
                return PostgresTarget(connection('operator', stack), lock_selection=config.get('lock_selection'))

            def journal():
                custody = _installation_journal()
                return RuntimeRevocationCustody(custody, plan, namespace)

            result = rollback(target, candidate, plan, journal, request['attempt_id'], authority)
            try:
                custody_check()
            except Exception as error:
                raise InstallationRevokedRecordingFailed(error) from None
            return result
        journal = _installation_journal()
        store = RuntimeCustody(journal, candidate, request['runtime_selection'], namespace)
        restricted = request.get('migration_profile') == RESTRICTED_PROFILE
        observer = 'installation_verifier' if restricted else 'verifier'
        target = PostgresTarget(connection(observer if operation == 'verify' else 'operator', stack),
            lock_selection=config.get('lock_selection'))
        if restricted and operation in ('plan', 'install'):
            target.reader = PostgresTarget(connection('installation_verifier', stack))
        authority = None
        configuration = None
        if operation != 'plan':
            authority = OnlinePostgresAuthority(connection('issuer', stack), config['issuer'], custody_check=custody_check)
        if operation == 'install':
            configuration = _protected_input(namespace, CONFIGURATION_INPUT)
            snapshots[CONFIGURATION_INPUT] = configuration
        custody_check()
        result = dispatch_request(operation, request, candidate, target, store,
            authority=authority, configuration=configuration)
        custody_check()
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description='Admission installer; protected operational configuration required.')
    commands = parser.add_subparsers(dest='operation', required=True)
    preflight = commands.add_parser('preflight')
    preflight.add_argument('--candidate', required=True)
    preflight.add_argument('--manifest-sha256', required=True)
    for name in ('plan', 'install', 'verify', 'rollback'):
        command = commands.add_parser(name)
        command.add_argument('--request')
        command.add_argument('--request-sha256')
    args = parser.parse_args(argv)
    try:
        if args.operation != 'preflight':
            if not args.request or not isinstance(args.request_sha256, str) or not SHA256.fullmatch(args.request_sha256):
                raise ValueError('EXACT_INSTALLATION_REQUEST_REQUIRED')
            request_path = Path(args.request).absolute()
            with _directory(request_path.parent) as fd:
                raw, _ = _read(fd, request_path.name)
            if digest(raw) != args.request_sha256:
                raise ValueError('INSTALLATION_REQUEST_DIGEST_MISMATCH')
            request = json.loads(raw, object_pairs_hook=_unique)
            print(json.dumps(run_configured(args.operation, request), sort_keys=True))
            return 0
        candidate = SourceCandidate.load(args.candidate, args.manifest_sha256)
        print(json.dumps({'state': 'SOURCE_VALIDATED', 'source_commit': candidate.source_commit,
                          'manifest_sha256': candidate.manifest_sha256, 'usable': False,
                          'certified': False, 'install_allowed': False}))
        return 0
    except InstallationRevokedRecordingFailed as error:
        print(json.dumps(dict(state='REVOKED_RECORDING_INCOMPLETE', issuer_revocation='CONFIRMED',
            target_recording=error.recording_outcome, usable=False, certified=False, activation_allowed=False)))
        return 1
    except InstallationOutcomeUnknown:
        print(json.dumps(dict(state='WRITE_OUTCOME_UNKNOWN_INSPECT_SAME_ATTEMPT',
            usable=False, certified=False, activation_allowed=False)))
        return 1
    except Exception:
        print('ADMISSION_INSTALLATION_UNAVAILABLE' if args.operation == 'preflight'
              else 'ADMISSION_INSTALLATION_OPERATIONALLY_UNAVAILABLE')
        return 1
