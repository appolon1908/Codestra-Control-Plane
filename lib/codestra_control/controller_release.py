"""Prepare a distinct complete controller source candidate; never install it.

The publisher-only packager and its historical candidates keep their scope.
Schema files are reviewed source artifacts, not an automatic migration plan.
"""
import hashlib
import ast
import json
from pathlib import Path
import re
import tomllib

from .publisher_installation import TEMPLATES
from .publisher_release import git, prepare_release


CONTROLLER_ENTRYPOINTS = (
    'bin/codestra-coordinate', 'bin/codestra-admission',
    'bin/codestra-register', 'bin/codestra-inspect-atomic',
)
REQUIRED_LIBRARIES = tuple('lib/codestra_control/' + name + '.py' for name in (
    '__init__', 'controller_coordinator', 'scoped_admission', 'certifier_adapter',
    'certifier_observer', 'lease_materialization', 'admission_materialization',
    'publisher_startup','atomic_receipts','atomic_issuer',
))
SCHEMA_SOURCES = (
    'schema.sql', '002-hierarchy-promotion.sql', '003-readiness-views.sql',
    '004-family-programs.sql', '005-scoped-registration.sql',
    '006-publisher-authority-read-model.sql', '007-assignment-leases.sql',
    '008-frozen-recovery.sql', '009-atomic-inspection.sql',
    '009-controller-coordinator.sql', '010-controller-coordinator-integration.sql',
    '010-scoped-operation-admission.sql', '011-certifier-authority.sql',
    '012-scope-assignment-leases.sql', '013-first-certification-pending.sql',
    '014-atomic-inclusion-receipts.sql',
)
CONFIGURATION_SOURCES = TEMPLATES + ('config/examples/lease-verifier.proposed.toml',
    'config/examples/atomic-inclusion-acceptance.proposed.json','config/examples/global-coverage.proposed.json',
    'config/examples/atomic-authority.proposed.json')
CONTRACT_SOURCES = (
    'docs/assignment-backed-leases.md', 'docs/controller-coordinator.md',
    'docs/scoped-operation-admission.md', 'docs/certifier-existing-receipt-source.md',
    'docs/publisher-certifier-action-time-approval.md',
    'docs/atomic-inclusion-receipts.md','docs/global-controller-coverage.md',
    'config/contracts/global-coverage-acceptance.schema.json',
)
EXCLUDED_LEGACY_WRITERS = (
    'bin/codestra-certify-scope', 'bin/codestra-section-certify', 'bin/codestra-devctl',
)
SCHEMA_PREREQUISITES = {
    'schema.sql': (), '002-hierarchy-promotion.sql': ('schema.sql',),
    '003-readiness-views.sql': ('002-hierarchy-promotion.sql',),
    '004-family-programs.sql': ('002-hierarchy-promotion.sql',),
    '005-scoped-registration.sql': ('002-hierarchy-promotion.sql',),
    '006-publisher-authority-read-model.sql': ('002-hierarchy-promotion.sql',),
    '007-assignment-leases.sql': ('005-scoped-registration.sql',),
    '008-frozen-recovery.sql': ('005-scoped-registration.sql','007-assignment-leases.sql'),
    '009-atomic-inspection.sql': ('005-scoped-registration.sql','007-assignment-leases.sql'),
    '009-controller-coordinator.sql': ('007-assignment-leases.sql',),
    '010-controller-coordinator-integration.sql': ('009-atomic-inspection.sql','009-controller-coordinator.sql'),
    '010-scoped-operation-admission.sql': ('005-scoped-registration.sql','007-assignment-leases.sql','009-controller-coordinator.sql'),
    '011-certifier-authority.sql': ('002-hierarchy-promotion.sql',),
    '012-scope-assignment-leases.sql': ('002-hierarchy-promotion.sql','005-scoped-registration.sql'),
    '013-first-certification-pending.sql': ('011-certifier-authority.sql','012-scope-assignment-leases.sql'),
    '014-atomic-inclusion-receipts.sql': ('005-scoped-registration.sql','007-assignment-leases.sql',
        '009-controller-coordinator.sql','011-certifier-authority.sql','013-first-certification-pending.sql'),
}


def _blob(root, source_sha, path, *, executable=False):
    raw = git(root, 'ls-tree', '-z', source_sha, '--', path)
    if not raw:
        raise ValueError('INCOMPLETE_CONTROLLER_PACKAGE: ' + path)
    metadata, observed = raw.rstrip(b'\0').split(b'\t', 1)
    mode, kind, oid = metadata.decode().split()
    expected_mode = '100755' if executable else '100644'
    if mode != expected_mode or kind != 'blob' or observed.decode() != path:
        raise ValueError('UNSAFE_CONTROLLER_PACKAGE_ENTRY: ' + path)
    return int(mode[-3:], 8), git(root, 'cat-file', 'blob', oid)


def _proposal(path, data):
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result: raise ValueError('DUPLICATE_CONTROLLER_PROPOSAL_KEY')
            result[key]=value
        return result
    value = json.loads(data,object_pairs_hook=unique) if path.endswith('.json') else tomllib.loads(data.decode())
    if not isinstance(value, dict):
        raise ValueError('INVALID_CONTROLLER_PROPOSAL')
    if 'state' in value and value['state'] != 'PROPOSED':
        raise ValueError('ACTIVE_AUTHORITY_NOT_A_SOURCE_TEMPLATE')
    # These are examples only. Packaging cannot grant an operational approval.
    def check(item):
        if isinstance(item, dict):
            for key, child in item.items():
                if (key.endswith('_approved') or key in ('install_allowed', 'activation_allowed')) and child is not False:
                    raise ValueError('ACTIVE_APPROVAL_NOT_A_SOURCE_TEMPLATE')
                if (key in ('created','app_created','account_created','install_authorized') or key.endswith('_created')) and child is not False:
                    raise ValueError('ACTIVE_IDENTITY_NOT_A_SOURCE_TEMPLATE')
                if key in ('PRODUCTION_GO','LIVE_CAPABILITIES_ENABLED') and child != 'NO':
                    raise ValueError('LIVE_CAPABILITY_NOT_A_SOURCE_TEMPLATE')
                if key in ('EXTERNAL_EFFECTS','production_go','live_capabilities_enabled','external_effects') and child is not False:
                    raise ValueError('LIVE_CAPABILITY_NOT_A_SOURCE_TEMPLATE')
                if (key in ('app_id','installation_id','accepted_role_oid') or key.endswith(('_app_id','_installation_id'))):
                    if type(child) is not int or child != 0:
                        raise ValueError('ACTIVE_IDENTITY_NOT_A_SOURCE_TEMPLATE')
                if key=='state' and child in ('ACCEPTED','ACTIVE'):
                    raise ValueError('ACTIVE_AUTHORITY_NOT_A_SOURCE_TEMPLATE')
                check(child)
        elif isinstance(item, list):
            for child in item:
                check(child)
    check(value)


def _validate_import_closure(root,source_sha,entrypoints):
    """Inspect internal imports without executing candidate code or Git filters."""
    names=git(root,'ls-tree','-r','--name-only',source_sha).decode().splitlines()
    modules={}
    for name in names:
        if name.startswith('lib/') and name.endswith('.py'):
            _,data=_blob(root,source_sha,name)
            module=name.removeprefix('lib/').removesuffix('.py').replace('/','.')
            if module.endswith('.__init__'): module=module.removesuffix('.__init__')
            modules[module]=(name,data)
    sources=list(modules.items())+[(None,(path,_blob(root,source_sha,path,executable=True)[1])) for path in entrypoints]
    for module,(path,data) in sources:
        try: tree=ast.parse(data,filename=path)
        except (SyntaxError,UnicodeError): raise ValueError('INVALID_CONTROLLER_PYTHON_SOURCE: '+path) from None
        for node in ast.walk(tree):
            imports=[]
            if isinstance(node,ast.Import): imports=[alias.name for alias in node.names]
            elif isinstance(node,ast.ImportFrom):
                if node.level:
                    package=(module or '').split('.')[:-1]
                    if path.endswith('/__init__.py'): package=(module or '').split('.')
                    prefix=package[:len(package)-node.level+1]
                    target='.'.join(prefix+([node.module] if node.module else []))
                    imports=[target] if node.module else [target+'.'+alias.name for alias in node.names]
                elif node.module:
                    imports=[node.module]
                    if node.module=='codestra_control': imports.extend(node.module+'.'+alias.name for alias in node.names)
            for target in imports:
                if target=='codestra_control' or target.startswith('codestra_control.'):
                    if target not in modules: raise ValueError('INCOMPLETE_CONTROLLER_IMPORT: '+path+' -> '+target)


def prepare_controller_release(root, source_sha, output, driver_wheel):
    """Stage only exact committed, reviewed kinds; all operational gates stay false."""
    if not re.fullmatch(r'[0-9a-f]{40}', source_sha):
        raise ValueError('EXACT_SOURCE_SHA_REQUIRED')
    if git(root, 'rev-parse', source_sha + '^{commit}').decode().strip() != source_sha:
        raise ValueError('EXACT_COMMIT_REQUIRED')
    additions = {}
    for path in CONTROLLER_ENTRYPOINTS:
        additions[path] = _blob(root, source_sha, path, executable=True)
    for path in SCHEMA_SOURCES + CONFIGURATION_SOURCES + CONTRACT_SOURCES:
        additions[path] = _blob(root, source_sha, path)
        if path in CONFIGURATION_SOURCES:
            _proposal(path, additions[path][1])
    for path in REQUIRED_LIBRARIES:
        _blob(root, source_sha, path)
    _validate_import_closure(root,source_sha,CONTROLLER_ENTRYPOINTS)
    # Complete preflight precedes any output; the old packager validates the
    # pinned driver/tools and refuses existing or symlinked output directories.
    output = Path(output)
    publisher = prepare_release(root, source_sha, output, driver_wheel)
    files = list(publisher['files'])
    runtime_root = publisher['proposed_runtime_root']
    for path, (mode, data) in additions.items():
        destination = output / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open('xb') as stream:
            stream.write(data)
        destination.chmod(mode)
        kind = ('entrypoint' if path in CONTROLLER_ENTRYPOINTS else
                'schema_source' if path in SCHEMA_SOURCES else
                'proposed_configuration' if path in CONFIGURATION_SOURCES else 'contract')
        files.append({'source_path': path, 'sha256': hashlib.sha256(data).hexdigest(),
                      'size': len(data), 'mode': oct(mode), 'kind': kind,
                      'proposed_target': None if kind == 'proposed_configuration' else runtime_root + '/' + path})
    manifest = {
        'schema': 'codestra.controller-candidate.v1', 'source_commit': source_sha,
        'proposed_runtime_root': runtime_root, 'release_approved': False,
        'install_allowed': False, 'activation_allowed': False,
        'database_setup_approved': False, 'authority_provisioning_approved': False,
        'publisher_component_manifest': 'release-manifest.json',
        'publisher_component_manifest_sha256': hashlib.sha256((output / 'release-manifest.json').read_bytes()).hexdigest(),
        'files': sorted(files, key=lambda item: item['source_path']),
        'driver_artifact': publisher['driver_artifact'], 'runtime': publisher['runtime'],
        'schema_sources': list(SCHEMA_SOURCES),
        'schema_contracts': [{'source':path,'sha256':hashlib.sha256(additions[path][1]).hexdigest(),
            'requires_reviewed_sources':list(SCHEMA_PREREQUISITES[path]),'target_compatibility_verified':False,
            'automatic_application_allowed':False} for path in SCHEMA_SOURCES],
        'schema_execution_policy': 'SOURCE_ONLY; no automatic DDL. Accept compatibility and exact migration prerequisites separately.',
        'configuration_templates': list(CONFIGURATION_SOURCES),
        'excluded_legacy_writer_entrypoints': list(EXCLUDED_LEGACY_WRITERS),
        'protected_code_custody': publisher['code_custody'],
        'certifier_source_api': 'codestra_control.certifier_adapter.build_first_certifier_service',
        'atomic_issuer_source_api': 'codestra_control.atomic_issuer.build_atomic_issuer_service',
        'global_coverage': 'structural acceptance specification only; no activated global consumer',
        'unmet_gates': ['independent exact-commit source review and governed publication',
                        'accepted operator, identities, custody, explicit per-product grants and real leases',
                        'accepted immutable installation, private recovery capture and fresh maintenance exclusion',
                        'separate actual provider/certifier capability and complete canonical receipt evidence'],
    }
    with (output / 'controller-release-manifest.json').open('x') as stream:
        json.dump(manifest, stream, indent=2)
        stream.write('\n')
    return manifest
