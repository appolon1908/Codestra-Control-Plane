"""Prepare a pinned, non-installable candidate from committed source only."""
import hashlib
import json
import platform
from pathlib import Path
import re
import subprocess

ENTRYPOINTS = ('bin/codestra-github-statusd', 'bin/codestra-github-check',
               'legacy/bin/github-status-sync', 'requirements-publisher.txt', 'runtime-publisher-tools.json', 'bin/codestra-lease')


def git(root, *args):
    return subprocess.run(['git', '-C', str(root), *args], check=True,
                          capture_output=True).stdout


def prepare_release(root, source_sha, output, driver_wheel):
    if not re.fullmatch(r'[0-9a-f]{40}', source_sha):
        raise ValueError('EXACT_SOURCE_SHA_REQUIRED')
    if git(root, 'rev-parse', source_sha + '^{commit}').decode().strip() != source_sha:
        raise ValueError('EXACT_COMMIT_REQUIRED')
    entries = {}
    for raw in git(root, 'ls-tree', '-r', '-z', source_sha).split(b'\0'):
        if not raw:
            continue
        metadata, raw_path = raw.split(b'\t', 1)
        path = raw_path.decode()
        mode, kind, oid = metadata.decode().split()
        if path in ENTRYPOINTS or path.startswith('lib/') and path.endswith('.py'):
            if mode not in ('100644', '100755') or kind != 'blob':
                raise ValueError('UNSAFE_PACKAGE_ENTRY')
            if any(part in ('', '.', '..') for part in Path(path).parts):
                raise ValueError('UNSAFE_PACKAGE_PATH')
            entries[path] = (int(mode[-3:], 8), git(root, 'cat-file', 'blob', oid))
    if not set(ENTRYPOINTS) <= entries.keys() or 'lib/codestra_control/publisher_ownership.py' not in entries:
        raise ValueError('INCOMPLETE_RUNTIME_PACKAGE')
    requirement = entries['requirements-publisher.txt'][1].decode()
    lines = [line for line in requirement.splitlines() if line and not line.startswith('#')]
    match = re.fullmatch(r'psycopg2-binary==2\.9\.10 --hash=sha256:([0-9a-f]{64})', lines[0]) if len(lines) == 1 else None
    wheel_bytes = Path(driver_wheel).read_bytes()
    wheel_sha = hashlib.sha256(wheel_bytes).hexdigest()
    if match is None or match[1] != wheel_sha:
        raise ValueError('DRIVER_HASH_MISMATCH')
    tools=json.loads(entries['runtime-publisher-tools.json'][1])
    if tools.get('schema')!='codestra.publisher-system-tools.v1' or tools.get('target_verified') is not False or tools.get('provisioning_approved') is not False:
        raise ValueError('INVALID_SYSTEM_TOOL_REQUIREMENTS')
    output = Path(output)
    output.mkdir(mode=0o700)  # Refuse overwrites, including an existing symlink.
    manifest = {'schema': 'codestra.publisher-candidate.v1', 'source_commit': source_sha,
                'release_approved': False, 'install_allowed': False, 'activation_allowed': False,
                'lock_provisioning': {'directory': '/run/codestra-control-plane', 'directory_owner': 'root',
                                     'directory_group': 'sentinelx', 'directory_mode': '0750',
                                     'file': '/run/codestra-control-plane/publisher.lock', 'file_owner': 'root',
                                     'file_group': 'sentinelx', 'file_mode': '0640', 'approved': False},
                'cutover_requires': ['both enabled publisher timers paused', 'both writer services verified stopped',
                                    'unused alias verified stopped', 'rollback backup verified before any installed write'],
                'designated_service': 'codestra-control-plane-status.service',
                'contexts': ['codestra-control-plane', 'codestra/control-plane'],
                'code_custody': {'required_owner': 'root', 'group_writable': False, 'other_writable': False, 'target_verified': False, 'provisioning_approved': False, 'isolated_imports_required': True, 'bytecode_and_site_packages_custody_required': True},
                'runtime': {'python': 'CPython3.12', 'platform': 'Linux x86_64',
                            'builder_python_version': platform.python_version(),
                            'target_interpreter_verified': False, 'target_driver_import_verified': False,
                            'system_tools': tools, 'driver': 'psycopg2-binary2.9.10', 'driver_installation_approved': False},
                'unmet_gates': ['governed dependency integration and candidate exact-head review',
                                'candidate independent review and governed promotion',
                                'accepted operator startup configuration, credential custody and actual issuer identities',
                                'registered bindings and genuine owned leases',
                                'separate installation/cutover approval'], 'files': []}
    for path, (mode, data) in sorted(entries.items()):
        destination = output / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        destination.chmod(mode)
        target = ('/opt/codestra-dev/control-plane/bin/github-status-sync'
                  if path.startswith('legacy/') else '/srv/codestra/dev-platform/control-plane/' + path)
        manifest['files'].append({'source_path': path, 'sha256': hashlib.sha256(data).hexdigest(),
                                  'size': len(data), 'mode': oct(mode), 'proposed_target': target})
    wheel_path = output / 'vendor/psycopg2_binary-2.9.10-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl'
    wheel_path.parent.mkdir()
    wheel_path.write_bytes(wheel_bytes)
    manifest['driver_artifact'] = {'path': str(wheel_path.relative_to(output)), 'sha256': wheel_sha,
                                   'size': len(wheel_bytes), 'proposed_target': None}
    (output / 'release-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest
