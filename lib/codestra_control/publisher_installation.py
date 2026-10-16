"""Stage a reviewable proposal from committed templates; never install or run it.

The output is a new private local directory. It contains no credentials, service
actions, database provisioner, token issuer or authority acceptance mechanism.
"""
import hashlib
import json
from pathlib import Path
import re

from .publisher_release import git


TEMPLATES = (
    'config/examples/authenticated-publisher.toml',
    'config/examples/producer-acceptance.json',
    'config/examples/certifier-observer.proposed.toml',
    'config/examples/publisher-certifier-action-time-approval.json',
)


def prepare_installation_packet(root, source_sha, output):
    """Copy only fixed Git blobs into a new proposal directory, without effects."""
    if not re.fullmatch(r'[0-9a-f]{40}', source_sha):
        raise ValueError('EXACT_SOURCE_SHA_REQUIRED')
    if git(root, 'rev-parse', source_sha + '^{commit}').decode().strip() != source_sha:
        raise ValueError('EXACT_COMMIT_REQUIRED')
    entries = {}
    for path in TEMPLATES:
        raw = git(root, 'ls-tree', '-z', source_sha, '--', path)
        if not raw:
            raise ValueError('INCOMPLETE_PROPOSAL_TEMPLATES')
        metadata, observed_path = raw.rstrip(b'\0').split(b'\t', 1)
        mode, kind, oid = metadata.decode().split()
        if mode != '100644' or kind != 'blob' or observed_path.decode() != path:
            raise ValueError('UNSAFE_TEMPLATE_ENTRY')
        entries[path] = git(root, 'cat-file', 'blob', oid)
    output = Path(output)
    output.mkdir(mode=0o700)  # Refuse an existing path, including a symlink.
    manifest = {
        'schema': 'codestra.publisher-installation-packet.v1',
        'source_commit': source_sha,
        'state': 'PROPOSED',
        'install_allowed': False,
        'activation_allowed': False,
        'database_setup_approved': False,
        'files': [],
    }
    for path, data in entries.items():
        destination = output / path
        for parent in (output / 'config', output / 'config/examples'):
            parent.mkdir(mode=0o700, exist_ok=True)
        with destination.open('xb') as stream:
            destination.chmod(0o600)
            stream.write(data)
        manifest['files'].append({'path': path, 'sha256': hashlib.sha256(data).hexdigest(),
                                  'size': len(data), 'mode': '0600'})
    manifest_path = output / 'installation-packet-manifest.json'
    with manifest_path.open('x') as stream:
        manifest_path.chmod(0o600)
        stream.write(json.dumps(manifest, indent=2) + '\n')
    return manifest
