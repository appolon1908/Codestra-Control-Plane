"""Independent, read-only observations for scoped source and push admissions.

The description comes from the authenticated admission API. This observer neither
creates grants nor executes mutations/pushes. Observations are bounded snapshots,
not an atomic fence against subsequent filesystem or remote changes.
"""
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import uuid

from .lease_materialization import GitMaterializer, MaterializationDenied, machine_identity, require
from .policy import valid_ref
from .publisher_startup import verify_system_tools


def _path_name(value):
    require(isinstance(value, str) and bool(value)
            and all(re.fullmatch(r'[A-Za-z0-9_.-]+', part)
                    and part not in ('.', '..', '.git') for part in value.split('/')),
            'INVALID_ADMISSION_PATH')
    return value


def _paths(value, *, empty=False):
    require(type(value) is list and (empty or bool(value)), 'INVALID_ADMISSION_PATHS')
    for item in value:
        _path_name(item)
    require(value == sorted(set(value)), 'INVALID_ADMISSION_PATHS')
    return set(value)


def _sha(value, size=40):
    require(isinstance(value, str) and bool(re.fullmatch('[0-9a-f]{' + str(size) + '}', value))
            and value != '0' * size, 'INVALID_ADMISSION_DIGEST')


class StageMaterializer(GitMaterializer):
    """Reuse hardened Git/path primitives without relaxing baseline verification."""

    def _validate(self, description):
        require(type(description) is dict and description['operation'] in ('L1', 'L2'),
                'INVALID_ADMISSION_DESCRIPTION')
        for value in (description['intent_id'], description['lease']['lease_id']):
            require(isinstance(value, str) and str(uuid.UUID(value)) == value,
                    'INVALID_ADMISSION_ID')
        _sha(description['request_digest'], 64)
        lease = description['lease']
        require(type(lease['epoch']) is int and lease['epoch'] > 0
                and type(lease['directory_device']) is int and lease['directory_device'] >= 0
                and type(lease['directory_inode']) is int and lease['directory_inode'] > 0,
                'INVALID_ADMISSION_LEASE')
        b = description['binding']
        require(type(b['worktree_uid']) is int and b['worktree_uid'] >= 0
                and type(b['repository_id']) is int and b['repository_id'] > 0,
                'INVALID_MATERIALIZATION_BINDING')
        require(bool(re.fullmatch('[A-Za-z0-9-]+/[A-Za-z0-9_.-]+', b['repository']))
                and all(valid_ref(b[k]) for k in ('source_ref', 'target_ref')),
                'INVALID_MATERIALIZATION_BINDING')
        for field in ('head_sha', 'base_sha'):
            _sha(b[field])
        grant_paths = _paths(description['grant']['paths'])
        payload = description['payload']
        require(type(payload) is dict and type(description['dependencies']) is list,
                'INVALID_ADMISSION_DESCRIPTION')
        require(_paths(payload['paths']) <= grant_paths, 'ADMISSION_SCOPE_MISMATCH')
        if description['operation'] == 'L1':
            require(set(payload) == {'paths', 'mutation_sha256'}, 'INVALID_ADMISSION_PAYLOAD')
            _sha(payload['mutation_sha256'], 64)
        else:
            require(set(payload) == {'paths', 'candidate_sha', 'candidate_tree_sha',
                                    'expected_remote_sha', 'target_base_sha'},
                    'INVALID_ADMISSION_PAYLOAD')
            for field in set(payload) - {'paths'}:
                _sha(payload[field])
            require(payload['expected_remote_sha'] == b['head_sha']
                    and payload['target_base_sha'] == b['base_sha'], 'ADMISSION_BASE_MISMATCH')
        return b, grant_paths

    def _identity(self, b, path):
        self._repository_safety(path)
        require(self._git(path, 'rev-parse', '--show-toplevel') == str(path), 'WORKTREE_ROOT_MISMATCH')
        require(self._git(path, 'symbolic-ref', '--short', 'HEAD') == b['source_ref'], 'BRANCH_MISMATCH')
        common = Path(self._git(path, 'rev-parse', '--path-format=absolute', '--git-common-dir'))
        require(str(common) == b['git_common_dir'], 'COMMON_GIT_DIRECTORY_MISMATCH')
        self._path(common, b['worktree_uid'])
        require(not os.path.lexists(common / 'info' / 'grafts')
                and self._git(path, 'rev-parse', '--is-shallow-repository') == 'false',
                'INCOMPLETE_MATERIALIZATION_HISTORY')
        require(self._git(path, 'remote', 'get-url', 'origin') in (
            'https://github.com/' + b['repository'] + '.git',
            'git@github.com:' + b['repository'] + '.git'), 'ORIGIN_REPOSITORY_MISMATCH')
        require(not self._git(path, 'config', '--get-regexp', '^filter\\.', allowed=(0, 1)),
                'UNSUPPORTED_REPOSITORY_FILTER')

    def _tree(self, path, commit):
        entries = {}
        for entry in self._git(path, 'ls-tree', '-r', '-z', '--full-tree', commit).split('\0'):
            if not entry:
                continue
            header, name = entry.split('\t', 1)
            mode, kind, digest = header.split()
            _path_name(name)
            require(mode in ('100644', '100755') and kind == 'blob', 'UNSUPPORTED_MATERIALIZATION_ENTRY')
            _sha(digest)
            require(name not in entries, 'UNSUPPORTED_MATERIALIZATION_ENTRY')
            entries[name] = (mode, digest)
        return entries

    def _history(self, path, baseline, head, deadline):
        self._git(path, 'merge-base', '--is-ancestor', baseline, head)
        self._tree(path, baseline)
        commits = self._git(path, 'rev-list', baseline + '..' + head).splitlines()
        require(len(commits) <= 1024, 'MATERIALIZATION_LIMIT')
        changed = set()
        for commit in commits:
            require(time.monotonic() < deadline, 'MATERIALIZATION_LIMIT')
            _sha(commit)
            self._tree(path, commit)
            parents = self._git(path, 'rev-list', '--parents', '-n', '1', commit).split()[1:]
            for parent in parents or [None]:
                require(time.monotonic() < deadline, 'MATERIALIZATION_LIMIT')
                # Disable rename collapsing: both old and new names belong to scope.
                comparison = (parent, commit) if parent is not None else ('--root', commit)
                names = self._git(path, 'diff-tree', '-r', '--no-commit-id', '--name-only',
                                  '-z', '--no-renames', '--no-ext-diff', '--no-textconv',
                                  *comparison, '--')
                changed.update(_path_name(name) for name in names.split('\0') if name)
        return changed

    def _index(self, path):
        entries = {}
        for entry in self._git(path, 'ls-files', '--stage', '-z').split('\0'):
            if not entry:
                continue
            header, name = entry.split('\t', 1)
            mode, digest, stage = header.split()
            _path_name(name)
            require(stage == '0' and mode in ('100644', '100755') and name not in entries,
                    'UNSUPPORTED_MATERIALIZATION_ENTRY')
            _sha(digest)
            entries[name] = (mode, digest)
        return entries

    def _files(self, path, index, uid, deadline):
        entries = {}
        total = 0
        def failed(error):
            raise error
        for directory, dirs, files in os.walk(path, followlinks=False, onerror=failed):
            require(time.monotonic() < deadline, 'MATERIALIZATION_LIMIT')
            if Path(directory) == path:
                dirs[:] = [name for name in dirs if name != '.git']
                files = [name for name in files if name != '.git']
            for name in dirs:
                item = Path(directory) / name
                _path_name(str(item.relative_to(path)))
                info = item.lstat()
                require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, uid)
                        and not info.st_mode & 0o022, 'UNTRUSTED_MATERIALIZATION_DIRECTORY')
            for name in files:
                item = Path(directory) / name
                relative = _path_name(str(item.relative_to(path)))
                info = item.lstat()
                require(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o7000
                        and info.st_uid in (0, uid), 'UNSUPPORTED_MATERIALIZATION_ENTRY')
                mode = '100755' if info.st_mode & 0o111 else '100644'
                require(relative not in index or index[relative][0] == mode, 'MATERIALIZATION_MODE_DRIFT')
                total += info.st_size
                require(total <= 200 * 1024 * 1024, 'MATERIALIZATION_LIMIT')
                digest = hashlib.sha1(('blob ' + str(info.st_size) + '\0').encode())
                descriptor = os.open(item, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(descriptor, 'rb') as source:
                    opened = os.fstat(source.fileno())
                    require(stat.S_ISREG(opened.st_mode)
                            and (opened.st_dev, opened.st_ino, opened.st_size) ==
                                (info.st_dev, info.st_ino, info.st_size), 'MATERIALIZATION_REPLACED')
                    while chunk := source.read(65536):
                        digest.update(chunk)
                        require(time.monotonic() < deadline, 'MATERIALIZATION_LIMIT')
                    after = os.fstat(source.fileno())
                    require((after.st_size, after.st_mtime_ns, after.st_ctime_ns) ==
                            (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns),
                            'MATERIALIZATION_CHANGED')
                entries[relative] = (mode, digest.hexdigest())
        return entries

    def _snapshot(self, description, path, grant_paths):
        b = description['binding']
        self._identity(b, path)
        head = self._git(path, 'rev-parse', 'HEAD')
        _sha(head)
        self._integrity(path, b['head_sha'], head)
        tree = self._git(path, 'rev-parse', 'HEAD^{tree}')
        _sha(tree)
        deadline = time.monotonic() + 10
        changed = self._history(path, b['head_sha'], head, deadline)
        head_entries = self._tree(path, head)
        index = self._index(path)
        if description['operation'] == 'L2':
            require(head == description['payload']['candidate_sha']
                    and tree == description['payload']['candidate_tree_sha'], 'ADMISSION_CANDIDATE_MISMATCH')
            self._clean(path)
        files = self._files(path, index, b['worktree_uid'], deadline)
        current_changes = {name for name in set(head_entries) | set(index) | set(files)
                           if head_entries.get(name) != index.get(name) or index.get(name) != files.get(name)}
        changed.update(current_changes)
        require(changed <= grant_paths, 'ADMISSION_SCOPE_MISMATCH')
        if description['operation'] == 'L2':
            require(not current_changes and sorted(changed) == description['payload']['paths'],
                    'ADMISSION_CANDIDATE_SCOPE_MISMATCH')
        return head, tree, sorted(changed), index, files

    def inspect(self, description):
        try:
            verify_system_tools()
            b, grant_paths = self._validate(description)
            uid = b['worktree_uid']
            require(self.host() == b['host'], 'MATERIALIZATION_HOST_MISMATCH')
            root = self._path(b['root_path'], uid)
            path = self._path(b['worktree'], uid, leaf_owner=True)
            require(root in path.parents, 'MATERIALIZATION_OUTSIDE_ASSIGNED_ROOT')
            initial = path.lstat()
            lease = description['lease']
            expected_directory = (lease['directory_device'], lease['directory_inode'])
            require((initial.st_dev, initial.st_ino) == expected_directory, 'MATERIALIZATION_REPLACED')
            git_entry = (path / '.git').lstat()
            require(not stat.S_ISLNK(git_entry.st_mode) and git_entry.st_uid in (0, uid)
                    and not git_entry.st_mode & 0o022, 'UNTRUSTED_GIT_ENTRY')
            if hasattr(self.observer, 'bind'):
                self.observer.bind(b)
            first = self._snapshot(description, path, grant_paths)
            self._remote(b)
            dependencies = {}
            for dependency in description['dependencies']:
                key = dependency['dependency_key']
                require(isinstance(key, str) and key and key not in dependencies, 'DUPLICATE_DEPENDENCY')
                actual = self.observer.dependency(dependency)
                require(actual == dependency, 'DEPENDENCY_BINDING_MISMATCH')
                dependencies[key] = actual
            if hasattr(self.observer, 'bind'):
                self.observer.bind(b)
            final_snapshot = self._snapshot(description, path, grant_paths)
            self._remote(b)
            final = path.lstat()
            require((final.st_dev, final.st_ino) == expected_directory, 'MATERIALIZATION_REPLACED')
            require(first == final_snapshot, 'MATERIALIZATION_CHANGED')
            return {'intent_id': description['intent_id'], 'request_digest': description['request_digest'],
                    'operation': description['operation'], 'lease_id': lease['lease_id'], 'epoch': lease['epoch'],
                    'head_sha': first[0], 'tree_sha': first[1], 'changed_paths': first[2],
                    'directory_device': final.st_dev, 'directory_inode': final.st_ino,
                    'dependencies': dependencies, 'observed_at': datetime.now(timezone.utc).isoformat()}
        except MaterializationDenied:
            raise
        except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError):
            raise MaterializationDenied('MATERIALIZATION_UNAVAILABLE') from None
