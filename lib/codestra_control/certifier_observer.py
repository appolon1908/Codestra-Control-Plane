"""Separate local custodian: public GitHub identity observations, never credentials.

The publisher receives no certifier key/JWT/token. This source server is not
installed or started automatically. Only a separately accepted root custodian
may serve the fixed protected socket to the designated publisher UID.
"""
import json
import os
from pathlib import Path
import socket
import stat
import struct
import tomllib

from .publisher_adapter import PublicationDenied, require
from .publisher_github import request_json

MAX_MESSAGE = 65536
CONFIG = Path('/etc/codestra/control-plane/certifier-observer.toml')


def verify_socket_path(path):
    path = Path(path)
    require(path.is_absolute(), 'OBSERVER_ABSOLUTE_SOCKET_REQUIRED')
    try:
        for ancestor in (path.parent, *path.parent.parents):
            info = ancestor.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                    'UNTRUSTED_OBSERVER_DIRECTORY')
        info = path.lstat()
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o007,
                'UNTRUSTED_OBSERVER_SOCKET')
    except OSError:
        raise PublicationDenied('OBSERVER_SOCKET_UNAVAILABLE') from None


def peer_uid(connection):
    return struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]


def receive_message(connection):
    raw = bytearray()
    while len(raw) <= MAX_MESSAGE:
        chunk = connection.recv(min(4096, MAX_MESSAGE + 1 - len(raw)))
        require(bool(chunk), 'OBSERVER_INCOMPLETE_MESSAGE')
        raw.extend(chunk)
        if b'\n' in raw:
            require(raw.endswith(b'\n') and raw.count(b'\n') == 1 and len(raw) <= MAX_MESSAGE,
                    'OBSERVER_INVALID_FRAME')
            try:
                value = json.loads(raw)
            except (UnicodeError, ValueError):
                raise PublicationDenied('OBSERVER_INVALID_MESSAGE') from None
            require(type(value) is dict, 'OBSERVER_INVALID_MESSAGE')
            return value
    raise PublicationDenied('OBSERVER_MESSAGE_TOO_LARGE')


def send_message(connection, value):
    raw = json.dumps(value, separators=(',', ':')).encode() + b'\n'
    require(len(raw) <= MAX_MESSAGE, 'OBSERVER_MESSAGE_TOO_LARGE')
    connection.sendall(raw)


class CertifierObservationClient:
    """The jwt_provider compatibility handle is a sentinel, never a JWT."""
    def __init__(self, path, *, expected_uid=0):
        self.path, self.expected_uid = str(path), expected_uid
        self._handle = object()

    def jwt_provider(self):
        return self._handle

    def request(self, method, path, handle, body=None):
        require(handle is self._handle and method == 'GET' and body is None,
                'OBSERVER_READ_ONLY')
        verify_socket_path(self.path)
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(20)
                connection.connect(self.path)
                require(peer_uid(connection) == self.expected_uid, 'OBSERVER_PEER_MISMATCH')
                send_message(connection, {'method': method, 'path': path})
                response = receive_message(connection)
            require(set(response) == {'ok', 'result'} and response['ok'] is True
                    and type(response['result']) is dict, 'OBSERVER_OBSERVATION_UNAVAILABLE')
            return response['result']
        except OSError:
            raise PublicationDenied('OBSERVER_OBSERVATION_UNAVAILABLE') from None


class CertifierObservationHandler:
    def __init__(self, accepted_identity, jwt_provider, *, request=request_json):
        self.accepted_identity = accepted_identity
        self.jwt_provider, self.request = jwt_provider, request

    def observe(self, value):
        require(type(value) is dict and set(value) == {'method', 'path'}
                and value['method'] == 'GET' and type(value['path']) is str,
                'OBSERVER_READ_ONLY')
        app_id, installation_id, repositories = self.accepted_identity()
        allowed = {'/app', f'/app/installations/{installation_id}',
                   *(f'/repos/{repo}/installation' for repo in repositories)}
        require(value['path'] in allowed, 'OBSERVER_PATH_NOT_ACCEPTED')
        result = self.request('GET', value['path'], self.jwt_provider())
        require(type(result) is dict, 'OBSERVER_INVALID_UPSTREAM')
        if value['path'] == '/app':
            require(type(result.get('id')) is int and result['id'] == app_id,
                    'OBSERVER_APP_IDENTITY_MISMATCH')
            return {'id': result['id']}
        require(type(result.get('id')) is int and result['id'] == installation_id
                and type(result.get('app_id')) is int and result['app_id'] == app_id
                and result.get('suspended_at', 'missing') is None,
                'OBSERVER_INSTALLATION_MISMATCH_OR_REVOKED')
        account, permissions = result.get('account'), result.get('permissions')
        require(type(account) is dict and type(account.get('login')) is str
                and type(account.get('id')) is int and account['id'] > 0
                and result.get('repository_selection') in ('all', 'selected')
                and type(permissions) is dict
                and all(type(k) is str and v in ('read', 'write') for k, v in permissions.items()),
                'OBSERVER_INVALID_UPSTREAM')
        # Explicit allowlist: never proxy JWTs, tokens, keys, arbitrary URLs,
        # private account metadata or upstream error bodies.
        return {'id': result['id'], 'app_id': result['app_id'], 'suspended_at': None,
                'account': {'login': account['login'], 'id': account['id']}, 'permissions': permissions,
                'repository_selection': result['repository_selection']}


def serve_connection(connection, handler, *, allowed_uid):
    require(peer_uid(connection) == allowed_uid, 'OBSERVER_CALLER_MISMATCH')
    connection.settimeout(20)
    try:
        result = handler.observe(receive_message(connection))
        send_message(connection, {'ok': True, 'result': result})
    except Exception:
        # Do not reveal upstream errors, paths, JWT provider details or config.
        send_message(connection, {'ok': False, 'result': {}})


def serve_observer(path, handler, *, allowed_uid, publisher_gid):
    """Root-only runtime entry; refuses existing socket, never unlinks it."""
    require(os.geteuid() == 0, 'OBSERVER_ROOT_CUSTODIAN_REQUIRED')
    path = Path(path)
    require(path.is_absolute(), 'OBSERVER_ABSOLUTE_SOCKET_REQUIRED')
    for ancestor in (path.parent, *path.parent.parents):
        info = ancestor.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'UNTRUSTED_OBSERVER_DIRECTORY')
    require(not path.exists() and not path.is_symlink(), 'OBSERVER_SOCKET_ALREADY_EXISTS')
    # The separately approved operator provisions the directory and caller UID.
    # Never create directories, credentials, installations or authority here.
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))
        os.chown(path, 0, publisher_gid); os.chmod(path, 0o660)
        listener.listen(8)
        while True:
            connection, _ = listener.accept()
            with connection:
                try:
                    serve_connection(connection, handler, allowed_uid=allowed_uid)
                except (OSError, PublicationDenied):
                    pass


def private_certifier_signer(path, app_id):
    from .publisher_startup import AppJWT
    signer = AppJWT(path, app_id)
    def sign():
        # Root-only signing custody must still hold after a long-lived server
        # starts. The publisher's more permissive group-readable key policy
        # must never apply to this independent certifier key.
        info = Path(path).lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
                'OBSERVER_PRIVATE_KEY_CUSTODY_REQUIRED')
        return signer()
    return sign


def run_configured_observer():
    """Source composition only; no daemon, units or credentials are provisioned."""
    import pwd
    from datetime import datetime, timezone
    from .publisher_ownership import PublisherUnavailable
    from .publisher_startup import protected_read, verify_code_custody
    try:
        config = tomllib.loads(protected_read(CONFIG).decode())
        require(set(config) == {'app_key_file', 'producer_acceptance_file', 'socket_file', 'publisher_user'}
                and config['publisher_user'] == 'sentinelx'
                and all(type(config[k]) is str and Path(config[k]).is_absolute()
                        for k in ('app_key_file', 'producer_acceptance_file', 'socket_file')),
                'INVALID_OBSERVER_CONFIGURATION')
        verify_code_custody()
        from .publisher_acceptance import load_acceptance
        def policy():
            return load_acceptance(protected_read(config['producer_acceptance_file']), datetime.now(timezone.utc))
        initial = policy()
        caller = pwd.getpwnam(config['publisher_user'])
        require(caller.pw_uid > 0, 'OBSERVER_DISTINCT_PUBLISHER_REQUIRED')
        # Even a group-readable certifier key would collapse independent custody.
        key = Path(config['app_key_file']).lstat()
        require(stat.S_ISREG(key.st_mode) and key.st_uid == 0 and stat.S_IMODE(key.st_mode) == 0o600
                and key.st_nlink == 1, 'OBSERVER_PRIVATE_KEY_CUSTODY_REQUIRED')
        signer = private_certifier_signer(config['app_key_file'], initial.certificate_app_id)
        def identity():
            current = policy()
            require(current.certificate_app_id == initial.certificate_app_id,
                    'OBSERVER_ACCEPTED_IDENTITY_CHANGED')
            return current.certificate_app_id, current.certificate_installation_id, tuple(name for name, _ in current.repositories)
        serve_observer(config['socket_file'], CertifierObservationHandler(identity, signer),
                       allowed_uid=caller.pw_uid, publisher_gid=caller.pw_gid)
    except PublisherUnavailable:
        raise
    except Exception:
        raise PublisherUnavailable('CERTIFIER_OBSERVER_REFUSED') from None
