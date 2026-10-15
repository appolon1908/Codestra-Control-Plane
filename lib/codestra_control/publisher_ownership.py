"""Designated local writer fencing; this is not certification authority.

No production authenticated publication adapter has been accepted. Publication
therefore refuses unconditionally until a separately reviewed integration exists.
The lock only fences this host's cooperating processes, not remote issuers.
"""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import stat

SERVICE = 'codestra-control-plane-status.service'
LOCK_PATH = Path('/run/codestra-control-plane/publisher.lock')


class PublisherUnavailable(RuntimeError):
    pass


def require_designated_service():
    try:
        paths = [line.split(':', 2)[2] for line in Path('/proc/self/cgroup').read_text().splitlines()]
    except (OSError, IndexError):
        raise PublisherUnavailable('SERVICE_IDENTITY_UNAVAILABLE') from None
    if '/system.slice/' + SERVICE not in paths:
        raise PublisherUnavailable('DESIGNATED_SERVICE_REQUIRED')


@contextmanager
def exclusive_lock(path=LOCK_PATH, *, expected_owner=0):
    """Use a pre-provisioned, nonreplaceable operator-owned file; never create it.

    Path/owner parameters are internal disposable-test seams. The entrypoint uses
    fixed defaults. A root administrator remains outside this process boundary.
    """
    path = Path(path)
    directory_fd = lock_fd = None
    try:
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        directory = os.fstat(directory_fd)
        if directory.st_uid != expected_owner or directory.st_mode & 0o022:
            raise PublisherUnavailable('UNTRUSTED_LOCK_DIRECTORY')
        lock_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        info = os.fstat(lock_fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != expected_owner
                or info.st_nlink != 1 or info.st_mode & 0o027):
            raise PublisherUnavailable('UNTRUSTED_LOCK_FILE')
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise PublisherUnavailable('PUBLISHER_ALREADY_RUNNING') from None
        current = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
        if (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
            raise PublisherUnavailable('LOCK_FILE_REPLACED')
        yield
    except OSError:
        raise PublisherUnavailable('PUBLISHER_LOCK_UNAVAILABLE') from None
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
        if directory_fd is not None:
            os.close(directory_fd)


@contextmanager
def publisher_session():
    require_designated_service()
    with exclusive_lock():
        yield


def require_publication_adapter():
    """No env flag, actor string, legacy row or JSON can enable publication."""
    raise PublisherUnavailable('AUTHENTICATED_PUBLICATION_ADAPTER_UNAVAILABLE')
