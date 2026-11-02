"""Private POSIX native-history snapshots, preserving plain/gzip representation.

No parsing, network, application paths or deployment policy. Missing history is
represented by None, independently of the filename suffix used by an existing
history. Callers bind each snapshot to their own input/configuration signature.
"""
import hashlib
import os
import stat


def read_history(base_path, owner_uid, max_bytes=64 * 1024 * 1024):
    """Read .txt or .txt.gz without following symlinks; plain files take priority."""
    if type(max_bytes) is not int or max_bytes < 1:
        raise ValueError('Invalid history byte cap')
    for suffix in ('', '.gz'):
        try:
            descriptor = os.open(str(base_path) + suffix, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            continue
        with os.fdopen(descriptor, 'rb') as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid:
                raise ValueError('Unexpected history ownership/type')
            if info.st_size > max_bytes:
                raise ValueError('History byte cap exceeded')
            raw = handle.read(max_bytes + 1)
            if len(raw) > max_bytes:
                raise ValueError('History byte cap exceeded')
        return {'suffix': suffix, 'sha256': hashlib.sha256(raw).hexdigest(), 'raw': raw}
    return None


def matches_history(snapshot, expected_sha256):
    """A missing receipt value cannot match a present compressed history."""
    return snapshot is None if expected_sha256 is None else (
        snapshot is not None and snapshot['sha256'] == expected_sha256)


def restore_history(snapshot, destination_base, owner_uid, group_gid):
    """Restore exact bytes under their actual suffix, refusing existing targets."""
    if snapshot is None:
        return None
    if snapshot['suffix'] not in ('', '.gz'):
        raise ValueError('Invalid history suffix')
    raw = snapshot['raw']
    if hashlib.sha256(raw).hexdigest() != snapshot['sha256']:
        raise ValueError('History snapshot changed')
    destination = str(destination_base) + snapshot['suffix']
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as handle:
        os.fchmod(handle.fileno(), 0o600)
        os.fchown(handle.fileno(), owner_uid, group_gid)
        handle.write(raw)
    return destination
