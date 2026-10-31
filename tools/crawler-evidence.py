#!/usr/bin/env python3
"""Collect public provider evidence; never read access logs or visitor addresses."""
import argparse
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import stat
import tempfile
import urllib.request

PROVIDER = 'google_common'
SOURCE_URL = 'https://developers.google.com/static/crawling/ipranges/common-crawlers.json'
MAX_RAW_BYTES = 2097152
MAX_SNAPSHOTS = 32
MAX_PREFIXES = 32768
MAX_BUNDLE_BYTES = 67108864


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate JSON key')
            result[key] = value
        return result
    def constant(value):
        raise ValueError('Nonstandard JSON constant')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant)


def validate_raw(raw):
    if len(raw) > MAX_RAW_BYTES:
        raise ValueError('Provider snapshot exceeds byte limit')
    data = strict_json(raw)
    if not isinstance(data, dict) or set(data) != {'creationTime', 'prefixes'}:
        raise ValueError('Unexpected provider schema')
    if not isinstance(data['creationTime'], str):
        raise ValueError('Invalid provider creation time')
    prefixes = data['prefixes']
    if not isinstance(prefixes, list) or not 0 < len(prefixes) <= MAX_PREFIXES:
        raise ValueError('Invalid provider prefix count')
    for item in prefixes:
        if not isinstance(item, dict) or len(item) != 1:
            raise ValueError('Invalid provider prefix')
        key = next(iter(item))
        if key not in ('ipv4Prefix', 'ipv6Prefix') or not isinstance(item[key], str):
            raise ValueError('Invalid provider prefix family')
        if not re.fullmatch(r'[^/%]+/(?:0|[1-9][0-9]{0,2})', item[key]):
            raise ValueError('Provider prefix must use numeric CIDR notation')
        address = ipaddress.ip_network(item[key], strict=True)
        if address.version != (4 if key == 'ipv4Prefix' else 6):
            raise ValueError('Mismatched provider prefix family')
        if address.version == 4 and str(address.network_address) != item[key].split('/')[0]:
            raise ValueError('Noncanonical IPv4 provider prefix')
    return data


def encoded(data):
    return (json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode('utf-8')


def checked(path, directory=False):
    info = path.lstat()
    valid = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not valid or info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
        raise ValueError('Unsafe evidence storage')


def read_bounded(path, cap):
    checked(path)
    with path.open('rb') as handle:
        raw = handle.read(cap + 1)
    if len(raw) > cap:
        raise ValueError('Archived evidence exceeds byte limit')
    return raw


def atomic_write(path, raw):
    checked(path.parent, True)
    if os.path.lexists(str(path)):
        checked(path)
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=str(path.parent))
    try:
        with os.fdopen(descriptor, 'wb') as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, str(path))
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def record_snapshot(directory, raw, retrieved_at):
    """Archive an actual retrieval; creationTime never substitutes for its time."""
    validate_raw(raw)
    when = datetime.datetime.strptime(retrieved_at, '%Y-%m-%dT%H:%M:%SZ')
    directory = Path(directory)
    directory.mkdir(mode=0o750, parents=True, exist_ok=True)
    checked(directory, True)
    blobs, attestations = directory / 'raw', directory / 'retrievals'
    for child in (blobs, attestations):
        child.mkdir(mode=0o700, exist_ok=True)
        checked(child, True)
    digest = hashlib.sha256(raw).hexdigest()
    blob = blobs / (digest + '.json')
    if os.path.lexists(str(blob)):
        checked(blob)
        if read_bounded(blob, MAX_RAW_BYTES) != raw:
            raise ValueError('Evidence content identity mismatch')
    else:
        atomic_write(blob, raw)
    metadata = {'raw_sha256': digest, 'attestation': {
        'provider_id': PROVIDER, 'source_url': SOURCE_URL, 'retrieved_at': retrieved_at}}
    receipt = attestations / (when.strftime('%Y%m%dT%H%M%SZ') + '.json')
    if os.path.lexists(str(receipt)):
        checked(receipt)
        if strict_json(read_bounded(receipt, 16384)) != metadata:
            raise ValueError('Conflicting retrievals within the same timestamp')
    else:
        atomic_write(receipt, encoded(metadata))
    entries = []
    names = sorted(p for p in attestations.iterdir() if re.fullmatch(r'\d{8}T\d{6}Z\.json', p.name))
    for path in names[-MAX_SNAPSHOTS:]:
        checked(path)
        item = strict_json(read_bounded(path, 16384))
        if not isinstance(item, dict) or set(item) != {'raw_sha256', 'attestation'}:
            raise ValueError('Invalid archived retrieval')
        sha, attestation = item['raw_sha256'], item['attestation']
        if not isinstance(sha, str) or not re.fullmatch(r'[0-9a-f]{64}', sha):
            raise ValueError('Invalid archived digest')
        if not isinstance(attestation, dict) or set(attestation) != {'provider_id', 'source_url', 'retrieved_at'}:
            raise ValueError('Invalid archived attestation')
        if attestation['provider_id'] != PROVIDER or attestation['source_url'] != SOURCE_URL:
            raise ValueError('Unregistered archived provider')
        actual = datetime.datetime.strptime(attestation['retrieved_at'], '%Y-%m-%dT%H:%M:%SZ')
        if actual.strftime('%Y%m%dT%H%M%SZ.json') != path.name:
            raise ValueError('Archived retrieval timestamp mismatch')
        archived = blobs / (sha + '.json')
        checked(archived)
        content = read_bounded(archived, MAX_RAW_BYTES)
        if hashlib.sha256(content).hexdigest() != sha:
            raise ValueError('Archived provider content changed')
        count = len(validate_raw(content)['prefixes'])
        entries.append((count, {'raw_json': content.decode('utf-8'),
                               'attestation_json': encoded(attestation).decode('utf-8')}))
    # Keep the same aggregate prefix bound as the native verifier. Older raw
    # evidence stays archived; omitted periods remain unverified.
    while sum(count for count, entry in entries) > MAX_PREFIXES:
        entries.pop(0)
    entries = [entry for count, entry in entries]
    bundle = encoded({'schema_version': 1, 'snapshots': entries})
    if len(bundle) > MAX_BUNDLE_BYTES:
        raise ValueError('Evidence bundle exceeds byte limit')
    target = directory / 'evidence.json'
    atomic_write(target, bundle)
    return {'provider_id': PROVIDER, 'source_url': SOURCE_URL,
            'retrieved_at': retrieved_at, 'raw_sha256': digest,
            'snapshots': len(entries), 'bundle_sha256': hashlib.sha256(bundle).hexdigest(),
            'bundle_path': str(target)}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def download(timeout=20):
    # This timeout is an operational guard, not a detector accuracy threshold.
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request = urllib.request.Request(SOURCE_URL, headers={'User-Agent': 'vstats-crawler-evidence/1'})
    with opener.open(request, timeout=timeout) as response:
        if response.geturl() != SOURCE_URL:
            raise ValueError('Provider redirected outside the registered source')
        raw = response.read(MAX_RAW_BYTES + 1)
    validate_raw(raw)
    return raw


def collect(directory, timeout=20):
    raw = download(timeout)
    # The request finished before this attested retrieval time. Never backdate it.
    retrieved_at = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    return record_snapshot(directory, raw, retrieved_at)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', required=True)
    options = parser.parse_args()
    try:
        print(json.dumps(collect(options.directory), sort_keys=True))
    except Exception as error:
        parser.exit(1, 'Crawler evidence was not refreshed: ' + type(error).__name__ + '\n')
