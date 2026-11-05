"""Read-only normalization of the configured Apache log copies for vstats."""
import calendar
import datetime
import glob
import gzip
import hashlib
import json
import os
import re
import stat
import subprocess

MONTHS = b'Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split()
LINE = re.compile(
    rb'^(?P<host>\S+) (?P<ident>\S+) (?P<user>\S+) '
    rb'\[(?P<day>\d{2})/(?P<month>[A-Za-z]{3})/(?P<year>\d{4}):'
    rb'(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2}) '
    rb'(?P<sign>[+-])(?P<tzhour>\d{2})(?P<tzminute>\d{2})\] '
    rb'(?P<request>"(?:[^"\\]|\\.)*") (?P<status>\d{3}) '
    rb'(?P<size>\d+|-)(?P<tail>.*)$'
)
COMBINED = re.compile(rb'^ "(?:[^"\\]|\\.)*" "(?:[^"\\]|\\.)*"\s*$')
ROTATION = re.compile(r'-\d{8}(?:\.gz)?$')
BASE_NAME = re.compile(r'^[A-Za-z0-9_.-]+$')


def normalize(line):
    line = line.rstrip(b'\r\n')
    match = LINE.fullmatch(line)
    if not match:
        raise ValueError('not an Apache common/combined record')
    tail = match.group('tail')
    if not tail.strip():
        tail, kind = b' "-" "-"', 'common'
    elif COMBINED.fullmatch(tail):
        tail, kind = tail.rstrip(), 'combined'
    else:
        raise ValueError('unsupported additional log fields')
    parts = match.group('request')[1:-1].split(b' ')
    if len(parts) > 1:
        uri = parts[1].split(b'?', 1)[0]
        if uri in (b'/vstats', b'/vstats-control') or uri.startswith((b'/vstats/', b'/vstats-control/')):
            return None, None, 'statistics-request'
    month = MONTHS.index(match.group('month')) + 1
    local = datetime.datetime(
        int(match.group('year')), month, int(match.group('day')),
        int(match.group('hour')), int(match.group('minute')), int(match.group('second')))
    zone_hour, zone_minute = int(match.group('tzhour')), int(match.group('tzminute'))
    if zone_hour > 14 or zone_minute > 59:
        raise ValueError('invalid numeric timezone')
    offset = (zone_hour * 60 + zone_minute) * 60
    if match.group('sign') == b'-':
        offset = -offset
    epoch = calendar.timegm(local.timetuple()) - offset
    utc = datetime.datetime.utcfromtimestamp(epoch)
    stamp = ('%02d/%s/%04d:%02d:%02d:%02d +0000' %
             (utc.day, MONTHS[utc.month - 1].decode('ascii'), utc.year,
              utc.hour, utc.minute, utc.second)).encode('ascii')
    result = (match.group('host') + b' ' + match.group('ident') + b' ' +
              match.group('user') + b' [' + stamp + b'] ' +
              match.group('request') + b' ' + match.group('status') + b' ' +
              # Apache %b uses '-' for a zero-byte response (mod_log_config).
              (b'0' if match.group('size') == b'-' else match.group('size')) + tail + b'\n')
    return epoch, result, kind


def input_files(log_root, bases):
    result = []
    seen = set()
    for base in bases:
        if not BASE_NAME.fullmatch(base):
            raise ValueError('unsafe configured log basename')
        path = os.path.join(log_root, base)
        rotations = [item for item in glob.glob(path + '-*')
                     if ROTATION.fullmatch(item[len(path):])]
        for item in sorted(rotations) + [path]:
            if not os.path.exists(item):
                continue
            info = os.lstat(item)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError('non-regular source log')
            identity = (info.st_dev, info.st_ino)
            if identity in seen:
                continue
            seen.add(identity)
            result.append((item, info))
    return result


def build_snapshot(log_root, bases, work):
    os.makedirs(work, mode=0o700, exist_ok=True)
    unsorted_path = os.path.join(work, 'unsorted.tsv')
    sorted_path = os.path.join(work, 'sorted.tsv')
    output_path = os.path.join(work, 'access.log')
    evidence = {'rows': 0, 'accepted': 0, 'common': 0, 'combined': 0,
                'statistics_requests': 0, 'rejected': 0, 'partial_lines': 0,
                'rejections': [], 'files': [], 'months': [], 'timezone': 'UTC'}
    months = set()
    low, high = None, None
    with open(unsorted_path, 'wb') as output:
        for path, before in input_files(log_root, bases):
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(descriptor, 'rb') as raw:
                actual = os.fstat(raw.fileno())
                if (actual.st_dev, actual.st_ino) != (before.st_dev, before.st_ino):
                    raise RuntimeError('source log rotated during open; retry the snapshot')
                evidence['files'].append({'path': path, 'bytes_at_open': actual.st_size,
                                          'device': actual.st_dev, 'inode': actual.st_ino})
                stream = gzip.GzipFile(fileobj=raw) if path.endswith('.gz') else raw
                limit = None if path.endswith('.gz') else actual.st_size
                while limit is None or stream.tell() < limit:
                    remaining = -1 if limit is None else limit - stream.tell()
                    line = stream.readline(remaining)
                    if not line:
                        break
                    if not line.endswith(b'\n'):
                        evidence['partial_lines'] += 1
                        continue
                    evidence['rows'] += 1
                    try:
                        epoch, normalized, kind = normalize(line)
                    except (ValueError, OverflowError) as exc:
                        evidence['rejected'] += 1
                        if len(evidence['rejections']) < 20:
                            evidence['rejections'].append({'path': path,
                                'source_offset': stream.tell(), 'reason': str(exc)})
                        continue
                    if kind == 'statistics-request':
                        evidence['statistics_requests'] += 1
                        continue
                    evidence['accepted'] += 1
                    evidence[kind] += 1
                    stamp = datetime.datetime.utcfromtimestamp(epoch)
                    months.add(stamp.strftime('%Y-%m'))
                    low = epoch if low is None else min(low, epoch)
                    high = epoch if high is None else max(high, epoch)
                    output.write(str(epoch).encode('ascii') + b'\t' + normalized)
    environment = dict(os.environ)
    environment['LC_ALL'] = 'C'
    subprocess.check_call(['nice', '-n', '15', 'sort', '--stable', '--numeric-sort',
                           '--field-separator=\t', '--key=1,1', '--temporary-directory=' + work,
                           '--output=' + sorted_path, unsorted_path], env=environment)
    digest = hashlib.sha256()
    with open(sorted_path, 'rb') as source, open(output_path, 'wb') as output:
        for row in source:
            normalized = row.partition(b'\t')[2]
            output.write(normalized)
            digest.update(normalized)
    os.chmod(output_path, 0o600)
    evidence['months'] = sorted(months)
    evidence['first_utc'] = None if low is None else datetime.datetime.utcfromtimestamp(low).isoformat() + 'Z'
    evidence['last_utc'] = None if high is None else datetime.datetime.utcfromtimestamp(high).isoformat() + 'Z'
    evidence['normalized_sha256'] = digest.hexdigest()
    evidence['normalized_bytes'] = os.path.getsize(output_path)
    os.unlink(unsorted_path)
    os.unlink(sorted_path)
    with open(os.path.join(work, 'input-receipt.json'), 'w', encoding='utf-8') as handle:
        json.dump(evidence, handle, indent=2, sort_keys=True)
    return output_path, evidence
