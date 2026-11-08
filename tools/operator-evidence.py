#!/usr/bin/env python3
"""Collect DNS observations for an explicitly authorized, bounded address list.

Never reads visitor logs. The pure Perl verifier decides association from the
recorded answers; neither a PTR name nor a collector success flag is evidence.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time

SOURCE = 'https://www.internet-census.org/home.html'
DOMAIN = 'internet-census.org'
MAX_CANDIDATES = 256


def name(value):
    value = value.rstrip('.').encode('idna').decode('ascii').lower()
    if len(value) > 253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                               for label in value.split('.')):
        raise ValueError('Invalid DNS name')
    return value


def address(value):
    if not isinstance(value, str) or '%' in value:
        raise ValueError('Expected an unscoped literal address')
    if '.' in value and not re.fullmatch(r'(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}', value.rsplit(':', 1)[-1]):
        raise ValueError('Legacy IPv4 forms are not accepted')
    parsed = ipaddress.ip_address(value)
    return parsed.ipv4_mapped if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped else parsed


def parse_answer(raw, qname, qtype):
    result = {'qname': name(qname), 'qtype': qtype, 'status': 'UNAVAILABLE', 'truncated': 1, 'answers': []}
    if len(raw) > 65536:
        return result
    text = raw.decode('ascii', 'strict')
    header = re.search(r'^;; ->>HEADER<<-.*status: ([A-Z]+),', text, re.M)
    flags = re.search(r'^;; flags: ([^;]*);', text, re.M)
    if not header or not flags:
        return result
    result.update(status=header[1], truncated=int('tc' in flags[1].split()))
    in_answers = False
    for line in text.splitlines():
        if line == ';; ANSWER SECTION:':
            in_answers = True
            continue
        if line.startswith(';;') or not line.strip():
            in_answers = False
            continue
        if not in_answers:
            continue
        parts = line.split()
        if len(parts) != 5 or parts[2] != 'IN' or not parts[1].isdigit() or int(parts[1]) > 2147483647:
            result['truncated'] = 1
            continue
        result['answers'].append({'owner': name(parts[0]), 'ttl': int(parts[1]), 'type': parts[3],
                                  'data': name(parts[4]) if parts[3] in ('PTR', 'CNAME') else parts[4]})
    if len(result['answers']) > 128:
        result.update(truncated=1, answers=[])
    return result


def query(resolver, qname, qtype):
    # No shell, user-selected executable, search suffix or log-derived query.
    command = ['/usr/bin/dig', '@' + resolver, qname + '.', qtype,
               '+time=2', '+tries=1', '+nosearch', '+noall', '+comments', '+answer']
    try:
        p = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'LANG': 'C'}, timeout=5)
        if p.returncode or p.stderr:
            raise ValueError('DNS query failed')
        return parse_answer(p.stdout, qname, qtype)
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        return {'qname': name(qname), 'qtype': qtype, 'status': 'UNAVAILABLE', 'truncated': 1, 'answers': []}


def ptr_targets(answer):
    if answer['status'] != 'NOERROR' or answer['truncated']:
        return []
    owner, seen = answer['qname'], set()
    for hop in range(9):
        if owner in seen:
            return []
        seen.add(owner)
        rows = [r for r in answer['answers'] if r['owner'] == owner]
        links = [r for r in rows if r['type'] == 'CNAME']
        if links:
            if len(links) != 1 or hop == 8 or any(r['type'] == 'PTR' for r in rows):
                return []
            owner = name(links[0]['data'])
            continue
        targets = sorted({name(r['data']) for r in rows if r['type'] == 'PTR'})
        return [s for s in targets if s == DOMAIN or s.endswith('.' + DOMAIN)] if len(targets) <= 16 else []
    return []


def collect(config, ask=query, now=time.time, previous=None):
    if set(config) != {'schema_version', 'authorized', 'selection', 'addresses', 'resolver', 'source_document_fetched_at'} or \
            config['schema_version'] != 1 or config['authorized'] is not True:
        raise ValueError('An explicit authorized candidate list is required')
    values = config['addresses']
    if not isinstance(values, list) or not 0 < len(values) <= MAX_CANDIDATES:
        raise ValueError('Candidate list exceeds its bounded scope')
    addresses = sorted({str(address(value)) for value in values})
    if len(addresses) != len(values):
        raise ValueError('Candidate addresses must be unique')
    resolver = config['resolver']
    if set(resolver) != {'address', 'nonrewriting'} or resolver['nonrewriting'] is not True:
        raise ValueError('A documented nonrewriting resolver is required')
    resolver_ip = str(address(resolver['address']))
    observations = []
    for value in addresses:
        ip = address(value)
        reverse = ask(resolver_ip, ip.reverse_pointer, 'PTR')
        queries = [reverse]
        for target in ptr_targets(reverse):
            queries.append(ask(resolver_ip, target, 'A' if ip.version == 4 else 'AAAA'))
        observations.append({'client': value, 'completed_at': int(now()), 'queries': queries})
    # An invocation never expands its candidate list from old observations.
    if previous and (previous.get('provider_id') != 'internet_census' or previous.get('source_url') != SOURCE or
                     previous.get('resolver') != {'address': resolver_ip, 'nonrewriting': 1}):
        raise ValueError('Existing observations have different provenance')
    prior = (previous or {}).get('observations', [])
    if len(prior) + len(observations) > 4096:
        raise ValueError('Evidence archive is full; retain it before starting a new archive')
    return {'schema_version': 1, 'provider_id': 'internet_census', 'source_url': SOURCE,
            'source_document_fetched_at': config['source_document_fetched_at'],
            'resolver': {'address': resolver_ip, 'nonrewriting': 1}, 'selection': config['selection'],
            'observations': prior + observations}


def read_private(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError('Untrusted candidate/evidence file')
        raw = handle.read(16777217)
    if len(raw) > 16777216:
        raise ValueError('Evidence exceeds byte limit')
    return json.loads(raw.decode('utf-8'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidates', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    target = Path(args.output)
    previous = read_private(target) if target.exists() else None
    value = collect(read_private(args.candidates), previous=previous)
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('utf-8')
    if len(raw) > 16777216:
        raise ValueError('Evidence exceeds byte limit')
    fd, temporary = tempfile.mkstemp(prefix='.operator-evidence-', dir=str(target.parent))
    try:
        with os.fdopen(fd, 'wb') as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(raw); handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, str(target))
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


if __name__ == '__main__':
    main()
