"""Bounded corpus analysis of Perl-validated requests. No DNS or geolocation.

The defaults are exploratory heuristics, not calibrated bot probabilities.
Evidence is request scoped; this module never creates an IP/month trigger.
"""
import bisect
import collections
import datetime
import hashlib
import ipaddress
import json
import re

RULES = ('compound_automation', 'scheduled_automation', 'inferred_scanner', 'declared_automation')
VERSION = 'vstats-corpus-automation-v1'
MAX_RECORDS = 500000
MAX_GROUPS = 100000
MAX_REPORT_BYTES = 128 * 1024 * 1024
MAX_CORPUS_BYTES = 768 * 1024 * 1024
ASSET = re.compile(r'\.(?:css|[cm]?js|map|png|jpe?g|gif|webp|avif|svg|ico|woff2?|ttf|otf|eot|pdf|zip|gz|mp[34]|webm|ogg|wav)$', re.I)
PLATFORMLESS = re.compile(r'^Mozilla/5\.0 AppleWebKit/[0-9.]+ \(KHTML, like Gecko\) Chrome/[0-9.]+ Safari/[0-9.]+$')


def identity(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')).hexdigest()


def canonical_ip(value):
    try:
        ip = ipaddress.ip_address(value)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        return str(ip)
    except (ValueError, TypeError):
        return None


def family(path):
    if re.match(r'^/(?:index\.php/)?wp-json(?:/|$)', path) or path.startswith('/api/'):
        return 'api'
    if path.endswith('/feed/') or path in ('/feed', '/feed/', '/xmlrpc.php'):
        return 'feed'
    if re.search(r'\.(?:woff2?|ttf|otf|eot)$', path, re.I):
        return 'font'
    return None


def metadata_family(path):
    if path == '/robots.txt':
        return 'robots'
    if path in ('/sitemap.xml', '/sitemap_index.xml', '/wp-sitemap.xml'):
        return 'sitemap'
    if path in ('/security.txt', '/.well-known/security.txt'):
        return 'security'
    return None


def cycle(timestamp):
    # UTC weeks start on Monday. This definition is independent of locale/DST.
    return (timestamp - 4 * 86400) // 604800


def phase(timestamp):
    return datetime.datetime.utcfromtimestamp(timestamp).weekday()


def _bare_host(value):
    value = (value or '').lower().rstrip('.')
    return value[4:] if value.startswith('www.') else value


def _continuity(rows):
    """Only observed positive navigation/asset edges supply a veto."""
    pages = {}
    for row in rows:
        row['_continuous'] = False
    for row in rows:
        previous = pages.get(row.get('referrer_path'))
        if (previous and row['timestamp'] - previous['timestamp'] <= 1800 and
                row['field_observability'].get('referrer') == 'value' and
                _bare_host(row.get('referrer_host')) == _bare_host(row['_host']) and
                row['status'] in (200, 206, 304)):
            previous['_continuous'] = row['_continuous'] = True
        if row['method'] == 'GET' and row['status'] == 200 and not ASSET.search(row['normalized_target']):
            pages[row['normalized_target']] = row
    times = [row['timestamp'] for row in rows]
    prefix = [0]
    for row in rows:
        prefix.append(prefix[-1] + int(row['_continuous']))

    def veto(start, end):
        lo, hi = bisect.bisect_left(times, start), bisect.bisect_right(times, end)
        return prefix[hi] != prefix[lo]
    return times, veto


def prepare(report_paths, config, valid_days):
    """Learn once from disjoint primary details, never duplicated day halos.

    Resource maxima bound this optional layer. On overflow the caller retains
    legacy classifications and clearly records this layer as unavailable.
    """
    result = {'version': VERSION, 'matches': {}, 'aggressive': {}, 'eligible_keys': set(), 'context_sha256': None,
              'status': 'evaluated', 'signatures': [], 'rule_counts': {k: 0 for k in RULES}}
    if not any(config[k]['enabled'] for k in RULES):
        result['status'] = 'disabled'
        result['context_sha256'] = identity({'version': VERSION, 'status': 'disabled'})
        return result
    features, bindings, quoted = [], [], collections.defaultdict(lambda: [0, 0, set()])
    byte_count = 0
    keep = ('client', 'user_agent', 'field_observability', 'normalized_target', 'method', 'status',
            'timestamp', 'source_format', 'observed_vhost', 'host', 'source_month', 'client_source',
            'request_id', 'line_index', 'referrer_host', 'referrer_path', 'operator_inference_candidate')
    for path in report_paths:
        if path.stat().st_size > MAX_REPORT_BYTES or byte_count + path.stat().st_size > MAX_CORPUS_BYTES:
            result.update(status='unavailable_capacity', context_sha256=identity({'version': VERSION, 'capacity': True}))
            return result
        raw = path.read_bytes()
        byte_count += len(raw)
        if len(raw) > MAX_REPORT_BYTES or byte_count > MAX_CORPUS_BYTES:
            result.update(status='unavailable_capacity', context_sha256=identity({'version': VERSION, 'capacity': True}))
            return result
        report = json.loads(raw.decode('utf-8'))
        bindings.append((path.stem, report['input_sha256'], report.get('observability_sha256'),
                         report.get('operator_evidence', {}).get('sha256')))
        for source in report['details']:
            if len(features) >= MAX_RECORDS:
                result.update(status='unavailable_capacity', context_sha256=identity({'version': VERSION, 'capacity': True}))
                return result
            row = {k: source.get(k) for k in keep}
            row['_key'] = (path.stem, row['line_index'])
            row['_host'] = row['observed_vhost'] or row['host']
            row['_client'] = canonical_ip(row['client'])
            row['field_observability'] = row['field_observability'] or {}
            ua = row['user_agent']
            if row['field_observability'].get('user_agent') == 'value' and ua:
                slot = quoted[(path.stem, row['source_format'])]
                is_quote = ua.startswith('"') and ua.endswith('"')
                slot[int(is_quote)] += 1
                if not is_quote:
                    slot[2].add(row['_client'])
            if (row['_host'] and row['_client'] and row['normalized_target'] and
                    row['client_source'] in ('socket_peer', 'trusted_proxy') and
                    row['method'] and row['status'] and
                    row['field_observability'].get('user_agent') in ('value', 'absent')):
                features.append(row)
    result['context_sha256'] = identity({'version': VERSION, 'config': {k: config[k] for k in RULES},
                                        'primary_inputs': bindings, 'valid_days': sorted(valid_days)})
    groups = collections.defaultdict(list)
    for row in features:
        groups[(row['_client'], row['_host'], row['user_agent'])].append(row)
    if len(groups) > MAX_GROUPS:
        result['status'] = 'unavailable_capacity'
        return result
    result['eligible_keys'] = {row['_key'] for row in features}

    def mark(row, rule, proof):
        selected = result['matches'].setdefault(row['_key'], {})
        selected.setdefault(rule, dict(proof, rule_id=rule + '_v1', corpus_sha256=result['context_sha256']))

    group_info = {}
    ca = config['compound_automation']
    for key, rows in groups.items():
        rows.sort(key=lambda r: (r['timestamp'], r['_key']))
        times, veto = _continuity(rows)
        group_info[key] = (times, veto)
        if not ca['enabled']:
            continue
        ua = key[2] or ''
        anomalous = ua.startswith('"') and ua.endswith('"')
        for mode in ('content', 'metadata'):
            if (mode == 'content' and not anomalous) or (mode == 'metadata' and key[2] is not None):
                continue
            candidates = []
            for row in rows:
                if mode == 'content':
                    controls, qcount, source_set = quoted[(row['_key'][0], row['source_format'])]
                    rare = (controls >= ca['quote_min_controls'] and len(source_set) >= ca['quote_min_sources'] and
                            100 * qcount <= ca['quote_max_percent'] * (controls + qcount))
                    if not (rare and row['method'] == 'GET' and row['status'] == 200 and
                            not ASSET.search(row['normalized_target'])):
                        continue
                    value = row['normalized_target']
                else:
                    value = metadata_family(row['normalized_target'])
                    if not value or row['method'] not in ('GET', 'HEAD'):
                        continue
                candidates.append((row, value))
            left, assigned, counts = 0, -1, collections.Counter()
            for right, (row, value) in enumerate(candidates):
                counts[value] += 1
                while row['timestamp'] - candidates[left][0]['timestamp'] > ca['window_seconds']:
                    old = candidates[left][1]
                    counts[old] -= 1
                    if not counts[old]:
                        del counts[old]
                    left += 1
                required = ca['distinct_pages'] if mode == 'content' else ca['metadata_families']
                start, end = candidates[left][0]['timestamp'], row['timestamp']
                if len(counts) < required or veto(start - 5, end + 5):
                    continue
                proof = {'from': start, 'until': end, 'requests': right - left + 1,
                         'distinct': len(counts), 'classes': ['malformed_claim' if mode == 'content' else 'observed_empty_claim',
                                                            'content_burst' if mode == 'content' else 'metadata_pattern']}
                for j in range(max(left, assigned + 1), right + 1):
                    mark(candidates[j][0], 'compound_automation', proof)
                assigned = right

    # Whole-UTC-week path/weekday signatures. Hold out the request's own cycle;
    # a cohort UA alone never labels a homepage or an entire source address.
    sa = config['scheduled_automation']
    if sa['enabled']:
        weeks = collections.defaultdict(dict)
        for row in features:
            if row['user_agent'] and row['method'] in ('GET', 'HEAD') and family(row['normalized_target']):
                key = (row['_host'], row['user_agent'])
                weeks[key].setdefault(cycle(row['timestamp']), []).append(row)
        for key, week_rows in weeks.items():
            signatures = collections.defaultdict(list)
            for week, rows in week_rows.items():
                monday = 4 * 86400 + week * 604800
                dates = {datetime.datetime.utcfromtimestamp(monday + i * 86400).strftime('%Y-%m-%d') for i in range(7)}
                if not dates <= valid_days:
                    continue
                shape = tuple(sorted({(phase(r['timestamp']), r['normalized_target']) for r in rows}))
                if not sa['min_phase_paths'] <= len(shape) <= 64:
                    continue
                if len({family(path) for _, path in shape}) < sa['min_families']:
                    continue
                if len({r['_client'] for r in rows}) < sa['min_sources']:
                    continue
                signatures[shape].append(week)
            for shape, supporting in signatures.items():
                if len(supporting) < sa['min_cycles']:
                    continue
                witnesses = [r for rows in week_rows.values() for r in rows
                             if (phase(r['timestamp']), r['normalized_target']) in shape]
                if (not witnesses or 100 * sum(r['_continuous'] for r in witnesses) >
                        sa['max_continuity_percent'] * len(witnesses)):
                    continue
                signature = identity({'vhost': key[0], 'agent_sha256': identity(key[1]), 'phase_paths': shape})
                result['signatures'].append({'signature_sha256': signature, 'cycles': len(supporting),
                                              'phase_paths': len(shape), 'families': len({family(p) for _, p in shape})})
                # L2 is explicitly a comparison, never a default classification.
                # Shared UA + calendar phase can falsely pool unrelated people.
                if sa['aggressive_comparison']:
                    clocks = collections.defaultdict(list)
                    for w in witnesses:
                        clocks[phase(w['timestamp'])].append(w['timestamp'] % 86400)
                    for gkey, own in groups.items():
                        if gkey[1:] != key:
                            continue
                        _, veto = group_info[gkey]
                        for entry in own:
                            times_of_day = clocks.get(phase(entry['timestamp']))
                            if (not times_of_day or entry['normalized_target'] not in ('/', '/index.php') or
                                    entry['method'] not in ('GET', 'HEAD') or entry['status'] not in (200, 301, 302, 307, 308)):
                                continue
                            clock = entry['timestamp'] % 86400
                            if not min(times_of_day) - sa['entry_seconds'] <= clock <= max(times_of_day) + sa['entry_seconds']:
                                continue
                            if veto(entry['timestamp'] - sa['entry_seconds'], entry['timestamp'] + sa['entry_seconds']):
                                continue
                            result['aggressive'][entry['_key']] = {'rule_id': 'aggressive_cohort_comparison_v1',
                                'signature_sha256': signature, 'corpus_sha256': result['context_sha256'],
                                'label': 'Aggressive candidate: shared claim/phase can include unrelated users; default retained'}
                for row in witnesses:
                    other_cycles = [w for w in supporting if w != cycle(row['timestamp'])]
                    if len(other_cycles) < sa['min_cycles']:
                        continue
                    gkey = (row['_client'], row['_host'], row['user_agent'])
                    times, veto = group_info[gkey]
                    if veto(row['timestamp'] - sa['entry_seconds'], row['timestamp'] + sa['entry_seconds']):
                        continue
                    proof = {'from': row['timestamp'], 'until': row['timestamp'], 'cycles': len(other_cycles),
                             'phase_paths': len(shape), 'families': len({family(p) for _, p in shape}),
                             'signature_sha256': signature, 'linked_entry': False}
                    mark(row, 'scheduled_automation', proof)
                    own = groups[gkey]
                    lo = bisect.bisect_left(times, row['timestamp'] - sa['entry_seconds'])
                    hi = bisect.bisect_right(times, row['timestamp'] + sa['entry_seconds'])
                    for entry in own[lo:hi]:
                        if (cycle(entry['timestamp']) == cycle(row['timestamp']) and entry['method'] in ('GET', 'HEAD') and
                                entry['status'] in (200, 301, 302, 307, 308) and
                                entry['normalized_target'] in ('/', '/index.php')):
                            linked = dict(proof, linked_entry=True)
                            linked.update({'from': min(entry['timestamp'], row['timestamp']),
                                           'until': max(entry['timestamp'], row['timestamp'])})
                            mark(entry, 'scheduled_automation', linked)

    isc = config['inferred_scanner']
    fingerprints = collections.defaultdict(set)
    if isc['enabled']:
        for row in features:
            proof = row.get('operator_inference_candidate') or {}
            if (proof.get('valid') == 1 and row['user_agent'] and PLATFORMLESS.fullmatch(row['user_agent']) and
                    abs(row['timestamp'] - proof['lookup_at']) <= isc['window_days'] * 86400):
                fingerprints[row['user_agent']].add(row['_client'])
        for row in features:
            proof = row.get('operator_inference_candidate') or {}
            ua = row['user_agent']
            if (row['source_month'] in isc['months'] and ua and len(fingerprints.get(ua, ())) >= isc['min_sources'] and
                    proof.get('valid') == 1 and abs(row['timestamp'] - proof['lookup_at']) <= isc['window_days'] * 86400):
                _, veto = group_info[(row['_client'], row['_host'], ua)]
                if veto(row['timestamp'] - 1800, row['timestamp'] + 1800):
                    continue
                mark(row, 'inferred_scanner', {'lookup_at': proof['lookup_at'], 'window_days': isc['window_days'],
                    'request_delta_seconds': row['timestamp'] - proof['lookup_at'], 'fingerprint_sources': len(fingerprints[ua]),
                    'fingerprint_sha256': identity(ua), 'dns_evidence_sha256': proof['evidence_sha256'],
                    'label': 'Inferred operator association; not verified historical identity or current membership'})
    dc = config['declared_automation']
    if dc['enabled']:
        for row in features:
            ua = row['user_agent'] or ''
            for token in dc['tokens']:
                if re.search(r'(?:^|[^A-Za-z0-9])' + re.escape(token) + r'(?=[\s/;)]|$)', ua, re.I):
                    mark(row, 'declared_automation', {'token': token, 'label': 'Declared automation (unverified)'})
                    break
    for values in result['matches'].values():
        for rule in values:
            result['rule_counts'][rule] += 1
    return result


def apply_report(report, day, analysis, config):
    """Add corpus evidence without changing actors or legacy expansion rights."""
    report['corpus_analysis'] = {k: analysis[k] for k in ('version', 'status', 'context_sha256', 'signatures')}
    old_counts = {rule: 0 for rule in RULES}
    included_ids = set(config['behavior_include'])
    report['behavior']['legacy_eligible_requests'] = report['behavior'].get('eligible_requests', 0)
    report['behavior']['corpus_eligible_requests'] = sum((day, r['line_index']) in analysis['eligible_keys'] for r in report['details'])
    if all('legacy_behavior_eligible' in r for r in report['details']):
        report['behavior']['eligible_requests'] = sum(bool(r['legacy_behavior_eligible']) or
            (day, r['line_index']) in analysis['eligible_keys'] for r in report['details'])
    for record in report['details']:
        aggressive = analysis['aggressive'].get((day, record['line_index']))
        if aggressive:
            record['aggressive_cohort_candidate'] = aggressive
        proofs = analysis['matches'].get((day, record['line_index']), {})
        old = bool(record['suspected_automation'])
        for rule in RULES:
            record[rule + '_flagged'] = rule in proofs
            if rule in proofs:
                record[rule + '_evidence'] = proofs[rule]
                old_counts[rule] += 1
        if not proofs:
            continue
        record['suspected_automation'] = True
        if not old:
            report['behavior']['flagged_requests'] += 1
            report['behavior']['actors'][record['actor']] += 1
        legacy_flags = sum(bool(record.get(key)) for key in (
            'broad_probing_flagged', 'probing_flagged', 'rapid_scan_flagged', 'distributed_login_flagged',
            'login_rotation_flagged', 'head_scan_flagged', 'sensitive_scan_flagged', 'wp_enumeration_flagged',
            'wp_query_probe_flagged', 'backdoor_probe_flagged', 'protocol_probe_flagged', 'service_discovery_flagged'))
        if legacy_flags < 2 and legacy_flags + len(proofs) >= 2:
            report['behavior']['overlap_requests'] += 1
        if record['request_id'] in included_ids:
            if not record['behavior_included']:
                report['behavior']['inclusion_overrides'] = report['behavior'].get('inclusion_overrides', 0) + 1
            record['behavior_included'] = True
        elif config['exclude']:
            record['excluded'] = True
    for rule, count in old_counts.items():
        report['behavior'][rule + '_flagged_requests'] = count
        report['behavior'][rule + '_rule'] = {'enabled': bool(config[rule]['enabled']),
            'rule_id': rule + '_v1', 'flagged_requests': count, 'evaluation_status': analysis['status']}
    report['behavior']['enabled'] = bool(report['behavior']['enabled'] or any(config[k]['enabled'] for k in RULES))
    report['behavior']['rule_id'] = 'behavior_union_v9'
    report['behavior']['flagged_source_groups'] = len({(r.get('source_key'), r.get('host'))
        for r in report['details'] if r['suspected_automation']})
    report['adjusted_requests']['excluded'] = sum(bool(r['excluded']) for r in report['details'])
    report['adjusted_requests']['remaining'] = report['counts']['analyzed'] - report['adjusted_requests']['excluded']
    # ip_expansion_eligible is deliberately never assigned or broadened here.
    return report
