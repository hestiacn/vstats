#!/usr/bin/env python3
"""Build private filtered daily logs and an escaped, reviewable HTML snapshot.

Optional Python 3.6+ orchestration. The Perl classifier remains the sole detector.
No network access, native-history edits, deployment or web backend is provided.
"""
import argparse
import collections
import datetime
import hashlib
import html
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
RECORD = re.compile(rb'^\S+ \S+ \S+ \[[^\]]+\] "((?:[^"\\]|\\.)*)" ([1-5][0-9]{2}) ([0-9]+|-) ')
CLAIM = re.compile(r'(?:^|[^A-Za-z0-9])((?:Chrome|CriOS|Firefox|FxiOS|Safari|Edg|OPR|Opera)/[0-9][0-9.]{0,31})', re.I | re.A)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def private_write(path, raw):
    with path.open('xb') as handle:
        os.chmod(str(path), 0o600)
        handle.write(raw)


def page(title, body):
    return ("<!doctype html><html lang='en'><meta charset='utf-8'>"
            "<meta name='robots' content='noindex,nofollow'><title>" + html.escape(title) +
            "</title><style>body{font:15px system-ui,sans-serif;margin:24px}"
            "table{border-collapse:collapse;width:100%}th,td{border:1px solid #cbd5e1;padding:8px;text-align:left;vertical-align:top}"
            "th{background:#eef2f6}code{overflow-wrap:anywhere}nav,section{margin:16px 0}"
            ".included{background:#effaf0}small{display:block}button{cursor:pointer}</style><body>" +
            body + "</body></html>").encode('utf-8')


def controls(prefix, exclude_automated_ips=True):
    default = ('Exclude flagged IPs (default)' if exclude_automated_ips else
               'Request-only filtering (default; IP exclusion disabled)')
    return ("<nav><a href='" + prefix + "'>" + default + "</a> &middot; "
            "<a href='" + prefix + "requests/'>Disable IP exclusion; filter matched requests only</a> &middot; "
            "<a href='" + prefix + "confirmed/'>Include suspected automation</a> &middot; "
            "<a href='" + prefix + "original/'>Original rules</a> &middot; "
            "<a href='" + prefix + "behavior-exclusions/'>Review exclusions</a></nav>")


def rule_evidence(record):
    """Keep independent covering witnesses when a request matches both rules."""
    result = []
    broad = record.get('broad_probing_flagged', bool(record.get('behavior_evidence')))
    for matched, label, key in [(broad, 'Broad path probing', 'behavior_evidence'),
                                (record.get('probing_flagged'), 'Endpoint probing', 'probing_evidence')]:
        if not matched:
            continue
        proof = record.get(key)
        if not proof or not proof['from'] <= record['timestamp'] <= proof['until']:
            raise RuntimeError('Review lacks a covering rule witness')
        result.append((label, proof))
    if record.get('ip_excluded'):
        evidence = record.get('ip_automation_evidence')
        if (not evidence or record.get('source_month_key') != evidence['source_month_key'] or
                record.get('source_month') != evidence['source_month'] or
                not re.fullmatch(r'[0-9a-f]{64}', evidence['trigger_request_id']) or not evidence['rules']):
            raise RuntimeError('Review lacks a same-IP/month trigger')
        for timestamp in (record['timestamp'], evidence['trigger_timestamp']):
            if datetime.datetime.utcfromtimestamp(timestamp).strftime('%Y-%m') != evidence['source_month']:
                raise RuntimeError('IP trigger crosses the report month')
        for item in evidence['rules']:
            proof = item['proof']
            if item['rule'] not in ('Broad path probing', 'Endpoint probing') or not proof['from'] <= evidence['trigger_timestamp'] <= proof['until']:
                raise RuntimeError('IP trigger lacks a covering rule witness')
    if not result and not record.get('ip_excluded'):
        raise RuntimeError('Review lacks a covering rule witness')
    return result


def render_review_row(record):
    stamp = datetime.datetime.utcfromtimestamp(record['timestamp']).isoformat() + 'Z'
    match = CLAIM.search(record.get('user_agent') or '')
    claim = match.group(1) if match else 'browser marker'
    platform = record.get('behavior_platform') or 'unknown'
    state = ('Included by request ID override' if record['behavior_included'] else
             'Excluded by automated-IP policy' if record.get('ip_excluded') and not record['suspected_automation'] else
             'Excluded by behavior and automated-IP policy' if record.get('ip_excluded') else 'Excluded by behavior filter')
    reasons = []
    for label, proof in rule_evidence(record):
        reason = label + ': ' + ('{requests} requests; {distinct_user_agents} user agents; '
                                '{distinct_platforms} platforms; {distinct_paths} paths; '
                                '{not_found_requests} HTTP 404s').format(**proof)
        reason += ' in {} seconds'.format(proof['until'] - proof['from'])
        if label == 'Endpoint probing':
            reason += ' (configured endpoints; no 404 requirement)'
        reasons.append(reason)
    if record.get('ip_excluded'):
        evidence = record['ip_automation_evidence']
        trigger_time = datetime.datetime.utcfromtimestamp(evidence['trigger_timestamp']).isoformat() + 'Z'
        reasons.append('Automated IP for ' + evidence['source_month'] + '; triggered at ' + trigger_time +
                       ' by request ' + evidence['trigger_request_id'] +
                       '. Applies to this whole site month, not just the trigger window.')
        for item in evidence['rules']:
            proof = item['proof']
            reasons.append('Trigger evidence, ' + item['rule'] + ': ' +
                           ('{requests} requests; {distinct_user_agents} user agents; {distinct_platforms} platforms; '
                            '{distinct_paths} paths; {not_found_requests} HTTP 404s').format(**proof) +
                           ' in {} seconds'.format(proof['until'] - proof['from']))
    reason = ' | '.join(reasons)
    request_id = record['request_id']
    if not re.fullmatch(r'[0-9a-f]{64}', request_id):
        raise ValueError('Invalid request ID')
    cells = [stamp, record['client'], record.get('method', ''), record['normalized_target'] or '[unsupported path]',
             str(record['status']), claim + ' / ' + platform, state, reason]
    return ("<tr class='" + ('included' if record['behavior_included'] else 'excluded') + "'>" +
            ''.join('<td>' + html.escape(value) + '</td>' for value in cells) +
            "<td><code>" + request_id + "</code><button data-request-id='" + request_id +
            "'>Copy request ID</button></td></tr>")


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result


def physical_records(raw):
    parts = raw.split(b'\n')
    for offset, line in enumerate(parts):
        terminated = offset < len(parts) - 1
        if not terminated and not line:
            break
        logical = line[:-1] if terminated and line.endswith(b'\r') else line
        yield offset + 1, logical, line + (b'\n' if terminated else b'')


def filtered_bytes(raw, omitted, input_sha256):
    if digest(raw) != input_sha256:
        raise RuntimeError('Input changed during policy export')
    records = list(physical_records(raw))
    if not omitted.issubset({index for index, _, _ in records}):
        raise RuntimeError('Selection references nonexistent physical records')
    kept = b''.join(piece for index, _, piece in records if index not in omitted)
    return kept, {'input_sha256': input_sha256, 'sha256': digest(kept),
                  'input_log_bytes': len(raw), 'kept_log_bytes': len(kept),
                  'removed_log_bytes': len(raw) - len(kept), 'input_records': len(records),
                  'excluded_records': len(omitted), 'kept_records': len(records) - len(omitted)}


def pagination(month, part, pages):
    # Bounded navigation keeps large IP-policy reviews linear in page count.
    indices = sorted({0, pages - 1} | set(range(max(0, part - 2), min(pages, part + 3))))
    return '<nav>' + ' &middot; '.join("<a href='{}-{:03d}.html'>{}</a>".format(month, i + 1, i + 1)
                                       for i in indices) + '</nav>'


def build(config, input_directory, output_directory, perl='perl', prefix='/vstats/example.test/', page_size=200,
          exclude_automated_ips=True):
    config, inputs, output = Path(config), Path(input_directory), Path(output_directory)
    if type(exclude_automated_ips) is not bool:
        raise ValueError('IP exclusion must be a boolean')
    if not 1 <= page_size <= 1000:
        raise ValueError('Invalid page size')
    if not re.fullmatch(r'/[A-Za-z0-9._/-]+/', prefix) or '..' in prefix.split('/') or '//' in prefix:
        raise ValueError('Invalid site URL prefix')
    if inputs.is_symlink() or not inputs.is_dir() or output.exists() or output.is_symlink():
        raise ValueError('Input must be a real directory and output must not exist')
    inp, out = inputs.resolve(), output.resolve()
    if inp == out or inp in out.parents or out in inp.parents:
        raise ValueError('Input and output directories must be separate')
    raw_config = config.read_bytes()
    cfg = json.loads(raw_config.decode('utf-8'), object_pairs_hook=strict_object)
    if not isinstance(cfg, dict) or cfg.get('exclude') != ['suspected_automation']:
        raise ValueError('Review builder requires exactly the suspected automation selector')
    days = sorted(inputs.glob('????-??-??.log'))
    if not days:
        raise ValueError('No daily input partitions')
    for path in days:
        datetime.datetime.strptime(path.stem, '%Y-%m-%d')
        if path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError('Daily input must be a regular file')
    output.mkdir(mode=0o700)
    for name in ['filtered', 'request-filtered', 'reports', 'classification', 'review']:
        (output / name).mkdir(mode=0o700)
    totals, actors, behavior = collections.Counter(), collections.Counter(), collections.Counter()
    excluded_by_month, request_excluded_by_month, flagged_by_month = {}, {}, collections.Counter()
    daily, review_rows, triggers = [], collections.defaultdict(list), {}
    first = last = None
    # First classify every partition before applying IP policy. A later day can
    # seed an exclusion for earlier requests in the same UTC month.
    for source in days:
        day = source.stem
        report_path = output / 'reports' / (day + '.json')
        request_filtered = output / 'request-filtered' / (day + '.log')
        command = [perl, str(ROOT / 'traffic-classify.pl'), '--config', str(config), '--input', str(source),
                   '--input-format', 'combined', '--output', str(report_path), '--details', '--filtered-log', str(request_filtered)]
        child = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
        if child.returncode or child.stderr or child.stdout:
            raise RuntimeError('Daily classification failed')
        report = json.loads(report_path.read_bytes().decode('utf-8'))
        manifest = report['filtered_log']
        raw = source.read_bytes()
        if digest(raw) != report['input_sha256'] or digest(request_filtered.read_bytes()) != manifest['sha256']:
            raise RuntimeError('Input or request-filtered output changed')
        expected, expected_manifest = filtered_bytes(raw, {r['line_index'] for r in report['details'] if r['excluded']}, report['input_sha256'])
        if expected_manifest != manifest or expected != request_filtered.read_bytes():
            raise RuntimeError('Request selection differs from classification')
        period = report['input']['period']
        start = datetime.datetime.strptime(day, '%Y-%m-%d').replace(tzinfo=datetime.timezone.utc).timestamp()
        if not start <= period['from'] <= period['until'] < start + 86400:
            raise ValueError('Input partition does not match its UTC day')
        for record in report['details']:
            if record.get('source_month') != day[:7]:
                raise RuntimeError('Classifier lacks matching source/month metadata')
            if not record['suspected_automation']:
                continue
            witnesses = rule_evidence(record)
            key = record.get('source_month_key')
            if not key:
                raise RuntimeError('Behavior trigger lacks a canonical source')
            trigger = {'source_month_key': key, 'source_month': record['source_month'], 'client': record['client'],
                       'trigger_request_id': record['request_id'], 'trigger_timestamp': record['timestamp'],
                       'rules': [{'rule': label, 'proof': proof} for label, proof in witnesses]}
            previous = triggers.get(key)
            if previous is None or (trigger['trigger_timestamp'], trigger['trigger_request_id']) < (previous['trigger_timestamp'], previous['trigger_request_id']):
                triggers[key] = trigger
            if len(triggers) > report['effective']['limits']['groups']:
                raise ValueError('IP/month policy group cap exceeded')
        totals.update(report['counts'])
        actors.update(report['actors'])
        for key in ['flagged_requests', 'eligible_requests', 'insufficient_fields', 'merged_sequences', 'flagged_source_groups',
                    'inclusion_overrides', 'broad_flagged_requests', 'probing_flagged_requests', 'overlap_requests']:
            behavior[key] += report['behavior'].get(key, 0)
        flagged_by_month[day[:7]] += report['behavior']['flagged_requests']
        first = period['from'] if first is None else min(first, period['from'])
        last = period['until'] if last is None else max(last, period['until'])
        daily.append({'day': day, 'counts': report['counts'], 'actors': report['actors'], 'behavior': report['behavior'],
                      'input_sha256': report['input_sha256'], 'request_filtered_log': manifest,
                      'config_sha256': report['config_sha256'], 'period': period})
    context = {}
    for month in sorted({entry['day'][:7] for entry in daily}):
        binding = {'policy': 'vstats-ip-month-v1', 'enabled': exclude_automated_ips, 'config_sha256': digest(raw_config),
                   'inputs': [(entry['day'], entry['input_sha256']) for entry in daily if entry['day'].startswith(month)],
                   'triggers': [(key, value['trigger_request_id']) for key, value in sorted(triggers.items()) if value['source_month'] == month]}
        context[month] = digest(json.dumps(binding, sort_keys=True).encode('utf-8'))
    include_ids = set(cfg.get('behavior_include', []))
    additional, ip_overrides, restored = 0, 0, set()
    render = ("use strict;use warnings;use JSON::PP;use VStats::TrafficClassifier;"
              "binmode STDIN,':raw';binmode STDOUT,':raw';my $b=do{local $/;<STDIN>};"
              "print VStats::TrafficClassifier::html_report(JSON::PP->new->utf8->decode($b));")
    for entry, source in zip(daily, days):
        day, month = entry['day'], entry['day'][:7]
        report = json.loads((output / 'reports' / (day + '.json')).read_bytes().decode('utf-8'))
        details = report.pop('details')
        report.pop('details_warning', None)
        raw = source.read_bytes()
        if digest(raw) != entry['input_sha256']:
            raise RuntimeError('Input changed between classification and IP policy')
        records = {index: (logical, piece) for index, logical, piece in physical_records(raw)}
        default_omitted = set()
        ledger = excluded_by_month.setdefault(month, {'records': 0, 'response_body_bytes': 0})
        request_ledger = request_excluded_by_month.setdefault(month, {'records': 0, 'response_body_bytes': 0})
        day_additional = 0
        for record in details:
            direct = bool(record['excluded'])
            trigger = triggers.get(record.get('source_month_key'))
            ip_selected = bool(exclude_automated_ips and trigger)
            included = bool(record['behavior_included'] or (ip_selected and record['request_id'] in include_ids))
            excluded = direct or (ip_selected and not included)
            if excluded:
                default_omitted.add(record['line_index'])
            if not (record['suspected_automation'] or ip_selected):
                continue
            logical, _ = records[record['line_index']]
            match = RECORD.match(logical)
            if not match or int(match[2]) != record['status'] or digest(logical) != record['request_id']:
                raise RuntimeError('Review could not bind the original request')
            record['method'] = match[1].split(b' ', 1)[0].decode('ascii')
            record['response_body_bytes'] = 0 if record['status'] == 304 or match[3] == b'-' else int(match[3])
            record.update(request_excluded=direct, ip_excluded=ip_selected, excluded=excluded,
                          behavior_included=included, ip_automation_evidence=trigger if ip_selected else None)
            rule_evidence(record)
            review_rows[month].append(record)
            if direct:
                request_ledger['records'] += 1
                request_ledger['response_body_bytes'] += record['response_body_bytes']
            if excluded:
                ledger['records'] += 1
                ledger['response_body_bytes'] += record['response_body_bytes']
            if excluded and not direct:
                additional += 1
                day_additional += 1
            if ip_selected and included:
                ip_overrides += 1
                restored.add(record['source_month_key'])
        kept, manifest = filtered_bytes(raw, default_omitted, entry['input_sha256'])
        private_write(output / 'filtered' / (day + '.log'), kept)
        entry.update(filtered_log=manifest, ip_policy_sha256=context[month], additional_ip_exclusions=day_additional)
        child = subprocess.run([perl, '-I' + str(ROOT / 'lib'), '-e', render],
                               input=json.dumps(report, sort_keys=True).encode('utf-8'), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
        if child.returncode or child.stderr:
            raise RuntimeError('Aggregate HTML rendering failed')
        note = ('<p>Request-level classification. The native default additionally excludes flagged IPs for the UTC month; '
                'additional IP-policy exclusions on this day: ' + format(day_additional, ',') + '.</p>' if exclude_automated_ips else
                '<p>IP exclusion is disabled; only individually matched requests are filtered.</p>')
        text = child.stdout.decode('utf-8').replace('<body>', '<body>' + controls(prefix, exclude_automated_ips) + note +
                "<p>UTC day: " + day + ". <a href='index.html'>Classification overview</a></p>", 1)
        private_write(output / 'classification' / (day + '.html'), text.encode('utf-8'))
    generated = datetime.datetime.utcnow().isoformat() + 'Z'
    scope = ('<p>Updated ' + generated + '. Complete configured site corpus; behavior windows use independent UTC days. '
             'A detected source can exclude its other requests throughout the same UTC month, including earlier days. '
             'No exclusion carries into another month without new evidence. Counts are requests, not verified people. '
             'Some removals were already non-viewed under native rules. No geography is used.</p>')
    disclaimer = ('<p>IP exclusion is ' + ('enabled by default' if exclude_automated_ips else 'disabled') +
                  '. Shared proxies, dynamic addresses and authorized automation can qualify. '
                  'Use the request-only view to disable IP expansion. Individual <code>behavior_include</code> request IDs '
                  'are explicit exceptions and may restore the IP to visitor counts. Copying an ID does not save server settings. '
                  'Byte-identical records share an ID. Detection flags remain separate from IP-policy exclusions.</p>')
    review_links = []
    nav = controls(prefix, exclude_automated_ips)
    for month, rows in sorted(review_rows.items(), reverse=True):
        rows.sort(key=lambda r: (r['timestamp'], r['request_id']))
        pages = (len(rows) + page_size - 1) // page_size
        for part in range(pages):
            links = pagination(month, part, pages)
            table = '<table><tr>' + ''.join('<th>' + h + '</th>' for h in ['UTC time', 'Source IP', 'Method', 'Path (query removed)',
                     'HTTP', 'Browser/platform claim', 'Decision', 'Rule or IP-exclusion evidence', 'Request ID']) + '</tr>'
            table += ''.join(render_review_row(r) for r in rows[part * page_size:(part + 1) * page_size]) + '</table>'
            script = ("<script>document.querySelectorAll('[data-request-id]').forEach(function(b){b.addEventListener('click',function(){"
                      "navigator.clipboard.writeText(b.dataset.requestId).then(function(){b.textContent='ID copied';});});});</script>")
            private_write(output / 'review' / '{}-{:03d}.html'.format(month, part + 1), page('Review exclusions', nav +
                          '<h1>Review exclusions: ' + month + '</h1>' + scope + disclaimer + links + table + links + script))
        review_links.append("<li id='" + month + "'><a href='" + month + "-001.html'>" + month + '</a>: ' +
                            format(excluded_by_month[month]['records'], ',') + ' excluded records; ' +
                            format(flagged_by_month[month], ',') + ' individually behavior-flagged requests</li>')
    total_removed = sum(v['records'] for v in excluded_by_month.values())
    description = ('<p>Individually behavior-flagged: <strong>' + format(behavior['flagged_requests'], ',') +
                   '</strong>; requests actually removed by the default view: <strong>' + format(total_removed, ',') +
                   '</strong>; additional IP-policy removals: ' + format(additional, ',') +
                   '; flagged IP/months: ' + format(len(triggers), ',') +
                   '. Broad path probing: ' + format(behavior['broad_flagged_requests'], ',') +
                   '; endpoint probing: ' + format(behavior['probing_flagged_requests'], ',') +
                   '; overlap: ' + format(behavior['overlap_requests'], ',') +
                   '. Full raw user-agent strings and query strings are omitted from review.</p>')
    private_write(output / 'review/index.html', page('Review exclusions', nav + '<h1>Review exclusions</h1>' + scope +
                  '<!-- NATIVE_EFFECT -->' + disclaimer + description + '<ul>' + ''.join(review_links) + '</ul>'))
    class_rows = ''.join("<tr><td><a href='" + r['day'] + ".html'>" + r['day'] + '</a></td><td>' +
                         format(r['counts']['analyzed'], ',') + '</td><td>' + format(r['behavior']['flagged_requests'], ',') +
                         '</td><td>' + format(r['request_filtered_log']['excluded_records'], ',') + '</td><td>' +
                         format(r['additional_ip_exclusions'], ',') + '</td><td>' + format(r['filtered_log']['excluded_records'], ',') + '</td></tr>' for r in daily)
    private_write(output / 'classification/index.html', page('Traffic classification', nav + '<h1>Traffic classification and visitor policy</h1>' +
                  scope + disclaimer + description + '<p>Analyzed requests: ' + format(totals['analyzed'], ',') + '; unparsed: ' +
                  format(totals['unparsed'], ',') + '. Provider evidence is applied by the separate native confirmed-crawler layer.</p>' +
                  '<table><tr><th>UTC day</th><th>Analyzed</th><th>Behavior flagged</th><th>Request-only removed</th>' +
                  '<th>Additional IP-policy removals</th><th>Default removed</th></tr>' + class_rows + '</table>'))
    policy = {'algorithm_id': 'vstats-ip-month-v1', 'enabled': exclude_automated_ips, 'scope': 'provided site input and UTC month',
              'flagged_source_months': len(triggers), 'source_month_counts': dict(collections.Counter(t['source_month'] for t in triggers.values())),
              'additional_excluded_requests': additional, 'inclusion_overrides': ip_overrides,
              'private_source_months': triggers, 'restored_source_months': sorted(restored), 'context_sha256_by_month': context}
    summary = {'schema_version': 1, 'generated_utc': generated, 'counts': dict(totals), 'actors': dict(actors), 'behavior': dict(behavior),
               'excluded_by_month': excluded_by_month, 'request_excluded_by_month': request_excluded_by_month,
               'flagged_by_month': dict(flagged_by_month), 'ip_exclusion': policy, 'daily_reports': daily,
               'period': {'from': first, 'until': last}, 'config_raw_sha256': digest(raw_config),
               'limitations': ['Daily detection windows may miss midnight crossings.', 'Heuristics; not calibrated identity or intent.',
                               'Whole-IP policy can remove legitimate traffic behind shared/dynamic addresses.',
                               'Input must contain the intended site/month coverage; unparsed or unattributable rows remain preserved.'],
               'classification_files': {path.name: digest(path.read_bytes()) for path in sorted((output / 'classification').iterdir())},
               'review_files': {path.name: digest(path.read_bytes()) for path in sorted((output / 'review').iterdir())}}
    private_write(output / 'summary.json', (json.dumps(summary, sort_keys=True, indent=2) + '\n').encode('utf-8'))
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--input-directory', required=True)
    parser.add_argument('--output-directory', required=True)
    parser.add_argument('--perl', default='perl')
    parser.add_argument('--site-url-prefix', default='/vstats/example.test/')
    parser.add_argument('--page-size', type=int, default=200)
    parser.add_argument('--include-automated-ips', action='store_true',
                        help='Disable default whole-IP/month exclusion; retain request-only filtering')
    args = parser.parse_args()
    build(args.config, args.input_directory, args.output_directory, args.perl, args.site_url_prefix, args.page_size,
          exclude_automated_ips=not args.include_automated_ips)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError):
        print('traffic-filter-report: analysis or output failed; keep prior published view', file=sys.stderr)
        sys.exit(1)
