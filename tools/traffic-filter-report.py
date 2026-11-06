#!/usr/bin/env python3
"""Build private filtered daily logs and an escaped, reviewable HTML snapshot.

Optional Python 3.6+ orchestration. The Perl classifier remains the sole detector.
No network access, native-history edits, deployment or web backend is provided.
"""
import argparse
import shutil
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


def validate_distributed_witness(proof):
    counts = ['requests', 'post_requests', 'distinct_sources', 'distinct_user_agents', 'distinct_platforms',
              'source_requests', 'source_post_requests', 'source_distinct_user_agents',
              'source_distinct_platforms', 'source_shared_user_agents']
    if any(type(proof.get(key)) is not int or proof[key] < 1 for key in counts):
        raise RuntimeError('Invalid distributed-login witness counts')
    if (not 2 <= proof['distinct_sources'] or
            not 2 <= proof['source_distinct_platforms'] <= proof['source_distinct_user_agents'] <= proof['source_post_requests'] < proof['source_requests'] <= proof['requests'] or
            not proof['source_post_requests'] <= proof['post_requests'] < proof['requests'] or
            not proof['source_distinct_user_agents'] <= proof['distinct_user_agents'] <= proof['post_requests'] or
            not proof['source_distinct_platforms'] <= proof['distinct_platforms'] <= proof['distinct_user_agents'] or
            proof['source_shared_user_agents'] > proof['source_distinct_user_agents']):
        raise RuntimeError('Inconsistent distributed-login source/pool evidence')
    for key in ['campaign_id', 'sequence_post_request_id', 'sequence_follow_request_id']:
        if not re.fullmatch(r'[0-9a-f]{64}', proof.get(key, '')):
            raise RuntimeError('Invalid distributed-login witness identity')
    if (not proof['from'] <= proof['sequence_post_timestamp'] <= proof['sequence_follow_timestamp'] <= proof['until'] or
            proof['sequence_post_request_id'] == proof['sequence_follow_request_id']):
        raise RuntimeError('Invalid distributed-login follow-up evidence')


def witness_text(label, proof):
    if label == 'Distributed login probing':
        validate_distributed_witness(proof)
        return (('Campaign: {requests} requests from {distinct_sources} sources; {post_requests} login POSTs; '
                 '{distinct_user_agents} POST user agents; {distinct_platforms} POST platforms. '
                 'This source: {source_requests} requests; {source_post_requests} login POSTs; '
                 '{source_distinct_user_agents} POST user agents; {source_distinct_platforms} POST platforms; '
                 '{source_shared_user_agents} POST user agents shared with qualifying peers. '
                 'POST/follow-up witnesses: {sequence_post_request_id}, {sequence_follow_request_id}.').format(**proof) +
                ' Campaign window: {} seconds; campaign {}. Coherent same-UA flow protection applied to intersecting windows; heuristic evidence, not login success or actor identity.'.format(
                    proof['until'] - proof['from'], proof['campaign_id']))
    reason = ('{requests} requests; {distinct_user_agents} user agents; {distinct_platforms} platforms; '
              '{distinct_paths} paths; {not_found_requests} HTTP 404s').format(**proof)
    reason += ' in {} seconds'.format(proof['until'] - proof['from'])
    if label == 'Endpoint probing':
        reason += ' (configured endpoints; no 404 requirement)'
    if label == 'Rapid content-path probing':
        reason += ' (content paths; no browser rotation requirement)'
    return reason


def rule_evidence(record):
    """Keep independent covering witnesses for every matching behavioral rule."""
    result = []
    broad = record.get('broad_probing_flagged', bool(record.get('behavior_evidence')))
    for matched, label, key in [(broad, 'Broad path probing', 'behavior_evidence'),
                                (record.get('probing_flagged'), 'Endpoint probing', 'probing_evidence'),
                                (record.get('rapid_scan_flagged'), 'Rapid content-path probing', 'rapid_scan_evidence'),
                                (record.get('distributed_login_flagged'), 'Distributed login probing', 'distributed_login_evidence')]:
        if not matched:
            continue
        proof = record.get(key)
        if not proof or not proof['from'] <= record['timestamp'] <= proof['until']:
            raise RuntimeError('Review lacks a covering rule witness')
        if label == 'Distributed login probing':
            validate_distributed_witness(proof)
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
            if item['rule'] not in ('Broad path probing', 'Endpoint probing', 'Rapid content-path probing', 'Distributed login probing') or not proof['from'] <= evidence['trigger_timestamp'] <= proof['until']:
                raise RuntimeError('IP trigger lacks a covering rule witness')
            if item['rule'] == 'Distributed login probing':
                validate_distributed_witness(proof)
    if not result and not record.get('ip_excluded'):
        raise RuntimeError('Review lacks a covering rule witness')
    return result


def render_review_row(record):
    stamp = datetime.datetime.utcfromtimestamp(record['timestamp']).isoformat() + 'Z'
    match = CLAIM.search(record.get('user_agent') or '')
    claim = match.group(1) if match else 'no recognized browser claim'
    platform = record.get('behavior_platform') or 'unknown'
    state = ('Included by request ID override' if record['behavior_included'] else
             'Excluded by automated-IP policy' if record.get('ip_excluded') and not record['suspected_automation'] else
             'Excluded by behavior and automated-IP policy' if record.get('ip_excluded') else 'Excluded by behavior filter')
    reasons = []
    for label, proof in rule_evidence(record):
        reasons.append(label + ': ' + witness_text(label, proof))
    if record.get('ip_excluded'):
        evidence = record['ip_automation_evidence']
        trigger_time = datetime.datetime.utcfromtimestamp(evidence['trigger_timestamp']).isoformat() + 'Z'
        reasons.append('Automated IP for ' + evidence['source_month'] + '; triggered at ' + trigger_time +
                       ' by request ' + evidence['trigger_request_id'] +
                       '. Applies to this whole site month, not just the trigger window.')
        for item in evidence['rules']:
            proof = item['proof']
            reasons.append('Trigger evidence, ' + item['rule'] + ': ' + witness_text(item['rule'], proof))
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


RETENTION_REASONS = {
    'disabled': 'Distributed-login detection disabled',
    'insufficient_fields': 'Insufficient source, method, target, status or browser/platform evidence',
    'other_route': 'Outside configured login/admin method and path combinations',
    'coherent_flow_window': 'Candidate window overlaps a coherent same-UA POST/follow-up',
    'source_post_count': 'Insufficient repeated login POSTs from this source',
    'source_agent_diversity': 'Insufficient POST user-agent variation from this source',
    'source_platform_diversity': 'Insufficient POST platform variation from this source',
    'source_followup_missing': 'No ordered POST/follow-up from this source in the candidate window',
    'peer_agent_evidence': 'Insufficient POST agents shared with surviving participants',
    'campaign_sources': 'Insufficient independently participating sources in the window',
    'campaign_requests': 'Insufficient pooled requests in the window',
    'campaign_posts': 'Insufficient pooled login POSTs in the window',
    'campaign_agent_diversity': 'Insufficient pooled POST user-agent variation',
    'campaign_platform_diversity': 'Insufficient pooled POST platform variation',
    'request_id_override': 'Explicit request-ID inclusion override',
    'no_behavior_witness': 'No qualifying evidence from enabled behavioral rules'}


def source_summary(groups, record, excluded, included, cap):
    key = record.get('source_month_key')
    if not key:
        return False
    if key not in groups:
        if len(groups) >= cap:
            raise ValueError('Source-review group cap exceeded')
        groups[key] = {'client': record['client'], 'month': record['source_month'], 'source_key': record['source_key'],
                       'requests': 0, 'retained': 0, 'excluded': 0, 'login_posts': 0,
                       'actors': collections.Counter(), 'reasons': collections.Counter(), 'examples': {}}
    group = groups[key]
    group['requests'] += 1
    group['excluded' if excluded else 'retained'] += 1
    if excluded:
        return True
    group['actors'][record['actor']] += 1
    diagnostics = record.get('distributed_login_diagnostics') or []
    if record.get('method') == 'POST' and any('source_post_requests' in d for d in diagnostics):
        group['login_posts'] += 1
    reasons = {'request_id_override'} if included else {
        reason for diagnostic in diagnostics for reason in diagnostic['reasons'] if reason != 'qualified'}
    if not reasons:
        reasons = {'no_behavior_witness'}
    for reason in reasons:
        if reason not in RETENTION_REASONS:
            raise RuntimeError('Unknown source-review diagnostic')
        group['reasons'][reason] += 1
        if reason in group['examples']:
            continue
        diagnostic = next((d for d in diagnostics if reason in d['reasons'] and 'source_requests' in d), None)
        if diagnostic:
            group['examples'][reason] = {k: diagnostic[k] for k in [
                'from', 'until', 'source_requests', 'source_post_requests', 'source_distinct_user_agents',
                'source_distinct_platforms', 'source_shared_user_agents', 'requests', 'post_requests', 'distinct_sources']
                if k in diagnostic}
    return True


def campaign_summary(groups, record, cap):
    if not record.get('distributed_login_flagged'):
        return
    proof = record['distributed_login_evidence']
    validate_distributed_witness(proof)
    key = (record['source_month'], proof['campaign_id'], record['source_key'])
    if key not in groups:
        if len(groups) >= cap:
            raise ValueError('Campaign-review group cap exceeded')
        groups[key] = {'month': record['source_month'], 'campaign_id': proof['campaign_id'],
                       'client': record['client'], 'proof': proof, 'primary_requests': 0}
    groups[key]['primary_requests'] += 1


def diagnostic_text(example):
    text = ('Example source window: {source_requests} requests; {source_post_requests} login POSTs; '
            '{source_distinct_user_agents} POST agents; {source_distinct_platforms} POST platforms').format(**example)
    if 'source_shared_user_agents' in example:
        text += '; {} shared POST agents'.format(example['source_shared_user_agents'])
    if 'distinct_sources' in example:
        text += '. Pool: {} requests, {} login POSTs, {} sources'.format(
            example['requests'], example['post_requests'], example['distinct_sources'])
    text += '. UTC {} through {}'.format(
        datetime.datetime.utcfromtimestamp(example['from']).isoformat() + 'Z',
        datetime.datetime.utcfromtimestamp(example['until']).isoformat() + 'Z')
    return text


def write_source_reviews(output, groups, campaigns, nav, scope, page_size):
    retained = collections.defaultdict(list)
    grouped_campaigns = collections.defaultdict(list)
    for group in groups.values():
        if group['requests'] != group['retained'] + group['excluded']:
            raise RuntimeError('Source-review accounting mismatch')
        if group['retained']:
            retained[group['month']].append(group)
    for group in campaigns.values():
        grouped_campaigns[group['month']].append(group)
    links = []
    for month, rows in sorted(retained.items(), reverse=True):
        rows.sort(key=lambda r: r['source_key'])
        pages = (len(rows) + page_size - 1) // page_size
        note = ('<p>These analyzed requests were retained by the behavioral filter. Native crawler, error and other '
                'AWStats rules may still treat them as non-viewed. Retention does not verify a human visitor. '
                'The reasons describe distributed-login diagnostics; explicit inclusion overrides are listed separately. '
                'Reason counts can overlap. Numeric window evidence can include neighboring days; request totals below '
                'count only primary requests in this UTC month.</p>')
        for part in range(pages):
            table = '<table><tr><th>Source IP</th><th>Analyzed / retained / excluded requests</th><th>Retained actor labels</th><th>Why retained</th></tr>'
            for row in rows[part * page_size:(part + 1) * page_size]:
                reasons = []
                for reason, count in sorted(row['reasons'].items()):
                    item = html.escape(RETENTION_REASONS[reason]) + ': ' + format(count, ',') + ' requests'
                    if reason in row['examples']:
                        item += '<details><summary>Numeric example</summary>' + html.escape(diagnostic_text(row['examples'][reason])) + '</details>'
                    reasons.append('<li>' + item + '</li>')
                actors = '; '.join(k + ': ' + format(v, ',') for k, v in sorted(row['actors'].items()))
                table += ("<tr class='retained-source'><td>" + html.escape(row['client']) +
                          '</td><td>{:,} / {:,} / {:,}</td><td>'.format(row['requests'], row['retained'], row['excluded']) +
                          html.escape(actors) + '</td><td><ul>' + ''.join(reasons) + '</ul></td></tr>')
            table += '</table>'
            paging = pagination('retained-' + month, part, pages)
            private_write(output / 'review' / ('retained-{}-{:03d}.html'.format(month, part + 1)),
                          page('Why sources were retained', nav + '<h1>Why sources were retained: ' + month + '</h1>' +
                               scope + note + paging + table + paging))
        links.append("<li><a href='retained-" + month + "-001.html'>" + month + '</a>: ' +
                     format(len(rows), ',') + ' source/months; ' + format(sum(r['retained'] for r in rows), ',') +
                     ' analyzed requests retained</li>')
    campaign_links = []
    for month, rows in sorted(grouped_campaigns.items(), reverse=True):
        rows.sort(key=lambda r: (r['proof']['from'], r['campaign_id'], r['client']))
        pages = (len(rows) + page_size - 1) // page_size
        for part in range(pages):
            table = '<table><tr><th>Campaign ID</th><th>Source IP</th><th>Flagged primary requests this month</th><th>Campaign and source evidence</th></tr>'
            for row in rows[part * page_size:(part + 1) * page_size]:
                table += ("<tr class='campaign-source'><td><code>" + html.escape(row['campaign_id']) + '</code></td><td>' +
                          html.escape(row['client']) + '</td><td>' + format(row['primary_requests'], ',') + '</td><td>' +
                          html.escape(witness_text('Distributed login probing', row['proof'])) + '</td></tr>')
            table += '</table>'
            paging = pagination('campaign-' + month, part, pages)
            private_write(output / 'review' / ('campaign-{}-{:03d}.html'.format(month, part + 1)),
                          page('Campaign source contributions', nav + '<h1>Campaign source contributions: ' + month +
                               '</h1>' + scope + '<p>One row per witnessing campaign/source. Overlapping windows can share requests; '
                               'pooled evidence and source contributions must not be added as independent traffic totals. '
                               'The flagged-primary column counts each assigned primary request once.</p>' + paging + table + paging))
        campaign_links.append("<li><a href='campaign-" + month + "-001.html'>" + month + '</a>: ' +
                              format(len(rows), ',') + ' campaign/source contributions</li>')
    return ('<h2 id="retained">Why sources were retained</h2><ul>' + ''.join(links) + '</ul>' +
            '<h2>Campaign source contributions</h2><ul>' + ''.join(campaign_links) + '</ul>',
            {'source_months': sum(len(r) for r in retained.values()),
             'retained_analyzed_requests': sum(r['retained'] for rows in retained.values() for r in rows),
             'campaign_source_rows': len(campaigns),
             'private_source_months': groups,
             'scope': 'Analyzed behavioral-retention decisions only; native viewed visitors may differ.'})


def validated_configuration(raw, perl):
    # The Perl library remains the only source of defaults, validation and caps.
    script = ("use strict;use warnings;use VStats::TrafficClassifier;binmode STDIN,':raw';"
              "my $raw=do{local $/;<STDIN>};my $c=VStats::TrafficClassifier->config($raw);"
              "print VStats::TrafficClassifier::canonical_json({config=>$c,"
              "window_seconds=>VStats::TrafficClassifier->analysis_window($c)});")
    child = subprocess.run([perl, '-I' + str(ROOT / 'lib'), '-e', script], input=raw,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
    if child.returncode or child.stderr:
        raise ValueError('Invalid behavioral configuration')
    return json.loads(child.stdout.decode('utf-8'))


def apache_epoch(logical):
    match = re.match(rb'^\S+ \S+ \S+ \[(\d{2})/([A-Z][a-z]{2})/(\d{4}):'
                     rb'(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})\] ', logical)
    if not match:
        return None
    try:
        day, month, year, hour, minute, second, sign, zh, zm = match.groups()
        months = b'Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split()
        if int(zh) > 23 or int(zm) > 59:
            return None
        stamp = datetime.datetime(int(year), months.index(month) + 1, int(day),
                                  int(hour), int(minute), int(second), tzinfo=datetime.timezone.utc)
        offset = (int(zh) * 3600 + int(zm) * 60) * (1 if sign == b'+' else -1)
        return int(stamp.timestamp()) - offset
    except (ValueError, OverflowError):
        return None


def boundary_context(source, start, end, cap):
    if source is None:
        return b''
    if source.is_symlink() or not stat.S_ISREG(source.lstat().st_mode) or source.stat().st_size > cap:
        raise ValueError('Invalid or oversized boundary source')
    raw = source.read_bytes()
    if len(raw) > cap:
        raise ValueError('Boundary source byte cap exceeded')
    # Unparseable context is preserved as unavailable evidence, never silently
    # treated as a timestamped request. The primary export remains untouched.
    pieces = []
    for _, logical, piece in physical_records(raw):
        timestamp = apache_epoch(logical)
        if timestamp is None or start <= timestamp < end:
            pieces.append(piece)
    return b''.join(pieces)


def _build(config, input_directory, output_directory, perl='perl', prefix='/vstats/example.test/', page_size=200,
          exclude_automated_ips=True, unavailable_months=None):
    unavailable_months = unavailable_months or {}
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
    validated = validated_configuration(raw_config, perl)
    cfg, window = validated['config'], validated['window_seconds']
    day_paths = {path.stem: path for path in days}
    output.mkdir(mode=0o700)
    for name in ['filtered', 'request-filtered', 'excluded', 'request-excluded', 'reports', 'classification', 'review', 'context']:
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
        if day[:7] in unavailable_months or source.stat().st_size == 0:
            h, size, rows, last_byte = hashlib.sha256(), 0, 0, b''
            with source.open('rb') as raw_stream:
                for chunk in iter(lambda: raw_stream.read(1024 * 1024), b''):
                    h.update(chunk); size += len(chunk); rows += chunk.count(b'\n'); last_byte = chunk[-1:]
            rows += int(bool(size and last_byte != b'\n'))
            shutil.copyfile(str(source), str(request_filtered))
            shutil.copyfile(str(source), str(output / 'filtered' / (day + '.log')))
            os.chmod(str(request_filtered), 0o600)
            os.chmod(str(output / 'filtered' / (day + '.log')), 0o600)
            # Inactive/empty partitions retain every input record.
            for name in ['excluded', 'request-excluded']:
                private_write(output / name / (day + '.log'), b'')
            manifest = {'input_sha256': h.hexdigest(), 'sha256': h.hexdigest(), 'input_log_bytes': size,
                        'kept_log_bytes': size, 'removed_log_bytes': 0, 'input_records': rows,
                        'excluded_records': 0, 'kept_records': rows}
            missing = day[:7] in unavailable_months
            totals['lines_total'] += rows
            if missing:
                totals['unclassified_due_to_limits'] += rows
            daily.append({'day': day, 'input_sha256': h.hexdigest(), 'request_filtered_log': manifest,
                          'filtered_log': manifest, 'analysis_context_sha256': digest(canonical_binding(unavailable_months.get(day[:7], {'empty': True}))),
                          'counts': {'lines_total': rows, 'analyzed': 0}, 'behavior': {},
                          'classification_unavailable': missing, 'empty_partition': not size, 'additional_ip_exclusions': 0})
            continue
        start_day = datetime.datetime.strptime(day, '%Y-%m-%d').replace(tzinfo=datetime.timezone.utc)
        start_epoch = int(start_day.timestamp())
        before_day = (start_day - datetime.timedelta(days=1)).strftime('%Y-%m-%d')
        after_day = (start_day + datetime.timedelta(days=1)).strftime('%Y-%m-%d')
        try:
            halo = {
                'before': boundary_context(day_paths.get(before_day), start_epoch - window, start_epoch, cfg['limits']['input_bytes']),
                'after': boundary_context(day_paths.get(after_day), start_epoch + 86400, start_epoch + 86400 + window, cfg['limits']['input_bytes'])}
        except ValueError:
            if cfg['limits']['input_bytes'] == 67108864 and any(p and p.stat().st_size > 67108864 for p in [day_paths.get(before_day), day_paths.get(after_day)]):
                raise CapacityLimit(day, 'input_bytes', 67108864)
            raise
        for side, raw_halo in halo.items():
            if raw_halo:
                context_path = output / 'context' / (day + '-' + side + '.log')
                private_write(context_path, raw_halo)
                command += ['--context-' + side, str(context_path)]
        child = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
        if child.returncode or child.stderr or child.stdout:
            reason = child.stderr.decode('ascii', 'replace').strip()
            maxima = {'input_bytes': 67108864, 'records': 100000, 'groups': 100000}
            messages = {'input_bytes': ['Input byte limit exceeded', 'Combined input byte limit exceeded'],
                        'records': ['Record count limit exceeded', 'Combined record count limit exceeded'],
                        'groups': ['Group count limit exceeded', 'Combined group count limit exceeded',
                                   'Behavior group count limit exceeded', 'Probing group count limit exceeded',
                                   'Rapid scan group count limit exceeded', 'Distributed-login source group cap exceeded',
                                   'Distributed-login source-window cap exceeded', 'Distributed-login window group cap exceeded']}
            for kind, maximum in maxima.items():
                if cfg['limits'][kind] == maximum and any(reason == 'traffic-classify: input: ' + m for m in messages[kind]):
                    raise CapacityLimit(day, kind, maximum)
            raise RuntimeError('Daily classification failed')
        report = json.loads(report_path.read_bytes().decode('utf-8'))
        manifest = report['filtered_log']
        context_identity = {side: {'sha256': digest(raw_halo), 'bytes': len(raw_halo)}
                            for side, raw_halo in sorted(halo.items())}
        for side, raw_halo in halo.items():
            observed = report['analysis_context'].get(side)
            if raw_halo and (not observed or observed['sha256'] != digest(raw_halo) or observed['bytes'] != len(raw_halo)):
                raise RuntimeError('Classifier boundary context identity mismatch')
        analysis_context_sha256 = digest(json.dumps({'window_seconds': window, 'context': context_identity},
                                                    sort_keys=True).encode('utf-8'))
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
                    'inclusion_overrides', 'broad_flagged_requests', 'probing_flagged_requests', 'rapid_scan_flagged_requests', 'distributed_login_flagged_requests', 'overlap_requests']:
            behavior[key] += report['behavior'].get(key, 0)
        flagged_by_month[day[:7]] += report['behavior']['flagged_requests']
        first = period['from'] if first is None else min(first, period['from'])
        last = period['until'] if last is None else max(last, period['until'])
        daily.append({'day': day, 'counts': report['counts'], 'actors': report['actors'], 'behavior': report['behavior'],
                      'input_sha256': report['input_sha256'], 'request_filtered_log': manifest,
                      'config_sha256': report['config_sha256'], 'period': period, 'analysis_context_sha256': analysis_context_sha256,
                      'analysis_context': context_identity, 'analysis_window_seconds': window})
    context = {}
    for month in sorted({entry['day'][:7] for entry in daily}):
        binding = {'policy': 'vstats-ip-month-v1', 'enabled': exclude_automated_ips, 'config_sha256': digest(raw_config),
                   'evidence_context_version': 2,
                   'inputs': [(entry['day'], entry['input_sha256'], entry['analysis_context_sha256']) for entry in daily if entry['day'].startswith(month)],
                   'triggers': [(key, value['trigger_request_id']) for key, value in sorted(triggers.items()) if value['source_month'] == month]}
        context[month] = digest(json.dumps(binding, sort_keys=True).encode('utf-8'))
    include_ids = set(cfg.get('behavior_include', []))
    additional, ip_overrides, restored = 0, 0, set()
    sources, campaigns = {}, {}
    unattributed_sources = collections.Counter()
    render = ("use strict;use warnings;use JSON::PP;use VStats::TrafficClassifier;"
              "binmode STDIN,':raw';binmode STDOUT,':raw';my $b=do{local $/;<STDIN>};"
              "print VStats::TrafficClassifier::html_report(JSON::PP->new->utf8->decode($b));")
    for entry in daily:
        source = day_paths[entry['day']]
        day, month = entry['day'], entry['day'][:7]
        if entry.get('classification_unavailable') or entry.get('empty_partition'):
            entry['ip_policy_sha256'] = context[month]
            title = 'Input over limits' if entry.get('classification_unavailable') else 'No requests in this input partition'
            private_write(output / 'classification' / (day + '.html'), page(title, '<h1>' + day + ': ' + title + '</h1><p>Native reporting retains this input. No classifier evidence or bot counts are inferred.</p>'))
            continue
        report = json.loads((output / 'reports' / (day + '.json')).read_bytes().decode('utf-8'))
        details = report.pop('details')
        report.pop('details_warning', None)
        raw = source.read_bytes()
        if digest(raw) != entry['input_sha256']:
            raise RuntimeError('Input changed between classification and IP policy')
        records = {index: (logical, piece) for index, logical, piece in physical_records(raw)}
        default_omitted, direct_omitted = set(), set()
        ledger = excluded_by_month.setdefault(month, {'records': 0, 'response_body_bytes': 0})
        request_ledger = request_excluded_by_month.setdefault(month, {'records': 0, 'response_body_bytes': 0})
        day_additional = 0
        for record in details:
            direct = bool(record['excluded'])
            if direct:
                direct_omitted.add(record['line_index'])
            trigger = triggers.get(record.get('source_month_key'))
            ip_selected = bool(exclude_automated_ips and trigger)
            included = bool(record['behavior_included'] or (ip_selected and record['request_id'] in include_ids))
            excluded = direct or (ip_selected and not included)
            if excluded:
                default_omitted.add(record['line_index'])
            if not source_summary(sources, record, excluded, included, cfg['limits']['groups']):
                unattributed_sources['excluded' if excluded else 'retained'] += 1
            campaign_summary(campaigns, record, cfg['limits']['groups'])
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
        # These private complements use exactly the same primary byte kernel.
        # Native AWStats, rather than a second method/Skip parser, counts them.
        for name, omitted, field in [('request-excluded', direct_omitted, 'request_excluded_log'),
                                     ('excluded', default_omitted, 'excluded_log')]:
            excluded_raw, excluded_manifest = filtered_bytes(raw, set(records) - omitted, entry['input_sha256'])
            private_write(output / name / (day + '.log'), excluded_raw)
            entry[field] = excluded_manifest
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
    scope = ('<p>Updated ' + generated + '. Complete configured site corpus; daily exports use overlapping boundary evidence without counting context requests twice. '
             'A detected source can exclude its other requests throughout the same UTC month, including earlier days. '
             'No exclusion carries into another month without new evidence. Counts are requests, not verified people. '
             'Native rules may classify omitted records as non-viewed or ignore them altogether; omitted log records are not the change in native totals. No geography is used.</p>')
    disclaimer = ('<p>IP exclusion is ' + ('enabled by default' if exclude_automated_ips else 'disabled') +
                  '. Shared proxies, dynamic addresses and authorized automation can qualify. '
                  'Use the request-only view to disable IP expansion. Individual <code>behavior_include</code> request IDs '
                  'are explicit exceptions and may restore the IP to visitor counts. Copying an ID does not save server settings. '
                  'Byte-identical records share an ID. Detection flags remain separate from IP-policy exclusions.</p>')
    if unavailable_months:
        scope += '<p><strong>Classifier results below cover available periods only.</strong> Native-only fallback months: ' + html.escape(', '.join(sorted(unavailable_months))) + '. Missing classifier results are unavailable, never zero.</p>'
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
                   '; rapid content-path probing: ' + format(behavior['rapid_scan_flagged_requests'], ',') +
                   '; distributed login probing: ' + format(behavior['distributed_login_flagged_requests'], ',') +
                   '; overlap (two or more rules): ' + format(behavior['overlap_requests'], ',') +
                   '. Full raw user-agent strings and query strings are omitted from review.</p>')
    if sum(r['requests'] for r in sources.values()) + sum(unattributed_sources.values()) != totals['analyzed']:
        raise RuntimeError('Source-review population does not conserve primary analysis')
    if sum(r['primary_requests'] for r in campaigns.values()) != behavior['distributed_login_flagged_requests']:
        raise RuntimeError('Campaign review does not conserve assigned primary matches')
    source_review_html, source_review_summary = write_source_reviews(output, sources, campaigns, nav, scope, page_size)
    source_review_summary['unattributed_analyzed_requests'] = dict(unattributed_sources)
    private_write(output / 'review/index.html', page('Review exclusions', nav + '<h1>Review exclusions</h1>' + scope +
                  '<!-- NATIVE_EFFECT -->' + disclaimer + description + '<ul>' + ''.join(review_links) + '</ul>' + source_review_html))
    class_rows = ''.join(("<tr><td><a href='" + r['day'] + ".html'>" + r['day'] + '</a></td><td colspan="5">' + ('Input over limits; classification unavailable' if r.get('classification_unavailable') else 'Empty input') + '</td></tr>') if r.get('classification_unavailable') or r.get('empty_partition') else "<tr><td><a href='" + r['day'] + ".html'>" + r['day'] + '</a></td><td>' +
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
              'context_binding_version': 2, 'private_source_months': triggers, 'restored_source_months': sorted(restored), 'context_sha256_by_month': context}
    summary = {'schema_version': 1, 'generated_utc': generated, 'counts': dict(totals), 'actors': dict(actors), 'behavior': dict(behavior),
               'excluded_by_month': excluded_by_month, 'request_excluded_by_month': request_excluded_by_month,
               'capacity_fallback': unavailable_months, 'flagged_by_month': dict(flagged_by_month), 'ip_exclusion': policy, 'daily_reports': daily,
               'period': {'from': first, 'until': last}, 'config_raw_sha256': digest(raw_config), 'source_review': source_review_summary,
               'limitations': ['Missing neighboring input limits boundary evidence; fixed grids can still miss some sliding sequences.', 'Heuristics; not calibrated identity or intent.',
                               'Whole-IP policy can remove legitimate traffic behind shared/dynamic addresses.',
                               'Input must contain the intended site/month coverage; unparsed or unattributable rows remain preserved.'],
               'classification_files': {path.name: digest(path.read_bytes()) for path in sorted((output / 'classification').iterdir())},
               'review_files': {path.name: digest(path.read_bytes()) for path in sorted((output / 'review').iterdir())}}
    private_write(output / 'summary.json', (json.dumps(summary, sort_keys=True, indent=2) + '\n').encode('utf-8'))
    return summary


class CapacityLimit(RuntimeError):
    def __init__(self, day, kind, maximum):
        self.day, self.kind, self.maximum = day, kind, maximum
        super().__init__('Documented classifier hard maximum exceeded')


def canonical_binding(value):
    return json.dumps(value, sort_keys=True).encode('utf-8')


def build(config, input_directory, output_directory, perl='perl', prefix='/vstats/example.test/', page_size=200,
          exclude_automated_ips=True, capacity_fallback=False):
    unavailable = {}
    while True:
        try:
            return _build(config, input_directory, output_directory, perl, prefix, page_size,
                          exclude_automated_ips=exclude_automated_ips, unavailable_months=unavailable)
        except CapacityLimit as e:
            if not capacity_fallback:
                raise
            month = e.day[:7]
            if month in unavailable:
                raise
            unavailable[month] = {'reason': 'Input over limits', 'limit': e.kind, 'hard_maximum': e.maximum,
                                  'trigger_day': e.day, 'inactive': ['behavior', 'probing', 'rapid_scan', 'distributed_login', 'exclude_automated_ips']}
            # Only our failed, newly created derived-output directory is removed.
            # Original daily input and any previously published output are untouched.
            shutil.rmtree(str(output_directory))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--input-directory', required=True)
    parser.add_argument('--output-directory', required=True)
    parser.add_argument('--perl', default='perl')
    parser.add_argument('--site-url-prefix', default='/vstats/example.test/')
    parser.add_argument('--page-size', type=int, default=200)
    parser.add_argument('--capacity-fallback', action='store_true', help='Keep native input for whole affected UTC months at documented hard maxima only')
    parser.add_argument('--include-automated-ips', action='store_true',
                        help='Disable default whole-IP/month exclusion; retain request-only filtering')
    args = parser.parse_args()
    build(args.config, args.input_directory, args.output_directory, args.perl, args.site_url_prefix, args.page_size,
          exclude_automated_ips=not args.include_automated_ips, capacity_fallback=args.capacity_fallback)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError):
        print('traffic-filter-report: analysis or output failed; keep prior published view', file=sys.stderr)
        sys.exit(1)
