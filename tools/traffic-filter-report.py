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


def controls(prefix):
    return ("<nav><a href='" + prefix + "'>Behavior filter on (default)</a> &middot; "
            "<a href='" + prefix + "confirmed/'>Include suspected automation</a> &middot; "
            "<a href='" + prefix + "original/'>Original rules</a> &middot; "
            "<a href='" + prefix + "behavior-exclusions/'>Review exclusions</a></nav>")


def render_review_row(record):
    proof = record['behavior_evidence']
    stamp = datetime.datetime.utcfromtimestamp(record['timestamp']).isoformat() + 'Z'
    match = CLAIM.search(record.get('user_agent') or '')
    claim = match.group(1) if match else 'browser marker'
    platform = record.get('behavior_platform') or 'unknown'
    state = 'Included by request ID override' if record['behavior_included'] else 'Excluded by behavior filter'
    reason = ('{requests} requests; {distinct_user_agents} user agents; {distinct_platforms} platforms; '
              '{distinct_paths} paths; {not_found_requests} HTTP 404s').format(**proof)
    reason += ' in {} seconds'.format(proof['until'] - proof['from'])
    request_id = record['request_id']
    if not re.fullmatch(r'[0-9a-f]{64}', request_id):
        raise ValueError('Invalid request ID')
    cells = [stamp, record['client'], record.get('method', ''), record['normalized_target'],
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


def build(config, input_directory, output_directory, perl='perl', prefix='/vstats/example.test/', page_size=200):
    config, inputs, output = Path(config), Path(input_directory), Path(output_directory)
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
    if not isinstance(cfg, dict):
        raise ValueError('Configuration must be an object')
    if cfg.get('exclude') != ['suspected_automation']:
        raise ValueError('Review builder requires exactly the suspected automation selector')
    days = sorted(inputs.glob('????-??-??.log'))
    if not days:
        raise ValueError('No daily input partitions')
    for path in days:
        datetime.datetime.strptime(path.stem, '%Y-%m-%d')
        if path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError('Daily input must be a regular file')
    output.mkdir(mode=0o700)
    for name in ['filtered', 'reports', 'classification', 'review']:
        (output / name).mkdir(mode=0o700)
    totals, actors, behavior = collections.Counter(), collections.Counter(), collections.Counter()
    excluded_by_month, flagged_by_month = {}, collections.Counter()
    daily, review_rows = [], collections.defaultdict(list)
    first = last = None
    render = ("use strict;use warnings;use JSON::PP;use VStats::TrafficClassifier;"
              "binmode STDIN,':raw';binmode STDOUT,':raw';my $b=do{local $/;<STDIN>};"
              "print VStats::TrafficClassifier::html_report(JSON::PP->new->utf8->decode($b));")
    for source in days:
        day = source.stem
        report_path = output / 'reports' / (day + '.json')
        filtered = output / 'filtered' / (day + '.log')
        command = [perl, str(ROOT / 'traffic-classify.pl'), '--config', str(config), '--input', str(source),
                   '--input-format', 'combined', '--output', str(report_path), '--details', '--filtered-log', str(filtered)]
        child = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
        if child.returncode or child.stderr or child.stdout:
            raise RuntimeError('Daily classification failed')
        raw_report = report_path.read_bytes()
        report = json.loads(raw_report.decode('utf-8'))
        manifest = report['filtered_log']
        raw = source.read_bytes()
        if digest(raw) != report['input_sha256'] or digest(filtered.read_bytes()) != manifest['sha256']:
            raise RuntimeError('Input or filtered output changed')
        if manifest['input_records'] != report['counts']['lines_total']:
            raise RuntimeError('Physical record accounting mismatch')
        details = report.pop('details')
        report.pop('details_warning', None)
        flagged = {r['line_index']: r for r in details if r['suspected_automation']}
        removed = sum(bool(r['excluded']) for r in flagged.values())
        if removed != manifest['excluded_records']:
            raise RuntimeError('Filtered selection differs from review')
        month = day[:7]
        ledger = excluded_by_month.setdefault(month, {'records': 0, 'response_body_bytes': 0})
        logical_lines = raw.split(b'\n')
        for index, line in enumerate(logical_lines, 1):
            if index not in flagged:
                continue
            record = flagged[index]
            match = RECORD.match(line)
            if not match or int(match[2]) != record['status']:
                raise RuntimeError('Review could not bind the original response')
            logical = line[:-1] if line.endswith(b'\r') and index < len(logical_lines) else line
            if digest(logical) != record['request_id']:
                raise RuntimeError('Review request ID mismatch')
            record['method'] = match[1].split(b' ', 1)[0].decode('ascii')
            record['response_body_bytes'] = 0 if record['status'] == 304 or match[3] == b'-' else int(match[3])
            proof = record['behavior_evidence']
            if not proof or not proof['from'] <= record['timestamp'] <= proof['until']:
                raise RuntimeError('Review lacks a covering witness')
            review_rows[month].append(record)
            if record['excluded']:
                ledger['records'] += 1
                ledger['response_body_bytes'] += record['response_body_bytes']
        flagged_by_month[month] += len(flagged)
        totals.update(report['counts'])
        actors.update(report['actors'])
        for key in ['flagged_requests', 'eligible_requests', 'insufficient_fields', 'merged_sequences', 'flagged_source_groups', 'inclusion_overrides']:
            behavior[key] += report['behavior'][key]
        period = report['input']['period']
        start = datetime.datetime.strptime(day, '%Y-%m-%d').replace(tzinfo=datetime.timezone.utc).timestamp()
        if not start <= period['from'] <= period['until'] < start + datetime.timedelta(days=1).total_seconds():
            raise ValueError('Input partition does not match its UTC day')
        first = period['from'] if first is None else min(first, period['from'])
        last = period['until'] if last is None else max(last, period['until'])
        child = subprocess.run([perl, '-I' + str(ROOT / 'lib'), '-e', render],
                               input=json.dumps(report, sort_keys=True).encode('utf-8'),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
        if child.returncode or child.stderr:
            raise RuntimeError('Aggregate HTML rendering failed')
        text = child.stdout.decode('utf-8').replace('<body>', '<body>' + controls(prefix) +
                "<p>UTC day: " + day + ". <a href='index.html'>Classification overview</a></p>", 1)
        private_write(output / 'classification' / (day + '.html'), text.encode('utf-8'))
        daily.append({'day': day, 'counts': report['counts'], 'actors': report['actors'], 'behavior': report['behavior'],
                      'input_sha256': report['input_sha256'], 'filtered_log': manifest,
                      'config_sha256': report['config_sha256'], 'period': period})
    generated = datetime.datetime.utcnow().isoformat() + 'Z'
    scope = ('<p>Updated ' + generated + '. Complete configured source corpus, analyzed as independent UTC days. '
             'Windows crossing midnight may be missed. Counts are requests, not visits or verified humans. '
             'Some flagged requests were already non-viewed under native rules. No geography is used.</p>')
    disclaimer = ('<p>Thresholds are heuristic; accuracy is unmeasured. Shared proxies and authorized automation can qualify. '
                  'The browser controls choose a statistics view. For an individual exception, copy its request ID and '
                  'add it to the operator-managed <code>behavior_include</code> list; copying an ID does not change totals. '
                  'Byte-identical duplicate records share an ID. Inclusion overrides retain the flag and its evidence.</p>')
    review_links = []
    for month, records in sorted(review_rows.items(), reverse=True):
        records.sort(key=lambda r: (r['timestamp'], r['request_id']))
        pages = (len(records) + page_size - 1) // page_size
        for part in range(pages):
            name = '{}-{:03d}.html'.format(month, part + 1)
            links = '<nav>' + ' &middot; '.join("<a href='{}-{:03d}.html'>{}</a>".format(month, i + 1, i + 1) for i in range(pages)) + '</nav>'
            table = '<table><tr>' + ''.join('<th>' + h + '</th>' for h in ['UTC time', 'Source IP', 'Method', 'Path (query removed)',
                     'HTTP', 'Browser/platform claim', 'Decision', 'Qualifying window evidence', 'Request ID']) + '</tr>'
            table += ''.join(render_review_row(r) for r in records[part * page_size:(part + 1) * page_size]) + '</table>'
            script = ("<script>document.querySelectorAll('[data-request-id]').forEach(function(b){b.addEventListener('click',function(){"
                      "navigator.clipboard.writeText(b.dataset.requestId).then(function(){b.textContent='ID copied';});});});</script>")
            private_write(output / 'review' / name, page('Review behavioral exclusions', controls(prefix) +
                          '<h1>Review behavioral exclusions: ' + month + '</h1>' + scope + disclaimer + links + table + links + script))
        review_links.append("<li id='" + month + "'><a href='" + month + "-001.html'>" + month + '</a>: ' +
                            format(excluded_by_month[month]['records'], ',') + ' excluded records, ' +
                            format(len(records) - excluded_by_month[month]['records'], ',') + ' inclusion overrides</li>')
    review_body = (controls(prefix) + '<h1>Review behavioral exclusions</h1>' + scope +
                   '<!-- NATIVE_EFFECT -->' + disclaimer + '<p>Total flagged: <strong>' + format(behavior['flagged_requests'], ',') +
                   '</strong>. Actually removed from the filtered input: <strong>' + format(sum(x['records'] for x in excluded_by_month.values()), ',') +
                   '</strong>. Full raw user-agent strings and query strings are omitted from these pages.</p><ul>' + ''.join(review_links) + '</ul>')
    private_write(output / 'review/index.html', page('Review behavioral exclusions', review_body))
    class_rows = ''.join("<tr><td><a href='" + r['day'] + ".html'>" + r['day'] + '</a></td><td>' +
                         format(r['counts']['analyzed'], ',') + '</td><td>' + format(r['behavior']['flagged_requests'], ',') +
                         '</td><td>' + format(r['filtered_log']['excluded_records'], ',') + '</td></tr>' for r in daily)
    class_body = (controls(prefix) + '<h1>Traffic classification and behavioral filtering</h1>' + scope +
                  '<p><strong>' + format(behavior['flagged_requests'], ',') + '</strong> suspected-automation requests; ' +
                  format(sum(x['records'] for x in excluded_by_month.values()), ',') + ' explicitly excluded from filtered input. '
                  'Behavioral flags overlap actor identities; unknown is neither verified human nor bot. '
                  'Native statistics are replayed independently for the selected view.</p>' +
                  '<p>Analyzed requests: ' + format(totals['analyzed'], ',') + '; unparsed: ' + format(totals['unparsed'], ',') +
                  '. Provider snapshots are not supplied to this companion analysis; the native confirmed-crawler layer '
                  'uses its own request-period evidence.</p><table><tr><th>UTC day</th><th>Analyzed</th><th>Flagged</th><th>Excluded</th></tr>' + class_rows + '</table>')
    private_write(output / 'classification/index.html', page('Traffic classification', class_body))
    summary = {'schema_version': 1, 'generated_utc': generated, 'counts': dict(totals), 'actors': dict(actors),
               'behavior': dict(behavior), 'excluded_by_month': excluded_by_month, 'flagged_by_month': dict(flagged_by_month),
               'daily_reports': daily, 'period': {'from': first, 'until': last}, 'config_raw_sha256': digest(raw_config),
               'limitations': ['Independent UTC-day windows; possible boundary misses.', 'Heuristics; not calibrated identity or intent.',
                               'Removed log records include requests native rules already treated as non-viewed.'],
               'classification_files': {p.name: digest(p.read_bytes()) for p in sorted((output / 'classification').iterdir())},
               'review_files': {p.name: digest(p.read_bytes()) for p in sorted((output / 'review').iterdir())}}
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
    args = parser.parse_args()
    build(args.config, args.input_directory, args.output_directory, args.perl, args.site_url_prefix, args.page_size)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError):
        print('traffic-filter-report: analysis or output failed; keep prior published view', file=sys.stderr)
        sys.exit(1)
