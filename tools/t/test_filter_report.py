import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('vstats_filter_report', str(ROOT / 'traffic-filter-report.py'))
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class ReviewRendering(unittest.TestCase):
    def test_escape_and_redaction(self):
        record = {'timestamp': 100, 'client': '192.0.2.1', 'method': 'GET',
                  'normalized_target': '/<script>', 'status': 404,
                  'user_agent': 'Mozilla/5.0 (Windows) Chrome/126 <img src=x> SECRET_SENTINEL',
                  'behavior_platform': 'windows', 'request_id': 'a' * 64, 'behavior_included': False,
                  'behavior_evidence': {'from': 90, 'until': 100, 'requests': 60, 'distinct_user_agents': 4,
                                        'distinct_platforms': 2, 'distinct_paths': 10, 'not_found_requests': 10}}
        row = builder.render_review_row(record)
        self.assertIn('&lt;script&gt;', row)
        self.assertNotIn('<script>', row)
        self.assertNotIn('<img', row)
        self.assertNotIn('SECRET_SENTINEL', row)
        self.assertIn('Chrome/126 / windows', row)
        self.assertIn('60 requests', row)
        self.assertIn('Copy request ID', row)

    def test_invalid_id(self):
        record = {'timestamp': 100, 'client': '192.0.2.1', 'normalized_target': '/', 'status': 404,
                  'request_id': '<script>', 'behavior_included': False,
                  'behavior_evidence': {'from': 90, 'until': 100, 'requests': 60, 'distinct_user_agents': 4,
                                       'distinct_platforms': 2, 'distinct_paths': 10, 'not_found_requests': 10}}
        with self.assertRaises(ValueError):
            builder.render_review_row(record)

    def test_probing_witnesses_and_missing_evidence(self):
        proof = {'from': 90, 'until': 100, 'requests': 30, 'distinct_user_agents': 4,
                 'distinct_platforms': 2, 'distinct_paths': 1, 'not_found_requests': 0}
        record = {'timestamp': 100, 'client': '192.0.2.1', 'method': 'POST',
                  'normalized_target': '/account/sign-in', 'status': 200,
                  'request_id': 'a' * 64, 'behavior_included': True,
                  'broad_probing_flagged': False, 'probing_flagged': True,
                  'behavior_evidence': None, 'probing_evidence': proof}
        row = builder.render_review_row(record)
        self.assertIn('Endpoint probing:', row)
        self.assertIn('0 HTTP 404s', row)
        self.assertIn('no 404 requirement', row)
        self.assertNotIn('Broad path probing:', row)
        self.assertIn('Included by request ID override', row)
        record['broad_probing_flagged'] = True
        record['behavior_evidence'] = dict(proof, distinct_paths=10, not_found_requests=10)
        row = builder.render_review_row(record)
        self.assertIn('Broad path probing:', row)
        self.assertIn('Endpoint probing:', row)
        self.assertEqual(row.count('<button data-request-id='), 1)
        record['probing_evidence'] = None
        with self.assertRaises(RuntimeError):
            builder.render_review_row(record)
        record['probing_evidence'] = dict(proof, until=99)
        with self.assertRaises(RuntimeError):
            builder.render_review_row(record)


class BatchIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.perl = os.environ.get('VSTATS_TEST_PERL', shutil.which('perl') or 'perl')
        try:
            child = subprocess.run([cls.perl, '-e', 'use v5.020;'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError:
            raise unittest.SkipTest('Perl 5.20+ unavailable for optional batch integration')
        if child.returncode:
            raise unittest.SkipTest('Perl 5.20+ unavailable for optional batch integration')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.inputs = self.root / 'input'
        self.inputs.mkdir()
        self.config = self.root / 'config.json'
        self.cfg = {'schema_version': 1, 'exclude': ['suspected_automation'],
                    'behavior': {'enabled': 1, 'window_seconds': 10, 'min_requests': 6, 'distinct_user_agents': 3,
                                 'distinct_platforms': 2, 'distinct_paths': 3, 'not_found_requests': 3}}
        uas = ['Mozilla/5.0 (Windows NT 10.0) Chrome/126', 'Mozilla/5.0 (Windows NT 10.0) Chrome/125',
               'Mozilla/5.0 (X11; Linux) Firefox/128']
        self.lines = [('192.0.2.1 - - [02/Oct/2026:10:00:{:02d} +0000] "GET /p{}?token=SECRET_SENTINEL HTTP/1.1" {} 100 "-" "{}"\n'.format(
                      i, i % 3, 404 if i < 3 else 200, uas[i % 3])).encode('ascii') for i in range(6)]
        self.ordinary = b'198.51.100.1 - - [02/Oct/2026:11:00:00 +0000] "GET / HTTP/1.1" 200 99 "-" "Mozilla/5.0 (Windows) Chrome/126"\n'
        (self.inputs / '2026-10-02.log').write_bytes(b''.join(self.lines) + self.ordinary)
        self.config.write_text(json.dumps(self.cfg), encoding='utf-8')

    def run_build(self, **kwargs):
        kwargs.setdefault('exclude_automated_ips', False)
        return builder.build(self.config, self.inputs, self.root / 'output', perl=self.perl,
                             prefix='/vstats/example.test/', **kwargs)

    def test_private_complements_partition_primary_records(self):
        source = self.inputs / '2026-10-02.log'
        unparsed = b'\nnot an apache request\n'
        raw = b''.join(self.lines) + self.ordinary + unparsed
        source.write_bytes(raw)
        result = self.run_build()
        day = result['daily_reports'][0]
        for selected, omitted, field in [('filtered', 'excluded', 'excluded_log'),
                                         ('request-filtered', 'request-excluded', 'request_excluded_log')]:
            self.assertEqual((self.root / 'output' / selected / source.name).read_bytes(), self.ordinary + unparsed)
            complement = (self.root / 'output' / omitted / source.name).read_bytes()
            self.assertEqual(complement, b''.join(self.lines))
            self.assertEqual(day[field]['sha256'], hashlib.sha256(complement).hexdigest())
            self.assertEqual(day[field]['input_sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(day[field]['kept_records'], 6)
            self.assertEqual(day[field]['input_records'], 9)
        self.assertEqual(source.read_bytes(), raw)

    def test_empty_or_explicitly_inactive_partition_has_empty_complements(self):
        source = self.inputs / '2026-10-02.log'
        for raw, unavailable in [(b'', {}), (b''.join(self.lines) + self.ordinary,
                                             {'2026-10': {'reason': 'declared inactive month'}})]:
            source.write_bytes(raw)
            builder._build(self.config, self.inputs, self.root / 'output', perl=self.perl,
                           unavailable_months=unavailable)
            for name in ['filtered', 'request-filtered']:
                self.assertEqual((self.root / 'output' / name / source.name).read_bytes(), raw)
            for name in ['excluded', 'request-excluded']:
                self.assertEqual((self.root / 'output' / name / source.name).read_bytes(), b'')
            self.assertEqual(source.read_bytes(), raw)
            shutil.rmtree(str(self.root / 'output'))

    def test_complete_filter_and_review(self):
        before = (self.inputs / '2026-10-02.log').read_bytes()
        result = self.run_build(page_size=2)
        self.assertEqual(result['counts']['analyzed'], 7)
        self.assertEqual(result['behavior']['flagged_requests'], 6)
        self.assertEqual(result['excluded_by_month']['2026-10'], {'records': 6, 'response_body_bytes': 600})
        self.assertEqual((self.root / 'output/filtered/2026-10-02.log').read_bytes(), self.ordinary)
        self.assertEqual((self.inputs / '2026-10-02.log').read_bytes(), before)
        pages = sorted((self.root / 'output/review').glob('2026-10-*.html'))
        self.assertEqual(len(pages), 3)
        text = ''.join(p.read_text(encoding='utf-8') for p in pages)
        self.assertEqual(text.count('<button data-request-id='), 6)
        self.assertNotIn('SECRET_SENTINEL', text)
        self.assertNotIn('Mozilla/5.0', text)
        self.assertIn('confirmed/', text)
        self.assertIn('original/', text)
        for p in (self.root / 'output/classification').glob('*.html'):
            self.assertNotIn('SECRET_SENTINEL', p.read_text(encoding='utf-8'))
        for p in (self.root / 'output').rglob('*'):
            if p.is_file():
                self.assertEqual(p.stat().st_mode & 0o777, 0o600)

    def test_midnight_context_has_primary_only_exports_and_boundary_cache_identity(self):
        before, after = [], []
        for i, line in enumerate(self.lines):
            old = '10:00:{:02d}'.format(i).encode('ascii')
            stamp = ('23:59:{:02d}'.format(57 + i) if i < 3 else '00:00:{:02d}'.format(i - 3)).encode('ascii')
            line = line.replace(old, stamp)
            (before if i < 3 else after).append(line.replace(b'02/Oct', b'01/Oct') if i < 3 else line)
        (self.inputs / '2026-10-01.log').write_bytes(b''.join(before))
        (self.inputs / '2026-10-02.log').write_bytes(b''.join(after))
        result = self.run_build()
        self.assertEqual(result['counts']['analyzed'], 6)
        self.assertEqual(result['behavior']['flagged_requests'], 6)
        self.assertEqual(result['excluded_by_month']['2026-10'], {'records': 6, 'response_body_bytes': 600})
        for day, primary in [('2026-10-01', before), ('2026-10-02', after)]:
            report = json.loads((self.root / 'output/reports' / (day + '.json')).read_text(encoding='utf-8'))
            self.assertEqual(report['counts']['lines_total'], 3)
            self.assertEqual(report['behavior']['flagged_requests'], 3)
            self.assertEqual(report['input_sha256'], hashlib.sha256(b''.join(primary)).hexdigest())
            self.assertEqual(report['filtered_log']['input_records'], 3)
            self.assertEqual((self.root / 'output/filtered' / (day + '.log')).read_bytes(), b'')
            self.assertTrue(report['analysis_context'])
        original_day = result['daily_reports'][0]
        # Change only the following day's boundary evidence: the prior day's
        # own input hash stays fixed while its cache dependency must change.
        (self.inputs / '2026-10-02.log').write_bytes(b''.join(after[:-1]))
        changed = builder.build(self.config, self.inputs, self.root / 'changed', perl=self.perl, exclude_automated_ips=False)
        self.assertEqual(changed['daily_reports'][0]['input_sha256'], original_day['input_sha256'])
        self.assertNotEqual(changed['daily_reports'][0]['analysis_context_sha256'], original_day['analysis_context_sha256'])
        self.assertEqual(changed['behavior']['flagged_requests'], 0)
        previous_context = changed['daily_reports'][0]['analysis_context_sha256']
        with (self.inputs / '2026-10-02.log').open('ab') as handle:
            handle.write(self.ordinary)
        outside = builder.build(self.config, self.inputs, self.root / 'outside', perl=self.perl, exclude_automated_ips=False)
        self.assertEqual(outside['daily_reports'][0]['analysis_context_sha256'], previous_context)

    def test_inclusion_override_visible_and_effective(self):
        request_id = hashlib.sha256(self.lines[0].rstrip(b'\n')).hexdigest()
        self.cfg['behavior_include'] = [request_id]
        self.config.write_text(json.dumps(self.cfg), encoding='utf-8')
        result = self.run_build()
        self.assertEqual(result['behavior']['flagged_requests'], 6)
        self.assertEqual(result['behavior']['inclusion_overrides'], 1)
        self.assertEqual(result['excluded_by_month']['2026-10']['records'], 5)
        self.assertEqual((self.root / 'output/filtered/2026-10-02.log').read_bytes(), self.lines[0] + self.ordinary)
        self.assertIn('Included by request ID override', (self.root / 'output/review/2026-10-001.html').read_text(encoding='utf-8'))

    def test_probing_only_with_inclusion_and_ordinary_same_source_request(self):
        self.cfg = {'schema_version': 1, 'exclude': ['suspected_automation'],
                    'probing': {'enabled': 1, 'window_seconds': 10, 'min_requests': 6,
                                'distinct_user_agents': 3, 'distinct_platforms': 2,
                                'paths': ['/account/sign-in']}}
        self.lines = [line.replace(b'GET /p' + str(i % 3).encode('ascii'), b'POST /account/sign-in').replace(
                      b' 404 100 ', b' 200 100 ') for i, line in enumerate(self.lines)]
        asset = self.ordinary.replace(b'198.51.100.1', b'192.0.2.1').replace(
            b'11:00:00', b'10:00:03').replace(b'GET / HTTP', b'GET /style.css HTTP')
        (self.inputs / '2026-10-02.log').write_bytes(b''.join(self.lines) + asset)
        self.cfg['behavior_include'] = [hashlib.sha256(self.lines[0].rstrip(b'\n')).hexdigest()]
        self.config.write_text(json.dumps(self.cfg), encoding='utf-8')
        result = self.run_build(page_size=2)
        self.assertEqual(result['behavior']['flagged_requests'], 6)
        self.assertEqual(result['behavior']['probing_flagged_requests'], 6)
        self.assertEqual(result['behavior']['broad_flagged_requests'], 0)
        self.assertEqual(result['excluded_by_month']['2026-10']['records'], 5)
        self.assertEqual((self.root / 'output/filtered/2026-10-02.log').read_bytes(), self.lines[0] + asset)
        pages = sorted((self.root / 'output/review').glob('2026-10-*.html'))
        text = ''.join(p.read_text(encoding='utf-8') for p in pages)
        self.assertEqual(text.count('<button data-request-id='), 6)
        self.assertIn('Endpoint probing:', text)
        self.assertIn('no 404 requirement', text)
        self.assertNotIn('Broad path probing:', text)
        self.assertNotIn('SECRET_SENTINEL', text)
        self.assertIn('POST', text)

    def test_overlapping_rules_have_one_review_row_and_two_witnesses(self):
        self.cfg['probing'] = {'enabled': 1, 'window_seconds': 10, 'min_requests': 6,
                               'distinct_user_agents': 3, 'distinct_platforms': 2,
                               'paths': ['/p0', '/p1', '/p2']}
        self.config.write_text(json.dumps(self.cfg), encoding='utf-8')
        result = self.run_build()
        self.assertEqual(result['behavior']['flagged_requests'], 6)
        self.assertEqual(result['behavior']['broad_flagged_requests'], 6)
        self.assertEqual(result['behavior']['probing_flagged_requests'], 6)
        self.assertEqual(result['behavior']['overlap_requests'], 6)
        self.assertEqual(result['excluded_by_month']['2026-10']['records'], 6)
        text = (self.root / 'output/review/2026-10-001.html').read_text(encoding='utf-8')
        self.assertEqual(text.count('<button data-request-id='), 6)
        self.assertIn('Broad path probing:', text)
        self.assertIn('Endpoint probing:', text)

    def test_distributed_login_pool_source_proofs_overrides_and_ip_expansion(self):
        self.cfg = {'schema_version': 1, 'exclude': ['suspected_automation'],
                    'distributed_login': {'enabled': 1, 'window_seconds': 60,
                                          'login_paths': ['/account/login'], 'admin_paths': ['/admin']}}
        campaign = []
        for ip in range(1, 4):
            uas = ['Mozilla/5.0 (Windows) Chrome/126', 'Mozilla/5.0 (Linux) Firefox/128',
                   'Mozilla/5.0 (Macintosh) Safari/60{}'.format(ip),
                   'Mozilla/5.0 (Windows) Chrome/13{}'.format(ip)]
            for i in range(10):
                campaign.append(('192.0.2.{} - - [02/Oct/2026:10:00:{:02d} +0000] "{} {}?token=SECRET_SENTINEL HTTP/1.1" 200 100 "-" "{}"\n'.format(
                    ip, i, 'POST' if i < 4 else 'GET', '/account/login' if i < 4 else '/admin',
                    uas[i] if i < 4 else 'Mozilla/5.0 (Macintosh) Safari/999')).encode('ascii'))
        # A coherent rotating office/admin source would otherwise participate.
        stable = []
        for i, (method, target, ua) in enumerate([
                ('POST', '/account/login', 'Mozilla/5.0 (Windows) Chrome/126'),
                ('POST', '/account/login', 'Mozilla/5.0 (Linux) Firefox/128'),
                ('GET', '/admin', 'Mozilla/5.0 (Windows) Chrome/126')]):
            stable.append(('198.51.100.200 - - [02/Oct/2026:10:00:{:02d} +0000] "{} {} HTTP/1.1" 200 100 "-" "{}"\n'.format(
                i, method, target, ua)).encode('ascii'))
        asset = self.ordinary.replace(b'198.51.100.1', b'192.0.2.1').replace(b'GET / HTTP', b'GET /style.css HTTP')
        earlier = asset.replace(b'02/Oct', b'01/Oct').replace(b'/style.css', b'/earlier')
        (self.inputs / '2026-10-01.log').write_bytes(earlier)
        (self.inputs / '2026-10-02.log').write_bytes(b''.join(campaign) + asset + b''.join(stable))
        self.cfg['behavior_include'] = [hashlib.sha256(campaign[0].rstrip(b'\n')).hexdigest()]
        self.config.write_text(json.dumps(self.cfg), encoding='utf-8')
        result = self.run_build(exclude_automated_ips=True)
        self.assertEqual(result['counts']['analyzed'], 35)
        self.assertEqual(result['behavior']['distributed_login_flagged_requests'], 30)
        self.assertEqual(result['behavior']['flagged_requests'], 30)
        self.assertEqual(result['request_excluded_by_month']['2026-10']['records'], 29)
        self.assertEqual(result['excluded_by_month']['2026-10']['records'], 31)
        self.assertEqual(result['ip_exclusion']['additional_excluded_requests'], 2)
        self.assertEqual((self.root / 'output/filtered/2026-10-01.log').read_bytes(), b'')
        self.assertEqual((self.root / 'output/filtered/2026-10-02.log').read_bytes(), campaign[0] + b''.join(stable))
        self.assertEqual((self.root / 'output/request-filtered/2026-10-02.log').read_bytes(), campaign[0] + asset + b''.join(stable))
        text = (self.root / 'output/review/2026-10-001.html').read_text(encoding='utf-8')
        self.assertEqual(text.count('<button data-request-id='), 32)
        self.assertIn('Campaign: 30 requests from 3 sources; 12 login POSTs', text)
        self.assertIn('This source: 10 requests; 4 login POSTs', text)
        self.assertIn('Trigger evidence, Distributed login probing:', text)
        self.assertIn('Included by request ID override', text)
        self.assertNotIn('198.51.100.200', text)
        self.assertEqual(result['source_review']['source_months'], 2)
        self.assertEqual(result['source_review']['retained_analyzed_requests'], 4)
        self.assertEqual(result['source_review']['campaign_source_rows'], 3)
        retained = (self.root / 'output/review/retained-2026-10-001.html').read_text(encoding='utf-8')
        self.assertIn('198.51.100.200', retained)
        self.assertIn('coherent same-UA POST/follow-up', retained)
        self.assertIn('Explicit request-ID inclusion override', retained)
        self.assertIn('Retention does not verify a human visitor', retained)
        self.assertNotIn('SECRET_SENTINEL', retained)
        self.assertNotIn('Mozilla/5.0', retained)
        campaigns = (self.root / 'output/review/campaign-2026-10-001.html').read_text(encoding='utf-8')
        self.assertEqual(campaigns.count("class='campaign-source'"), 3)
        self.assertIn('This source: 10 requests; 4 login POSTs', campaigns)
        self.assertNotIn('SECRET_SENTINEL', campaigns)
        self.assertNotIn('Mozilla/5.0', campaigns)
        self.assertNotIn('SECRET_SENTINEL', text)
        self.assertNotIn('Mozilla/5.0', text)
        details = json.loads((self.root / 'output/reports/2026-10-02.json').read_text(encoding='utf-8'))['details']
        matched = next(r for r in details if r.get('distributed_login_flagged'))
        matched['distributed_login_evidence']['source_requests'] = 10000
        with self.assertRaises(RuntimeError):
            builder.render_review_row(matched)

    def test_rapid_scan_witness_and_ip_policy_propagation(self):
        self.cfg = {'schema_version': 1, 'exclude': ['suspected_automation'],
                    'rapid_scan': {'enabled': 1, 'window_seconds': 10, 'min_requests': 6,
                                   'distinct_paths': 3, 'not_found_requests': 3}}
        self.lines = [('192.0.2.1 - - [02/Oct/2026:10:00:{:02d} +0000] '
                       '"GET /probe{}?token=SECRET_SENTINEL HTTP/1.1" {} 100 "-" "single-agent/1"\n'.format(
                           i, i % 3, 404 if i < 3 else 200)).encode('ascii') for i in range(6)]
        asset = b'192.0.2.1 - - [02/Oct/2026:10:00:03 +0000] "GET /style.css HTTP/1.1" 404 99 "-" "single-agent/1"\n'
        earlier = b'192.0.2.1 - - [01/Oct/2026:10:00:00 +0000] "GET /earlier HTTP/1.1" 200 99 "-" "single-agent/1"\n'
        (self.inputs / '2026-10-01.log').write_bytes(earlier)
        (self.inputs / '2026-10-02.log').write_bytes(b''.join(self.lines) + asset)
        self.config.write_text(json.dumps(self.cfg), encoding='utf-8')
        result = self.run_build(exclude_automated_ips=True)
        self.assertEqual(result['behavior']['rapid_scan_flagged_requests'], 6)
        self.assertEqual(result['behavior']['broad_flagged_requests'], 0)
        self.assertEqual(result['behavior']['probing_flagged_requests'], 0)
        self.assertEqual(result['request_excluded_by_month']['2026-10']['records'], 6)
        self.assertEqual(result['excluded_by_month']['2026-10']['records'], 8)
        self.assertEqual(result['ip_exclusion']['additional_excluded_requests'], 2)
        self.assertEqual((self.root / 'output/filtered/2026-10-01.log').read_bytes(), b'')
        self.assertEqual((self.root / 'output/filtered/2026-10-02.log').read_bytes(), b'')
        self.assertEqual((self.root / 'output/request-filtered/2026-10-02.log').read_bytes(), asset)
        text = (self.root / 'output/review/2026-10-001.html').read_text(encoding='utf-8')
        self.assertEqual(text.count('<button data-request-id='), 8)
        self.assertIn('Rapid content-path probing:', text)
        self.assertIn('no browser rotation requirement', text)
        self.assertIn('Trigger evidence, Rapid content-path probing:', text)
        self.assertIn('1 user agents; 0 platforms', text)
        self.assertNotIn('SECRET_SENTINEL', text)
        self.assertNotIn('single-agent/1', text)
        self.assertIn('no recognized browser claim', text)
        shutil.rmtree(str(self.root / 'output'))
        self.cfg['behavior_include'] = [hashlib.sha256(self.lines[0].rstrip(b'\n')).hexdigest()]
        self.config.write_text(json.dumps(self.cfg), encoding='utf-8')
        included = self.run_build(exclude_automated_ips=True)
        self.assertEqual(included['behavior']['inclusion_overrides'], 1)
        self.assertEqual(included['excluded_by_month']['2026-10']['records'], 7)
        self.assertEqual((self.root / 'output/filtered/2026-10-02.log').read_bytes(), self.lines[0])

    def test_refuses_existing_output_and_invalid_policy(self):
        self.cfg['exclude'] = []
        self.config.write_text(json.dumps(self.cfg), encoding='utf-8')
        with self.assertRaises(ValueError):
            self.run_build()
        self.assertFalse((self.root / 'output').exists())
        self.cfg['exclude'] = ['suspected_automation']
        self.config.write_text(json.dumps(self.cfg), encoding='utf-8')
        (self.root / 'output').mkdir()
        with self.assertRaises(ValueError):
            self.run_build()

    def test_partition_date_and_symlink_guards(self):
        source = self.inputs / '2026-10-02.log'
        wrong = self.inputs / '2026-10-03.log'
        source.rename(wrong)
        with self.assertRaises(ValueError):
            self.run_build()
        shutil.rmtree(str(self.root / 'output'))
        wrong.rename(source)
        wrong.symlink_to(source)
        with self.assertRaises(ValueError):
            self.run_build()


class VisitorIpPolicy(unittest.TestCase):
    # Reuse fixture construction, not inherited request-only test methods.
    setUpClass = classmethod(BatchIntegration.setUpClass.__func__)
    setUp = BatchIntegration.setUp
    def line(self, day, ip='192.0.2.1', path='/ordinary', second=0):
        import datetime
        stamp = datetime.datetime.strptime(day, '%Y-%m-%d').strftime('%d/%b/%Y')
        return ('{} - - [{}:10:00:{:02d} +0000] "GET {} HTTP/1.1" 200 99 "-" '
                '"Mozilla/5.0 (Windows) Chrome/126"\n'.format(ip, stamp, second, path)).encode('ascii')

    def policy_build(self, **kwargs):
        return builder.build(self.config, self.inputs, self.root / 'output', perl=self.perl,
                             prefix='/vstats/example.test/', **kwargs)

    def test_default_excludes_source_across_days_but_not_months(self):
        before = self.line('2026-10-01', path='/before?token=SECRET_SENTINEL')
        after = self.line('2026-10-03', path='/after')
        other = self.line('2026-10-03', ip='198.51.100.1')
        november = self.line('2026-11-01')
        asset = self.line('2026-10-02', path='/style.css', second=30)
        (self.inputs / '2026-10-01.log').write_bytes(before)
        (self.inputs / '2026-10-02.log').write_bytes(b''.join(self.lines) + asset + self.ordinary)
        (self.inputs / '2026-10-03.log').write_bytes(after + other)
        (self.inputs / '2026-11-01.log').write_bytes(november)
        result = self.policy_build(page_size=2)
        self.assertTrue(result['ip_exclusion']['enabled'])
        self.assertEqual(result['behavior']['flagged_requests'], 6)
        self.assertEqual(result['ip_exclusion']['additional_excluded_requests'], 3)
        self.assertEqual(result['excluded_by_month']['2026-10']['records'], 9)
        self.assertEqual(result['request_excluded_by_month']['2026-10']['records'], 6)
        self.assertEqual((self.root / 'output/filtered/2026-10-01.log').read_bytes(), b'')
        self.assertEqual((self.root / 'output/filtered/2026-10-02.log').read_bytes(), self.ordinary)
        self.assertEqual((self.root / 'output/filtered/2026-10-03.log').read_bytes(), other)
        self.assertEqual((self.root / 'output/filtered/2026-11-01.log').read_bytes(), november)
        self.assertEqual((self.root / 'output/request-filtered/2026-10-01.log').read_bytes(), before)
        self.assertEqual((self.root / 'output/request-filtered/2026-10-02.log').read_bytes(), asset + self.ordinary)
        text = ''.join(p.read_text(encoding='utf-8') for p in (self.root / 'output/review').glob('2026-10-*.html'))
        self.assertEqual(text.count('<button data-request-id='), 9)
        self.assertIn('Automated IP for 2026-10', text)
        self.assertIn('Trigger evidence, Broad path probing:', text)
        self.assertNotIn('SECRET_SENTINEL', text)
        self.assertNotIn('Mozilla/5.0', text)
        self.assertIn('requests/', text)

    def test_disable_preserves_unflagged_source_traffic(self):
        ordinary = self.line('2026-10-02', second=30)
        (self.inputs / '2026-10-02.log').write_bytes(b''.join(self.lines) + ordinary)
        result = self.policy_build(exclude_automated_ips=False)
        self.assertFalse(result['ip_exclusion']['enabled'])
        self.assertEqual(result['ip_exclusion']['additional_excluded_requests'], 0)
        self.assertEqual((self.root / 'output/filtered/2026-10-02.log').read_bytes(), ordinary)
        self.assertEqual((self.root / 'output/request-filtered/2026-10-02.log').read_bytes(), ordinary)

    def test_explicit_inclusion_can_restore_an_ip(self):
        before = self.line('2026-10-01')
        (self.inputs / '2026-10-01.log').write_bytes(before)
        self.cfg['behavior_include'] = [hashlib.sha256(before.rstrip(b'\n')).hexdigest()]
        self.config.write_text(json.dumps(self.cfg), encoding='utf-8')
        result = self.policy_build()
        self.assertEqual((self.root / 'output/filtered/2026-10-01.log').read_bytes(), before)
        self.assertEqual(result['ip_exclusion']['inclusion_overrides'], 1)
        self.assertEqual(len(result['ip_exclusion']['restored_source_months']), 1)
        text = (self.root / 'output/review/2026-10-001.html').read_text(encoding='utf-8')
        self.assertIn('Included by request ID override', text)
        self.assertIn('Automated IP for 2026-10', text)

    def test_canonical_ipv6_and_distinct_ipv4_scope(self):
        self.lines = [line.replace(b'192.0.2.1', b'2001:db8::1') for line in self.lines]
        alias = self.line('2026-10-01', ip='2001:0DB8:0:0:0:0:0:1')
        separate = self.line('2026-10-01', ip='192.0.2.1')
        (self.inputs / '2026-10-01.log').write_bytes(alias + separate)
        (self.inputs / '2026-10-02.log').write_bytes(b''.join(self.lines))
        self.policy_build()
        self.assertEqual((self.root / 'output/filtered/2026-10-01.log').read_bytes(), separate)

    def test_policy_requires_boolean(self):
        for value in ('false', 0, None):
            with self.assertRaises(ValueError):
                self.policy_build(exclude_automated_ips=value)

    def test_filter_bytes_preserves_unattributed_and_line_endings(self):
        raw = b'first\r\n\nmalformed\nlast\r'
        kept, manifest = builder.filtered_bytes(raw, {1, 4}, hashlib.sha256(raw).hexdigest())
        self.assertEqual(kept, b'\nmalformed\n')
        self.assertEqual(manifest['excluded_records'], 2)
        self.assertEqual(manifest['input_records'], 4)


if __name__ == '__main__':
    unittest.main()
