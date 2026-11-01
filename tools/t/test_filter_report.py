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
