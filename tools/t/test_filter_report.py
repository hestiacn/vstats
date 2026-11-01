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


if __name__ == '__main__':
    unittest.main()
