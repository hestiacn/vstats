import copy
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import automation_analysis as analysis

PERL = os.environ.get('VSTATS_TEST_PERL', '/opt/vstats/runtime/perl-5.44.0/bin/perl')
UA = 'Mozilla/5.0 (Synthetic Mobile) Safari/600.1'
SCANNER = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36'
MONDAY = 1790553600  # 2026-09-28 00:00 UTC


class CorpusRules(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vstats-city-tests-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        code = 'use VStats::TrafficClassifier;print VStats::TrafficClassifier::canonical_json(VStats::TrafficClassifier->defaults);'
        self.config = json.loads(subprocess.check_output([PERL, '-I' + str(ROOT / 'lib'), '-e', code],
            env=dict(os.environ, LC_ALL='C', LANG='C')).decode('utf-8'))
        self.config['exclude'] = ['suspected_automation']
        self.index = 0

    def row(self, timestamp, path='/', client='192.0.2.1', ua=UA, **values):
        self.index += 1
        row = {'client': client, 'timestamp': timestamp, 'normalized_target': path, 'user_agent': ua,
            'method': 'GET', 'status': 200, 'observed_vhost': 'example.test', 'host': None,
            'client_source': 'socket_peer', 'field_observability': {'user_agent': 'value' if ua else 'absent', 'referrer': 'absent'},
            'source_format': 'combined', 'source_month': datetime.datetime.utcfromtimestamp(timestamp).strftime('%Y-%m'),
            'request_id': hashlib.sha256(str(self.index).encode()).hexdigest(), 'line_index': self.index,
            'source_key': client, 'actor': 'unknown', 'suspected_automation': False,
            'ip_expansion_eligible': False, 'excluded': False, 'behavior_included': False}
        row.update(values)
        return row

    def prepare(self, rows, extra_days=None):
        daily = {}
        for row in rows:
            day = datetime.datetime.utcfromtimestamp(row['timestamp']).strftime('%Y-%m-%d')
            daily.setdefault(day, []).append(row)
        paths = []
        for day, details in daily.items():
            path = self.root / (day + '.json')
            path.write_text(json.dumps({'input_sha256': analysis.identity([(r['request_id'], r['timestamp']) for r in details]),
                'details': details, 'observability_sha256': '1' * 64}), encoding='utf-8')
            paths.append(path)
        return analysis.prepare(sorted(paths), self.config, set(daily) | set(extra_days or ()))

    def flags(self, rows, result, rule):
        return [rule in result['matches'].get((datetime.datetime.utcfromtimestamp(r['timestamp']).strftime('%Y-%m-%d'),
                                             r['line_index']), {}) for r in rows]

    def burst(self):
        quoted = '"Mozilla/5.0 (Synthetic) Chrome/123 Safari/537.36"'
        rows = [self.row(MONDAY + 100 + i, '/page-' + str(i), ua=quoted) for i in range(8)]
        rows += [self.row(MONDAY + 1000 + i, client='198.51.100.' + str(i + 1)) for i in range(100)]
        return rows

    def test_compound_requires_independent_claim_and_rate(self):
        self.config['compound_automation']['enabled'] = 1
        rows = self.burst()
        result = self.prepare(rows)
        self.assertEqual(self.flags(rows, result, 'compound_automation'), [True] * 8 + [False] * 100)
        self.assertTrue(all(len(p['compound_automation']['classes']) == 2 for p in result['matches'].values()))
        for row in rows[:8]:
            row['user_agent'] = UA
        self.assertFalse(any(self.flags(rows, self.prepare(rows), 'compound_automation')), 'session restore with normal browser claim retained')

    def test_quote_format_artifact_and_missing_peer_controls_abstain(self):
        self.config['compound_automation']['enabled'] = 1
        rows = self.burst()
        self.assertFalse(self.prepare(rows[:8])['matches'])
        for row in rows:
            row['user_agent'] = '"Wrapped/1.0"'
        self.assertFalse(self.prepare(rows)['matches'])

    def test_continuity_veto(self):
        self.config['compound_automation']['enabled'] = 1
        rows = self.burst()
        rows.append(self.row(MONDAY + 107, '/app.css', ua=rows[0]['user_agent'],
            referrer_host='www.example.test', referrer_path='/page-0',
            field_observability={'user_agent': 'value', 'referrer': 'value'}))
        self.assertFalse(self.prepare(rows)['matches'])
        rows[-1]['field_observability']['referrer'] = 'unobserved'
        self.assertTrue(self.prepare(rows)['matches'])

    def test_metadata_substream_never_inherits_other_uas(self):
        self.config['compound_automation']['enabled'] = 1
        rows = [self.row(MONDAY + 100)] + [self.row(MONDAY + 101 + i, p, ua=None)
            for i, p in enumerate(['/robots.txt', '/sitemap.xml', '/.well-known/security.txt'])]
        rows.append(self.row(MONDAY + 105, '/favicon.ico', ua='Other/1.0'))
        self.assertEqual(self.flags(rows, self.prepare(rows), 'compound_automation'), [False, True, True, True, False])
        for row in rows[1:4]:
            row['field_observability']['user_agent'] = 'unobserved'
        self.assertFalse(self.prepare(rows)['matches'])

    def test_single_page_robots_geography_and_nats_are_not_rules(self):
        for rule in analysis.AUTOMATION_RULES:
            self.config[rule]['enabled'] = 1
        rows = [self.row(MONDAY + 100), self.row(MONDAY + 101, ua='DifferentBrowser/2'),
                self.row(MONDAY + 102, '/robots.txt')]
        for r in rows:
            r.update(city='Amsterdam', country='NL', asn='hosting')
        first = self.prepare(rows)
        for r in rows:
            r.update(city='Frankfurt', country='DE', asn='residential')
        second = self.prepare(rows)
        self.assertFalse(first['matches'])
        self.assertEqual(first, second)

    def scheduled(self, count=4):
        rows, days = [], set()
        phase_paths = [(1, '/wp-json/'), (1, '/feed/'), (1, '/fonts/a.woff2'),
                       (4, '/api/pages'), (4, '/news/feed/'), (4, '/fonts/b.woff2')]
        for week in range(count):
            days.update(datetime.datetime.utcfromtimestamp(MONDAY + week * 604800 + i * 86400).strftime('%Y-%m-%d') for i in range(7))
            for i, (weekday, path) in enumerate(phase_paths):
                rows.append(self.row(MONDAY + week * 604800 + weekday * 86400 + i,
                    path, client='192.0.2.' + str(i + 1)))
        return rows, days

    def test_weekly_signature_and_positive_homepage_link(self):
        self.config['scheduled_automation']['enabled'] = 1
        rows, days = self.scheduled()
        anchor = rows[-1]
        linked = self.row(anchor['timestamp'] - 2, client=anchor['client'])
        unrelated = self.row(anchor['timestamp'] - 1, client='203.0.113.99')
        later = self.row(anchor['timestamp'] + 1801, client=anchor['client'])
        rows += [linked, unrelated, later]
        flags = self.flags(rows, self.prepare(rows, days), 'scheduled_automation')
        self.assertEqual(flags[:24], [True] * 24)
        self.assertEqual(flags[-3:], [True, False, False])
        self.assertFalse(any(r['ip_expansion_eligible'] for r in rows))

    def test_target_cycle_cannot_corroborate_itself(self):
        self.config['scheduled_automation']['enabled'] = 1
        rows, days = self.scheduled(3)
        self.assertFalse(self.prepare(rows, days)['matches'])

    def test_aggressive_candidates_never_change_default_classification(self):
        self.config['scheduled_automation'].update(enabled=1, aggressive_comparison=1)
        rows, days = self.scheduled()
        candidate = self.row(rows[-1]['timestamp'], client='203.0.113.99')
        rows.append(candidate)
        result = self.prepare(rows, days)
        key = (datetime.datetime.utcfromtimestamp(candidate['timestamp']).strftime('%Y-%m-%d'), candidate['line_index'])
        self.assertIn(key, result['aggressive'])
        self.assertNotIn(key, result['matches'])
        report = {'details': [candidate], 'counts': {'analyzed': 1},
                  'behavior': {'enabled': False, 'flagged_requests': 0, 'overlap_requests': 0, 'actors': {'unknown': 0}},
                  'adjusted_requests': {'original': 1, 'excluded': 0, 'remaining': 1}}
        analysis.apply_report(report, key[0], result, self.config)
        self.assertFalse(candidate['excluded'])
        self.assertFalse(candidate['suspected_automation'])
        self.assertIn('aggressive_cohort_candidate', candidate)

    def test_positive_classification_is_geography_invariant(self):
        self.config['compound_automation']['enabled'] = 1
        rows = self.burst()
        for r in rows:
            r.update(city='Amsterdam', country='NL')
        first = self.prepare(rows)
        self.assertTrue(first['matches'])
        for r in rows:
            r.update(city='Dublin', country='US')
        self.assertEqual(first, self.prepare(rows))

    def test_incomplete_weeks_and_ua_only_abstain(self):
        self.config['scheduled_automation']['enabled'] = 1
        rows, days = self.scheduled()
        self.assertFalse(self.prepare(rows)['matches'])
        for row in rows:
            row['normalized_target'] = '/'
        self.assertFalse(self.prepare(rows, days)['matches'])

    def test_inferred_is_bounded_exact_address_and_fingerprint(self):
        cfg = self.config['inferred_scanner']
        cfg.update(enabled=1, months=['2026-09'])
        proof = {'valid': 1, 'lookup_at': MONDAY + 1000, 'evidence_sha256': 'a' * 64}
        rows = [self.row(MONDAY + 100, ua=SCANNER, operator_inference_candidate=proof),
                self.row(MONDAY + 200, client='192.0.2.2', ua=SCANNER, operator_inference_candidate=proof),
                self.row(MONDAY + 300, client='192.0.2.3', ua=SCANNER),
                self.row(MONDAY + 400, client='192.0.2.1', ua=UA, operator_inference_candidate=proof)]
        self.assertEqual(self.flags(rows, self.prepare(rows), 'inferred_scanner'), [True, True, False, False])
        cfg['months'] = []
        self.assertFalse(self.prepare(rows)['matches'])
        cfg['months'] = ['2026-09']; cfg['window_days'] = 1
        proof['lookup_at'] += 2 * 86400
        self.assertFalse(self.prepare(rows)['matches'])

    def test_inference_does_not_use_failed_or_unobserved_provenance(self):
        self.config['inferred_scanner'].update(enabled=1, months=['2026-09'])
        proof = {'valid': 1, 'lookup_at': MONDAY + 1000, 'evidence_sha256': 'a' * 64}
        rows = [self.row(MONDAY + i, client='192.0.2.' + str(i + 1), ua=SCANNER,
                         operator_inference_candidate=copy.deepcopy(proof)) for i in range(2)]
        rows[1]['operator_inference_candidate']['valid'] = 0
        self.assertFalse(self.prepare(rows)['matches'])
        rows[1]['operator_inference_candidate']['valid'] = 1
        rows[1]['client_source'] = 'unknown'
        self.assertFalse(self.prepare(rows)['matches'])

    def test_explicit_tool_tokens_not_arbitrary_products(self):
        self.config['declared_automation'].update(enabled=1, tokens=['SyntheticCrawler'])
        rows = [self.row(MONDAY + 1, ua='SyntheticCrawler/1.0'), self.row(MONDAY + 2, ua='ReaderApp/1.0 contact@example.test'),
                self.row(MONDAY + 3, ua='NotSyntheticCrawler/1.0')]
        self.assertEqual(self.flags(rows, self.prepare(rows), 'declared_automation'), [True, False, False])

    def micro_rows(self, branch='login', start=MONDAY + 100):
        if branch == 'login':
            events = [('HEAD', '/wp/wp-login.php', 'windows'), ('HEAD', '/wp-login.php', 'windows'),
                      ('HEAD', '/site/wp-login.php', 'windows'), ('GET', '/wp-login.php', 'linux')]
        else:
            events = [('GET', '/', 'mac'), ('POST', '/', 'windows'),
                      ('POST', '/wp-json/batch/v1', 'mac'), ('POST', '/index.php', 'mac')]
        return [self.row(start + i, path, method=method, status=500 if method == 'POST' else 200,
                        ua='Browser-' + platform + '/1', browser_claim_platform=platform)
                for i, (method, path, platform) in enumerate(events)]

    def test_micro_probe_branches_and_request_scope(self):
        self.config['wp_micro_probe']['enabled'] = 1
        for branch in ['login', 'post']:
            rows = [self.row(MONDAY + 1)] + self.micro_rows(branch) + [self.row(MONDAY + 300)]
            result = self.prepare(rows)
            self.assertEqual(self.flags(rows, result, 'wp_micro_probe'), [False] + [True] * 4 + [False])
            for proof in result['matches'].values():
                self.assertEqual(proof['wp_micro_probe']['branch'], branch)
            self.assertFalse(any(r['ip_expansion_eligible'] for r in rows))

    def test_micro_probe_browser_admin_nat_and_missing_provenance_controls(self):
        self.config['wp_micro_probe']['enabled'] = 1
        for branch in ['login', 'post']:
            for field, value in [('client', '192.0.2.2'), ('observed_vhost', 'other.test'),
                                 ('client_source', 'unknown'), ('browser_claim_platform', None),
                                 ('user_agent', None)]:
                rows = self.micro_rows(branch); rows[-1][field] = value
                self.assertFalse(self.prepare(rows)['matches'], (branch, field))
            rows = self.micro_rows(branch)
            for r in rows:
                r['user_agent'] = UA; r['browser_claim_platform'] = 'ios'
            self.assertFalse(self.prepare(rows)['matches'], 'stable browser/admin cannot supply rotation')
            rows = self.micro_rows(branch); rows[-1]['timestamp'] = rows[0]['timestamp'] + 20
            self.assertFalse(self.prepare(rows)['matches'], 'outside micro window')
        edge = self.micro_rows('post'); edge[-1]['timestamp'] = edge[1]['timestamp'] + 10
        self.assertEqual(self.flags(edge, self.prepare(edge), 'wp_micro_probe'), [False, True, True, True],
                         'inclusive POST boundary retains an entry outside the actual witness window')
        rows = self.micro_rows('post')
        for r in rows:
            r['status'] = 200
        self.assertFalse(self.prepare(rows)['matches'], 'successful browser/API calls are insufficient')
        rows = self.micro_rows('post'); rows[2]['normalized_target'] = '/other-endpoint'
        self.assertFalse(self.prepare(rows)['matches'], 'configured API witness required')
        rows = self.micro_rows('login'); rows[2]['method'] = 'GET'
        self.assertFalse(self.prepare(rows)['matches'], 'three distinct HEAD locations required')

    def test_micro_probe_midnight_continuity_and_inclusion(self):
        self.config['wp_micro_probe']['enabled'] = 1
        rows = self.micro_rows('post', MONDAY + 86398)
        result = self.prepare(rows)
        self.assertTrue(all(self.flags(rows, result, 'wp_micro_probe')), 'disjoint days share bounded evidence')
        # A real page/asset edge from another browser behind the same gateway
        # conservatively vetoes the coincident micro episode.
        page = self.row(MONDAY + 86398, '/ordinary', ua=UA)
        asset = self.row(MONDAY + 86399, '/style.css', ua=UA, referrer_host='example.test',
                         referrer_path='/ordinary', field_observability={'user_agent': 'value', 'referrer': 'value'})
        self.assertFalse(self.prepare(rows + [page, asset])['matches'])
        self.config['behavior_include'] = [rows[0]['request_id']]
        report = {'details': rows[:2], 'counts': {'analyzed': 2}, 'behavior': {'enabled': False,
            'flagged_requests': 0, 'overlap_requests': 0, 'actors': {'unknown': 0}}, 'adjusted_requests': {}}
        analysis.apply_report(report, '2026-09-28', result, self.config)
        self.assertFalse(rows[0]['excluded']); self.assertTrue(rows[1]['excluded'])
        self.assertEqual(report['behavior']['flagged_requests'], 2)

    def test_metadata_policy_never_claims_automation_or_expands_a_source(self):
        self.config['metadata_requests']['enabled'] = 1
        paths = ['/robots.txt', '/page-sitemap.xml', '/wp-sitemap-posts-page-1.xml',
                 '/ro/sitemap.xml.gz', '/', '/sitemap.xml.html', '/robots.txt.bak', '/wp-sitemap-admin.php']
        rows = [self.row(MONDAY + i, path) for i, path in enumerate(paths)]
        rows[0]['user_agent'] = None; rows[0]['field_observability']['user_agent'] = 'unobserved'
        result = self.prepare(rows)
        self.assertEqual(self.flags(rows, result, 'metadata_requests'), [True] * 4 + [False] * 4)
        report = {'details': rows, 'counts': {'analyzed': len(rows)}, 'behavior': {'enabled': False,
            'flagged_requests': 0, 'overlap_requests': 0, 'actors': {'unknown': 0}}, 'adjusted_requests': {}}
        self.config['behavior_include'] = [rows[0]['request_id']]
        analysis.apply_report(report, '2026-09-28', result, self.config)
        self.assertEqual(report['adjusted_requests']['excluded'], 3)
        self.assertEqual(report['behavior']['flagged_requests'], 0)
        self.assertFalse(any(r['suspected_automation'] or r['ip_expansion_eligible'] for r in rows))
        self.assertFalse(rows[0]['excluded']); self.assertTrue(rows[0]['behavior_included'])
        self.config['metadata_requests']['enabled'] = 0
        self.assertFalse(self.prepare(rows)['matches'])

    def test_metadata_capacity_abstains_without_partial_exclusions(self):
        self.config['metadata_requests']['enabled'] = 1
        rows = [self.row(MONDAY + i, '/robots.txt', ua=None) for i in range(3)]
        with mock.patch.object(analysis, 'MAX_RECORDS', 2):
            result = self.prepare(rows)
        self.assertEqual(result['status'], 'unavailable_capacity')
        self.assertFalse(result['matches'])

    def test_over_capacity_retains_legacy_and_records_unavailable(self):
        self.config['compound_automation']['enabled'] = 1
        rows = self.burst()
        with mock.patch.object(analysis, 'MAX_RECORDS', 2):
            result = self.prepare(rows)
        self.assertEqual(result['status'], 'unavailable_capacity')
        self.assertFalse(result['matches'])

    def test_inclusion_and_no_new_ip_expansion(self):
        self.config['compound_automation']['enabled'] = 1
        rows = self.burst();result = self.prepare(rows)
        self.config['behavior_include'] = [rows[0]['request_id']]
        report = {'details': rows, 'counts': {'analyzed': len(rows)},
                  'behavior': {'enabled': False, 'flagged_requests': 0, 'overlap_requests': 0, 'actors': {'unknown': 0}},
                  'adjusted_requests': {'original': len(rows), 'excluded': 0, 'remaining': len(rows)}}
        analysis.apply_report(report, '2026-09-28', result, self.config)
        self.assertFalse(rows[0]['excluded']);self.assertTrue(rows[0]['behavior_included'])
        self.assertEqual(report['adjusted_requests']['excluded'], 7)
        self.assertEqual(report['behavior']['flagged_requests'], 8)
        self.assertEqual(report['behavior']['inclusion_overrides'], 1)
        self.assertTrue(all(not r['ip_expansion_eligible'] for r in rows))


if __name__ == '__main__':
    unittest.main()
