"""Independent design cases for native fallback, coverage and UI isolation."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, str(ROOT / 'tools' / filename))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


export = load('filters_export_test', 'traffic-filter-report.py')
publisher = load('filters_publisher_test', 'publish-static-reports.py')
from vstats_filters import add_filters_menu, identity, validate_profile, defaults, filter_catalogue
PERL = os.environ.get('VSTATS_TEST_PERL', '/opt/vstats/runtime/perl-5.44.0/bin/perl')


def record(day, path='/a', status=200, stamp='12:00:00'):
    return ('192.0.2.1 - - [' + day + '/Oct/2026:' + stamp + ' +0000] "GET ' + path +
            ' HTTP/1.1" ' + str(status) + ' 12 "-" "Mozilla/5.0"\n').encode('ascii')


class Publisher(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='vstats-filters-tests-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.input = self.root / 'input'; self.input.mkdir()
        self.config = self.root / 'config.json'
        self.settings = {'schema_version': 1, 'exclude': ['suspected_automation'],
                         'rapid_scan': {'enabled': 1, 'min_requests': 2, 'distinct_paths': 2, 'not_found_requests': 2}}
        self.config.write_text(json.dumps(self.settings), encoding='utf-8')

    def build(self, name='output', fallback=True):
        return export.build(self.config, self.input, self.root / name, perl=PERL, capacity_fallback=fallback)

    def test_actual_hard_record_limit_disables_the_whole_month(self):
        earlier = record('01', '/a', 404) + record('01', '/b', 404)
        (self.input / '2026-10-01.log').write_bytes(earlier)
        control = self.build('control')
        self.assertEqual(control['excluded_by_month']['2026-10']['records'], 2)
        large = record('02') * 100001
        (self.input / '2026-10-02.log').write_bytes(large)
        result = self.build()
        self.assertEqual(set(result['capacity_fallback']), {'2026-10'})
        self.assertEqual(result['capacity_fallback']['2026-10']['limit'], 'records')
        self.assertEqual((self.root / 'output/filtered/2026-10-01.log').read_bytes(), earlier)
        self.assertEqual((self.root / 'output/filtered/2026-10-02.log').read_bytes(), large)
        self.assertEqual(result['ip_exclusion']['private_source_months'], {})
        self.assertEqual(result['counts']['unclassified_due_to_limits'], 100003)
        self.assertIn('unavailable, never zero', (self.root / 'output/classification/index.html').read_text())

    def test_operator_lowered_quota_remains_a_failure(self):
        self.settings['limits'] = {'records': 2}
        self.config.write_text(json.dumps(self.settings), encoding='utf-8')
        original = record('01') * 3
        (self.input / '2026-10-01.log').write_bytes(original)
        with self.assertRaises(RuntimeError):
            self.build()
        self.assertEqual((self.input / '2026-10-01.log').read_bytes(), original)

    def test_unparsed_input_does_not_masquerade_as_a_capacity_refusal(self):
        original = b'unsupported syntax\n'
        (self.input / '2026-10-01.log').write_bytes(original)
        with self.assertRaises(RuntimeError):
            self.build()
        self.assertEqual((self.input / '2026-10-01.log').read_bytes(), original)

    def test_empty_partition_has_zero_input_not_invented_classifications(self):
        (self.input / '2026-10-01.log').write_bytes(b'')
        result = self.build()
        self.assertEqual(result['capacity_fallback'], {})
        self.assertTrue(result['daily_reports'][0]['empty_partition'])
        self.assertEqual(result['counts']['lines_total'], 0)

    def test_missing_or_changed_old_input_requires_explicit_acknowledgement(self):
        old = {'applied': {'known': True}, 'input_days': {'2026-10-01': {'sha256': 'a'}, '2026-10-02': {'sha256': 'b'}}}
        result = publisher.coverage(old, {'2026-10-01': {'sha256': 'changed'}})
        self.assertTrue(result['needs_acknowledgement'])
        self.assertEqual(result['missing_previous_days'], ['2026-10-02'])
        self.assertEqual(result['changed_previous_days'], ['2026-10-01'])
        unknown = publisher.coverage({'applied': None, 'input_days': None}, {})
        self.assertFalse(unknown['known_previous_input'])
        self.assertTrue(unknown['needs_acknowledgement'])

    def test_copy_of_mutable_history_has_no_shared_inode(self):
        source, destination = self.root / 'source', self.root / 'destination'
        source.mkdir(); (source / 'history').write_bytes(b'previous history')
        publisher.clone_private(str(source), str(destination))
        (destination / 'history').write_bytes(b'new staged history')
        self.assertEqual((source / 'history').read_bytes(), b'previous history')
        self.assertNotEqual((source / 'history').stat().st_ino, (destination / 'history').stat().st_ino)

    def test_native_reports_keep_data_and_get_one_matching_filters_menu(self):
        html = '<html><body><nav style=\'padding:10px 16px;font:14px sans-serif\'>old controls</nav><section style=\'margin:10px 16px;padding:12px;border:1px solid #cbd5e1;font:14px sans-serif\'>filter explanation</section><div class="header-right"><div class="dropdown-menu" id="mobileMenu">\t</div>\n\t<button id="theme-toggle">theme</button></div><table id="counts"><td>123</td></table></body></html>'
        cleaned = publisher.remove_filter_chrome(html)
        decorated = add_filters_menu(cleaned, 'example.test', '/vstats/example.test/2026-10/report.html#TOP')
        self.assertNotIn('filter explanation', decorated)
        self.assertIn('<table id="counts"><td>123</td></table>', decorated)
        self.assertEqual(decorated.count('vstats-filters-menu'), 1)
        self.assertIn('return=%2Fvstats%2Fexample.test%2F2026-10%2Freport.html%23TOP', decorated)

    def test_native_kernel_validates_before_control_pages_are_bound(self):
        root = self.root / 'kernel'; root.mkdir()
        (root / 'index.html').write_text('<html><body>Sites</body></html>', encoding='utf-8')
        native = b'<html><body><table><tr><td>1</td></tr></table></body></html>'
        def render(account, site, options, label, output=None, config_dir=None):
            output.write(native)
        with mock.patch.object(publisher, 'TOPICS', ['main']), mock.patch.object(publisher, 'invoke', side_effect=render):
            publisher.render_site_view(None, 'example.test', str(root / 'example.test'),
                {'2026-10': {'hits': 1, 'nonviewed_hits': 0}}, os.getgid(), [])
        for path in root.glob('**/*.html'):
            self.assertNotIn('/filters/', path.read_text(encoding='utf-8'))
        self.assertGreater(publisher.validate_report_links(str(root)), 0)

    def test_control_requests_do_not_create_visits_in_the_website_report(self):
        from normalize_logs import normalize
        for path in ['/vstats/', '/vstats-control/session', '/vstats-control/sites/example.test/state?view=one']:
            self.assertEqual(normalize(record('01',path)), (None,None,'statistics-request'))
        self.assertIsNotNone(normalize(record('01','/vstats-control-other'))[1])

    def test_history_documentation_has_same_link_scope_as_current_docs(self):
        root = self.root / 'pages'
        for relative in ['docs','history/20261105T120000Z-12345678/docs']:
            directory=root/relative;directory.mkdir(parents=True)
            (directory/'contrib.html').write_text('<html><a href="/files/legacy-tool.tgz">Upstream reference</a></html>',encoding='utf-8')
        self.assertEqual(publisher.validate_report_links(str(root)),0)
        report=root/'history/20261105T120000Z-12345678/example.test';report.mkdir()
        (report/'index.html').write_text('<html><a href="missing-report.html">Broken report</a></html>',encoding='utf-8')
        with self.assertRaises(RuntimeError):publisher.validate_report_links(str(root))


    def test_import_normalizes_classifier_and_keeps_provenance_refusals(self):
        site = 'example.test'
        config = self.root / 'native-config'; (config / 'traffic-classification').mkdir(parents=True)
        cfg = config / 'traffic-classification' / ('awstats.' + site + '.json')
        cfg.write_text(json.dumps({'schema_version': 1, 'behavior': {'enabled': 1}}), encoding='utf-8')
        native_config = config / ('awstats.' + site + '.conf')
        text = 'LevelForRobotsDetection=1\n'; native_config.write_text(text, encoding='utf-8')
        base = self.root / 'managed'; corpus = base / 'corpus' / site / 'version1'; corpus.mkdir(parents=True)
        (corpus.parent / 'current').symlink_to('version1')
        receipt_file = corpus / 'receipt.json'; receipt = {'days': {}, 'native_months': {}}
        receipt_file.write_text(json.dumps(receipt), encoding='utf-8')
        sites = {site: {'behavior_filter': True, 'verified_crawler_filter': False}}
        account = types.SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        state = {'completed_utc': '2026-11-09T12:00:00Z'}
        def run():
            return publisher.imported_profiles(sites, str(base), str(config), str(ROOT), state, account)[site]
        with mock.patch.object(publisher, 'APP', str(ROOT)), mock.patch.object(publisher, 'PERL', PERL), mock.patch.object(publisher, 'archived_evidence_for_days', return_value={}):
            imported = run()['applied']
            self.assertEqual(imported, validate_profile(imported, str(ROOT), PERL))
            self.assertEqual(set(imported['filters']), {r['key'] for r in filter_catalogue()['components']})
            self.assertTrue(imported['filters']['behavior'])
            for bad in [text + 'LevelForRobotsDetection=2\n', 'Include "other.conf"\n' + text]:
                native_config.write_text(bad, encoding='utf-8')
                with self.assertRaisesRegex(RuntimeError, 'Cannot verify the existing managed profile'): run()
            native_config.write_text(text, encoding='utf-8')
            receipt['days'] = {'2026-11-01': {'sha256': 'a' * 64}}
            receipt_file.write_text(json.dumps(receipt), encoding='utf-8')
            with self.assertRaisesRegex(RuntimeError, 'corpus bytes'): run()
            receipt = {'days': {}, 'native_months': {'2026-11': {'signature': 'a' * 64}}}
            receipt_file.write_text(json.dumps(receipt), encoding='utf-8')
            with self.assertRaisesRegex(RuntimeError, 'Cannot verify the existing managed profile'): run()
            # An empty-input signature can pass while the independent history gate fails.
            sources = ['wwwroot/cgi-bin/awstats.pl', 'wwwroot/cgi-bin/lib/robots.pm',
                       'tools/lib/VStats/TrafficClassifier.pm', 'tools/traffic-filter-report.py',
                       'tools/traffic-classify.pl', 'tools/native_history_cache.py']
            native = hashlib.sha256(b''.join((ROOT / p).read_bytes() for p in sources) +
                json.dumps({'ip_month_policy': True, 'views': 4}, sort_keys=True).encode()).hexdigest()
            prefix = hashlib.sha256(cfg.read_bytes() + text.encode() + native.encode()).hexdigest()
            receipt['native_months']['2026-11'] = {'signature': hashlib.sha256((prefix + '[]').encode()).hexdigest(),
                'history_sha256': {key: 'a' * 64 for key in ['original', 'confirmed', 'requests', 'behavior']}}
            receipt_file.write_text(json.dumps(receipt), encoding='utf-8')
            with self.assertRaisesRegex(RuntimeError, 'Managed native history identity changed'): run()
            receipt_file.unlink()
            with self.assertRaises(FileNotFoundError): run()


@unittest.skipUnless(os.geteuid() == 0, 'Root is needed for the isolated publisher ownership fixture')
class Publication(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='vstats-filters-tests-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.base, self.web, self.config, self.state = [self.root / s for s in ['base','web','config','state']]
        for p in [self.base,self.web,self.config,self.state,self.state/'runs']:
            p.mkdir(exist_ok=True)
        self.old = '20261105T100000Z-abcdef12'
        self.generation = self.web / 'generations' / self.old
        site = self.generation / 'example.test'
        (site / '2026-10').mkdir(parents=True)
        for kind in ['css','js']:(self.generation / 'assets' / kind).mkdir(parents=True)
        self.report = ('<html><head><style>:root{--text-color:black}</style></head><body><div class="header-right"><div class="dropdown-menu" id="mobileMenu">\t</div>\n\t<button id="theme-toggle">Theme</button></div><button id="back-to-top">Top</button><table id="native-counts"><tr><td>123</td></tr></table></body></html>')
        (site / '2026-10/awstats.example.test.html').write_text(self.report,encoding='utf-8')
        (site / 'index.html').write_text('<html><body><h1>example.test</h1><a href="2026-10/awstats.example.test.html">October</a></body></html>',encoding='utf-8')
        (self.generation / 'index.html').write_text('<html><body><a href="example.test/">Website</a></body></html>',encoding='utf-8')
        (self.web / 'current').symlink_to('generations/' + self.old)
        (self.base / 'status.json').write_text(json.dumps({'generation':self.old,'sites':{'example.test':{'totals':{'2026-10':{'hits':123}}}}}),encoding='utf-8')
        (self.config / 'sites.json').write_text(json.dumps({'example.test':{'base_names':['example-access_log']}}),encoding='utf-8')
        self.settings={'base':str(self.base),'web':str(self.web),'config':str(self.config),'state':str(self.state),
                       'app':str(ROOT),'legacy_app':str(ROOT),'perl':PERL,'log':str(self.root/'logs'),
                       'source_log':str(self.root/'source'),'statistics_user':'root','web_group':'root','api_user':'root',
                       'perl_libraries':[]}
        self.settings_file=self.root/'settings.json';self.settings_file.write_text(json.dumps(self.settings),encoding='utf-8')
        values={k:getattr(publisher,k) for k in ['BASE','WEB','CONFIG','APP','LOG','LAUNCHER','PERL','PERL_LIBRARIES','SOURCE_LOG','PROFILE_MAP','PREVIEW_BASELINE','build_snapshot']}
        self.addCleanup(lambda:[setattr(publisher,k,v) for k,v in values.items()])

    def run_publisher(self):
        with mock.patch.object(sys,'argv',['publisher','--control-settings',str(self.settings_file),'--bootstrap-ui']), mock.patch.object(publisher.subprocess,'check_call',return_value=0):
            publisher.main()

    def test_bootstrap_preserves_native_values_and_commits_one_matching_profile_manifest(self):
        self.run_publisher()
        token=(self.web/'current').resolve().name
        manifest=json.loads((self.state/'runs'/token/'manifest.json').read_text())
        self.assertEqual(manifest['generation'],token)
        report=(self.web/'current/example.test/2026-10/awstats.example.test.html').read_text()
        self.assertIn('<table id="native-counts"><tr><td>123</td></tr></table>',report)
        self.assertIn('vstats-filters-menu',report)
        self.assertIsNone(manifest['profiles']['example.test']['applied'])
        self.assertFalse(manifest['profiles']['example.test']['managed'])
        self.assertTrue(all(value for key, value in manifest['profiles']['example.test']['default_profile']['filters'].items() if key != 'historical_operator'))
        self.assertFalse(manifest['profiles']['example.test']['default_profile']['filters']['historical_operator'])
        self.assertEqual((self.generation/'example.test/2026-10/awstats.example.test.html').read_text(),self.report)

    def test_bootstrap_cannot_relabel_a_generation_missing_its_matching_state(self):
        status = json.loads((self.base / 'status.json').read_text(encoding='utf-8'))
        status['generation'] = '20261105T090000Z-12345678'
        (self.base / 'status.json').write_text(json.dumps(status), encoding='utf-8')
        with self.assertRaisesRegex(RuntimeError, 'no verified profile manifest'):
            self.run_publisher()
        self.assertEqual((self.web / 'current').resolve(), self.generation)
        self.assertEqual((self.generation / 'example.test/2026-10/awstats.example.test.html').read_text(), self.report)

    def test_incomplete_stored_profile_is_refused_before_publication(self):
        profile = validate_profile(defaults(str(ROOT), PERL), str(ROOT), PERL)
        del profile['filters']['behavior']
        run = self.state / 'runs' / self.old; run.mkdir()
        (run / 'manifest.json').write_text(json.dumps({'generation': self.old, 'private_base': str(self.base),
            'profiles': {'example.test': {'applied': profile}}}), encoding='utf-8')
        before = (self.generation / 'example.test/2026-10/awstats.example.test.html').read_bytes()
        with self.assertRaisesRegex(ValueError, 'Invalid filter list'): self.run_publisher()
        self.assertEqual((self.web / 'current').resolve(), self.generation)
        self.assertEqual((self.generation / 'example.test/2026-10/awstats.example.test.html').read_bytes(), before)
        self.assertEqual([p.name for p in (self.state / 'runs').iterdir()], [self.old])

    def test_corpus_capacity_is_unavailable_for_every_component_and_match_count(self):
        import automation_analysis as corpus
        profile = validate_profile(defaults(str(ROOT), PERL), str(ROOT), PERL)
        inputs = self.root / 'capacity-input'; inputs.mkdir()
        (inputs / '2026-10-01.log').write_bytes(record('01') + record('01', stamp='12:00:01'))
        config = self.root / 'capacity-config.json'
        config.write_text(json.dumps(profile['classifier']), encoding='utf-8')
        with mock.patch.object(corpus, 'MAX_RECORDS', 1):
            result = export.build(config, inputs, self.root / 'capacity-output', perl=PERL)
        self.assertEqual(result['corpus_automation']['status'], 'unavailable_capacity')
        for key in corpus.RULES:
            self.assertEqual(result['evidence_classes'][key]['by_month'], {}, key)
        with mock.patch.object(publisher, 'APP', str(ROOT)), mock.patch.object(publisher, 'PERL', PERL):
            info = publisher.profile_state(True, profile, {}, {'totals': {'2026-10': {'hits': 123}}})
        info['corpus_automation'] = result['corpus_automation']
        info['matched_requests'] = {key + '_flagged_requests': result['behavior'][key + '_flagged_requests']
                                    for key in corpus.RULES}
        run = self.state / 'runs' / self.old; run.mkdir()
        (run / 'manifest.json').write_text(json.dumps({'generation': self.old,
            'private_base': str(self.base), 'profiles': {'example.test': info}}), encoding='utf-8')
        self.run_publisher()
        token = (self.web / 'current').resolve().name
        published = json.loads((self.state / 'runs' / token / 'manifest.json').read_text(encoding='utf-8'))
        actual = published['profiles']['example.test']
        for key in corpus.RULES:
            self.assertEqual(actual['effective'][key], 'Corpus evidence over limits; retained', key)
            self.assertNotIn(key + '_flagged_requests', actual['matched_requests'], key)

    def test_scheduled_status_respects_month_refusal_with_and_without_corpus_signatures(self):
        profile = validate_profile(defaults(str(ROOT), PERL), str(ROOT), PERL)
        earlier = self.generation / 'example.test/2026-09'; earlier.mkdir()
        (earlier / 'awstats.example.test.html').write_text(self.report, encoding='utf-8')
        signature = dict(signature_sha256='a' * 64, cycles=3, phase_paths=6, families=3)
        for signatures in ([signature], []):
            with self.subTest(signatures=bool(signatures)):
                with mock.patch.object(publisher, 'APP', str(ROOT)), mock.patch.object(publisher, 'PERL', PERL):
                    info = publisher.profile_state(True, profile, {}, {'totals': {
                        '2026-09': {'hits': 123}, '2026-10': {'hits': 123}}})
                info['capacity_fallback'] = {'2026-10': {'limit': 'records'}}
                info['corpus_automation'] = {'status': 'evaluated', 'signatures': signatures}
                previous = (self.web / 'current').resolve().name
                run = self.state / 'runs' / previous; run.mkdir(exist_ok=True)
                (run / 'manifest.json').write_text(json.dumps({'generation': previous,
                    'private_base': str(self.base), 'profiles': {'example.test': info}}), encoding='utf-8')
                self.run_publisher()
                token = (self.web / 'current').resolve().name
                manifest = json.loads((self.state / 'runs' / token / 'manifest.json').read_text(encoding='utf-8'))
                actual = manifest['profiles']['example.test']
                self.assertEqual(actual['effective_by_month']['2026-10']['scheduled_automation'], 'Input over limits')
                self.assertEqual(actual['effective']['scheduled_automation'], 'Input over limits')
                expected = 'Active for witnessed episodes' if signatures else 'Needs repeated corpus evidence'
                self.assertEqual(actual['effective_by_month']['2026-09']['scheduled_automation'], expected)

    def test_render_failure_cannot_publish_settings_or_modify_old_report(self):
        with mock.patch.object(publisher,'decorate_generation',side_effect=RuntimeError('synthetic precommit failure')):
            with self.assertRaises(RuntimeError):self.run_publisher()
        self.assertEqual((self.web/'current').resolve(),self.generation)
        self.assertEqual((self.generation/'example.test/2026-10/awstats.example.test.html').read_text(),self.report)

    def test_browser_request_disabled_in_native_config_stops_before_log_snapshot(self):
        (self.config / 'awstats.example.test.conf').write_text('AllowToUpdateStatsFromBrowser=0\n', encoding='utf-8')
        self.run_publisher()
        current = (self.web / 'current').resolve()
        request = self.root / 'request.json'
        request.write_text(json.dumps({'site': 'example.test', 'actor': 'browser-access',
            'authentication': 'access-rule', 'action': 'apply', 'id': 'a' * 32,
            'base_generation': current.name, 'profile': {}}), encoding='utf-8')
        with mock.patch.object(sys, 'argv', ['publisher', '--control-settings', str(self.settings_file), '--filter-job', str(request)]), mock.patch.object(publisher, 'build_snapshot') as snapshot:
            with self.assertRaises(PermissionError): publisher.main()
            snapshot.assert_not_called()
        self.assertEqual((self.web / 'current').resolve(), current)

    def test_interrupted_commit_leaves_complete_previous_generation_selected(self):
        original_replace=os.replace
        def interrupted(source,destination):
            if str(destination)==str(self.web/'current'):raise OSError('synthetic pointer interruption')
            return original_replace(source,destination)
        with mock.patch.object(os,'replace',side_effect=interrupted):
            with self.assertRaises(OSError):self.run_publisher()
        self.assertEqual((self.web/'current').resolve(),self.generation)
        self.assertEqual((self.generation/'example.test/2026-10/awstats.example.test.html').read_text(),self.report)


if __name__ == '__main__':
    unittest.main()
