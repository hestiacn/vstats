import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from vstats_filters import (Control, atomic_json, canonical, identity, defaults, validate_profile,
                           filter_status, password_hash, add_filters_menu, read_json)

PERL = os.environ.get('VSTATS_TEST_PERL', '/opt/vstats/runtime/perl-5.44.0/bin/perl')
GEN = '20261105T120000Z-12345678'


class Controls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='vstats-filters-tests-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state, self.web = self.root / 'state', self.root / 'web'
        for name in ['requests', 'jobs', 'drafts', 'runs/' + GEN]:
            (self.state / name).mkdir(parents=True)
        (self.web / 'generations' / GEN).mkdir(parents=True)
        (self.web / 'current').symlink_to('generations/' + GEN)
        self.profile = validate_profile(defaults(str(ROOT), PERL), str(ROOT), PERL)
        self.manifest = {'generation': GEN, 'generated_utc': '2026-11-05T12:00:00Z', 'actor': 'test',
                         'profiles': {s: {'applied': self.profile, 'managed': True, 'profile_id': identity(self.profile)}
                                      for s in ['example.test', 'other.test']}}
        atomic_json(self.state / 'runs' / GEN / 'manifest.json', self.manifest)
        self.credentials = self.root / 'credentials.json'
        atomic_json(self.credentials, {'users': {'admin': {'password': password_hash('synthetic-test-password'),
                   'role': 'administrator', 'sites': ['example.test']}}})
        self.settings = {'state': str(self.state), 'web': str(self.web), 'app': str(ROOT), 'perl': PERL,
                         'credentials': str(self.credentials), 'origins': ['https://example.test']}
        self.control = Control(self.settings)
        self.user = {'name': 'admin', 'role': 'administrator', 'sites': ['example.test']}
        self.body = {'generation': GEN, 'profile': self.profile, 'action_id': 'a' * 32}

    def test_all_default_choices_on_missing_prerequisites_inactive(self):
        self.assertTrue(all(self.profile['filters'].values()))
        self.assertTrue(self.profile['exclude_automated_ips'])
        states = filter_status(self.profile)
        self.assertEqual(states['probing'], 'Needs configuration')
        self.assertEqual(states['distributed_login'], 'Needs configuration')
        self.assertEqual(states['verified_crawlers'], 'Evidence unavailable')
        self.assertEqual(filter_status(self.profile, evidence=True, over_limits=True)['behavior'], 'Input over limits')
        self.assertEqual(filter_status(self.profile, evidence=True, over_limits=True)['verified_crawlers'], 'Active')

    def test_classifier_coupled_bounds_and_schema_are_authoritative(self):
        for change in [('window_seconds', 3601), ('distinct_platforms', 1), ('min_requests', 1)]:
            p = copy.deepcopy(self.profile); p['classifier']['behavior'][change[0]] = change[1]
            with self.assertRaises(ValueError):
                validate_profile(p, str(ROOT), PERL)
        p = copy.deepcopy(self.profile); p['classifier']['shell_command'] = 'anything'
        with self.assertRaises(ValueError):
            validate_profile(p, str(ROOT), PERL)
        p = copy.deepcopy(self.profile); p['filters']['behavior'] = 1
        with self.assertRaises(ValueError):
            validate_profile(p, str(ROOT), PERL)

    def test_pending_save_reset_discard_never_publish(self):
        before = (self.state / 'runs' / GEN / 'manifest.json').read_bytes()
        p = copy.deepcopy(self.profile); p['filters']['rapid_scan'] = False
        self.control.change('example.test', 'save', dict(self.body, profile=p), self.user)
        self.assertFalse(read_json(self.state / 'drafts/example.test.json')['profile']['filters']['rapid_scan'])
        self.control.change('example.test', 'reset', self.body, self.user)
        self.assertTrue(read_json(self.state / 'drafts/example.test.json')['profile']['filters']['rapid_scan'])
        self.control.change('example.test', 'discard', self.body, self.user)
        self.assertFalse((self.state / 'drafts/example.test.json').exists())
        self.assertEqual(before, (self.state / 'runs' / GEN / 'manifest.json').read_bytes())

    def test_every_action_checks_role_and_website(self):
        for action in ['save', 'discard', 'reset', 'preview', 'apply', 'restore']:
            for user, site in [(dict(self.user, role='viewer'), 'example.test'), (self.user, 'other.test')]:
                with self.assertRaises(PermissionError):
                    self.control.change(site, action, self.body, user)

    def test_preview_only_queues_and_duplicate_action_is_durable(self):
        before = (self.state / 'runs' / GEN / 'manifest.json').read_bytes()
        first = self.control.change('example.test', 'preview', self.body, self.user)
        second = self.control.change('example.test', 'preview', self.body, self.user)
        self.assertEqual(first, second)
        self.assertEqual(len(list((self.state / 'requests').glob('*.json'))), 1)
        self.assertEqual(before, (self.state / 'runs' / GEN / 'manifest.json').read_bytes())
        finished = dict(first, status='Completed')
        atomic_json(self.state / 'jobs' / ('a' * 32 + '.json'), finished)
        new = '20261105T130000Z-abcdef01'
        (self.web / 'generations' / new).mkdir()
        (self.state / 'runs' / new).mkdir()
        manifest = dict(self.manifest, generation=new)
        atomic_json(self.state / 'runs' / new / 'manifest.json', manifest)
        (self.web / 'current').unlink(); (self.web / 'current').symlink_to('generations/' + new)
        self.assertEqual(self.control.change('example.test', 'preview', self.body, self.user)['status'], 'Completed')
        with self.assertRaises(ValueError):
            self.control.change('example.test', 'apply', dict(self.body, action_id='b' * 32), self.user)

    def test_concurrent_duplicate_requests_publish_one_complete_spool_file(self):
        results, errors = [], []
        def send():
            try:
                results.append(self.control.change('example.test', 'preview', self.body, self.user))
            except Exception as e:
                errors.append(e)
        threads = [threading.Thread(target=send) for _ in range(3)]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 3)
        self.assertEqual({x['id'] for x in results}, {'a' * 32})
        self.assertEqual(read_json(self.state / 'requests' / ('a' * 32 + '.json'))['request']['profile'], self.profile)

    def test_exceptions_preserve_identity_and_require_a_reason(self):
        p = copy.deepcopy(self.profile)
        p['exceptions'] = [{'request_id': 'f' * 64, 'reason': '<script>literal reason</script>'}]
        normalized = validate_profile(p, str(ROOT), PERL)
        self.assertEqual(normalized['classifier']['behavior_include'], ['f' * 64])
        p['exceptions'][0]['reason'] = ' '
        with self.assertRaises(ValueError): validate_profile(p, str(ROOT), PERL)

    def test_jobs_ignore_internal_request_and_result_records(self):
        job = {'id': 'a' * 32, 'site': 'example.test', 'created_utc': 'now', 'status': 'Completed'}
        atomic_json(self.state / 'jobs' / ('a' * 32 + '.json'), job)
        atomic_json(self.state / 'jobs' / ('a' * 32 + '-result.json'), {'after': {}})
        atomic_json(self.state / 'jobs' / ('a' * 32 + '-request.json'), self.body)
        self.assertEqual(self.control.jobs('example.test'), [job])

    def test_unpublished_preview_is_not_applied_history_or_a_restore_target(self):
        token = '20261105T140000Z-aaaaaaaa'
        (self.state / 'runs' / token).mkdir()
        candidate = dict(self.manifest, generation=token, previous_generation=GEN)
        atomic_json(self.state / 'runs' / token / 'manifest.json', candidate)
        self.assertEqual([r['generation'] for r in self.control.history_for('example.test')], [GEN])
        with self.assertRaises(ValueError):
            self.control.change('example.test', 'restore', dict(self.body, restore_generation=token), self.user)
        self.assertFalse((self.state / 'drafts/example.test.json').exists())

    def test_authentication_and_csrf_are_not_ip_based(self):
        header = 'Basic ' + base64.b64encode(b'admin:synthetic-test-password').decode('ascii')
        self.assertIsNotNone(self.control.user(header))
        self.assertIsNone(self.control.user('Basic ' + base64.b64encode(b'admin:wrong').decode('ascii')))
        self.assertIsNone(self.control.user(None))
        self.assertNotEqual(self.control.csrf(self.user), self.control.csrf(dict(self.user, name='other')))

    def test_http_requires_https_authentication_origin_and_csrf(self):
        spec = importlib.util.spec_from_file_location('filters_server_test', str(ROOT / 'tools/filters-server.py'))
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        path = str(self.root / 'api.sock')
        server = module.Server(path, module.Handler); server.control = self.control
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        from http.client import HTTPConnection
        def request(method, url, headers, body=None):
            connection = HTTPConnection('localhost')
            connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); connection.sock.connect(path)
            connection.request(method, url, body=body, headers=headers)
            response = connection.getresponse(); data = response.read(); code = response.status; connection.close()
            return code, json.loads(data.decode())
        self.assertEqual(request('GET', '/session', {})[0], 403)
        headers = {'X-Forwarded-Proto': 'https'}
        self.assertEqual(request('GET', '/session', headers)[0], 401)
        headers['Authorization'] = 'Basic ' + base64.b64encode(b'admin:synthetic-test-password').decode('ascii')
        code, session = request('GET', '/session', headers)
        self.assertEqual(code, 200)
        headers['Content-Type'] = 'application/json'; headers['Origin'] = 'https://hostile.example'
        self.assertEqual(request('POST', '/sites/example.test/save', headers, canonical(self.body))[0], 403)
        headers['Origin'] = 'https://example.test'; headers['X-VStats-CSRF'] = 'wrong'
        self.assertEqual(request('POST', '/sites/example.test/save', headers, canonical(self.body))[0], 403)
        headers['X-VStats-CSRF'] = session['csrf']
        self.assertEqual(request('POST', '/sites/example.test/save', headers, canonical(self.body))[0], 200)
        self.assertEqual(request('POST', '/sites/other.test/save', headers, canonical(self.body))[0], 403)


if __name__ == '__main__':
    unittest.main()
