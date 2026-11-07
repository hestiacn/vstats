import copy
import importlib.util
import json
import os
import pwd
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from vstats_filters import (Control, atomic_json, canonical, identity, defaults, validate_profile,
                           filter_status, add_filters_menu, read_json, browser_policy, publish_browser_policy, queued_user)

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
        self.config = self.root / 'config'; self.config.mkdir()
        atomic_json(self.config / 'sites.json', {'example.test': {}, 'other.test': {}})
        for site, enabled in [('example.test', 1), ('other.test', 0)]:
            (self.config / ('awstats.' + site + '.conf')).write_text(
                'AllowToUpdateStatsFromBrowser=' + str(enabled) + '\n', encoding='utf-8')
        self.settings = {'state': str(self.state), 'web': str(self.web), 'app': str(ROOT), 'perl': PERL,
                         'config': str(self.config), 'origins': ['https://example.test']}
        publish_browser_policy(self.settings)
        self.control = Control(self.settings)
        self.user = {'name': 'browser-access', 'role': 'operator', 'sites': ['example.test'], 'authenticated': False}
        self.body = {'generation': GEN, 'profile': self.profile, 'action_id': 'a' * 32}

    def test_operator_settings_owner_mode_and_symlink_boundary(self):
        path = self.root / 'operator-settings.json'
        path.write_text('{"settings": true}', encoding='utf-8')
        path.chmod(0o600)
        if os.geteuid() == 0:
            self.assertEqual(read_json(path, root_owned=True), {'settings': True})
            path.chmod(0o620)
            with self.assertRaises(ValueError): read_json(path, root_owned=True)
            path.chmod(0o600)
            os.chown(str(path), 65534, -1)
        with self.assertRaises(ValueError): read_json(path, root_owned=True)
        self.assertEqual(read_json(path), {'settings': True})
        link = self.root / 'operator-link.json'
        link.symlink_to(path)
        with self.assertRaises(OSError): read_json(link, root_owned=True)

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

    def test_browser_flag_is_enforced_for_every_action_and_stale_cache(self):
        config = self.config / 'awstats.example.test.conf'
        config.write_text('AllowToUpdateStatsFromBrowser=0\n', encoding='utf-8')
        for action in ['save', 'discard', 'reset', 'preview', 'apply', 'restore']:
            with self.assertRaises(PermissionError):
                self.control.change('example.test', action, self.body, self.user)
        publish_browser_policy(self.settings)
        self.control.authorize(self.user, 'example.test', write=False)
        for action in ['save', 'discard', 'reset', 'preview', 'apply', 'restore']:
            with self.assertRaises(PermissionError):
                self.control.change('example.test', action, self.body, self.user)
        self.assertEqual(list((self.state / 'requests').glob('*.json')), [])

    def test_native_includes_overrides_missing_and_invalid_flags(self):
        config = self.config / 'awstats.example.test.conf'
        (self.config / 'shared.conf').write_text('AllowToUpdateStatsFromBrowser=1\n', encoding='utf-8')
        config.write_text('Include "shared.conf"\nAllowToUpdateStatsFromBrowser="0" # override\n', encoding='utf-8')
        self.assertFalse(browser_policy(self.config, 'example.test')['allow_updates'])
        config.write_text('#include "shared.conf"\n', encoding='utf-8')
        self.assertTrue(browser_policy(self.config, 'example.test')['allow_updates'])
        (self.config / 'shared.conf').write_text('AllowToUpdateStatsFromBrowser=unexpected\n', encoding='utf-8')
        self.assertFalse(browser_policy(self.config, 'example.test')['valid'])
        config.unlink()
        self.assertFalse(browser_policy(self.config, 'example.test')['allow_updates'])

    def test_native_optional_web_authentication_and_named_user_list(self):
        config = self.config / 'awstats.example.test.conf'
        config.write_text('AllowToUpdateStatsFromBrowser=1\nAllowAccessFromWebToAuthenticatedUsersOnly=1\nAllowAccessFromWebToFollowingAuthenticatedUsers="Alice"\n', encoding='utf-8')
        publish_browser_policy(self.settings)
        with self.assertRaises(PermissionError): self.control.authorize(self.user, 'example.test')
        self.control.authorize(self.control.web_user('alice'), 'example.test')
        with self.assertRaises(PermissionError): self.control.authorize(self.control.web_user('bob'), 'example.test')
        config.write_text('AllowToUpdateStatsFromBrowser=1\nAllowAccessFromWebToAuthenticatedUsersOnly=1\nAllowAccessFromWebToFollowingAuthenticatedUsers="__REMOTE_USER__"\n', encoding='utf-8')
        publish_browser_policy(self.settings)
        self.control.authorize(self.control.web_user('other authenticated user'), 'example.test')
        self.assertNotEqual(self.control.csrf(self.user), self.control.csrf(self.control.web_user('alice')))

    def test_worker_authorization_rereads_native_config_after_queueing(self):
        self.control.change('example.test', 'preview', self.body, self.user)
        request = read_json(self.state / 'requests' / ('a' * 32 + '.json'))['request']
        self.assertEqual(request['authentication'], 'access-rule')
        user = queued_user(request)
        self.control.authorize(user, request['site'], fresh=True)
        (self.config / 'awstats.example.test.conf').write_text('AllowToUpdateStatsFromBrowser=0\n', encoding='utf-8')
        with self.assertRaises(PermissionError): self.control.authorize(user, request['site'], fresh=True)
        with self.assertRaises(ValueError): queued_user(dict(request, actor='forged-name'))

    def test_disabled_queued_job_cannot_launch_the_publisher(self):
        self.settings['api_user'] = pwd.getpwuid(os.getuid()).pw_name
        self.control.change('example.test', 'preview', self.body, self.user)
        path = self.state / 'requests' / ('a' * 32 + '.json')
        (self.config / 'awstats.example.test.conf').write_text('AllowToUpdateStatsFromBrowser=0\n', encoding='utf-8')
        spec = importlib.util.spec_from_file_location('filters_worker_test', str(ROOT / 'tools/filters-worker.py'))
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        with mock.patch.object(module.subprocess, 'run') as launch:
            module.process(self.control, path)
            launch.assert_not_called()
        self.assertEqual(read_json(self.state / 'jobs' / ('a' * 32 + '.json'))['status'], 'Failed')

    def test_enabled_job_uses_fixed_worker_without_any_account_file(self):
        self.settings['api_user'] = pwd.getpwuid(os.getuid()).pw_name
        self.settings['settings_path'] = str(self.root / 'settings.json')
        self.control.change('example.test', 'preview', self.body, self.user)
        spec = importlib.util.spec_from_file_location('filters_worker_enabled_test', str(ROOT / 'tools/filters-worker.py'))
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        original_run = module.subprocess.run
        def rebuilt(command, **kwargs):
            if '--filter-job' not in command:
                return original_run(command, **kwargs)
            self.assertEqual(command[2], str(ROOT / 'tools/publish-static-reports.py'))
            atomic_json(self.state / 'jobs' / ('a' * 32 + '-result.json'), {'before': {}, 'after': {}})
            return type('Result', (), {'returncode': 0})()
        with mock.patch.object(module.subprocess, 'run', side_effect=rebuilt):
            module.process(self.control, self.state / 'requests' / ('a' * 32 + '.json'))
        self.assertEqual(read_json(self.state / 'jobs' / ('a' * 32 + '.json'))['status'], 'Completed')

    def test_http_requires_https_origin_csrf_and_native_permission_without_login(self):
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
        code, session = request('GET', '/session', headers)
        self.assertEqual(code, 200)
        self.assertFalse(session['authenticated'])
        self.assertEqual(session['actor'], 'browser-access')
        headers['Content-Type'] = 'application/json'; headers['Origin'] = 'https://hostile.example'
        self.assertEqual(request('POST', '/sites/example.test/save', headers, canonical(self.body))[0], 403)
        headers['Origin'] = 'https://example.test'; headers['X-VStats-CSRF'] = 'wrong'
        self.assertEqual(request('POST', '/sites/example.test/save', headers, canonical(self.body))[0], 403)
        headers['X-VStats-CSRF'] = session['csrf']
        self.assertEqual(request('POST', '/sites/example.test/save', headers, canonical(self.body))[0], 200)
        self.assertEqual(request('POST', '/sites/other.test/save', headers, canonical(self.body))[0], 403)


    def test_nonfinite_json_refused_without_lowering_state_cap(self):
        from vstats_filters import decode, MAX_REQUEST_BYTES
        path = self.root / 'strict-state.json'
        for token in ['NaN', 'Infinity', '-Infinity', '1e999', '-1e999']:
            for raw in [token.encode(), ('{"nested":[' + token + ']}').encode()]:
                with self.subTest(raw=raw):
                    with self.assertRaises(ValueError):
                        decode(raw)
                    path.write_bytes(raw)
                    with self.assertRaises(ValueError):
                        read_json(path)
        for value in [float('nan'), float('inf'), -float('inf')]:
            with self.assertRaises(ValueError):
                canonical({'nested': [value]})
        with self.assertRaises(ValueError):
            decode(b'{"same":1,"same":2}')
        self.assertEqual(decode(b'{"n":1.25,"small":1e-99,"flag":true,"missing":null}'),
                         {'n': 1.25, 'small': 1e-99, 'flag': True, 'missing': None})
        raw = json.dumps({'text': 'a' * MAX_REQUEST_BYTES}).encode()
        path.write_bytes(raw)
        self.assertEqual(len(read_json(path)['text']), MAX_REQUEST_BYTES)
        with self.assertRaises(ValueError):
            decode(raw)
        path.write_bytes(b' ' * (16 * 1024 * 1024 + 1))
        with self.assertRaises(ValueError):
            read_json(path)

    def test_http_rejects_untyped_coverage_before_creating_queue_entries(self):
        spec = importlib.util.spec_from_file_location('filters_server_coverage_test', str(ROOT / 'tools/filters-server.py'))
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        socket_path = str(self.root / 'coverage.sock')
        server = module.Server(socket_path, module.Handler); server.control = self.control
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        from http.client import HTTPConnection
        def send(method, route, headers, body=None):
            connection = HTTPConnection('localhost')
            connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.sock.connect(socket_path)
            connection.request(method, route, body=body, headers=headers)
            response = connection.getresponse(); data = response.read()
            code = response.status; connection.close()
            return code, json.loads(data.decode())
        code, session = send('GET', '/session', {'X-Forwarded-Proto': 'https'})
        self.assertEqual(code, 200)
        headers = {'X-Forwarded-Proto': 'https', 'Content-Type': 'application/json',
                   'Origin': 'https://example.test', 'X-VStats-CSRF': session['csrf']}
        tokens = ['1e999', '-1e999', 'NaN', 'Infinity', '-Infinity', '{}', '[]', 'false',
                  '1', '""', '"x"', '"' + 'F' * 64 + '"', '"' + 'f' * 63 + '"', '"' + 'f' * 65 + '"']
        for index, token in enumerate(tokens, 1):
            action_id = format(index, '032x')
            body = dict(self.body, action_id=action_id, coverage_ack='__RAW_ACK__')
            raw = json.dumps(body).replace('"__RAW_ACK__"', token).encode()
            with self.subTest(token=token):
                self.assertEqual(send('POST', '/sites/example.test/apply', headers, raw)[0], 400)
                self.assertFalse((self.state / 'requests' / (action_id + '.json')).exists())
        for index, (action, ack) in enumerate([(a, k) for a in ['preview', 'apply'] for k in [None, 'f' * 64]], 100):
            action_id = format(index, '032x')
            body = dict(self.body, action_id=action_id, coverage_ack=ack)
            first = send('POST', '/sites/example.test/' + action, headers, canonical(body))
            self.assertEqual(first[0], 200)
            self.assertEqual(send('POST', '/sites/example.test/' + action, headers, canonical(body)), first)
            queued = read_json(self.state / 'requests' / (action_id + '.json'))
            self.assertEqual(queued['request']['coverage_ack'], ack)
        for field in ['generation', 'classifier']:
            body = copy.deepcopy(self.body); body['action_id'] = ('c' if field == 'generation' else 'd') * 32
            if field == 'generation':
                body['generation'] = '__RAW_NUMBER__'
            else:
                body['profile']['classifier']['behavior']['window_seconds'] = '__RAW_NUMBER__'
            raw = json.dumps(body).replace('"__RAW_NUMBER__"', '1e999').encode()
            self.assertEqual(send('POST', '/sites/example.test/apply', headers, raw)[0], 400)
            self.assertFalse((self.state / 'requests' / (body['action_id'] + '.json')).exists())
        self.assertEqual(list((self.state / 'requests').glob('.request-*')), [])

    def test_worker_restart_recovers_current_and_ancestor_apply_generations(self):
        spec = importlib.util.spec_from_file_location('filters_worker_restart_test', str(ROOT / 'tools/filters-worker.py'))
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        a, b, later = '20261105T130000Z-aaaaaaaa', '20261105T140000Z-bbbbbbbb', '20261105T150000Z-cccccccc'
        action_id = 'a' * 32
        for scenario in ['current', 'ancestor', 'two_later', 'uncommitted', 'preview', 'missing', 'cycle', 'invalid']:
            with self.subTest(scenario=scenario):
                root = self.root / scenario
                state, web = root / 'state', root / 'web'
                for name in ['jobs', 'requests', 'runs/' + GEN, 'runs/' + a, 'runs/' + b, 'runs/' + later]:
                    (state / name).mkdir(parents=True, exist_ok=True)
                for token in [GEN, a, b, later]:
                    (web / 'generations' / token).mkdir(parents=True, exist_ok=True)
                atomic_json(state / 'runs' / GEN / 'manifest.json', self.manifest)
                if scenario != 'missing':
                    atomic_json(state / 'runs' / a / 'manifest.json',
                                dict(self.manifest, generation=a, previous_generation=GEN, action_id=action_id))
                parent = b if scenario == 'cycle' else 'invalid' if scenario == 'invalid' else GEN if scenario in ['uncommitted', 'preview'] else a
                atomic_json(state / 'runs' / b / 'manifest.json',
                            dict(self.manifest, generation=b, previous_generation=parent, action_id=None))
                atomic_json(state / 'runs' / later / 'manifest.json',
                            dict(self.manifest, generation=later, previous_generation=b, action_id=None))
                selected = a if scenario == 'current' else later if scenario == 'two_later' else b
                (web / 'current').symlink_to('generations/' + selected)
                settings = dict(self.settings, state=str(state), web=str(web),
                                api_user=pwd.getpwuid(os.getuid()).pw_name)
                settings_path = root / 'settings.json'; atomic_json(settings_path, settings, mode=0o600)
                control = Control(settings)
                job_path = state / 'jobs' / (action_id + '.json')
                atomic_json(job_path, {'id': action_id, 'site': 'example.test',
                                      'action': 'preview' if scenario == 'preview' else 'apply',
                                      'status': 'Running', 'created_utc': '2026-11-05T12:00:00Z'})
                with mock.patch.object(module, 'Control', return_value=control), \
                        mock.patch.object(module, 'publish_browser_policy'), \
                        mock.patch.object(module.subprocess, 'run') as launch, \
                        mock.patch.object(sys, 'argv', ['filters-worker.py', '--settings', str(settings_path), '--once']):
                    before_job = job_path.read_bytes()
                    if scenario in ['cycle', 'invalid']:
                        with self.assertRaises(ValueError):
                            module.main()
                        self.assertEqual(job_path.read_bytes(), before_job)
                    else:
                        module.main()
                    launch.assert_not_called()
                job = read_json(job_path)
                expected = 'Running' if scenario in ['cycle', 'invalid'] else 'Completed' if scenario in ['current', 'ancestor', 'two_later'] else 'Failed'
                self.assertEqual(job['status'], expected)
                if expected == 'Completed':
                    self.assertEqual(job['generation'], a)
                    self.assertEqual(job['phase'], 'Committed generation recovered')
                self.assertEqual(control.current()['generation'], selected)

    def test_worker_error_recovers_ancestor_commit_without_replaying_action(self):
        spec = importlib.util.spec_from_file_location('filters_worker_commit_error_test', str(ROOT / 'tools/filters-worker.py'))
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        original_run = module.subprocess.run
        a, b, later = '20261105T130000Z-aaaaaaaa', '20261105T140000Z-bbbbbbbb', '20261105T150000Z-cccccccc'
        for scenario in ['current', 'ancestor', 'two_later', 'uncommitted', 'cycle', 'invalid']:
            with self.subTest(scenario=scenario):
                root = self.root / ('process-' + scenario)
                state, web = root / 'state', root / 'web'
                for name in ['jobs', 'requests', 'drafts', 'runs/' + GEN]:
                    (state / name).mkdir(parents=True)
                (web / 'generations' / GEN).mkdir(parents=True)
                (web / 'current').symlink_to('generations/' + GEN)
                atomic_json(state / 'runs' / GEN / 'manifest.json', self.manifest)
                settings = dict(self.settings, state=str(state), web=str(web),
                                api_user=pwd.getpwuid(os.getuid()).pw_name, settings_path=str(root / 'settings.json'))
                publish_browser_policy(settings)
                control = Control(settings)
                control.change('example.test', 'apply', self.body, self.user)
                launches = []
                def failed_after_commit(command, **kwargs):
                    if '--filter-job' not in command:
                        return original_run(command, **kwargs)
                    launches.append(command)
                    if scenario == 'uncommitted':
                        return type('Result', (), {'returncode': 1})()
                    generations = [(a, GEN, 'a' * 32)]
                    if scenario != 'current':
                        parent = b if scenario == 'cycle' else 'invalid' if scenario == 'invalid' else a
                        generations.append((b, parent, None))
                    if scenario == 'two_later':
                        generations.append((later, b, None))
                    for token, parent, action_id in generations:
                        (state / 'runs' / token).mkdir(); (web / 'generations' / token).mkdir()
                        atomic_json(state / 'runs' / token / 'manifest.json',
                                    dict(self.manifest, generation=token, previous_generation=parent, action_id=action_id))
                    selected = generations[-1][0]
                    (web / 'current').unlink(); (web / 'current').symlink_to('generations/' + selected)
                    return type('Result', (), {'returncode': 1})()
                request_path = state / 'requests' / ('a' * 32 + '.json')
                with mock.patch.object(module.subprocess, 'run', side_effect=failed_after_commit):
                    if scenario in ['cycle', 'invalid']:
                        with self.assertRaises(ValueError):
                            module.process(control, request_path)
                    else:
                        module.process(control, request_path)
                    module.process(control, request_path)
                self.assertEqual(len(launches), 1)
                job = read_json(state / 'jobs' / ('a' * 32 + '.json'))
                expected = 'Running' if scenario in ['cycle', 'invalid'] else 'Failed' if scenario == 'uncommitted' else 'Completed'
                self.assertEqual(job['status'], expected)
                if expected == 'Completed':
                    self.assertEqual(job['generation'], a)
                selected = GEN if scenario == 'uncommitted' else a if scenario == 'current' else later if scenario == 'two_later' else b
                self.assertEqual(control.current()['generation'], selected)

    def test_worker_refuses_nonfinite_spool_without_job_or_launch(self):
        spec = importlib.util.spec_from_file_location('filters_worker_nonfinite_test', str(ROOT / 'tools/filters-worker.py'))
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        self.control.change('example.test', 'preview', self.body, self.user)
        path = self.state / 'requests' / ('a' * 32 + '.json')
        raw = path.read_bytes()
        self.assertEqual(raw.count(b'"coverage_ack":null'), 1)
        path.write_bytes(raw.replace(b'"coverage_ack":null', b'"coverage_ack":1e999'))
        with mock.patch.object(module.subprocess, 'run') as launch:
            with self.assertRaises(ValueError):
                module.process(self.control, path)
            launch.assert_not_called()
        self.assertFalse((self.state / 'jobs' / ('a' * 32 + '.json')).exists())
        self.assertFalse((self.state / 'jobs' / ('a' * 32 + '-request.json')).exists())


if __name__ == '__main__':
    unittest.main()
