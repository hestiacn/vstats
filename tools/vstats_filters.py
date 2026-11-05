"""Profiles and the authenticated, structured control plane for static vstats.

The HTTP process cannot run the publisher. It writes bounded requests which a
separate privileged worker validates again. Published settings are read through
the same current-generation pointer as the reports, never from pending edits.
"""
import base64
import copy
import datetime
import hashlib
import hmac
import html
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import tempfile

FILTERS = [('native_crawlers', 'Native crawler signatures', 'Existing AWStats user-agent detection.'),
           ('verified_crawlers', 'Verified crawlers', 'Dated provider evidence; independent of browser claims.'),
           ('behavior', 'Broad probing', 'Repeated diverse requests and missing paths in a bounded window.'),
           ('probing', 'Endpoint probing', 'Repeated requests to explicitly configured paths.'),
           ('rapid_scan', 'Rapid content-path scanning', 'Rapid diverse paths with repeated missing resources.'),
           ('distributed_login', 'Distributed login probing', 'Coordinated sources targeting configured login paths.')]
RULES = ['behavior', 'probing', 'rapid_scan', 'distributed_login']
SITE = re.compile(r'^[a-z0-9][a-z0-9._-]{0,252}$')
IDENTIFIER = re.compile(r'^[a-f0-9]{32}$')
GENERATION = re.compile(r'^\d{8}T\d{6}Z-[a-f0-9]{8}$')
MAX_REQUEST_BYTES = 131072


def utcnow():
    return datetime.datetime.utcnow().isoformat() + 'Z'


def canonical(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')


def identity(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def strict_object(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise ValueError('Duplicate JSON key')
        result[k] = v
    return result


def decode(raw):
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError('Request is too large')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=strict_object,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError('Non-finite JSON')))


def read_json(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise ValueError('Expected a regular state file')
        raw = f.read(16 * 1024 * 1024 + 1)
    if len(raw) > 16 * 1024 * 1024:
        raise ValueError('State file is too large')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=strict_object)


def atomic_json(path, value, mode=0o640, gid=None):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        if gid is not None:
            os.fchown(fd, -1, gid)
        with os.fdopen(fd, 'wb') as f:
            f.write(canonical(value)); f.flush(); os.fsync(f.fileno())
        os.replace(temporary, str(path))
        directory = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def classifier_config(raw, app, perl):
    """Use the classifier's own strict schema and coupled bounds, not a replica."""
    code = ("use strict;use warnings;use VStats::TrafficClassifier;"
            "binmode STDIN,':raw';binmode STDOUT,':raw';"
            "my $s=do{local $/;<STDIN>};my $c=VStats::TrafficClassifier->config($s);"
            "print VStats::TrafficClassifier::canonical_json($c);")
    p = subprocess.run([perl, '-I' + str(Path(app) / 'tools/lib'), '-e', code],
                       input=canonical(raw), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'LANG': 'C'}, timeout=10)
    if p.returncode or p.stderr:
        raise ValueError('Unsupported classifier settings or coupled threshold bounds')
    return json.loads(p.stdout.decode('utf-8'))


def defaults(app, perl, current=None):
    classifier = classifier_config({'schema_version': 1, 'exclude': ['suspected_automation']}, app, perl)
    if current:
        # Keep explicitly configured endpoint lists when resetting other options.
        for rule, keys in [('probing', ['paths']), ('distributed_login', ['login_paths', 'admin_paths'])]:
            for key in keys:
                classifier[rule][key] = copy.deepcopy(current['classifier'][rule][key])
    return {'schema_version': 1, 'filters': {f[0]: True for f in FILTERS},
            'exclude_automated_ips': True, 'native_level': 3,
            'classifier': classifier, 'exceptions': []}


def validate_profile(value, app, perl):
    if not isinstance(value, dict) or set(value) != {'schema_version', 'filters', 'exclude_automated_ips',
                                                   'native_level', 'classifier', 'exceptions'}:
        raise ValueError('Invalid profile fields')
    p = copy.deepcopy(value)
    if type(p['schema_version']) is not int or p['schema_version'] != 1:
        raise ValueError('Unsupported profile version')
    if not isinstance(p['filters'], dict) or set(p['filters']) != {f[0] for f in FILTERS}:
        raise ValueError('Invalid filter list')
    if any(type(v) is not bool for v in p['filters'].values()) or type(p['exclude_automated_ips']) is not bool:
        raise ValueError('Filter choices must be booleans')
    if type(p['native_level']) is not int or not 1 <= p['native_level'] <= 3:
        raise ValueError('Native crawler level must be 1, 2 or 3')
    if not isinstance(p['exceptions'], list) or len(p['exceptions']) > 2048:
        raise ValueError('Too many inclusion exceptions')
    ids = set()
    for e in p['exceptions']:
        if not isinstance(e, dict) or set(e) != {'request_id', 'reason'}:
            raise ValueError('Invalid inclusion exception')
        if not isinstance(e['request_id'], str) or not re.fullmatch(r'[a-f0-9]{64}', e['request_id']):
            raise ValueError('An inclusion needs a lowercase SHA-256 request ID')
        if e['request_id'] in ids:
            raise ValueError('Duplicate inclusion exception')
        ids.add(e['request_id'])
        if not isinstance(e['reason'], str) or not 1 <= len(e['reason'].strip()) <= 500:
            raise ValueError('An inclusion needs a reason of at most 500 characters')
    if not isinstance(p['classifier'], dict):
        raise ValueError('Invalid classifier configuration')
    cfg = p['classifier']
    cfg['schema_version'] = 1
    cfg['exclude'] = ['suspected_automation']
    cfg['behavior_include'] = sorted(ids)
    for rule in RULES:
        if not isinstance(cfg.get(rule, {}), dict):
            raise ValueError('Invalid rule configuration')
        cfg.setdefault(rule, {})['enabled'] = int(p['filters'][rule])
    # Intended enablement remains saved even where required paths are unavailable.
    if not cfg['probing'].get('paths'):
        cfg['probing']['enabled'] = 0
    if not cfg['distributed_login'].get('login_paths'):
        cfg['distributed_login']['enabled'] = 0
    p['classifier'] = classifier_config(cfg, app, perl)
    p['exceptions'].sort(key=lambda e: e['request_id'])
    return p


def filter_status(profile, evidence=False, over_limits=False):
    statuses = {}
    for key, _, _ in FILTERS:
        if not profile['filters'][key]:
            statuses[key] = 'Disabled'
        elif key == 'verified_crawlers' and not evidence:
            statuses[key] = 'Evidence unavailable'
        elif key == 'probing' and not profile['classifier'][key]['paths']:
            statuses[key] = 'Needs configuration'
        elif key == 'distributed_login' and not profile['classifier'][key]['login_paths']:
            statuses[key] = 'Needs configuration'
        elif key in RULES and over_limits:
            statuses[key] = 'Input over limits'
        else:
            statuses[key] = 'Active'
    return statuses


def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    return {'salt': salt, 'iterations': 600000,
            'hash': hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(salt), 600000).hex()}


def verify_password(password, record):
    actual = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(record['salt']),
                                 record['iterations']).hex()
    return hmac.compare_digest(actual, record['hash'])


class Control:
    def __init__(self, settings):
        self.settings = settings
        self.state = Path(settings['state'])
        self.web = Path(settings['web'])
        self.app = settings['app']
        self.perl = settings['perl']
        self.key = secrets.token_bytes(32)

    def current(self):
        link = self.web / 'current'
        generation = os.path.basename(os.path.realpath(str(link)))
        if not GENERATION.fullmatch(generation):
            raise ValueError('No recognized report generation')
        manifest = self.state / 'runs' / generation / 'manifest.json'
        if not manifest.exists():
            raise ValueError('Filters have not been initialized')
        value = read_json(manifest)
        if value['generation'] != generation:
            raise ValueError('Profile and report generation identities do not match')
        return value

    def user(self, header):
        if not isinstance(header, str) or not header.startswith('Basic '):
            return None
        try:
            raw = base64.b64decode(header[6:], validate=True).decode('utf-8')
            name, password = raw.split(':', 1)
            users = read_json(self.settings['credentials'])['users']
            record = users.get(name)
            if record and verify_password(password, record['password']):
                return dict(record, name=name)
        except (ValueError, UnicodeError, KeyError):
            pass
        return None

    def csrf(self, user):
        return hmac.new(self.key, user['name'].encode('utf-8'), hashlib.sha256).hexdigest()

    def authorize(self, user, site):
        if not SITE.fullmatch(site) or site not in self.current()['profiles']:
            raise ValueError('Unknown website')
        if user['role'] != 'administrator' or site not in user['sites']:
            raise PermissionError('Website administrator access required')

    def state_for(self, site):
        manifest = self.current()
        data = copy.deepcopy(manifest['profiles'][site])
        data.update(generation=manifest['generation'], generated_utc=manifest['generated_utc'], site=site)
        draft = self.state / 'drafts' / (site + '.json')
        data['pending'] = read_json(draft) if draft.exists() else None
        data['jobs'] = self.jobs(site)
        return data

    def jobs(self, site):
        values = []
        for path in (self.state / 'jobs').glob('*.json'):
            if not IDENTIFIER.fullmatch(path.stem):
                continue
            job = read_json(path)
            if job['site'] == site:
                values.append(job)
        return sorted(values, key=lambda x: x['created_utc'], reverse=True)[:50]

    def committed_manifests(self):
        item = self.current()
        result, seen = [], set()
        while item is not None:
            token = item['generation']
            if not GENERATION.fullmatch(token) or token in seen:
                raise ValueError('Invalid generation ancestry')
            seen.add(token); result.append(item)
            parent = item.get('previous_generation')
            if parent is None:
                break
            if not GENERATION.fullmatch(parent):
                raise ValueError('Invalid previous generation')
            path = self.state / 'runs' / parent / 'manifest.json'
            item = read_json(path) if path.exists() else None
        return result

    def history_for(self, site):
        current = self.current()
        result = []
        for item in self.committed_manifests():
            info = item['profiles'].get(site)
            if info is None:
                continue
            token = item['generation']
            retained = token == current.get('previous_generation') and bool(info.get('totals'))
            result.append({'generation': token, 'time': item['generated_utc'], 'actor': item['actor'],
                           'profile_id': info.get('profile_id'), 'verified_profile': info.get('applied') is not None,
                           'current': token == current['generation'],
                           'report_url': '/vstats/history/' + token + '/' + site + '/' if retained else None})
        return sorted(result, key=lambda x: x['time'], reverse=True)[:50]

    def change(self, site, action, body, user):
        self.authorize(user, site)
        if action not in ['save', 'discard', 'reset', 'preview', 'apply', 'restore']:
            raise ValueError('Unsupported action')
        if not isinstance(body, dict) or set(body) - {'profile', 'generation', 'action_id', 'coverage_ack', 'restore_generation'}:
            raise ValueError('Invalid action fields')
        current = self.current()
        if action not in ['preview', 'apply'] and body.get('generation') != current['generation']:
            raise ValueError('Reports changed; reload settings before submitting')
        draft_path = self.state / 'drafts' / (site + '.json')
        if action == 'discard':
            if draft_path.exists():
                draft_path.unlink()
            return {'status': 'Discarded'}
        existing = current['profiles'][site]
        if action == 'reset':
            profile = defaults(self.app, self.perl, existing.get('applied'))
        elif action == 'restore':
            token = body.get('restore_generation', '')
            if not GENERATION.fullmatch(token):
                raise ValueError('Invalid previous generation')
            old = next((m for m in self.committed_manifests() if m['generation'] == token), None)
            if old is None:
                raise ValueError('That profile has not been published')
            profile = old['profiles'][site].get('applied')
            if profile is None:
                raise ValueError('That historical profile is unverified')
        else:
            profile = body.get('profile')
        profile = validate_profile(profile, self.app, self.perl)
        if action in ['save', 'reset', 'restore']:
            result = {'profile': profile, 'actor': user['name'], 'saved_utc': utcnow(),
                      'based_on_generation': current['generation']}
            atomic_json(draft_path, result, mode=0o640)
            return {'status': 'Pending', 'pending': result}
        action_id = body.get('action_id', '')
        if not isinstance(action_id, str) or not IDENTIFIER.fullmatch(action_id):
            raise ValueError('An explicit action ID is required')
        # A retry with the same ID returns the original job, including terminal state.
        request = {'schema_version': 1, 'id': action_id, 'site': site, 'action': action,
                   'profile': profile, 'base_generation': body['generation'],
                   'actor': user['name'], 'coverage_ack': body.get('coverage_ack')}
        path = self.state / 'requests' / (action_id + '.json')
        if path.exists():
            old = read_json(path)
            if old['request'] != request:
                raise ValueError('Action ID already belongs to a different request')
            job = self.state / 'jobs' / (action_id + '.json')
            return read_json(job) if job.exists() else old['queued']
        if body.get('generation') != current['generation']:
            raise ValueError('Reports changed; reload settings before submitting')
        queued = {'id': action_id, 'site': site, 'action': action, 'status': 'Queued',
                  'phase': 'Waiting for the report worker', 'created_utc': utcnow(), 'actor': user['name']}
        raw = canonical({'request': request, 'queued': queued})
        fd, temporary = tempfile.mkstemp(prefix='.request-', dir=str(path.parent))
        try:
            os.fchmod(fd, 0o640)
            with os.fdopen(fd, 'wb') as f:
                f.write(raw); f.flush(); os.fsync(f.fileno())
            try:
                os.link(temporary, str(path))
            except FileExistsError:
                old = read_json(path)
                if old['request'] != request:
                    raise ValueError('Action ID already belongs to a different request')
                job = self.state / 'jobs' / (action_id + '.json')
                return read_json(job) if job.exists() else old['queued']
            directory = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            os.unlink(temporary)
        return queued


def funnel():
    return ('<svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24" '
            'fill="none" stroke="currentColor" stroke-width="2"><path d="M3 4h18l-7 8v7l-4 2v-9z"/></svg>')


def filters_menu(site, return_to=''):
    from urllib.parse import urlencode
    base = '/vstats/' + site + '/filters/'
    suffix = '?' + urlencode({'return': return_to}) if return_to else ''
    return ('<div class="dropdown-item vstats-filters-menu"><a class="dropdown-title" target="_top" href="' +
            html.escape(base + suffix, quote=True) + '" style="text-decoration:none;color:inherit;display:flex;'
            'align-items:center;gap:6px">' + funnel() + '<span>Filters</span></a>'
            '<div class="dropdown-content">' + ''.join('<a target="_top" href="' + html.escape(base + suffix, quote=True) +
            '#' + key + '">' + label + '</a>' for key, label in [('settings', 'Settings'), ('impact', 'Impact &amp; reprocessing'),
              ('review', 'Review'), ('history', 'History')]) + '</div></div>')


def add_filters_menu(text, site, return_to=''):
    if 'class="dropdown-item vstats-filters-menu"' in text:
        return text
    marker = '\t</div>\n\t<button id="theme-toggle"'
    if marker not in text:
        raise ValueError('Native vstats navigation marker was not found')
    return text.replace(marker, filters_menu(site, return_to) + marker, 1)


def native_shell(report, title, body):
    """Reuse native styles/menu/theme code, without copying any report counters."""
    styles = ''.join(re.findall(r'<style\b[^>]*>.*?</style>', report, flags=re.S | re.I))
    scripts = ''.join(re.findall(r'<script\b[^>]*>.*?</script>', report, flags=re.S | re.I))
    start = report.index('<div class="header-right">')
    end = report.index('<button id="back-to-top"', start)
    header = report[start:end]
    frame = report.find('<iframe name="doc-frame"', end)
    controls = ''
    if frame >= 0:
        controls = report[end:report.index('</div>', report.index('</iframe>', frame)) + len('</div>')]
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta name="robots" content="noindex,nofollow"><title>' + html.escape(title) + '</title>' + styles +
            '<link rel="stylesheet" href="/vstats/assets/css/filters.css"></head><body class="aws-main">'
            '<div class="aws-container">' + header + controls + body + '</div>' + scripts + '</body></html>')
