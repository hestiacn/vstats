"""Profiles and the structured browser control plane for static vstats.

The HTTP process cannot run the publisher. It writes bounded requests which a
separate privileged worker validates again. Published settings are read through
the same current-generation pointer as the reports, never from pending edits.
"""
import copy
import datetime
import hashlib
import hmac
import html
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import tempfile

# Display metadata has one owner. Detector identifiers remain owned by their
# classifiers; these descriptions never decide whether a request is excluded.
FILTER_CATALOGUE = [
    dict(key='native_crawlers', label='Native crawler signatures', family='signatures', section=None,
         summary='Unverified user-agent signatures, including broad legacy matches.',
         help='Uses AWStats user-agent signature tables at the selected native detection level. This is not verified crawler identity. Extended tables include ordinary Windows desktop user agents; see Native detection level before choosing them.'),
    dict(key='verified_crawlers', label='Verified crawlers', family='provider_evidence', section=None,
         summary='A registered crawler marker and dated provider IP-range evidence.',
         help='Excludes requests with a registered crawler user-agent marker, currently Googlebot, and provider IP-range snapshots bracketing the request time. One snapshot exactly at that time can supply both brackets. An IP address or user-agent claim alone is insufficient.'),
    dict(key='behavior', label='Broad probing', family='probing_and_scanning', section='behavior', ip_policy='yes',
         count_key='broad_flagged_requests', summary='Diverse browser claims, paths and missing resources in a bounded window.',
         help='Looks for the configured request volume, diversity of claimed user agents and platforms, distinct paths and missing responses within a time window. This is suspected automation, not verified identity; shared addresses may contain unrelated users.'),
    dict(key='probing', label='Endpoint probing', family='probing_and_scanning', section='probing', ip_policy='yes',
         summary='Repeated probing of explicitly configured endpoint paths.',
         help='Requires repeated requests to the configured endpoint list with the configured diversity of browser and platform claims. An empty path list makes this rule inactive. Paths are supplied by the operator rather than guessed.'),
    dict(key='rapid_scan', label='Rapid content-path scanning', family='probing_and_scanning', section='rapid_scan', ip_policy='yes',
         summary='Many content paths and missing resources in a short window.',
         help='Looks for rapid requests across distinct content paths together with the configured volume of missing responses. Browser rotation is not required. The thresholds are heuristics, not a measured probability of automation.'),
    dict(key='distributed_login', label='Distributed login probing', family='probing_and_scanning', section='distributed_login', ip_policy='yes',
         summary='Corroborated login probing across multiple sources.',
         help='Uses coordinated evidence across sources targeting configured login and administration paths, including coherent login activity and browser/platform diversity. Both path lists are required. A shared browser string or a single login attempt is insufficient.')]

FILTER_FAMILIES = [
    dict(key='signatures', label='Bot and tool signatures',
         help='Matches explicit or legacy user-agent signatures. These are unverified claims and patterns; the native extended tables can also match ordinary Windows browsers.'),
    dict(key='provider_evidence', label='Provider evidence',
         help='Uses the component\'s dated provider evidence and its own identity requirements. Evidence must cover the request; a browser claim alone is insufficient.'),
    dict(key='probing_and_scanning', label='Probing and scanning',
         help='Combines the selected probing detectors. All four behavioral components can seed the optional IP/month policy. Individual controls and thresholds are in Advanced.')]

PARAMETER_HELP = {
    'window_seconds': 'Time window for combining the rule\'s evidence, in seconds.',
    'min_requests': 'Minimum number of requests needed by this rule, in requests.',
    'distinct_user_agents': 'Minimum number of distinct claimed user-agent strings.',
    'distinct_platforms': 'Minimum number of distinct claimed platform families; these are claims, not authenticated devices.',
    'distinct_paths': 'Minimum number of distinct request paths.',
    'not_found_requests': 'Minimum number of observed HTTP 404 responses, in requests.',
    'paths': 'Configured endpoint paths considered by this rule, one exact path per line.',
    'min_sources': 'Minimum number of distinct source addresses meeting the rule\'s witness requirements.',
    'min_post_requests': 'Minimum number of POST requests across qualifying sources.',
    'min_source_posts': 'Minimum number of POST requests from each qualifying source.',
    'distinct_source_user_agents': 'Minimum number of distinct claimed user-agent strings for each qualifying source.',
    'distinct_source_platforms': 'Minimum number of distinct claimed platform families for each qualifying source.',
    'shared_user_agents': 'Minimum number of exact user-agent strings shared by the qualifying sources.',
    'login_paths': 'Configured login paths used by this rule, one exact path per line.',
    'admin_paths': 'Configured administration paths used to corroborate login probing, one exact path per line.'}

FILTER_STATUS_CLASSES = {
    'Active': 'active', 'Active for covered requests': 'active',
    'Active for witnessed episodes': 'active', 'Dated intervals only': 'active',
    'Disabled': 'off', 'Needs configuration': 'needs', 'Evidence unavailable': 'needs',
    'Needs curated tool tokens': 'needs', 'Needs repeated corpus evidence': 'needs',
    'Needs evidence and selected months': 'needs', 'Select UTC months in Advanced': 'needs',
    'Input over limits': 'needs', 'Corpus evidence over limits; retained': 'needs',
    'Not selected for this month': 'needs'}

FILTER_POLICIES = {
    'ip_policy': dict(label='Exclude other requests from behavior-flagged IPs',
                      summary='Extends qualifying evidence to the same website, address and UTC month.'),
    'native_level': dict(label='Native crawler detection level',
        summary='Extended legacy tables also match ordinary Windows desktop browsers.',
        help='Level 1 uses the common and generic signature lists. Levels 2 and 3 also use the extended list; this release defines no third list, so their signature coverage is the same. At level 2 or higher, a desktop user agent containing Windows NT 10.0 is classified as a robot/non-viewed, except for the existing download-file exemption. Microsoft Edge on Windows is an example. The extended list also includes Edge below 100 and MSIE patterns. These signatures do not prove automation.',
        options=[dict(value=1, label='1 — common and generic'), dict(value=2, label='2 — extended'),
                 dict(value=3, label='3 — extended (same tables as 2)')]),
    'aggressive_comparison': dict(label='Include phase-linked candidates in the optional comparison only',
        summary='Adds weaker shared-phase candidates to the separate inferred comparison.',
        help='Adds phase-linked cohort candidates to the optional inferred/aggressive comparison. Shared browser claims and calendar phases can include unrelated users. This switch never changes default report totals; the comparison is explicitly unverified.')}

FILTERS = [(row['key'], row['label'], row['summary']) for row in FILTER_CATALOGUE]
RULES = [row['key'] for row in FILTER_CATALOGUE if row.get('section') == row['key']]


def filter_catalogue():
    """Public display data, shared by static pages and the current state API."""
    rows = copy.deepcopy(FILTER_CATALOGUE)
    eligible = []
    for row in rows:
        policy = row.get('ip_policy')
        if policy == 'yes':
            eligible.append(row['label'])
            row['help'] += ' This component can trigger the optional IP/month policy.'
        elif policy == 'original':
            eligible.append(row['label'] + ' (original stronger witness only)')
            row['help'] += ' Only its original stronger witness can trigger the IP/month policy; alternative witnesses remain request-only.'
        else:
            row['help'] += ' This component never seeds additional IP/month exclusions.'
        if row.get('section') == row['key']:
            row.setdefault('count_key', row['key'] + '_flagged_requests')
    policies = copy.deepcopy(FILTER_POLICIES)
    policies['ip_policy']['help'] = ('Only these components can trigger same-website, same-address, same-UTC-month expansion: ' +
        ', '.join(eligible) + '. Every other component is request-only for this policy. Independent native and provider/actor treatment still applies. Request-ID inclusions can retain selected behavioral/IP matches. Shared addresses can include unrelated users.')
    return dict(components=rows, families=copy.deepcopy(FILTER_FAMILIES), policies=policies,
                status_classes=dict(FILTER_STATUS_CLASSES), parameter_help=dict(PARAMETER_HELP))
SITE = re.compile(r'^[a-z0-9][a-z0-9._-]{0,252}$')
IDENTIFIER = re.compile(r'^[a-f0-9]{32}$')
GENERATION = re.compile(r'^\d{8}T\d{6}Z-[a-f0-9]{8}$')
MAX_REQUEST_BYTES = 131072


def utcnow():
    return datetime.datetime.utcnow().isoformat() + 'Z'


def canonical(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(',', ':')) + '\n').encode('utf-8')


def identity(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def strict_object(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise ValueError('Duplicate JSON key')
        result[k] = v
    return result


def finite_json_number(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError('Non-finite JSON')
    return number


def strict_json(raw):
    return json.loads(raw.decode('utf-8'), object_pairs_hook=strict_object,
                      parse_float=finite_json_number, parse_constant=finite_json_number)


def decode(raw):
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError('Request is too large')
    return strict_json(raw)


def read_json(path, root_owned=False):
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise ValueError('Expected a regular state file')
        if root_owned and (st.st_uid != 0 or st.st_mode & 0o022):
            raise ValueError('Operator settings must be root-owned and not writable by group or others')
        raw = f.read(16 * 1024 * 1024 + 1)
    if len(raw) > 16 * 1024 * 1024:
        raise ValueError('State file is too large')
    return strict_json(raw)


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
    return strict_json(p.stdout)


def defaults(app, perl, current=None):
    classifier = classifier_config({'schema_version': 1, 'exclude': ['suspected_automation']}, app, perl)
    if current:
        current = validate_profile(current, app, perl)
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
    reference = classifier_config({'schema_version': 1}, app, perl)
    if (not set(reference) <= set(cfg) or any(
            isinstance(value, dict) and
            (not isinstance(cfg[key], dict) or not set(value) <= set(cfg[key]))
            for key, value in reference.items())):
        raise ValueError('Invalid rule configuration')
    cfg['exclude'] = ['suspected_automation']
    cfg['behavior_include'] = sorted(ids)
    for rule in RULES:
        if not isinstance(cfg.get(rule, {}), dict):
            raise ValueError('Invalid rule configuration')
        cfg[rule]['enabled'] = int(p['filters'][rule])
    # Intended enablement remains saved even where required paths are unavailable.
    if not cfg['probing']['paths']:
        cfg['probing']['enabled'] = 0
    if not (cfg['distributed_login']['login_paths'] and cfg['distributed_login']['admin_paths']):
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
        elif key == 'distributed_login' and not (profile['classifier'][key]['login_paths'] and profile['classifier'][key]['admin_paths']):
            statuses[key] = 'Needs configuration'
        elif key in RULES and over_limits:
            statuses[key] = 'Input over limits'
        else:
            statuses[key] = 'Active'
    return statuses


def browser_policy(config, site):
    """Read only AWStats browser-access directives; never execute configuration.

    Includes use the top-level configuration directory, as AWStats does. Missing,
    malformed or unsupported values fail closed. The native ten-level include
    limit is retained; one MiB per file is a defensive policy-reader bound.
    """
    values = {'AllowToUpdateStatsFromBrowser': '0',
              'AllowAccessFromWebToAuthenticatedUsersOnly': '0',
              'AllowAccessFromWebToFollowingAuthenticatedUsers': ''}
    root = Path(config)
    sources = []
    def parse(path, depth=0):
        if depth > 10:
            raise ValueError('Configuration include depth exceeded')
        with open(str(path), 'rb') as f:
            raw = f.read(1048577)
            st = os.fstat(f.fileno())
        sources.append({'path': str(path), 'device': st.st_dev, 'inode': st.st_ino,
                        'mtime_ns': st.st_mtime_ns, 'size': st.st_size})
        if len(raw) > 1048576:
            raise ValueError('Configuration exceeds policy-reader bound')
        for line in raw.decode('utf-8').splitlines():
            include = re.match(r'^(?:Include|#include) "([^"]+)"', line)
            if include:
                name = re.sub(r'__([^\s]+?)__', lambda m: os.environ.get(m.group(1), ''), include.group(1))
                target = Path(name)
                parse(target if target.is_absolute() else root / target, depth + 1)
                continue
            if line.lstrip().startswith('#'):
                continue
            line = re.sub(r'\s#.*$', '', line)
            if '=' not in line:
                continue
            key, value = [v.strip() for v in line.split('=', 1)]
            if key not in values:
                continue
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            values[key] = value
    try:
        if not SITE.fullmatch(site):
            raise ValueError('Invalid site')
        parse(root / ('awstats.' + site + '.conf'))
        for key in ['AllowToUpdateStatsFromBrowser', 'AllowAccessFromWebToAuthenticatedUsersOnly']:
            if values[key] not in ['0', '1']:
                raise ValueError('Browser-access flags require 0 or 1')
        return {'allow_updates': values['AllowToUpdateStatsFromBrowser'] == '1',
                'require_auth': values['AllowAccessFromWebToAuthenticatedUsersOnly'] == '1',
                'users': values['AllowAccessFromWebToFollowingAuthenticatedUsers'].split(),
                'sources': sources, 'valid': True}
    except (OSError, UnicodeError, ValueError):
        return {'allow_updates': False, 'require_auth': True, 'users': [], 'valid': False}


def public_browser_policy(policy):
    return {k: policy[k] for k in ['allow_updates', 'require_auth', 'valid']}


def publish_browser_policy(settings, gid=None):
    """Root publishes sanitized access policy without exposing native configs."""
    sites = read_json(Path(settings['config']) / 'sites.json')
    value = {'schema_version': 1, 'sites': {s: browser_policy(settings['config'], s) for s in sites}}
    path = Path(settings['state']) / 'browser-policy.json'
    try:
        if read_json(path) == value:
            return
    except (OSError, ValueError):
        pass
    atomic_json(path, value, gid=gid)


def queued_user(request):
    mode, actor = request.get('authentication'), request.get('actor')
    if mode not in ['web-server', 'access-rule'] or not isinstance(actor, str) or not actor or len(actor) > 255:
        raise ValueError('Invalid browser authorization provenance')
    if mode == 'access-rule' and actor != 'browser-access':
        raise ValueError('Anonymous access must not claim an authenticated identity')
    return {'name': actor, 'role': 'operator', 'sites': [request['site']],
            'authenticated': mode == 'web-server'}


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

    def web_user(self, remote_user=None):
        name = (remote_user or '').strip()
        if len(name) > 255 or any(ord(c) < 32 for c in name):
            raise PermissionError('Invalid web-server identity')
        return {'name': name or 'browser-access', 'authenticated': bool(name),
                'role': 'operator', 'sites': list(self.current()['profiles'])}

    def policy(self, site, fresh=False):
        if fresh:
            return browser_policy(self.settings['config'], site)
        try:
            value = read_json(self.state / 'browser-policy.json')['sites'][site]
            if (type(value['allow_updates']) is bool and type(value['require_auth']) is bool
                    and type(value['valid']) is bool and isinstance(value['users'], list)):
                # Metadata requires traversal, never config read permission. A
                # changed source invalidates stale permission even mid-rebuild.
                for source in value.get('sources', []):
                    st = os.stat(source['path'])
                    if any(source[k] != v for k, v in [('device', st.st_dev), ('inode', st.st_ino),
                            ('mtime_ns', st.st_mtime_ns), ('size', st.st_size)]):
                        raise ValueError('Browser-access policy changed')
                return value
        except (OSError, KeyError, ValueError, TypeError):
            pass
        return {'allow_updates': False, 'require_auth': True, 'users': [], 'valid': False}

    def csrf(self, user):
        return hmac.new(self.key, user['name'].encode('utf-8'), hashlib.sha256).hexdigest()

    def authorize(self, user, site, write=True, fresh=False):
        if not SITE.fullmatch(site) or site not in self.current()['profiles']:
            raise ValueError('Unknown website')
        if user['role'] != 'operator' or site not in user['sites']:
            raise PermissionError('Website access required')
        policy = self.policy(site, fresh=fresh)
        if not policy['valid']:
            raise PermissionError('Browser-access configuration unavailable')
        if policy['require_auth']:
            name = re.sub(r'\s', '%20', user['name']).casefold()
            if (not user.get('authenticated') or
                    (policy['users'] and '__REMOTE_USER__' not in policy['users']
                     and name not in [v.casefold() for v in policy['users']])):
                raise PermissionError('Web-server authentication for this website is required')
        if write and not policy['allow_updates']:
            raise PermissionError('Browser updates are disabled by AllowToUpdateStatsFromBrowser')

    def state_for(self, site):
        manifest = self.current()
        data = copy.deepcopy(manifest['profiles'][site])
        for profile in (data.get('applied'), data.get('default_profile')):
            if profile is not None:
                validate_profile(profile, self.settings['app'], self.settings['perl'])
        data.update(generation=manifest['generation'], generated_utc=manifest['generated_utc'], site=site)
        data['filter_catalogue'] = filter_catalogue()
        data['browser_access'] = public_browser_policy(self.policy(site))
        draft = self.state / 'drafts' / (site + '.json')
        data['pending'] = read_json(draft) if draft.exists() else None
        if data['pending'] is not None:
            validate_profile(data['pending']['profile'], self.settings['app'], self.settings['perl'])
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
        coverage_ack = body.get('coverage_ack')
        if coverage_ack is not None and (not isinstance(coverage_ack, str) or
                                         not re.fullmatch(r'[a-f0-9]{64}', coverage_ack)):
            raise ValueError('Coverage acknowledgement must be a lowercase SHA-256 or null')
        action_id = body.get('action_id', '')
        if not isinstance(action_id, str) or not IDENTIFIER.fullmatch(action_id):
            raise ValueError('An explicit action ID is required')
        # A retry with the same ID returns the original job, including terminal state.
        request = {'schema_version': 1, 'id': action_id, 'site': site, 'action': action,
                   'profile': profile, 'base_generation': body['generation'],
                   'actor': user['name'], 'coverage_ack': coverage_ack,
                   'authentication': 'web-server' if user.get('authenticated') else 'access-rule'}
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
