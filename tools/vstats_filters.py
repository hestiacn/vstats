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
CORPUS_PROVENANCE_HELP = (' Needs a known website, a trustworthy source for the client address and an observed or explicitly empty user-agent field. Without these, this rule abstains.')

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
         help='Requires corroborated login POST activity across sources, browser/platform diversity and shared agent claims on configured login and administration paths. Coherent same-browser POST-to-GET flows are protected. Both path lists are required. A shared browser string or a single login attempt is insufficient.')]

FILTER_FAMILIES = [
    dict(key='signatures', label='Bot and tool signatures',
         help='Matches explicit or legacy user-agent signatures. These are unverified claims and patterns; the native extended tables can also match ordinary Windows browsers.'),
    dict(key='provider_evidence', label='Provider evidence',
         help='Uses the component\'s dated provider evidence and its own identity requirements. Evidence must cover the request; a browser claim alone is insufficient.'),
    dict(key='probing_and_scanning', label='Probing and scanning',
         help='Combines the selected probing detectors. Some can seed the optional IP/month policy; others remove matching requests only. Each component explains its eligibility. Individual controls and thresholds are in Advanced.'),
    dict(key='automated_browsing', label='Automated browsing',
         help='Combines independent client anomalies with request evidence, or learns repeated weekly fetching patterns with corroboration. These are heuristic suspicions, not verified identity, and affect witnessed requests only.'),
    dict(key='scanner_inference', label='Bounded scanner inference',
         help='Uses selected UTC months, a bounded time distance from recorded scanner DNS evidence and corroborated client fingerprints. Historical ownership is inferred, not verified; no IP/month expansion.'),
    dict(key='metadata', label='Metadata requests',
         help='A separate reporting policy for configured robots and sitemap fetches. It does not identify the visitor or establish automation; it never seeds IP/month expansion.')]

FILTER_CATALOGUE += [
    dict(key='login_rotation', label='Login browser rotation', family='probing_and_scanning', section='login_rotation', ip_policy='original',
         parameter_help={'distinct_user_agents': 'Minimum number of distinct POST user-agent claims for the repeated-pair witness; the separated-switch witness instead uses distinct platforms as its POST-agent minimum.',
                         'distinct_platforms': 'Minimum number of distinct POST platform claims; also the POST-agent minimum for the separated-switch witness.'},
         summary='Adjacent login GET/POST pairs with changing browser or platform claims.',
         help='Pairs adjacent GET then POST requests to the same configured login path within pair seconds. Requires repeated pairs with browser changes, or platform-switching pairs across separated visits. Pair and diversity thresholds apply in the time window. Stable sessions and GET-only login reads do not qualify. Claims do not establish authentication outcomes or a single actor.'),
    dict(key='head_scan', label='HEAD path sweeps', family='probing_and_scanning', section='head_scan', ip_policy='yes',
         summary='Many HEAD requests to content paths with observed missing resources.',
         help='Requires the configured number of HEAD requests, distinct content paths and observed HTTP 404 responses in one source/site window. Static assets do not supply content paths. HEAD or zero response bytes alone is insufficient.'),
    dict(key='sensitive_scan', label='Sensitive-file probing', family='probing_and_scanning', section='sensitive_scan', ip_policy='yes',
         summary='Concentrated GET/HEAD reads of configured sensitive paths.',
         help='Requires the configured request and distinct-path counts for exact sensitive paths within one source/site window. The operator controls the path list. A response does not establish component absence, compromise or successful access.'),
    dict(key='wp_enumeration', label='WordPress enumeration', family='probing_and_scanning', section='wp_enumeration', ip_policy='yes',
         summary='Author-ID and user-API queries with rotating browser/platform claims.',
         help='Requires all configured request, browser, platform, author-ID, API and HTTP 404 minima together in one source/site window. Only configured author paths, user paths and REST routes qualify. Ambiguous query features abstain; successful enumeration or malicious intent is not established.'),
    dict(key='wp_query_probe', label='WordPress query probing', family='probing_and_scanning', section='wp_query_probe',
         summary='Internal query keys together with plugin-file probes.',
         help='Requires configured WordPress internal query keys on configured query paths and plugin-file probes in one bounded source/site episode. Response failure is not required. Marks matching query/plugin probes only. Ordinary pages and unrelated requests do not inherit suspicion.'),
    dict(key='backdoor_probe', label='Backdoor path probing', family='probing_and_scanning', section='backdoor_probe',
         parameter_help={'not_found_requests': 'Minimum number of observed HTTP 404 or 410 responses among backdoor-path probes.'},
         summary='Configured backdoor-path probes with POST activity and missing responses.',
         help='Requires the configured requests, distinct backdoor paths, POSTs and HTTP 404/410 responses in one source/site window. Only qualifying probes and nearby configured entry requests are marked. Observed failures do not establish that a backdoor exists or an exploit succeeded.'),
    dict(key='protocol_probe', label='Protocol endpoint discovery', family='probing_and_scanning', section='protocol_probe',
         summary='Failed POST/GET endpoint discovery with an explicit tool declaration.',
         help='Combines missing POST and GET endpoints from the configured lists, a curated tool user-agent token and a short source/site window. Marks the witnessed probes and nearby configured entry requests. A tool claim alone does not qualify or verify identity.'),
    dict(key='service_discovery', label='Service-manifest discovery', family='probing_and_scanning', section='service_discovery',
         summary='Failed probes across independent service and manifest families.',
         help='Requires GET/HEAD responses of 404 or 410 across the configured number of registered service families within the time window. Evidence is scoped to one source, known site and exact observed user agent. OpenAPI/Swagger aliases form one family; MCP, AI plugin and AI/LLM descriptions supply others. Successful catch-all responses and ordinary metadata do not qualify. Marks the probes only.'),
    dict(key='wp_micro_probe', label='WordPress micro-probing', family='probing_and_scanning', section='wp_micro_probe',
         parameter_help={'post_requests': 'Minimum number of POST requests to configured POST paths with HTTP 400–599 responses in the failing POST/API witness.',
                         'entry_paths': 'Exact entry paths, one per line. Only the failing POST/API witness also marks GET/HEAD requests to them, with a recognized browser/platform claim, inside its episode window; the login-discovery witness never marks them.'},
         summary='Small multi-installation login or failing POST/API episodes.',
         help='Requires either HEAD discovery across configured login locations plus a login GET, or failing POSTs across configured paths including an API endpoint, with browser/platform diversity in the source/site window. A positive same-user-agent page/asset edge vetoes the episode. Marks witnessed probes; only the failing POST/API witness also marks configured entry requests. Sparse ordinary browsing is insufficient.' + CORPUS_PROVENANCE_HELP),
    dict(key='operator_associated', label='Operator-associated scanners', family='provider_evidence', section='operator_association',
         section_label='Operator evidence and comparison', count_key='operator_associated_requests',
         summary='Forward-confirmed scanner DNS during its dated validity interval.',
         help='Uses recorded reverse and forward DNS confirmation for a registered scanner operator and trusted client-address provenance. Only requests strictly after lookup completion and before the smallest chain TTL expires qualify. A later lookup cannot backdate identity; generic hosting DNS and provider claims abstain. TTL does not establish exclusive address use.'),
    dict(key='historical_operator', label='Retrospective operator inference', family=None, section='operator_association',
         count_key='historical_operator_requests', impact_note='Applies only to the optional inferred report.',
         summary='Optional comparison for explicitly selected UTC months; off by default.',
         help='Adds a separate inferred comparison for selected UTC months using recorded scanner associations. Historical ownership remains unverified and is not backdated as identity. This option never changes the default or request-only report totals; select months under Operator evidence and comparison in Advanced.'),
    dict(key='compound_automation', label='Compound scripted browsing', family='automated_browsing', section='compound_automation',
         summary='Independent client anomalies plus resource/rate evidence.',
         help='Requires an independent client anomaly together with resource or rate evidence in a witnessed visit. Metadata-family traversal and fast distinct-page traversal are bounded by their thresholds. Literal quote wrapping in the user agent qualifies as an anomaly only with sufficient unquoted controls and when rare in that day/log format. Missing assets or one page alone is insufficient. Positive browser continuity can veto the episode; no actor identity is inferred.' + CORPUS_PROVENANCE_HELP),
    dict(key='scheduled_automation', label='Scheduled crawling', family='automated_browsing', section='scheduled_automation',
         parameter_help={'min_sources': 'Minimum number of distinct source addresses, in each supporting complete UTC week, making the same site and exact user agent\'s API/feed/font GET/HEAD requests.'},
         summary='Repeated weekly fetching patterns with corroborated witnesses.',
         help='Learns repeated weekly path/phase signatures across complete UTC weeks, corroborating sources and resource families. The target week is held out of the required other cycles. Positive browser continuity limits training and vetoes target episodes. Only structurally witnessed visits are excluded; a shared user-agent string or calendar phase alone never changes default totals.' + CORPUS_PROVENANCE_HELP),
    dict(key='inferred_scanner', label='Bounded scanner inference', family='scanner_inference', section='inferred_scanner',
         parameter_help={'min_sources': 'Minimum number of distinct source addresses sharing the exact platformless client fingerprint, each with valid scanner DNS evidence within window days; counted across the whole corpus, not only selected months.'},
         summary='Recent selected months and corroborated scanner fingerprints.',
         help='Requires selected UTC months, scanner DNS evidence within window days of the request and the configured number of corroborating scanner sources for a client fingerprint. Association is inferred historical evidence, not verified ownership. Unsupported provenance and positive browser continuity abstain. Marks witnessed requests only; the comparison and evidence remain reviewable.'),
    dict(key='declared_automation', label='Declared automation', family='signatures', section='declared_automation',
         summary='Curated explicit crawler/tool declarations, unverified.',
         help='Matches curated bounded crawler or tool tokens in the observed user agent. An empty token list is inactive. Declarations can be forged and do not verify provider identity; generic browser strings are not crawler evidence.' + CORPUS_PROVENANCE_HELP),
    dict(key='metadata_requests', label='Metadata requests', family='metadata', section='metadata_requests',
         summary='Exclude robots and sitemap fetches as a reporting policy.',
         help='Excludes GET/HEAD requests at configured exact paths and, when selected, recognized XML/XML.gz sitemap names. Can remove hits and response bytes even when the request has zero pages. Actor labels stay unchanged: robots.txt or sitemap access alone does not prove a bot or invalidate other visits.')]

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
    'admin_paths': 'Configured administration paths used to corroborate login probing, one exact path per line.',
    'pair_seconds': 'Maximum elapsed seconds from a login GET to its adjacent POST; also separates platform-switching visits.',
    'min_pairs': 'Minimum number of qualifying adjacent GET/POST pairs in the repeated-pair witness.',
    'min_platform_switches': 'Minimum number of platform-switching pairs, or separated switch visits for the alternative witness.',
    'author_paths': 'Exact paths accepting the author-ID or REST-route query feature, one per line.',
    'user_paths': 'Exact user-API endpoint paths, one per line.',
    'rest_routes': 'Exact decoded REST-route values accepted as user-API evidence, one per line.',
    'distinct_author_ids': 'Minimum number of distinct positive author IDs in the enumeration window.',
    'user_api_requests': 'Minimum number of requests carrying configured user-API evidence.',
    'query_paths': 'Exact paths at which configured internal query keys are considered, one per line.',
    'plugin_prefixes': 'Plugin directory prefixes, one per line. A GET/HEAD of a plugin readme or PHP file below one supplies plugin-file evidence whatever its response status.',
    'query_keys': 'Internal query-parameter names considered for probing evidence, one per line.',
    'entry_paths': 'Exact entry paths eligible for the witnessed episode only, one per line.',
    'post_requests': 'Minimum number of qualifying POST requests in the episode.',
    'post_paths': 'Exact paths eligible for POST evidence, one per line.',
    'get_paths': 'Exact paths eligible for GET endpoint evidence, one per line.',
    'tool_tokens': 'Bounded explicit tool user-agent tokens, one per line; claims remain unverified.',
    'distinct_families': 'Minimum number of distinct registered service families, rather than URL aliases.',
    'retrospective_months': 'UTC calendar months (YYYY-MM, one per line) for the optional inferred comparison; never backdates identity or changes default totals.',
    'distinct_pages': 'Minimum number of distinct page paths in the fast-page witness.',
    'metadata_families': 'Minimum number of distinct metadata resource families in the metadata-traversal witness.',
    'quote_min_controls': 'Minimum number of requests with an observed, unquoted user-agent value in the same UTC day and configured log format.',
    'quote_min_sources': 'Minimum number of distinct literal client IP addresses among those unquoted requests; a client value that is not a literal IP address does not count as a source.',
    'quote_max_percent': 'Maximum percentage of quote-wrapped user-agent values among all requests with an observed user-agent value in the same UTC day and configured log format; a higher share is treated as a format convention and vetoes this anomaly.',
    'min_cycles': 'Minimum number of other complete UTC weeks with the repeated signature; the target week is held out.',
    'min_phase_paths': 'Minimum number of distinct weekly phase/path pairs in the learned signature.',
    'min_families': 'Minimum number of resource families corroborating a scheduled signature.',
    'entry_seconds': 'Maximum visit window in seconds for connecting a scheduled entry and its resources.',
    'max_continuity_percent': 'Maximum percentage of learned witnesses with positive browser continuity; target episodes also have a continuity veto.',
    'window_days': 'Maximum absolute distance in days between a request and recorded scanner DNS lookup.',
    'months': 'Selected UTC calendar months (YYYY-MM, one per line) for bounded scanner inference; no other months qualify.',
    'tokens': 'Curated bounded explicit crawler/tool user-agent declarations, one per line; not verified identities.',
    'login_distinct_paths': 'Minimum number of distinct configured login paths in the login-discovery witness.',
    'login_head_paths': 'Minimum number of distinct configured login paths requested with HEAD.',
    'login_get_requests': 'Minimum number of GET requests to configured login paths.',
    'post_distinct_paths': 'Minimum number of distinct configured POST paths in the failing POST/API witness.',
    'api_paths': 'Exact API paths required to corroborate the failing POST witness, one per line.',
    'sitemap_patterns': '0/1 switch: 1 also recognizes the built-in XML/XML.gz sitemap filename patterns; 0 uses the configured exact paths only.'}

FILTER_STATUS_CLASSES = {
    'Active': 'active', 'Active for covered requests': 'active',
    'Active for witnessed episodes': 'active', 'Dated intervals only': 'active',
    'Disabled': 'off', 'Needs configuration': 'needs', 'Evidence unavailable': 'needs',
    'Needs curated tool tokens': 'needs', 'Needs repeated corpus evidence': 'needs',
    'Needs evidence and selected months': 'needs', 'Select UTC months in Advanced': 'needs',
    'Input over limits': 'needs', 'Corpus evidence over limits; retained': 'needs',
    'Not selected for this month': 'needs'}

FILTER_POLICIES = {
    'ip_policy': dict(label='Exclude other requests from IPs with eligible behavior evidence',
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
        for rule, keys in [('probing', ['paths']), ('distributed_login', ['login_paths', 'admin_paths']), ('login_rotation', ['login_paths']), ('sensitive_scan', ['paths']),
                           ('wp_enumeration', ['author_paths', 'user_paths', 'rest_routes']),
                           ('wp_query_probe', ['query_paths', 'plugin_prefixes', 'query_keys']),
                           ('backdoor_probe', ['paths', 'entry_paths']),
                           ('protocol_probe', ['post_paths', 'get_paths', 'tool_tokens', 'entry_paths']),
                           ('declared_automation', ['tokens']), ('inferred_scanner', ['months']),
                           ('wp_micro_probe', ['login_paths', 'post_paths', 'api_paths', 'entry_paths']),
                           ('metadata_requests', ['paths'])]:
            for key in keys:
                classifier[rule][key] = copy.deepcopy(current['classifier'][rule][key])
    return validate_profile({'schema_version': 1, 'filters': {f[0]: f[0] != 'historical_operator' for f in FILTERS},
                             'exclude_automated_ips': True, 'native_level': 3,
                             'classifier': classifier, 'exceptions': []}, app, perl)


def micro_probe_unready(rule):
    """True when well-typed lists cannot meet the classifier's enabled-only
    micro-probe minima; malformed values are left for classifier_config."""
    paths = [rule[k] for k in ('login_paths', 'post_paths', 'api_paths')]
    minima = [rule[k] for k in ('login_distinct_paths', 'post_distinct_paths')]
    if not all(type(v) is list for v in paths) or not all(type(v) is int for v in minima):
        return False
    return len(paths[0]) < minima[0] or len(paths[1]) < minima[1] or not paths[2]


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
        cfg[rule]['enabled'] = int(p['filters'][rule])
    cfg['operator_association']['enabled'] = int(p['filters']['operator_associated'])
    cfg['operator_association']['retrospective_enabled'] = int(p['filters']['historical_operator'])
    # Intended enablement remains saved even where required paths are unavailable.
    if not cfg['sensitive_scan']['paths']:
        cfg['sensitive_scan']['enabled'] = 0
    en = cfg['wp_enumeration']
    if not (en['author_paths'] and (en['user_paths'] or en['rest_routes'])):
        en['enabled'] = 0
    if not all(cfg['wp_query_probe'][k] for k in ('query_paths', 'plugin_prefixes', 'query_keys')):
        cfg['wp_query_probe']['enabled'] = 0
    if not cfg['backdoor_probe']['paths']:
        cfg['backdoor_probe']['enabled'] = 0
    if not all(cfg['protocol_probe'][k] for k in ('post_paths', 'get_paths', 'tool_tokens')):
        cfg['protocol_probe']['enabled'] = 0
    if not cfg['login_rotation']['login_paths']:
        cfg['login_rotation']['enabled'] = 0
    if not cfg['probing']['paths']:
        cfg['probing']['enabled'] = 0
    if not (cfg['distributed_login']['login_paths'] and cfg['distributed_login']['admin_paths']):
        cfg['distributed_login']['enabled'] = 0
    if micro_probe_unready(cfg['wp_micro_probe']):
        cfg['wp_micro_probe']['enabled'] = 0
    p['classifier'] = classifier_config(cfg, app, perl)
    p['exceptions'].sort(key=lambda e: e['request_id'])
    return p


def filter_status(profile, evidence=False, over_limits=False, operator_evidence=False):
    statuses = {}
    for key, _, _ in FILTERS:
        if not profile['filters'][key]:
            statuses[key] = 'Disabled'
        elif key == 'verified_crawlers' and not evidence:
            statuses[key] = 'Evidence unavailable'
        elif key == 'inferred_scanner' and (not operator_evidence or not profile['classifier'][key]['months']):
            statuses[key] = 'Needs evidence and selected months'
        elif key == 'declared_automation' and not profile['classifier'][key]['tokens']:
            statuses[key] = 'Needs curated tool tokens'
        elif key == 'scheduled_automation':
            statuses[key] = 'Needs repeated corpus evidence'
        elif key in ('operator_associated', 'historical_operator') and not operator_evidence:
            statuses[key] = 'Evidence unavailable'
        elif key == 'historical_operator' and not profile['classifier']['operator_association']['retrospective_months']:
            statuses[key] = 'Select UTC months in Advanced'
        elif key == 'probing' and not profile['classifier'][key]['paths']:
            statuses[key] = 'Needs configuration'
        elif key == 'distributed_login' and not (profile['classifier'][key]['login_paths'] and profile['classifier'][key]['admin_paths']):
            statuses[key] = 'Needs configuration'
        elif key == 'login_rotation' and not profile['classifier'][key]['login_paths']:
            statuses[key] = 'Needs configuration'
        elif key == 'sensitive_scan' and not profile['classifier'][key]['paths']:
            statuses[key] = 'Needs configuration'
        elif key == 'wp_enumeration' and not (profile['classifier'][key]['author_paths'] and
                (profile['classifier'][key]['user_paths'] or profile['classifier'][key]['rest_routes'])):
            statuses[key] = 'Needs configuration'
        elif key == 'wp_query_probe' and not all(profile['classifier'][key][k] for k in ('query_paths', 'plugin_prefixes', 'query_keys')):
            statuses[key] = 'Needs configuration'
        elif key == 'backdoor_probe' and not profile['classifier'][key]['paths']:
            statuses[key] = 'Needs configuration'
        elif key == 'protocol_probe' and not all(profile['classifier'][key][k] for k in ('post_paths', 'get_paths', 'tool_tokens')):
            statuses[key] = 'Needs configuration'
        elif key == 'wp_micro_probe' and micro_probe_unready(profile['classifier'][key]):
            statuses[key] = 'Needs configuration'
        elif (key in RULES or key in ('operator_associated', 'historical_operator')) and over_limits:
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
