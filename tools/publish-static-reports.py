"""Root log reader/publisher; vstats itself always runs as its dedicated UID."""
import argparse
import bisect
import calendar
from collections import Counter
from pathlib import Path
import datetime
import fcntl
import grp
import gzip
import hashlib
import importlib.util
import html
import io
from html.parser import HTMLParser
import json
import os
import pwd
import re
import shutil
import stat
import socket
import subprocess
import sys
import uuid

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from normalize_logs import build_snapshot
from native_history_cache import read_history, restore_history
from vstats_filters import (add_filters_menu, native_shell, canonical, identity, read_json,
                            atomic_json, validate_profile, defaults, filter_status, FILTERS, GENERATION,
                            Control, browser_policy, public_browser_policy, publish_browser_policy, queued_user)

BASE = '/var/lib/vstats'
WEB = '/var/www/vstats'
APP = '/opt/vstats/current'
CONFIG = '/etc/vstats'
NATIVE_INCLUDE_BASE = None
LAUNCHER = '/opt/vstats/bin/vstats'
LOG = '/var/log/vstats'
SOURCE_LOG = '/var/log/httpd'
PERL = '/opt/vstats/runtime/perl-5.44.0/bin/perl'
PERL_LIBRARIES = ['/opt/vstats/runtime/perl-5.44.0/modules/lib/perl5', '/opt/vstats/lib']
PROFILE_MAP = {}
PREVIEW_BASELINE = {}
TOPICS = ['main', 'alldomains', 'allhosts', 'allrobots', 'browserdetail', 'downloads',
          'errors400', 'errors403', 'errors404', 'keyphrases', 'keywords', 'lasthosts',
          'lastrobots', 'osdetail', 'refererpages', 'refererse', 'session',
          'unknownbrowser', 'unknownip', 'unknownos', 'urldetail', 'urlentry', 'urlexit']
DOCS = {name: 'awstats_' + name + '.html' for name in
        ['benchmark', 'changelog', 'compare', 'config', 'contrib', 'dolibarr', 'extra',
         'faq', 'glossary', 'license', 'security', 'setup', 'tools', 'upgrade', 'webmin', 'what']}
DOCS.update({'dev_plugins': 'awstats_dev_plugins.html', 'dev_hooks': 'awstats_dev_plugins_hooks.html',
             'dev_graphs': 'awstats_dev_plugins_graphs.html'})
DOC_LINK = re.compile(r'''(?P<q>["'])/cgi-bin/awstats\.pl\?[^"']*\bdoc=(?P<name>\w+)[^"']*(?P=q)''')
SITE_NAME = re.compile(r'^[a-z0-9][a-z0-9._-]*$')
ERROR_MARKERS = ['Use of uninitialized', 'Undefined subroutine', "Can't locate ",
                 'Global symbol ', 'syntax error at ', 'Error: AWStats']


def private_directory(path, gid, owner=0, mode=0o750):
    os.makedirs(path, exist_ok=True)
    if not stat.S_ISDIR(os.lstat(path).st_mode):
        raise RuntimeError('Expected a real directory: ' + path)
    os.chown(path, owner, gid)
    os.chmod(path, mode)


def write_text(path, text, gid):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
        handle.write(text)
    os.chown(path, 0, gid)


def as_statistics_user(account):
    def demote():
        os.setgroups([account.pw_gid])
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)
        os.umask(0o077)
        os.nice(15)
    return demote


def invoke(account, site, arguments, log_label, output=None, config_dir=None):
    environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC'}
    effective_config = config_dir or CONFIG
    if NATIVE_INCLUDE_BASE is not None:
        if os.path.commonpath([os.path.abspath(effective_config), os.path.abspath(CONFIG)]) == os.path.abspath(CONFIG):
            include_base = os.path.join(NATIVE_INCLUDE_BASE, os.path.relpath(effective_config, CONFIG))
        else:
            # Replay/baseline configs originate from the main site config.
            include_base = NATIVE_INCLUDE_BASE
        environment['VSTATS_NATIVE_INCLUDE_ROOT'] = os.path.join(os.getcwd(), include_base)
    command = ([LAUNCHER] if isinstance(LAUNCHER, str) else LAUNCHER) + [ '-config=' + site, '-configdir=' + effective_config] + arguments
    proc = subprocess.Popen(command, cwd=BASE, env=environment,
                            preexec_fn=as_statistics_user(account),
                            stdout=output if output is not None else subprocess.PIPE,
                            stderr=subprocess.PIPE)
    try:
        out, err = proc.communicate(timeout=900 if '-update' in arguments else 90)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise RuntimeError('Statistics worker exceeded the heuristic execution guard: ' + site)
    diagnostic = os.path.join(LOG, log_label)
    with open(diagnostic, 'wb') as handle:
        if out:
            handle.write(out)
        if err:
            handle.write(b'\nSTDERR:\n' + err)
    os.chmod(diagnostic, 0o600)
    if proc.returncode or err:
        raise RuntimeError('Statistics worker failed; see ' + diagnostic)
    return (out or b'').decode('utf-8', 'replace')


def cache_lines(path, owner):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as raw:
        info = os.fstat(raw.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != owner:
            raise RuntimeError('Unexpected statistics-cache ownership/type')
        stream = gzip.GzipFile(fileobj=raw) if path.endswith('.gz') else raw
        with io.TextIOWrapper(stream, encoding='utf-8') as handle:
            yield from handle


def cache_totals(site, account, data_root=None):
    directory = os.path.join(data_root or os.path.join(BASE, 'data'), site)
    result = {}
    expected = re.compile(r'^awstats(\d{2})(\d{4})\.' + re.escape(site) + r'\.txt(?:\.gz)?$')
    for name in sorted(os.listdir(directory)):
        match = expected.fullmatch(name)
        if not match:
            continue
        month, year = int(match.group(1)), int(match.group(2))
        if not 1 <= month <= 12:
            raise RuntimeError('Unexpected statistics month')
        path = os.path.join(directory, name)
        if name.endswith('.gz') and os.path.isfile(path[:-3]):
            continue
        values = {'pages': 0, 'nonviewed_pages': 0, 'hits': 0, 'bytes': 0, 'nonviewed_hits': 0, 'nonviewed_bytes': 0,
                  'unique': 0, 'visits': 0}
        section = ''
        for line in cache_lines(path, account.pw_uid):
            if line.startswith('BEGIN_'):
                section = line.split()[0][6:]
                continue
            if line.startswith('END_'):
                if section == 'TIME':
                    break
                section = ''
                continue
            fields = line.split()
            if section == 'GENERAL' and len(fields) > 1:
                if fields[0] == 'TotalUnique':
                    values['unique'] = int(fields[1])
                elif fields[0] == 'TotalVisits':
                    values['visits'] = int(fields[1])
            elif section == 'TIME' and len(fields) >= 7:
                values['pages'] += int(fields[1])
                values['nonviewed_pages'] += int(fields[4])
                values['hits'] += int(fields[2])
                values['bytes'] += int(fields[3])
                values['nonviewed_hits'] += int(fields[5])
                values['nonviewed_bytes'] += int(fields[6])
        result['%04d-%02d' % (year, month)] = values
    return result


def cache_fingerprints(site, account, data_root=None):
    directory = os.path.join(data_root or os.path.join(BASE, 'data'), site)
    expected = re.compile(r'^awstats(\d{2})(\d{4})\.' + re.escape(site) + r'\.txt(?:\.gz)?$')
    result = {}
    for name in sorted(os.listdir(directory)):
        if not expected.fullmatch(name):
            continue
        path = os.path.join(directory, name)
        if name.endswith('.gz') and os.path.isfile(path[:-3]):
            continue
        sections, section = {}, None
        for line in cache_lines(path, account.pw_uid):
            if line.startswith('BEGIN_'):
                section = line.split()[0][6:]
                if section != 'MAP':
                    sections[section] = []
            elif line.startswith('END_'):
                section = None
            elif section and section != 'MAP' and line.strip() and not line.startswith('#'):
                if section == 'GENERAL' and line.startswith('LastUpdate '):
                    continue
                sections[section].append(line.rstrip())
        result[name[:-3] if name.endswith('.gz') else name] = {
            key: hashlib.sha256('\n'.join(sorted(rows)).encode('utf-8')).hexdigest()
            for key, rows in sections.items()}
    return result


def supplemental_reports(site):
    # Approved static summaries live outside application source and rotating pages.
    def checked(path, directory):
        info = os.lstat(path)
        valid = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        if not valid or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError('Unsafe supplemental report source: ' + path)
    if not SITE_NAME.fullmatch(site):
        raise RuntimeError('Unsafe supplemental site identifier')
    base = os.path.join(BASE, 'supplements')
    if not os.path.lexists(base):
        return []
    checked(base, True)
    directory = os.path.join(base, site)
    if not os.path.lexists(directory):
        return []
    checked(directory, True)
    reports = []
    for slug in sorted(os.listdir(directory)):
        if not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', slug):
            raise RuntimeError('Unsafe supplemental report identifier')
        source = os.path.join(directory, slug)
        checked(source, True)
        names = sorted(os.listdir(source))
        if 'index.html' not in names:
            raise RuntimeError('Supplemental report has no index')
        for name in names:
            if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}\.html', name):
                raise RuntimeError('Only aggregate HTML reports may be published')
            checked(os.path.join(source, name), False)
        reports.append((slug, slug.replace('-', ' ').capitalize(), source, names))
    return reports


def supplemental_links(site):
    return ' &middot; '.join(
        "<a href='/vstats/" + html.escape(site, quote=True) + '/' +
        html.escape(slug, quote=True) + "/'>" + html.escape(title) + '</a>'
        for slug, title, source, names in supplemental_reports(site))


def copy_supplemental_reports(site, site_web, apache_gid, skip=()):
    for slug, title, source, names in supplemental_reports(site):
        if slug in skip:
            continue
        destination = os.path.join(site_web, slug)
        if os.path.lexists(destination):
            raise RuntimeError('Supplemental report target already exists')
        private_directory(destination, apache_gid)
        for name in names:
            with open(os.path.join(source, name), encoding='utf-8') as handle:
                text = handle.read()
            if '<html' not in text.lower():
                raise RuntimeError('Supplemental report is not HTML')
            write_text(os.path.join(destination, name), text, apache_gid)
    return supplemental_links(site)


def adapt_static_report(path, site, layer_info=None, original=False, confirmed=False, request_only=False):
    with open(path, encoding='utf-8') as handle:
        text = handle.read()
    if '<html' not in text.lower() or any(marker in text for marker in ERROR_MARKERS):
        raise RuntimeError('Invalid rendered report: ' + path)
    def document(match):
        key = match.group('name')
        if key not in DOCS:
            raise RuntimeError('Unmapped documentation target: ' + key)
        return match.group('q') + '/vstats/docs/' + DOCS[key] + match.group('q')
    text = DOC_LINK.sub(document, text)
    text = re.sub(r'(<body\b[^>]*>)', lambda m: m.group(1) + basic_navigation(site), text, count=1, flags=re.I)
    # The transaction wrapper adds controls after binding the complete profile.
    with open(path, 'w', encoding='utf-8') as handle:
        handle.write(text)


def copy_public_assets(generation, apache_gid):
    assets = os.path.join(generation, 'assets')
    private_directory(assets, apache_gid)
    for name in ['icon', 'css', 'js']:
        source = os.path.join(APP, 'wwwroot', name)
        if os.path.isdir(source):
            shutil.copytree(source, os.path.join(assets, name), symlinks=True)
    docs = os.path.join(generation, 'docs')
    private_directory(docs, apache_gid)
    source_docs = os.path.join(APP, 'docs')
    for name in os.listdir(source_docs):
        source = os.path.join(source_docs, name)
        if os.path.isfile(source) and os.path.splitext(name)[1].lower() in ['.html', '.css', '.js', '.pdf', '.txt']:
            shutil.copyfile(source, os.path.join(docs, name))
    # The release accidentally ships the benchmark HTML with a .khtml suffix.
    benchmark = os.path.join(source_docs, 'awstats_benchmark.khtml')
    if not os.path.isfile(os.path.join(docs, 'awstats_benchmark.html')) and os.path.isfile(benchmark):
        shutil.copyfile(benchmark, os.path.join(docs, 'awstats_benchmark.html'))
    for name in set(DOCS.values()):
        if not os.path.isfile(os.path.join(docs, name)):
            raise RuntimeError('Missing documentation file: ' + name)
    for name in ['images', 'css', 'js', 'scripts']:
        source = os.path.join(source_docs, name)
        if os.path.isdir(source):
            shutil.copytree(source, os.path.join(docs, name), symlinks=True)
    for current, directories, files in os.walk(generation, followlinks=False):
        for name in directories + files:
            path = os.path.join(current, name)
            info = os.lstat(path)
            if stat.S_ISLNK(info.st_mode):
                raise RuntimeError('No source symlinks are allowed in published reports')
            os.chown(path, 0, apache_gid)
            os.chmod(path, 0o750 if stat.S_ISDIR(info.st_mode) else 0o640)


class LinkCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attributes):
        data = dict(attributes)
        for key in ['href', 'src', 'action']:
            if key in data:
                self.links.append(data[key])


def add_native_icon_fallback(generation, target):
    # Native mime/ and os/ icon stems come from registries, history keys and the
    # notavailable default with no glyph check. Only <generation>[/history/<id>]
    # /assets/icon/{mime,os}/<stem>.svg is repairable: an exclusive, no-follow,
    # byte-exact copy of that directory's unknown.svg with its owner and mode.
    # Returns None once created, {} outside that class, else {'reason': ...}.
    import re
    name = os.path.basename(target)
    parts = Path(target).relative_to(Path(generation)).parts
    if len(parts) == 6 and parts[0] == 'history' and GENERATION.fullmatch(parts[1]):
        parts = parts[2:]
    if (len(parts) != 4 or parts[:2] != ('assets', 'icon') or parts[2] not in ('mime', 'os')
            or name == 'unknown.svg' or not re.fullmatch('[A-Za-z0-9_][A-Za-z0-9_.-]*[.]svg', name)):
        return {}
    directory = os.path.dirname(target)
    current = generation
    for component in Path(directory).relative_to(Path(generation)).parts:
        current = os.path.join(current, component)
        try:
            info = os.lstat(current)
        except OSError:
            return {'reason': 'native icon directory unavailable'}
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            return {'reason': 'native icon directory is not a private real directory'}
    try:
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        return {'reason': 'native icon directory unavailable'}
    try:
        try:
            source_fd = os.open('unknown.svg', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                dir_fd=directory_fd)
        except OSError:
            return {'reason': 'native icon fallback unknown.svg unavailable'}
        with os.fdopen(source_fd, 'rb') as handle:
            source = os.fstat(handle.fileno())
            if not stat.S_ISREG(source.st_mode):
                return {'reason': 'native icon fallback unknown.svg is not a regular file'}
            data = handle.read()
        try:
            target_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                0o600, dir_fd=directory_fd)
        except OSError:
            return {'reason': 'native icon target name is occupied or not creatable'}
        try:
            with os.fdopen(target_fd, 'wb') as handle:
                handle.write(data)
                os.fchown(handle.fileno(), source.st_uid, source.st_gid)
                os.fchmod(handle.fileno(), stat.S_IMODE(source.st_mode))
        except OSError:
            os.unlink(name, dir_fd=directory_fd)
            return {'reason': 'native icon fallback copy failed'}
        return None
    finally:
        os.close(directory_fd)


def validate_report_links(generation):
    from urllib.parse import unquote, urlsplit
    checked, missing = 0, []
    for current, directories, files in os.walk(generation):
        if os.path.commonpath([current, os.path.join(generation, 'docs')]) == os.path.join(generation, 'docs'):
            continue
        relative = Path(current).relative_to(Path(generation)).parts
        if len(relative) >= 3 and relative[0] == 'history' and GENERATION.fullmatch(relative[1]) and relative[2] == 'docs':
            continue  # same unchanged documentation scope in a retained generation
        for name in files:
            if not name.endswith('.html'):
                continue
            path = os.path.join(current, name)
            parser = LinkCollector()
            with open(path, encoding='utf-8') as handle:
                parser.feed(handle.read())
            for value in parser.links:
                parts = urlsplit(value)
                if parts.scheme or parts.netloc or not parts.path:
                    continue
                if parts.path.startswith('/vstats/'):
                    target = os.path.join(generation, unquote(parts.path[len('/vstats/'):]))
                elif parts.path.startswith('/'):
                    missing.append({'file': path, 'target': value, 'reason': 'unexpected server route'})
                    continue
                else:
                    target = os.path.normpath(os.path.join(current, unquote(parts.path)))
                target = os.path.abspath(target)
                if os.path.commonpath([generation, target]) != generation:
                    raise RuntimeError('Rendered report link escapes its published generation')
                if os.path.isdir(target):
                    target = os.path.join(target, 'index.html')
                checked += 1
                if not os.path.isfile(target):
                    refusal = add_native_icon_fallback(generation, target)
                    if refusal is not None:
                        missing.append(dict({'file': path, 'target': value}, **refusal))
    if missing:
        raise RuntimeError('Generated navigation contains missing targets: ' + json.dumps(missing[:8]))
    return checked


def page(title, body):
    return ("<!doctype html><html lang='en'><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<meta name='robots' content='noindex,nofollow'><title>" + html.escape(title) +
            "</title><style>body{font:16px system-ui,sans-serif;max-width:1000px;margin:40px auto;padding:0 20px;"
            "background:#f6f8fb;color:#182333}a{color:#075bb5}table{width:100%;border-collapse:collapse;background:white}"
            "td,th{text-align:left;padding:14px;border-bottom:1px solid #dde4ee}small{color:#536273}</style><body>" +
            body + '</body></html>')


def render_root_index(generation, profiles, sites, generated_utc, apache_gid):
    rows = []
    for site, profile in sorted(profiles.items()):
        if not SITE_NAME.fullmatch(site):
            raise RuntimeError('Unsafe configured site identifier')
        if not (Path(generation) / site).is_dir():
            continue
        totals = profile.get('totals', {})
        known = totals and all(isinstance(v, dict) and all(
            type(v.get(k)) is int and v[k] >= 0 for k in ['hits', 'nonviewed_hits'])
            for v in totals.values())
        count = format(sum(v['hits'] + v['nonviewed_hits'] for v in totals.values()), ',') if known else 'unavailable'
        label = html.escape(sites.get(site, {}).get('label', site))
        updated = html.escape(profile.get('updated_utc') or 'unavailable')
        rows.append("<tr><td style='overflow-wrap:anywhere'><a href='" + html.escape(site, quote=True) +
                    "/'>" + label + '</a><br><small>Reports as of ' + updated +
                    '</small></td><td>' + count + '</td></tr>')
    target = Path(generation) / 'index.html'
    if os.path.lexists(str(target)):
        info = os.lstat(str(target))
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
            raise RuntimeError('Unexpected generated index ownership/type')
        target.unlink()
    write_text(str(target), page('Website statistics',
               '<h1>Website statistics</h1><p>Choose a site and month to view its vstats report.</p>'
               '<table><tr><th>Website</th><th>Requests analyzed</th></tr>' + ''.join(rows) +
               '</table><p><small>Updated ' + html.escape(generated_utc) +
               '. Reports update hourly. Times are shown in UTC.</small></p>'), apache_gid)


def remove_owned_directory(parent, name):
    if not re.fullmatch(r'\d{8}T\d{6}Z-[0-9a-f]{8}', name):
        raise RuntimeError('Unexpected generated directory name')
    path = os.path.join(parent, name)
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
        raise RuntimeError('Refusing to remove a directory not owned by the publisher')
    shutil.rmtree(path)


def retain_generated_files(token, previous):
    # Keep the current reports and their immediate predecessor for rollback.
    # These are disposable generated pages, never source logs or history data.
    generations = os.path.join(WEB, 'generations')
    keep = {token}
    if previous:
        if os.path.dirname(previous) != generations:
            raise RuntimeError('Previous report generation is outside the expected directory')
        keep.add(os.path.basename(previous))
    for name in os.listdir(generations):
        if name not in keep:
            remove_owned_directory(generations, name)
    for name in os.listdir(os.path.join(BASE, 'work')):
        if name != token:
            remove_owned_directory(os.path.join(BASE, 'work'), name)


def retain_failed_files(token):
    generations = os.path.join(WEB, 'generations')
    keep = {token}
    current = os.path.join(WEB, 'current')
    if os.path.islink(current):
        target = os.path.realpath(current)
        if os.path.dirname(target) != generations:
            raise RuntimeError('Current report generation is outside its expected directory')
        keep.add(os.path.basename(target))
    status = os.path.join(BASE, 'status.json')
    if os.path.isfile(status):
        with open(status, encoding='utf-8') as handle:
            previous = json.load(handle).get('previous_generation')
        if previous:
            if os.path.dirname(previous) != generations:
                raise RuntimeError('Previous report generation is outside its expected directory')
            keep.add(os.path.basename(previous))
    for name in os.listdir(generations):
        if name not in keep:
            remove_owned_directory(generations, name)
    for name in os.listdir(os.path.join(BASE, 'work')):
        if name != token:
            remove_owned_directory(os.path.join(BASE, 'work'), name)


def _refresh_verified_evidence(account):
    directory = os.path.join(BASE, 'crawler-evidence')
    private_directory(directory, account.pw_gid)
    bundle = os.path.join(directory, 'evidence.json')
    if not os.path.isfile(bundle) or os.path.islink(bundle):
        raise RuntimeError('Initialize the private evidence bundle before enabling its layer')
    spec = importlib.util.spec_from_file_location('vstats_evidence_collector',
                                                os.path.join(APP, 'tools', 'crawler-evidence.py'))
    collector = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(collector)
    result = {'enabled': True, 'refresh_status': 'unavailable', 'provider_id': collector.PROVIDER}
    try:
        today = datetime.datetime.utcnow().strftime('%Y%m%d')
        retrievals = os.path.join(directory, 'retrievals')
        daily_count = sum(bool(re.fullmatch(today + r'T\d{6}Z\.json', name))
                          for name in os.listdir(retrievals)) if os.path.isdir(retrievals) else 0
        # Reserve the nearest earlier/later retrievals in each strict day bundle.
        if daily_count >= collector.MAX_SNAPSHOTS - 2:
            result['refresh_status'] = 'skipped_daily_snapshot_bound'
        else:
            receipt = collector.collect(directory)
            result.update({'refresh_status': 'success', 'retrieved_at': receipt['retrieved_at'],
                           'raw_sha256': receipt['raw_sha256']})
    except Exception as error:
        # Preserve the prior bundle. Its request-period rules cannot verify later
        # requests without covering evidence; declarations are never a fallback.
        result['refresh_error_type'] = type(error).__name__
    os.chown(bundle, 0, account.pw_gid)
    os.chmod(bundle, 0o640)
    with open(bundle, 'rb') as handle:
        raw = handle.read()
    data = json.loads(raw.decode('utf-8'))
    result['snapshots'] = len(data['snapshots'])
    result['bundle_sha256'] = hashlib.sha256(raw).hexdigest()
    result['scope'] = 'Additional verified-crawler evidence; existing AWStats rules remain active'
    return result


_EVIDENCE_REFRESH = None

def refresh_verified_evidence(account):
    global _EVIDENCE_REFRESH
    if _EVIDENCE_REFRESH is None:
        _EVIDENCE_REFRESH = _refresh_verified_evidence(account)
    return dict(_EVIDENCE_REFRESH)


def check_layer_conservation(original, filtered):
    if set(original) != set(filtered):
        raise RuntimeError('Original and additional-layer history periods differ')
    for period, baseline in original.items():
        adjusted = filtered[period]
        if (baseline['hits'] + baseline['nonviewed_hits'] != adjusted['hits'] + adjusted['nonviewed_hits']
                or baseline['bytes'] + baseline['nonviewed_bytes'] != adjusted['bytes'] + adjusted['nonviewed_bytes']
                or adjusted['hits'] > baseline['hits']):
            raise RuntimeError('Additional layer did not conserve request/byte totals')


def crawler_layer_controls(site, period, filename, info, original=False, confirmed=False, request_only=False):
    if info.get("behavior_filter"):
        return behavior_layer_controls(site, period, filename, info, original, confirmed, request_only)
    base = '/vstats/' + html.escape(site, quote=True) + '/'
    suffix = (html.escape(period, quote=True) + '/' + html.escape(filename, quote=True)) if period else ''
    enabled = base + suffix
    disabled = base + 'original/' + suffix
    title = 'Original AWStats rules' if original else 'Original AWStats rules + verified crawler evidence'
    note = ('Provider evidence could not be refreshed; requests without covering evidence keep their original treatment.'
            if info.get('refresh_status') != 'success' else
            'Only request-period provider evidence can add crawler classifications. Earlier history is not reclassified.')
    return ("<section style='margin:10px 16px;padding:12px;border:1px solid #cbd5e1;font:14px sans-serif'>"
            '<strong>' + title + '</strong><br>'
            "Additional layer: <a href='" + enabled + "'>On (default)</a> &middot; "
            "<a href='" + disabled + "'>Off — original rules</a>"
            '<p>This layer requires verified crawler evidence. User-agent declarations, unknown labels and scanner flags '
            'do not add exclusions. Existing AWStats user-agent rules continue to apply.</p><small>' + note +
            ' Remaining visitor figures are not verified human counts.</small></section>')


def render_site_view(account, site, site_web, totals_by_period, apache_gid, extra_links,
                     config_dir=None, layer_info=None, original=False, confirmed=False, request_only=False):
    private_directory(site_web, apache_gid)
    periods = []
    for period in sorted(totals_by_period, reverse=True):
        year, month = period.split('-')
        directory = os.path.join(site_web, period)
        private_directory(directory, apache_gid)
        for topic in TOPICS:
            name = 'awstats.' + site + ('' if topic == 'main' else '.' + topic) + '.html'
            destination = os.path.join(directory, name)
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
            with os.fdopen(descriptor, 'wb') as output:
                invoke(account, site, ['-staticlinks', '-month=' + month, '-year=' + year,
                                       '-lang=en', '-output' + ('' if topic == 'main' else '=' + topic)],
                       site + ('-original' if original else '-confirmed' if confirmed else '-requests' if request_only else '') + '-render.log', output=output,
                       config_dir=config_dir)
            os.chown(destination, 0, apache_gid)
            adapt_static_report(destination, site, layer_info=layer_info, original=original, confirmed=confirmed, request_only=request_only)
        write_text(os.path.join(directory, 'index.html'), page(site + ' - ' + period,
                   "<meta http-equiv='refresh' content='0;url=awstats." + html.escape(site, quote=True) +
                   ".html'><a href='awstats." + html.escape(site, quote=True) + ".html'>Open report</a>"), apache_gid)
        totals = totals_by_period[period]
        periods.append("<tr><td><a href='" + period + '/awstats.' + html.escape(site, quote=True) +
                       ".html'>" + period + '</a></td><td>' +
                       format(totals['hits'] + totals['nonviewed_hits'], ',') + '</td></tr>')
    controls = ''
    write_text(os.path.join(site_web, 'index.html'), page(site,
               "<p><a href='/vstats/'>All sites</a></p><h1>" + html.escape(site) +
               '</h1><p>Report times: UTC.</p>' + controls +
               '<table><tr><th>Month</th><th>Requests analyzed</th></tr>' + ''.join(periods) + '</table>'), apache_gid)



def atomic_private_json(path, data, gid):
    temporary = path + '.new'
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
            json.dump(data, handle, sort_keys=True, indent=2)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(temporary, 0, gid)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def normalized_day(line):
    match = re.match(rb'^\S+ \S+ \S+ \[([0-9]{2}/[A-Za-z]{3}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2}) \+0000\]', line)
    if not match:
        raise RuntimeError('Corpus requires normalized UTC Apache input')
    stamp = datetime.datetime.strptime(match.group(1).decode('ascii'), '%d/%b/%Y:%H:%M:%S')
    return stamp.strftime('%Y-%m-%d'), stamp


def update_behavior_corpus(site, snapshot, account, token):
    parent = os.path.join(BASE, 'corpus', site)
    current = os.path.join(parent, 'current')
    if not os.path.islink(current):
        raise RuntimeError('Initialize complete private corpus before enabling behavior filtering')
    old = os.path.realpath(current)
    if os.path.dirname(old) != parent:
        raise RuntimeError('Corpus points outside its private parent')
    with open(os.path.join(old, 'receipt.json'), encoding='utf-8') as handle:
        receipt = json.load(handle)
    known = Counter()
    all_rows = {}
    for day, info in sorted(receipt['days'].items()):
        if not re.fullmatch(r'\d{4}-\d{2}-\d{2}', day):
            raise RuntimeError('Invalid corpus day')
        path = os.path.join(old, day + '.log')
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, 'rb') as handle:
            entry = os.fstat(handle.fileno())
            if not stat.S_ISREG(entry.st_mode) or entry.st_uid != 0:
                raise RuntimeError('Untrusted corpus file')
            raw = handle.read()
        if hashlib.sha256(raw).hexdigest() != info['sha256']:
            raise RuntimeError('Corpus identity mismatch')
        if raw and not raw.endswith(b'\n'):
            raise RuntimeError('Unterminated canonical source record')
        rows = [row + b'\n' for row in raw.split(b'\n')[:-1]]
        if len(rows) != info['rows']:
            raise RuntimeError('Corpus row count mismatch')
        known.update(rows)
        all_rows[day] = rows
    incoming = Counter()
    with open(snapshot, 'rb') as handle:
        for row in handle:
            normalized_day(row)
            incoming[row] += 1
    changed = set()
    appended = 0
    for row, count in incoming.items():
        additional = max(0, count - known[row])
        if additional:
            day, stamp = normalized_day(row)
            all_rows.setdefault(day, []).extend([row] * additional)
            appended += additional
            changed.add(day)
    destination = os.path.join(parent, token)
    private_directory(destination, account.pw_gid)
    days = {}
    for day, rows in sorted(all_rows.items()):
        target = os.path.join(destination, day + '.log')
        if day not in changed and day in receipt['days']:
            os.link(os.path.join(old, day + '.log'), target)
            days[day] = receipt['days'][day]
        else:
            rows.sort(key=lambda row: normalized_day(row)[1])
            raw = b''.join(rows)
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
            with os.fdopen(descriptor, 'wb') as handle:
                handle.write(raw)
            os.chown(target, 0, account.pw_gid)
            days[day] = {'rows': len(rows), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    new = {'schema_version': 1, 'days': days, 'native_months': receipt.get('native_months', {}),
           'updated_utc': datetime.datetime.utcnow().isoformat() + 'Z', 'previous': old,
           'new_rows': appended, 'merge_policy': 'Maximum observed multiplicity of identical normalized records; retained history is never removed when source logs rotate.'}
    atomic_private_json(os.path.join(destination, 'receipt.json'), new, account.pw_gid)
    link = os.path.join(parent, '.current-' + token)
    os.symlink(token, link)
    os.replace(link, current)
    return destination, new


def archived_evidence_for_days(days, directory, account, until=None):
    archive = os.path.join(BASE, 'crawler-evidence')
    entries = []
    blobs = {}
    for name in sorted(os.listdir(os.path.join(archive, 'retrievals'))):
        if not re.fullmatch(r'\d{8}T\d{6}Z.json', name):
            continue
        path = os.path.join(archive, 'retrievals', name)
        if os.path.islink(path):
            raise RuntimeError('Untrusted provider attestation')
        with open(path, encoding='utf-8') as handle:
            item = json.load(handle)
        meta = item['attestation']
        if set(meta) != {'provider_id', 'source_url', 'retrieved_at'} or meta['provider_id'] != 'google_common' or meta['source_url'] != 'https://developers.google.com/static/crawling/ipranges/common-crawlers.json':
            raise RuntimeError('Invalid archived provider binding')
        when = datetime.datetime.strptime(meta['retrieved_at'], '%Y-%m-%dT%H:%M:%SZ')
        if until is not None and when > until:
            continue
        if when.strftime('%Y%m%dT%H%M%SZ.json') != name:
            raise RuntimeError('Provider attestation timestamp mismatch')
        sha = item['raw_sha256']
        if not re.fullmatch(r'[0-9a-f]{64}', sha):
            raise RuntimeError('Invalid provider digest')
        if sha not in blobs:
            raw_path = os.path.join(archive, 'raw', sha + '.json')
            if os.path.islink(raw_path):
                raise RuntimeError('Untrusted provider blob')
            with open(raw_path, 'rb') as handle:
                raw = handle.read()
            if hashlib.sha256(raw).hexdigest() != sha:
                raise RuntimeError('Archived provider bytes changed')
            blobs[sha] = raw.decode('utf-8')
        entry = {'raw_json': blobs[sha], 'attestation_json': json.dumps(meta, sort_keys=True)}
        entries.append((calendar.timegm(when.timetuple()), entry))
    stamps = [entry[0] for entry in entries]
    if directory is not None:
        private_directory(directory, account.pw_gid)
    result = {}
    for day in days:
        start = calendar.timegm(datetime.datetime.strptime(day, '%Y-%m-%d').timetuple())
        end = start + int(datetime.timedelta(days=1).total_seconds()) - 1
        left = max(0, bisect.bisect_left(stamps, start) - 1)
        right = min(len(entries), bisect.bisect_right(stamps, end) + 1)
        selected = [entry for epoch, entry in entries[left:right]]
        if len(selected) > 32:
            raise RuntimeError('Daily provider evidence exceeds the existing snapshot cap')
        raw = json.dumps({'schema_version': 1, 'snapshots': selected}, sort_keys=True).encode('utf-8')
        path = None
        if directory is not None:
            path = os.path.join(directory, day + '.json')
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
            with os.fdopen(descriptor, 'wb') as handle:
                handle.write(raw)
            os.chown(path, 0, account.pw_gid)
        result[day] = {'path': path, 'sha256': hashlib.sha256(raw).hexdigest(), 'snapshots': len(selected)}
    return result


def behavior_layer_controls(site, period, filename, info, original=False, confirmed=False, request_only=False):
    base = '/vstats/' + html.escape(site, quote=True) + '/'
    suffix = (html.escape(period, quote=True) + '/' + html.escape(filename, quote=True)) if period else ''
    enabled = info.get('ip_exclusion_enabled', True)
    title = ('Original AWStats rules' if original else 'Confirmed-only; behavior included' if confirmed else
             'Request-only filtering; IP exclusion disabled' if request_only else
             'Flagged IPs excluded for the site month (default)' if enabled else 'Request-only filtering (default; IP exclusion disabled)')
    body = ("<section style='margin:10px 16px;padding:12px;border:1px solid #cbd5e1;font:14px sans-serif'><strong>" + title +
            "</strong><p><a href='" + base + suffix + "'>Default visitor policy</a> &middot; <a href='" + base + 'requests/' + suffix +
            "'>Disable IP exclusion; filter matched requests only</a> &middot; <a href='" + base + 'confirmed/' + suffix +
            "'>Include suspected automation</a> &middot; <a href='" + base + 'original/' + suffix + "'>Original rules</a> &middot; <a href='" +
            base + 'behavior-exclusions/' + ('#' + html.escape(period) if period else '') + "'>Review exclusions and overrides</a></p>")
    if period in info['view_totals']['confirmed']:
        before = info['view_totals']['confirmed'][period]
        requests = info['view_totals']['requests'][period]
        after = info['view_totals']['behavior'][period]
        body += ('<p>Unique visitors: confirmed-only ' + format(before['unique'], ',') + '; request-only ' +
                 format(requests['unique'], ',') + '; default ' + format(after['unique'], ',') +
                 '. Visits: ' + format(before['visits'], ',') + ' / ' + format(requests['visits'], ',') + ' / ' + format(after['visits'], ',') +
                 '. All counters are recalculated from each selected input.</p>')
    return body + '<p>Behavioral suspicion is heuristic. The default IP policy applies throughout this site UTC month, including earlier requests; it does not carry to another month without new evidence. Shared or dynamic IPs can include real users. Explicit request-ID inclusions may restore an IP to visitor counts. These views affect statistics only; remaining visitors are not verified people.</p></section>'


NATIVE_FINAL = '# vstats: publisher-owned settings; must follow every Include'


def final_native_settings(text, values):
    lines = []
    for name, value in values.items():
        value = str(value)
        if not re.fullmatch(r'[A-Za-z]+', name) or re.search(r'["#\r\n]|__', value):
            raise RuntimeError('Unsafe publisher-owned native setting')
        lines.append(name + '="' + value + '"')
    return text.rstrip('\n') + '\n' + NATIVE_FINAL + '\n' + '\n'.join(lines) + '\n'


def behavior_config(text, logfile, data, evidence):
    return final_native_settings(text, {'LogFile': logfile, 'DirData': data,
        'VerifiedCrawlerEvidenceFile': evidence, 'PurgeLogFile': 0, 'ArchiveLogRecords': 0})


def empty_totals():
    return {key: 0 for key in ['pages', 'nonviewed_pages', 'hits', 'bytes', 'nonviewed_hits', 'nonviewed_bytes', 'unique', 'visits']}


def verify_ip_visitor_policy(summary, data_root, site, account):
    policy = summary['ip_exclusion']
    blocked = set(policy['private_source_months']) - set(policy['restored_source_months'])
    checked = 0
    if policy['enabled']:
        for month in sorted({key.split('|', 1)[0] for key in blocked}):
            name = 'awstats' + month[5:] + month[:4] + '.' + site + '.txt'
            path = os.path.join(data_root, site, name)
            if not os.path.exists(path):
                if os.path.exists(path + '.gz'):
                    path += '.gz'
                else:
                    continue
            active = False
            for line in cache_lines(path, account.pw_uid):
                if line.startswith('BEGIN_VISITOR '):
                    active = True
                    continue
                if line.strip() == 'END_VISITOR':
                    break
                if not active or not line.strip() or line.startswith('#'):
                    continue
                client = line.split()[0]
                checked += 1
                for family, prefix in [(socket.AF_INET, '4:'), (socket.AF_INET6, '6:')]:
                    try:
                        key = month + '|' + prefix + socket.inet_pton(family, client).hex()
                    except OSError:
                        continue
                    if key in blocked:
                        raise RuntimeError('Excluded automated IP remains in native visitors: ' + month)
                    break
    return {'enabled': policy['enabled'], 'flagged_source_months': policy['flagged_source_months'],
            'source_month_counts': policy['source_month_counts'], 'restored_source_months': len(policy['restored_source_months']),
            'additional_excluded_requests': policy['additional_excluded_requests'], 'checked_native_visitor_rows': checked,
            'blocked_ip_rows_remaining': 0}


def write_replay_config(directory, site, template, logfile, data, evidence, account):
    path = os.path.join(directory, 'awstats.' + site + '.conf')
    with open(path, 'w', encoding='utf-8') as handle:
        handle.write(behavior_config(template, logfile, data, evidence))
    os.chown(path, 0, account.pw_gid)
    os.chmod(path, 0o640)


def native_complement_totals(account, site, work, result_dir, template, days, evidence, mode, verify_repeat):
    # Scratch histories never become another public view or persistent cache.
    data = os.path.join(work, 'audit-data-' + mode)
    config = os.path.join(work, 'audit-config-' + mode)
    private_directory(data, account.pw_gid)
    private_directory(os.path.join(data, site), account.pw_gid, owner=account.pw_uid, mode=0o700)
    private_directory(config, account.pw_gid)
    folder = 'request-excluded' if mode == 'requests' else 'excluded'
    for day in days:
        logfile = os.path.join(result_dir, folder, day + '.log')
        write_replay_config(config, site, template, logfile, os.path.join(data, site), evidence[day]['path'], account)
        invoke(account, site, ['-update'], site + '-' + mode + '-omitted-replay.log', config_dir=config)
    totals = cache_totals(site, account, data)
    if verify_repeat:
        before = cache_fingerprints(site, account, data)
        invoke(account, site, ['-update'], site + '-' + mode + '-omitted-repeat.log', config_dir=config)
        if cache_totals(site, account, data) != totals or cache_fingerprints(site, account, data) != before:
            raise RuntimeError('Omitted native history changed on identical repeat: ' + mode)
    for month in {day[:7] for day in days}:
        totals.setdefault(month, empty_totals())
    return totals


def replay_behavior_site(account, site, snapshot, site_work, layer_info, token, verify_repeat):
    # Load from the selected application release so the tested helper and its
    # cache identity move together; this also supports isolated replay trials.
    import importlib.util
    cache_path = os.path.join(APP, 'tools', 'native_history_cache.py')
    spec = importlib.util.spec_from_file_location('vstats_native_history_cache', cache_path)
    history_cache = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(history_cache)
    corpus, receipt = update_behavior_corpus(site, snapshot, account, token)
    work = os.path.join(site_work, 'behavior')
    private_directory(work, account.pw_gid, owner=account.pw_uid, mode=0o700)
    result_dir = os.path.join(work, 'result')
    config = os.path.join(CONFIG, 'traffic-classification', 'awstats.' + site + '.json')
    if os.path.islink(config):
        raise RuntimeError('Classifier configuration must be a real file')
    with open(config, 'rb') as handle:
        config_raw = handle.read()
    command = [sys.executable, os.path.join(APP, 'tools', 'traffic-filter-report.py'), '--config', config,
               '--input-directory', corpus, '--output-directory', result_dir, '--perl', PERL, '--capacity-fallback',
               '--site-url-prefix', '/vstats/' + site + '/']
    if not layer_info.get('exclude_automated_ips', True):
        command.append('--include-automated-ips')
    environment = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'LANG': 'C', 'TZ': 'UTC', 'PYTHONDONTWRITEBYTECODE': '1',
                   'PERL5LIB': os.pathsep.join(PERL_LIBRARIES)}
    proc = subprocess.Popen(command, cwd=BASE, env=environment, preexec_fn=as_statistics_user(account), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = proc.communicate(timeout=600)
    except subprocess.TimeoutExpired:
        proc.kill(); proc.communicate()
        raise RuntimeError('Behavioral export exceeded its heuristic execution guard')
    diagnostic = os.path.join(LOG, site + '-behavior-export.log')
    with open(diagnostic, 'wb') as handle:
        handle.write(stdout + stderr)
    os.chmod(diagnostic, 0o600)
    if proc.returncode or stdout or stderr:
        raise RuntimeError('Behavioral export failed; see private diagnostics')
    with open(os.path.join(result_dir, 'summary.json'), encoding='utf-8') as handle:
        summary = json.load(handle)
    if summary['counts']['lines_total'] != sum(day['rows'] for day in receipt['days'].values()):
        raise RuntimeError('Complete corpus was not exported exactly once')
    days = sorted(receipt['days'])
    evidence = archived_evidence_for_days(days, os.path.join(work, 'evidence'), account)
    with open(os.path.join(CONFIG, 'awstats.' + site + '.conf'), encoding='utf-8') as handle:
        template = handle.read()
    selected = PROFILE_MAP.get(site)
    if selected:
        level = selected['native_level'] if selected['filters']['native_crawlers'] else 0
        # Explicit profile choice follows optional defaults and included settings.
        template += '\nLevelForRobotsDetection="' + str(level) + '"\n'
        if not selected['filters']['verified_crawlers']:
            evidence = {day: dict(item, path='', sha256=hashlib.sha256(b'').hexdigest()) for day, item in evidence.items()}
    native_hash = hashlib.sha256(Path(os.path.join(APP, 'wwwroot/cgi-bin/awstats.pl')).read_bytes() +
                                 Path(os.path.join(APP, 'wwwroot/cgi-bin/lib/robots.pm')).read_bytes() +
                                 Path(os.path.join(APP, 'tools/lib/VStats/TrafficClassifier.pm')).read_bytes() +
                                 Path(os.path.join(APP, 'tools/traffic-filter-report.py')).read_bytes() +
                                 Path(os.path.join(APP, 'tools/traffic-classify.pl')).read_bytes() +
                                 Path(cache_path).read_bytes() +
                                 json.dumps({'ip_month_policy': layer_info.get('exclude_automated_ips', True), 'views': 4}, sort_keys=True).encode()).hexdigest()
    history_roots = {'original': os.path.join(BASE, 'data'), 'confirmed': os.path.join(BASE, 'data-verified'), 'requests': os.path.join(BASE, 'data-requests'), 'behavior': os.path.join(BASE, 'data-behavior')}
    configs, data_roots = {}, {}
    for mode in history_roots:
        data_roots[mode] = os.path.join(work, 'data-' + mode)
        private_directory(data_roots[mode], account.pw_gid)
        private_directory(os.path.join(data_roots[mode], site), account.pw_gid, owner=account.pw_uid, mode=0o700)
        configs[mode] = os.path.join(work, 'config-' + mode)
        private_directory(configs[mode], account.pw_gid)
    day_context = {entry['day']: entry['analysis_context_sha256'] for entry in summary['daily_reports']}
    if set(day_context) != set(days):
        raise RuntimeError('Missing daily boundary cache identities')
    months = sorted({day[:7] for day in days})
    native_months = {}
    # Included native configuration is read at replay time, outside this
    # top-level signature. Rebuild every retained month rather than reuse it.
    cache_reusable = not re.search(r'^(?:Include|#include) "', template, re.M)
    stable_template = re.sub(r'^(LogFile|DirData)\s*=.*$', lambda m: m.group(1) + '="<generation-private>"', template, flags=re.M)
    prefix_signature = hashlib.sha256(config_raw + stable_template.encode('utf-8') + native_hash.encode('ascii')).hexdigest()
    for month in months:
        month_days = [day for day in days if day.startswith(month + '-')]
        signature = hashlib.sha256((prefix_signature + json.dumps([(day, receipt['days'][day]['sha256'], evidence[day]['sha256'], day_context[day]) for day in month_days], sort_keys=True)).encode('utf-8')).hexdigest()
        prefix_signature = signature
        filename = 'awstats' + month[5:] + month[:4] + '.' + site + '.txt'
        old = receipt.get('native_months', {}).get(month, {})
        reuse = cache_reusable and old.get('signature') == signature
        contents = {}
        if reuse:
            for mode, root in history_roots.items():
                path = os.path.join(root, site, filename)
                snapshot = history_cache.read_history(path, account.pw_uid)
                if not history_cache.matches_history(snapshot, old['history_sha256'].get(mode)):
                    reuse = False
                contents[mode] = snapshot
        if reuse:
            for mode, snapshot in contents.items():
                history_cache.restore_history(snapshot, os.path.join(data_roots[mode], site, filename),
                                              account.pw_uid, account.pw_gid)
        else:
            for day in month_days:
                for mode in history_roots:
                    logfile = os.path.join(result_dir, 'filtered' if mode == 'behavior' else 'request-filtered', day + '.log') if mode in ('behavior', 'requests') else os.path.join(corpus, day + '.log')
                    proof = '' if mode == 'original' else evidence[day]['path']
                    write_replay_config(configs[mode], site, template, logfile,
                                        os.path.join(data_roots[mode], site), proof, account)
                    invoke(account, site, ['-update'], site + '-' + mode + '-replay.log', config_dir=configs[mode])
        native_months[month] = {'signature': signature, 'reused': reuse, 'history_sha256': {}}
        for mode in history_roots:
            path = os.path.join(data_roots[mode], site, filename)
            snapshot = history_cache.read_history(path, account.pw_uid)
            native_months[month]['history_sha256'][mode] = snapshot['sha256'] if snapshot else None
            native_months[month].setdefault('history_suffix', {})[mode] = snapshot['suffix'] if snapshot else None
    # Always provide a valid last-day configuration, including for cached months.
    last_day = days[-1]
    totals = {}
    for mode in history_roots:
        logfile = os.path.join(result_dir, 'filtered' if mode == 'behavior' else 'request-filtered', last_day + '.log') if mode in ('behavior', 'requests') else os.path.join(corpus, last_day + '.log')
        write_replay_config(configs[mode], site, template, logfile, os.path.join(data_roots[mode], site),
                            '' if mode == 'original' else evidence[last_day]['path'], account)
        totals[mode] = cache_totals(site, account, data_roots[mode])
        if verify_repeat:
            fingerprints = cache_fingerprints(site, account, data_roots[mode])
            invoke(account, site, ['-update'], site + '-' + mode + '-replay-repeat.log', config_dir=configs[mode])
            if cache_totals(site, account, data_roots[mode]) != totals[mode] or cache_fingerprints(site, account, data_roots[mode]) != fingerprints:
                raise RuntimeError('Replayed native history changed on identical repeat: ' + mode)
        for month in months:
            totals[mode].setdefault(month, empty_totals())
    check_layer_conservation(totals['original'], totals['confirmed'])
    complements = {mode: native_complement_totals(account, site, work, result_dir, template, days,
                                                 evidence, mode, verify_repeat)
                   for mode in ['requests', 'behavior']}
    for month in months:
        full = totals['confirmed'][month]
        for mode, ledger_name in [('requests', 'request_excluded_by_month'), ('behavior', 'excluded_by_month')]:
            filtered = totals[mode][month]
            ledger = summary[ledger_name].get(month, {'records': 0, 'response_body_bytes': 0})
            if filtered['hits'] > full['hits'] or filtered['pages'] > full['pages']:
                raise RuntimeError('Filtering unexpectedly increased viewed requests: ' + mode)
            omitted = complements[mode][month]
            counted = omitted['hits'] + omitted['nonviewed_hits']
            body = omitted['bytes'] + omitted['nonviewed_bytes']
            if counted > ledger['records'] or body > ledger['response_body_bytes']:
                raise RuntimeError('Native omitted totals exceed the raw exclusion ledger: ' + mode)
            if full['hits'] + full['nonviewed_hits'] != filtered['hits'] + filtered['nonviewed_hits'] + counted:
                raise RuntimeError('Native omitted requests do not conserve accounting: ' + mode)
            if full['bytes'] + full['nonviewed_bytes'] != filtered['bytes'] + filtered['nonviewed_bytes'] + body:
                raise RuntimeError('Native omitted response bodies do not conserve accounting: ' + mode)
            ledger.update(native_counted_records=counted, native_viewed_records=omitted['hits'],
                          native_nonviewed_records=omitted['nonviewed_hits'],
                          native_dropped_records=ledger['records'] - counted,
                          native_response_body_bytes=body,
                          native_dropped_response_body_bytes=ledger['response_body_bytes'] - body)
        if totals['behavior'][month]['unique'] > totals['requests'][month]['unique']:
            raise RuntimeError('Whole-IP filtering increased unique visitors')
    ip_audit = verify_ip_visitor_policy(summary, data_roots['behavior'], site, account)
    # Repeats may update operational timestamps. Bind cache reuse to final bytes.
    for month in months:
        filename = 'awstats' + month[5:] + month[:4] + '.' + site + '.txt'
        for mode in history_roots:
            path = os.path.join(data_roots[mode], site, filename)
            snapshot = history_cache.read_history(path, account.pw_uid)
            native_months[month]['history_sha256'][mode] = snapshot['sha256'] if snapshot else None
            native_months[month].setdefault('history_suffix', {})[mode] = snapshot['suffix'] if snapshot else None
    # The same summary is reread when building the public Filters payload.
    atomic_private_json(os.path.join(result_dir, 'summary.json'), summary, account.pw_gid)
    layer_info.update({'behavior_filter': True, 'view_totals': totals, 'excluded_by_month': summary['excluded_by_month'],
                       'flagged_requests': summary['behavior'].get('flagged_requests', 0), 'inclusion_overrides': summary['behavior'].get('inclusion_overrides', 0),
                       'request_excluded_by_month': summary['request_excluded_by_month'],
                       'ip_exclusion_enabled': summary['ip_exclusion']['enabled'], 'ip_visitor_audit': ip_audit})
    return {'corpus': corpus, 'receipt': receipt, 'native_months': native_months, 'data_roots': data_roots,
            'configs': configs, 'totals': totals, 'result_dir': result_dir, 'summary': summary, 'layer_info': layer_info}


def copy_behavior_html(result, site, site_web, apache_gid, account):
    effects = '<h2>Effect on native statistics</h2><table><tr><th>Month</th><th>View</th><th>Unique visitors</th><th>Visits</th><th>Pages</th><th>Hits</th></tr>'
    for month in sorted(result['totals']['confirmed'], reverse=True):
        for mode, title in [('confirmed', 'Confirmed only'), ('requests', 'Request-only behavior filtering'), ('behavior', 'Default visitor policy')]:
            values = result['totals'][mode][month]
            effects += '<tr><td>' + month + '</td><td>' + title + '</td>' + ''.join('<td>' + format(values[key], ',') + '</td>' for key in ['unique', 'visits', 'pages', 'hits']) + '</tr>'
    effects += '</table><p>All counters are recomputed natively. IP-policy exceptions and a request-only view remain available.</p>'
    for folder, slug, expected in [('classification', 'traffic-classification', result['summary']['classification_files']), ('review', 'behavior-exclusions', result['summary']['review_files'])]:
        destination = os.path.join(site_web, slug)
        private_directory(destination, apache_gid)
        for name, sha in sorted(expected.items()):
            if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._-]*\.html', name):
                raise RuntimeError('Invalid generated review filename')
            path = os.path.join(result['result_dir'], folder, name)
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(descriptor, 'rb') as handle:
                st = os.fstat(handle.fileno())
                if not stat.S_ISREG(st.st_mode) or st.st_uid != account.pw_uid:
                    raise RuntimeError('Unexpected generated report ownership/type')
                raw = handle.read()
            if hashlib.sha256(raw).hexdigest() != sha:
                raise RuntimeError('Generated review identity mismatch')
            text = raw.decode('utf-8').replace('<!-- NATIVE_EFFECT -->', effects)
            write_text(os.path.join(destination, name), text, apache_gid)


def persist_behavior_views(result, site, account, token):
    roots = {'original': os.path.join(BASE, 'data'), 'confirmed': os.path.join(BASE, 'data-verified'), 'requests': os.path.join(BASE, 'data-requests'), 'behavior': os.path.join(BASE, 'data-behavior')}
    for mode, root in roots.items():
        private_directory(root, account.pw_gid)
        target = os.path.join(root, site)
        if os.path.exists(target):
            os.rename(target, os.path.join(os.path.dirname(result['data_roots'][mode]), 'previous-' + mode))
        os.rename(os.path.join(result['data_roots'][mode], site), target)
    receipt = dict(result['receipt'])
    receipt['native_months'] = result['native_months']
    atomic_private_json(os.path.join(result['corpus'], 'receipt.json'), receipt, account.pw_gid)
    parent = os.path.dirname(result['corpus'])
    keep = {os.path.basename(result['corpus']), os.path.basename(result['receipt']['previous'])}
    for name in os.listdir(parent):
        if re.fullmatch(r'\d{8}T\d{6}Z-[0-9a-f]{8}', name) and name not in keep:
            path = os.path.join(parent, name)
            if os.path.isdir(path) and not os.path.islink(path) and os.stat(path).st_uid == 0:
                shutil.rmtree(path)


def legacy_main(account, apache_gid):
    parser = argparse.ArgumentParser()
    parser.add_argument('--verify-repeat', action='store_true')
    options = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('Run the log-reader/publisher as root; the parser is demoted internally')
    os.umask(0o027)
    with open(os.path.join(CONFIG, 'sites.json'), encoding='utf-8') as handle:
        sites = json.load(handle)
    with open(os.path.join(BASE, 'update.lock'), 'w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('A vstats update is already running', flush=True)
            return
        token = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]
        work = os.path.join(BASE, 'work', token)
        private_directory(work, account.pw_gid)
        generation = os.path.join(WEB, 'generations', token)
        private_directory(generation, apache_gid)
        state = {'generation': token, 'started_utc': datetime.datetime.utcnow().isoformat() + 'Z',
                 'timezone': 'UTC', 'sites': {}, 'scope': 'Derived statistics; Apache input logs are read only'}
        try:
            copy_public_assets(generation, apache_gid)
            pending_behavior = []
            for site, settings in sorted(sites.items()):
                if not SITE_NAME.fullmatch(site):
                    raise RuntimeError('Unsafe configured site identifier')
                site_work = os.path.join(work, site)
                private_directory(site_work, account.pw_gid)
                snapshot, evidence = build_snapshot(SOURCE_LOG, settings['base_names'], site_work)
                if evidence['rejected']:
                    raise RuntimeError('Unexplained Apache record normalization failures: ' + site)
                input_directory = os.path.join(BASE, 'input', site)
                private_directory(input_directory, account.pw_gid)
                os.chown(snapshot, 0, account.pw_gid)
                os.chmod(snapshot, 0o640)
                os.replace(snapshot, os.path.join(input_directory, 'access.log'))

                behavior_enabled = settings.get('behavior_filter', False)
                if not isinstance(behavior_enabled, bool):
                    raise RuntimeError('behavior_filter must be a boolean')
                if behavior_enabled:
                    if settings.get('verified_crawler_filter') is not True:
                        raise RuntimeError('Behavior view requires the existing confirmed-crawler comparison')
                    info = refresh_verified_evidence(account)
                    ip_enabled = settings.get('exclude_automated_ips', True)
                    if type(ip_enabled) is not bool:
                        raise RuntimeError('exclude_automated_ips must be a boolean')
                    info['exclude_automated_ips'] = ip_enabled
                    if site in PREVIEW_BASELINE:
                        proposed = PROFILE_MAP[site]
                        applied = PREVIEW_BASELINE[site]['profile']
                        cfg_path = os.path.join(CONFIG, 'traffic-classification', 'awstats.' + site + '.json')
                        with open(cfg_path, 'rb') as h:
                            proposed_config = h.read()
                        with open(cfg_path, 'wb') as h:
                            h.write(canonical(applied['classifier']))
                        PROFILE_MAP[site] = applied
                        baseline_work = os.path.join(site_work, 'baseline')
                        private_directory(baseline_work, account.pw_gid)
                        baseline_info = dict(info, exclude_automated_ips=applied['exclude_automated_ips'])
                        baseline_token = token[:-8] + uuid.uuid4().hex[:8]
                        baseline = replay_behavior_site(account, site, os.path.join(input_directory, 'access.log'), baseline_work, baseline_info, baseline_token, options.verify_repeat)
                        PREVIEW_BASELINE[site]['totals'] = baseline['totals']['behavior']
                        with open(cfg_path, 'wb') as h:
                            h.write(proposed_config)
                        PROFILE_MAP[site] = proposed
                    result = replay_behavior_site(account, site, os.path.join(input_directory, 'access.log'), site_work, info, token, options.verify_repeat)
                    after = result['totals']['behavior']
                    state['sites'][site] = {'input': evidence, 'totals': after, 'original_totals': result['totals']['original'],
                        'confirmed_totals': result['totals']['confirmed'], 'request_totals': result['totals']['requests'], 'verified_layer': info,
                        'behavior_layer': {'flagged_requests': result['summary']['behavior'].get('flagged_requests', 0),
                            'inclusion_overrides': result['summary']['behavior'].get('inclusion_overrides', 0),
                            'excluded_by_month': result['summary']['excluded_by_month'],
                            'request_excluded_by_month': result['summary']['request_excluded_by_month'],
                            'ip_exclusion': info['ip_visitor_audit'], 'corpus': result['corpus'],
                            'counts': result['summary']['counts'], 'period': result['summary']['period'],
                            'native_months_reused': [m for m,v in result['native_months'].items() if v['reused']]},
                        'repeat_checked': options.verify_repeat, 'history_sections_preserved': options.verify_repeat,
                        'scope': 'Complete retained corpus; original, confirmed-only, request-only and configured IP/month-policy native replays'}
                    site_web = os.path.join(generation, site)
                    private_directory(site_web, apache_gid)
                    extra_links = copy_supplemental_reports(site, site_web, apache_gid, skip=('traffic-classification',))
                    extra_links += " &middot; <a href='/vstats/" + html.escape(site, quote=True) + "/behavior-exclusions/'>Review excluded requests</a>"
                    copy_behavior_html(result, site, site_web, apache_gid, account)
                    render_site_view(account, site, site_web, after, apache_gid, extra_links,
                                     config_dir=result['configs']['behavior'], layer_info=info)
                    render_site_view(account, site, os.path.join(site_web, 'requests'), result['totals']['requests'], apache_gid, extra_links,
                                     config_dir=result['configs']['requests'], layer_info=info, request_only=True)
                    render_site_view(account, site, os.path.join(site_web, 'confirmed'), result['totals']['confirmed'], apache_gid, extra_links,
                                     config_dir=result['configs']['confirmed'], layer_info=info, confirmed=True)
                    render_site_view(account, site, os.path.join(site_web, 'original'), result['totals']['original'], apache_gid, extra_links,
                                     config_dir=result['configs']['original'], layer_info=info, original=True)
                    request_count = sum(v['hits'] + v['nonviewed_hits'] for v in after.values())
                    pending_behavior.append((site, result))
                    print(json.dumps({'site': site, 'requests_analyzed': request_count, 'behavior_flagged': info['flagged_requests'],
                                      'behavior_excluded': sum(x['records'] for x in info['excluded_by_month'].values()),
                                      'repeat_checked': options.verify_repeat}), flush=True)
                    continue

                enabled = settings.get('verified_crawler_filter', False)
                if not isinstance(enabled, bool):
                    raise RuntimeError('verified_crawler_filter must be a boolean')
                layer_info = None
                verified_config = os.path.join(CONFIG, 'verified')
                verified_data = os.path.join(BASE, 'data-verified')
                if enabled:
                    if (not os.path.isdir(os.path.join(verified_data, site)) or
                            not os.path.isfile(os.path.join(verified_config, 'awstats.' + site + '.conf'))):
                        raise RuntimeError('Initialize independent verified-layer configuration and history first')
                    layer_info = refresh_verified_evidence(account)
                before = cache_totals(site, account)
                diagnostic = invoke(account, site, ['-update'], site + '-update.log')
                original_after = cache_totals(site, account)
                if options.verify_repeat:
                    fingerprints = cache_fingerprints(site, account)
                    invoke(account, site, ['-update'], site + '-repeat.log')
                    if cache_totals(site, account) != original_after:
                        raise RuntimeError('Actual-log repeated update changed totals: ' + site)
                    if cache_fingerprints(site, account) != fingerprints:
                        raise RuntimeError('Actual-log repeated update changed history sections: ' + site)
                after = original_after
                if enabled:
                    invoke(account, site, ['-update'], site + '-verified-update.log', config_dir=verified_config)
                    after = cache_totals(site, account, verified_data)
                    if options.verify_repeat:
                        fingerprints = cache_fingerprints(site, account, verified_data)
                        invoke(account, site, ['-update'], site + '-verified-repeat.log', config_dir=verified_config)
                        if cache_totals(site, account, verified_data) != after:
                            raise RuntimeError('Verified-layer repeat changed totals: ' + site)
                        if cache_fingerprints(site, account, verified_data) != fingerprints:
                            raise RuntimeError('Verified-layer repeat changed history sections: ' + site)
                    check_layer_conservation(original_after, after)
                    layer_info['viewed_hit_difference'] = {
                        period: original_after[period]['hits'] - after[period]['hits'] for period in after}
                state['sites'][site] = {'input': evidence, 'totals': after,
                                        'update_stdout': diagnostic, 'repeat_checked': options.verify_repeat,
                                        'history_sections_preserved': options.verify_repeat}
                if enabled:
                    state['sites'][site]['original_totals'] = original_after
                    state['sites'][site]['verified_layer'] = layer_info
                if not after:
                    print(json.dumps({'site': site, 'retained_records': evidence['accepted'], 'months': [], 'state': 'empty'}), flush=True)
                    continue
                site_web = os.path.join(generation, site)
                private_directory(site_web, apache_gid)
                extra_links = copy_supplemental_reports(site, site_web, apache_gid)
                render_site_view(account, site, site_web, after, apache_gid, extra_links,
                                 config_dir=verified_config if enabled else None, layer_info=layer_info)
                if enabled:
                    render_site_view(account, site, os.path.join(site_web, 'original'), original_after,
                                     apache_gid, extra_links, config_dir=CONFIG,
                                     layer_info=layer_info, original=True)
                request_count = sum(value['hits'] + value['nonviewed_hits'] for value in after.values())
                print(json.dumps({'site': site, 'retained_records': evidence['accepted'],
                                  'months': sorted(after), 'requests_analyzed': request_count,
                                  'repeat_checked': options.verify_repeat}), flush=True)
            state['completed_utc'] = datetime.datetime.utcnow().isoformat() + 'Z'
            render_root_index(generation,
                              {site: dict(values, updated_utc=state['completed_utc'])
                               for site, values in state['sites'].items()},
                              sites, state['completed_utc'], apache_gid)
            state['validated_local_links'] = validate_report_links(generation)
            subprocess.check_call(['/sbin/restorecon', '-R', generation])
            for site, result in pending_behavior:
                persist_behavior_views(result, site, account, token)
            current = os.path.join(WEB, 'current')
            state['previous_generation'] = os.path.realpath(current) if os.path.islink(current) else None
            new_link = os.path.join(WEB, '.current-' + token)
            os.symlink(os.path.join('generations', token), new_link)
            os.replace(new_link, current)
            state['status'] = 'SUCCESS'
            temporary = os.path.join(BASE, 'status-new.json')
            with open(temporary, 'w', encoding='utf-8') as handle:
                json.dump(state, handle, indent=2, sort_keys=True)
            os.chmod(temporary, 0o640)
            os.replace(temporary, os.path.join(BASE, 'status.json'))
            retain_generated_files(token, state['previous_generation'])
            print(json.dumps({'status': 'SUCCESS', 'generation': token,
                              'validated_local_links': state['validated_local_links']}), flush=True)
        except Exception as exc:
            state['status'] = 'FAILED'
            state['error'] = str(exc)
            with open(os.path.join(BASE, 'last-failure.json'), 'w', encoding='utf-8') as handle:
                json.dump(state, handle, indent=2, sort_keys=True)
            try:
                retain_failed_files(token)
            except Exception as cleanup_error:
                print('Failed-generation cleanup: ' + str(cleanup_error), file=sys.stderr)
            raise


def clone_private(source, destination, immutable=False):
    """Copy mutable state; never hard-link a history a parser may rewrite."""
    if not os.path.isdir(source):
        os.makedirs(destination, mode=0o750)
        return
    if immutable:
        shutil.copytree(source, destination, symlinks=True, copy_function=os.link)
    else:
        shutil.copytree(source, destination, symlinks=True)
    for directory, dirs, files in os.walk(destination, followlinks=False):
        relative = os.path.relpath(directory, destination)
        original = source if relative == '.' else os.path.join(source, relative)
        info = os.lstat(original)
        os.chown(directory, info.st_uid, info.st_gid)
        for name in dirs + files:
            info = os.lstat(os.path.join(original, name))
            os.lchown(os.path.join(directory, name), info.st_uid, info.st_gid)


def retained_input(base, site):
    directory = os.path.join(base, 'corpus', site, 'current')
    result = {}
    if not os.path.islink(directory):
        return result
    real = os.path.realpath(directory)
    parent = os.path.realpath(os.path.dirname(directory))
    if os.path.dirname(real) != parent:
        raise RuntimeError('Invalid retained corpus link')
    for path in sorted(Path(real).glob('????-??-??.log')):
        if path.is_symlink() or not path.is_file():
            raise RuntimeError('Invalid retained input file')
        h, size, rows = hashlib.sha256(), 0, 0
        with path.open('rb') as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b''):
                h.update(chunk); size += len(chunk); rows += chunk.count(b'\n')
        result[path.stem] = {'sha256': h.hexdigest(), 'bytes': size, 'rows': rows}
    return result


def coverage(old, retained):
    previous = old.get('input_days')
    known = old.get('applied') is not None and previous is not None
    missing = sorted(set(previous or {}) - set(retained))
    changed = sorted(day for day in set(previous or {}) & set(retained)
                     if previous[day]['sha256'] != retained[day]['sha256'])
    value = {'known_previous_input': known, 'retained_days': sorted(retained),
             'missing_previous_days': missing, 'changed_previous_days': changed}
    value['acknowledgement'] = identity(value)
    value['needs_acknowledgement'] = not known or bool(missing or changed)
    return value


def native_evidence_dates(base, max_gap):
    """Readiness dates only. The native parser still checks each marker/IP/time."""
    stamps = []
    for path in (Path(base) / 'crawler-evidence/retrievals').glob('*.json'):
        if not re.fullmatch(r'\d{8}T\d{6}Z\.json', path.name):
            continue
        record = read_json(path)
        stamp = datetime.datetime.strptime(record['attestation']['retrieved_at'], '%Y-%m-%dT%H:%M:%SZ')
        stamps.append(stamp)
    stamps = sorted(set(stamps))
    dates = {t.strftime('%Y-%m-%d') for t in stamps}  # exact-time evidence can suffice
    for first, last in zip(stamps, stamps[1:]):
        if (last - first).total_seconds() > max_gap:
            continue
        day = first.date()
        while day <= last.date():
            dates.add(day.isoformat()); day += datetime.timedelta(days=1)
    return dates


def profile_state(managed, profile, retained, values):
    return {'managed': managed, 'applied': profile,
            'profile_id': identity(profile) if profile else None,
            'input_days': retained if managed else None,
            'totals': values.get('totals', {}),
            'view_totals': {'original': values.get('original_totals', {}), 'confirmed': values.get('confirmed_totals', {}),
                           'requests': values.get('request_totals', {}), 'behavior': values.get('totals', {})},
            'excluded_by_month': values.get('behavior_layer', {}).get('excluded_by_month', {}),
            'request_excluded_by_month': values.get('behavior_layer', {}).get('request_excluded_by_month', {}),
            'matched_requests': {'flagged_requests': values['behavior_layer']['flagged_requests']} if 'behavior_layer' in values else {},
            'coverage': coverage({'applied': profile, 'input_days': retained if managed else None}, retained),
            'effective': {}, 'default_profile': defaults(APP, PERL, profile),
            'note': 'Imported and identity-verified existing profile' if managed else
                    'Native reports remain on their existing updater until Filters is explicitly applied. Historical filter profile unverified.'}


def stage_native_site(real_base, stage_base, site, settings, account):
    roots = ['data'] + (['data-verified'] if settings.get('verified_crawler_filter') else [])
    for name in roots:
        source = Path(real_base) / name / site
        target = Path(stage_base) / name / site
        if os.path.lexists(str(target)):
            # Earlier private bases may carry an unmanaged clone of this site;
            # stage only the guarded copy of the original history.
            shutil.rmtree(str(target))
        if name == 'data-verified' and not os.path.lexists(str(source)):
            # Preserve the existing independent verified-history setup refusal.
            continue
        private_directory(str(target), account.pw_gid)
        if os.path.lexists(str(source)):
            descriptor = os.open(str(source), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                for filename in sorted(os.listdir(descriptor)):
                    # The shared history kernel validates regular type, owner,
                    # no-follow and byte cap; restore creates an independent file.
                    snapshot = read_history('/proc/self/fd/' + str(descriptor) + '/' + filename, account.pw_uid)
                    if snapshot is None:
                        raise RuntimeError('New-site native history changed while staging')
                    restore_history(snapshot, str(target / filename), account.pw_uid, account.pw_gid)
            finally:
                os.close(descriptor)
        private_directory(str(target), account.pw_gid, owner=account.pw_uid, mode=0o700)


def imported_profiles(sites, real_base, config, legacy_app, old_state, account):
    profiles = {}
    for site, site_settings in sites.items():
        managed = site_settings.get('behavior_filter', False)
        profile = None
        if managed:
            cfg_file = Path(config) / 'traffic-classification' / ('awstats.' + site + '.json')
            classifier = read_json(cfg_file)
            text = (Path(config) / ('awstats.' + site + '.conf')).read_text(encoding='utf-8')
            # Replay appends this level as the final native assignment. Import it
            # only from one unambiguous top-level line; otherwise fail closed.
            assigned = re.findall(r'^[ \t]*LevelForRobotsDetection[ \t]*=', text, re.M)
            level = re.findall(r'^LevelForRobotsDetection[ \t]*=[ \t]*([0-3])\b', text, re.M)
            if len(assigned) > 1 or len(level) != len(assigned) or re.search(r'^(?:Include|#include) "', text, re.M):
                raise RuntimeError('Cannot verify the existing managed profile: ' + site)
            level = int(level[0]) if level else 3
            profile = {'schema_version': 1,
                       'filters': dict(native_crawlers=bool(level), verified_crawlers=site_settings.get('verified_crawler_filter', False),
                                       **{key: bool(classifier.get(key, {}).get('enabled', 0)) for key in ['behavior', 'probing', 'rapid_scan', 'distributed_login']}),
                       'exclude_automated_ips': site_settings.get('exclude_automated_ips', True),
                       'native_level': level or 3, 'classifier': classifier,
                       'exceptions': [{'request_id': i, 'reason': 'Imported existing inclusion; original reason not recorded'} for i in classifier.get('behavior_include', [])]}
            profile = validate_profile(profile, APP, PERL)
            # Adopt only an existing output whose producing source/settings and
            # every native history are still bound by the current replay receipt.
            corpus = Path(real_base) / 'corpus' / site / 'current'
            receipt = read_json(corpus / 'receipt.json')
            observed = retained_input(real_base, site)
            if observed != receipt['days']:
                raise RuntimeError('Existing corpus bytes no longer match their replay receipt')
            export_spec = importlib.util.spec_from_file_location('bootstrap_export', str(Path(legacy_app) / 'tools/traffic-filter-report.py'))
            old_export = importlib.util.module_from_spec(export_spec); export_spec.loader.exec_module(old_export)
            window = old_export.validated_configuration(cfg_file.read_bytes(), PERL)['window_seconds']
            paths = {day: corpus / (day + '.log') for day in receipt['days']}
            contexts = {}
            for day in sorted(paths):
                start = datetime.datetime.strptime(day, '%Y-%m-%d').replace(tzinfo=datetime.timezone.utc)
                epoch = int(start.timestamp())
                before = (start - datetime.timedelta(days=1)).strftime('%Y-%m-%d')
                after = (start + datetime.timedelta(days=1)).strftime('%Y-%m-%d')
                halo = {'before': old_export.boundary_context(paths.get(before), epoch-window, epoch, 67108864),
                        'after': old_export.boundary_context(paths.get(after), epoch+86400, epoch+86400+window, 67108864)}
                context = {side: {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)} for side,raw in sorted(halo.items())}
                contexts[day] = hashlib.sha256(json.dumps({'window_seconds': window, 'context': context}, sort_keys=True).encode()).hexdigest()
            cutoff = datetime.datetime.strptime(old_state['completed_utc'].split('.')[0].rstrip('Z'), '%Y-%m-%dT%H:%M:%S')
            proofs = archived_evidence_for_days(sorted(paths), None, account, until=cutoff)
            cache_file = Path(legacy_app) / 'tools/native_history_cache.py'
            src = importlib.util.spec_from_file_location('bootstrap_history', str(cache_file))
            cache = importlib.util.module_from_spec(src); src.loader.exec_module(cache)
            sources = ['wwwroot/cgi-bin/awstats.pl', 'wwwroot/cgi-bin/lib/robots.pm',
                       'tools/lib/VStats/TrafficClassifier.pm', 'tools/traffic-filter-report.py',
                       'tools/traffic-classify.pl', 'tools/native_history_cache.py']
            native = hashlib.sha256(b''.join((Path(legacy_app) / p).read_bytes() for p in sources) +
                                   json.dumps({'ip_month_policy': profile['exclude_automated_ips'], 'views': 4}, sort_keys=True).encode()).hexdigest()
            prefix = hashlib.sha256(cfg_file.read_bytes() + text.encode('utf-8') + native.encode('ascii')).hexdigest()
            roots = {'original': 'data', 'confirmed': 'data-verified', 'requests': 'data-requests', 'behavior': 'data-behavior'}
            for month in sorted(receipt['native_months']):
                values = []
                for day in sorted(d for d in receipt['days'] if d.startswith(month + '-')):
                    values.append((day, receipt['days'][day]['sha256'], proofs[day]['sha256'], contexts[day]))
                prefix = hashlib.sha256((prefix + json.dumps(values, sort_keys=True)).encode()).hexdigest()
                if prefix != receipt['native_months'][month]['signature']:
                    raise RuntimeError('Cannot verify the existing managed profile: ' + site)
                filename = 'awstats' + month[5:] + month[:4] + '.' + site + '.txt'
                for mode, root in roots.items():
                    snap = cache.read_history(str(Path(real_base) / root / site / filename), account.pw_uid)
                    if not cache.matches_history(snap, receipt['native_months'][month]['history_sha256'][mode]):
                        raise RuntimeError('Managed native history identity changed: ' + site)
        retained = retained_input(real_base, site)
        values = old_state.get('sites', {}).get(site, {})
        profiles[site] = profile_state(managed, profile, retained, values)
    return profiles


def remove_filter_chrome(text):
    # These are the exact extra controls added by the older static publisher.
    text = re.sub(r"<nav style='padding:10px 16px;font:14px sans-serif'>.*?</nav>", '', text, flags=re.S)
    text = re.sub(r"<section style='margin:10px 16px;padding:12px;border:1px solid #cbd5e1;font:14px sans-serif'>.*?</section>", '', text, flags=re.S)
    text = re.sub(r'<div class="dropdown-item vstats-filters-menu">.*?</div></div>', '', text, flags=re.S)
    return text


def basic_navigation(site):
    return ("<nav style='padding:10px 16px;font:14px sans-serif'><a href='/vstats/'>All sites</a> &middot; "
            "<a href='/vstats/" + html.escape(site, quote=True) + "/'>Months</a></nav>")


def render_filters(generation, site, data, manifest, apache_gid):
    site_web = Path(generation) / site
    reports = sorted(site_web.glob('????-??/awstats.' + site + '.html'))
    if not reports:
        return
    directory = site_web / 'filters'
    private_directory(str(directory), apache_gid)
    if (directory / 'index.html').exists():
        (directory / 'index.html').unlink()
    for old, new in [('behavior-exclusions', 'review'), ('traffic-classification', 'classification')]:
        source = site_web / old
        if source.is_dir():
            if (directory / new).is_dir() and '../filters/' + new + '/' in (source / 'index.html').read_text(encoding='utf-8'):
                continue
            if (directory / new).exists():
                shutil.rmtree(str(directory / new))
            shutil.move(str(source), str(directory / new))
            for path in (directory / new).glob('*.html'):
                text = path.read_text(encoding='utf-8').replace('/' + site + '/' + old + '/', '/' + site + '/filters/' + new + '/')
                path.write_text(text, encoding='utf-8')
            # Preserve old bookmarks without putting comparisons on report pages.
            private_directory(str(source), apache_gid)
            for path in (directory / new).glob('*.html'):
                href = '../filters/' + new + '/' + path.name
                write_text(str(source / path.name), page('Filters', '<meta http-equiv="refresh" content="0;url=' +
                           html.escape(href, quote=True) + '"><a href="' + html.escape(href, quote=True) + '">Open Filters</a>'), apache_gid)
    payload = dict(data, site=site, generation=manifest['generation'], generated_utc=manifest['generated_utc'])
    # No private filesystem paths, raw log content or credential data are carried.
    template = (Path(APP) / 'wwwroot/filters.html').read_text(encoding='utf-8')
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
    body = template.replace('<!-- FILTERS_STATE -->', '<script type="application/json" id="filters-state">' + encoded + '</script>')
    shell = native_shell(reports[-1].read_text(encoding='utf-8'), 'Filters — ' + site, body)
    write_text(str(directory / 'index.html'), shell, apache_gid)


def decorate_generation(generation, manifest, apache_gid):
    for site, data in manifest['profiles'].items():
        site_web = Path(generation) / site
        if not site_web.is_dir():
            continue
        for path in site_web.glob('**/awstats.*.html'):
            if 'filters' in path.relative_to(site_web).parts:
                continue
            text = remove_filter_chrome(path.read_text(encoding='utf-8'))
            text = re.sub(r'(<body\b[^>]*>)', lambda m: m.group(1) + basic_navigation(site), text, count=1, flags=re.I)
            relative = path.relative_to(Path(generation)).as_posix()
            text = add_filters_menu(text, site, '/vstats/' + relative)
            path.write_text(text, encoding='utf-8')
        # Restore the plain site/month landing, without old filter-view banners.
        index = site_web / 'index.html'
        if index.exists():
            text = remove_filter_chrome(index.read_text(encoding='utf-8'))
            text = re.sub(r'<p>[^<]*(?:<a[^>]*>[^<]*</a>[^<]*)*</p>',
                          lambda m: '' if any(w in m.group() for w in ['Traffic classification', 'Review excluded requests', 'Behavior exclusions']) else m.group(), text)
            if '/filters/' not in text:
                text = text.replace('</h1>', '</h1><p><a href="/vstats/' + html.escape(site, quote=True) + '/filters/">Filters</a></p>', 1)
            index.write_text(text, encoding='utf-8')
        render_filters(generation, site, data, manifest, apache_gid)
    root = Path(generation) / 'index.html'
    if root.exists():
        text = root.read_text(encoding='utf-8')
        text = re.sub(r"\s*&middot;\s*<a href=['\"][^'\"]*/(?:behavior-exclusions|traffic-classification)/['\"]>.*?</a>", '', text)
        root.write_text(text, encoding='utf-8')


def main():
    global BASE, WEB, CONFIG, NATIVE_INCLUDE_BASE, APP, LOG, LAUNCHER, PERL, PERL_LIBRARIES, SOURCE_LOG, PROFILE_MAP, PREVIEW_BASELINE, build_snapshot
    parser = argparse.ArgumentParser(description='Transactional static report publisher and Filters rebuild worker')
    parser.add_argument('--verify-repeat', action='store_true')
    parser.add_argument('--control-settings', default='/etc/vstats/filters.json')
    parser.add_argument('--filter-job')
    parser.add_argument('--bootstrap-ui', action='store_true')
    parser.add_argument('--trial', action='store_true')
    parser.add_argument('--lock-fd', type=int, help='Root deployment wrapper: inherit the already held publisher lock')
    options = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('The publisher requires root; log parsing runs as the statistics user')
    settings = read_json(options.control_settings, root_owned=True)
    real_base, real_web, real_config = settings['base'], settings['web'], settings['config']
    NATIVE_INCLUDE_BASE = real_config
    state_root = Path(settings['state'])
    APP, PERL, LOG, SOURCE_LOG = settings['app'], settings['perl'], settings['log'], settings['source_log']
    PERL_LIBRARIES = settings['perl_libraries']
    LAUNCHER = [PERL] + ['-I' + p for p in PERL_LIBRARIES] + [str(Path(APP) / 'wwwroot/cgi-bin/awstats.pl')]
    account = pwd.getpwnam(settings.get('statistics_user', 'vstats'))
    apache_gid = grp.getgrnam(settings.get('web_group', 'apache')).gr_gid
    control_gid = pwd.getpwnam(settings.get('api_user', 'vstats-control')).pw_gid
    os.umask(0o027)
    request = read_json(options.filter_job) if options.filter_job else None
    current = Path(real_web) / 'current'
    lock_path = str(Path(real_base) / 'update.lock')
    if options.lock_fd is not None:
        if os.fstat(options.lock_fd).st_ino != os.stat(lock_path).st_ino or os.fstat(options.lock_fd).st_dev != os.stat(lock_path).st_dev:
            raise RuntimeError('Inherited descriptor is not the publisher lock')
        lock_handle = os.fdopen(os.dup(options.lock_fd), 'a')
    else:
        lock_handle = open(lock_path, 'a')
    with lock_handle as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        previous = os.path.basename(os.path.realpath(str(current)))
        previous_manifest_path = state_root / 'runs' / previous / 'manifest.json'
        old_status = read_json(Path(real_base) / 'status.json')
        sites = read_json(Path(real_config) / 'sites.json')
        publish_browser_policy(settings, gid=control_gid)
        if previous_manifest_path.exists():
            previous_manifest = read_json(previous_manifest_path)
            profiles = json.loads(json.dumps(previous_manifest['profiles']))
            private_base = previous_manifest['private_base']
        else:
            if not options.bootstrap_ui:
                raise RuntimeError('Initialize the current UI generation before enabling the control worker')
            if old_status.get('generation') != previous:
                raise RuntimeError('Current report generation has no verified profile manifest; restore its matching state before bootstrapping')
            profiles = imported_profiles(sites, real_base, real_config, settings['legacy_app'], old_status, account)
            private_base = real_base
        new_sites = sorted(set(sites) - set(profiles))
        for site in new_sites:
            if not SITE_NAME.fullmatch(site):
                raise RuntimeError('Unsafe configured site identifier')
        token = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]
        run = state_root / 'runs' / token
        # Both the control service and the separate parser must traverse this
        # parent; raw data below remains readable only by the statistics group.
        private_directory(str(run), control_gid, mode=0o751)
        if request:
            Control(settings).authorize(queued_user(request), request['site'], fresh=True)
            if request['base_generation'] != previous or request['site'] not in sites:
                raise RuntimeError('Queued generation is stale or website is unknown')
            site = request['site']
            profile = validate_profile(request['profile'], APP, PERL)
            selected_sites = {site: sites[site]}
            old_profile = profiles[site].get('applied')
            observed = retained_input(private_base, site)
            preflight = run / 'preflight'
            private_directory(str(preflight), account.pw_gid)
            frozen_bases = tuple(sites[site]['base_names'])
            frozen_snapshot, frozen_input = build_snapshot(SOURCE_LOG, frozen_bases, str(preflight))
            if frozen_input['rejected']:
                raise RuntimeError('Input normalization failed; current reports remain applied')
            source_days = set(observed)
            with open(frozen_snapshot, 'rb') as f:
                for line in f:
                    source_days.add(normalized_day(line)[0])
            scope = coverage(profiles[site], observed)
            scope['retained_days'] = sorted(source_days)
            scope.pop('acknowledgement')
            scope['acknowledgement'] = identity({k:v for k,v in scope.items() if k != 'needs_acknowledgement'})
            normal_snapshot = build_snapshot
            def frozen_builder(log_root, bases, work):
                if tuple(bases) == frozen_bases:
                    return frozen_snapshot, frozen_input
                return normal_snapshot(log_root, bases, work)
            build_snapshot = frozen_builder
            if request['action'] == 'apply' and scope['needs_acknowledgement'] and request.get('coverage_ack') != scope['acknowledgement']:
                atomic_json(state_root / 'jobs' / (request['id'] + '-result.json'), {'coverage_required': scope}, gid=control_gid)
                raise RuntimeError('Confirm the listed retained-input coverage before applying this rebuild')
            if request['action'] == 'preview' and old_profile is not None:
                PREVIEW_BASELINE[site] = {'profile': old_profile}
            profiles[site] = dict(profiles[site], managed=True, applied=profile, profile_id=identity(profile))
        else:
            selected_sites = dict(sites)
            for site, info in profiles.items():
                if info['managed'] and info['applied'] is not None:
                    old_coverage = coverage(info, retained_input(private_base, site))
                    if old_coverage['needs_acknowledgement']:
                        raise RuntimeError('Previously published source coverage is unavailable; explicit retained-input rebuild required: ' + site)
        stage_base, stage_config, stage_web = run / 'base', run / 'config', run / 'web'
        private_directory(str(stage_base), account.pw_gid)
        private_directory(str(stage_config), account.pw_gid)
        private_directory(str(stage_web), apache_gid)
        manifest = {'schema_version': 1, 'generation': token, 'generated_utc': datetime.datetime.utcnow().isoformat() + 'Z',
                    'profiles': profiles, 'private_base': str(stage_base), 'previous_generation': previous,
                    'action_id': request['id'] if request else None, 'actor': request['actor'] if request else 'scheduled publisher'}
        if options.bootstrap_ui:
            generated = stage_web / token
            shutil.copytree(str(current.resolve()), str(generated), symlinks=False)
            manifest['private_base'] = private_base
            for asset in ['filters.css', 'filters.js']:
                kind = 'css' if asset.endswith('.css') else 'js'
                shutil.copyfile(str(Path(APP) / 'wwwroot' / kind / asset), str(generated / 'assets' / kind / asset))
        else:
            for name in ['data', 'data-verified', 'data-requests', 'data-behavior', 'corpus', 'crawler-evidence', 'supplements']:
                clone_private(os.path.join(private_base, name), str(stage_base / name), immutable=(name == 'corpus'))
            for site in new_sites:
                if site in selected_sites:
                    stage_native_site(real_base, stage_base, site, sites[site], account)
                    profiles[site] = profile_state(False, None, {}, {})
            for name in ['input', 'work']:
                private_directory(str(stage_base / name), account.pw_gid)
            shutil.copytree(real_config, str(stage_config / 'source'), symlinks=False, ignore=shutil.ignore_patterns('filters-admin.json', 'filters.json'))
            CONFIG = str(stage_config / 'source')
            os.chown(CONFIG, 0, account.pw_gid); os.chmod(CONFIG, 0o750)
            for directory, dirs, files in os.walk(CONFIG):
                os.chown(directory, 0, account.pw_gid); os.chmod(directory, 0o750)
                for name in files:
                    os.chown(os.path.join(directory, name), 0, account.pw_gid); os.chmod(os.path.join(directory, name), 0o640)
                    if name.endswith('.conf'):
                        cfg = Path(directory) / name
                        cfg.write_text(cfg.read_text(encoding='utf-8').replace(real_base + '/', str(stage_base) + '/'), encoding='utf-8')
            for site in selected_sites:
                for sub, data in [('', 'data'), ('verified', 'data-verified')]:
                    path = Path(CONFIG) / sub / ('awstats.' + site + '.conf')
                    if path.is_file():
                        values = {'LogFile': str(stage_base / 'input' / site / 'access.log'),
                                  'DirData': str(stage_base / data / site), 'PurgeLogFile': 0, 'ArchiveLogRecords': 0}
                        if sub:
                            values['VerifiedCrawlerEvidenceFile'] = str(stage_base / 'crawler-evidence' / 'evidence.json')
                        path.write_text(final_native_settings(path.read_text(encoding='utf-8'), values), encoding='utf-8')
            for site, info in profiles.items():
                if site not in selected_sites:
                    continue
                if not info['managed']:
                    selected_sites[site] = dict(selected_sites[site], behavior_filter=False)
                    continue
                if info['applied'] is None:
                    # Managed unknown history is deliberately frozen; native-only
                    # sites outside Filters retain their separate existing updater.
                    selected_sites.pop(site, None)
                    continue
                PROFILE_MAP[site] = info['applied']
                selected_sites[site] = dict(selected_sites[site], behavior_filter=True, verified_crawler_filter=True,
                                            exclude_automated_ips=info['applied']['exclude_automated_ips'])
                classifier_path = Path(CONFIG) / 'traffic-classification' / ('awstats.' + site + '.json')
                private_directory(str(classifier_path.parent), account.pw_gid)
                atomic_json(classifier_path, info['applied']['classifier'], gid=account.pw_gid)
                parent = stage_base / 'corpus' / site
                if not (parent / 'current').is_symlink() or request:
                    # Explicit rebuilds use all actually retained input, without
                    # pretending that missing old input is present.
                    actual = retained_input(private_base, site)
                    private_directory(str(parent.parent), account.pw_gid)
                    private_directory(str(parent), account.pw_gid)
                    seed = parent / ('seed-' + token)
                    private_directory(str(seed), account.pw_gid)
                    for day in actual:
                        shutil.copyfile(str(Path(private_base) / 'corpus' / site / 'current' / (day + '.log')), str(seed / (day + '.log')))
                        os.chown(str(seed / (day + '.log')), 0, account.pw_gid); os.chmod(str(seed / (day + '.log')), 0o640)
                    atomic_json(seed / 'receipt.json', {'days': actual, 'native_months': {}}, gid=account.pw_gid)
                    if (parent / 'current').is_symlink():
                        (parent / 'current').unlink()
                    os.symlink(seed.name, str(parent / 'current'))
            atomic_json(Path(CONFIG) / 'sites.json', selected_sites, gid=account.pw_gid)
            BASE, WEB = str(stage_base), str(stage_web)
            saved_argv = sys.argv
            sys.argv = [saved_argv[0]] + (['--verify-repeat'] if options.verify_repeat else [])
            try:
                legacy_main(account, apache_gid)
            finally:
                sys.argv = saved_argv
            generated = Path(WEB) / 'current'
            generated = generated.resolve()
            stage_state = read_json(stage_base / 'status.json')
            # The staging kernel owns its own token; bind our public generation
            # identity only after it has completed every native/link check.
            for site, values in stage_state['sites'].items():
                profiles[site]['totals'] = values.get('totals', {})
                profiles[site]['view_totals'] = {'original': values.get('original_totals', values.get('totals', {})),
                    'confirmed': values.get('confirmed_totals', {}), 'requests': values.get('request_totals', {}),
                    'behavior': values.get('totals', {})}
                if profiles[site]['managed']:
                    profiles[site]['note'] = 'Filters applied; native statistics rebuilt from retained input.'
                    inputs = retained_input(str(stage_base), site)
                    profiles[site]['input_days'] = inputs
                    profiles[site]['coverage'] = coverage(profiles[site], inputs)
                    result_summary = read_json(stage_base / 'work' / stage_state['generation'] / site / 'behavior/result/summary.json')
                    profiles[site]['capacity_fallback'] = result_summary.get('capacity_fallback', {})
                    profiles[site]['matched_requests'] = result_summary['behavior']
                    profiles[site]['excluded_by_month'] = result_summary['excluded_by_month']
                    profiles[site]['request_excluded_by_month'] = result_summary['request_excluded_by_month']
                    profiles[site]['native_overlap_note'] = 'Per-filter matches overlap; native before/after metrics are recalculated, not sums of those matches.'
                profiles[site]['updated_utc'] = stage_state['completed_utc']
            # Single-site jobs preserve every unrelated site's current HTML.
            for site in profiles:
                if not (generated / site).exists() and (current / site).is_dir():
                    shutil.copytree(str(current / site), str(generated / site))
            render_root_index(generated, profiles, sites, manifest['generated_utc'], apache_gid)
        native_gap = defaults(APP, PERL)['classifier']['verification']['max_gap_seconds']
        evidence_dates = native_evidence_dates(private_base if options.bootstrap_ui else str(stage_base), native_gap)
        for site, info in profiles.items():
            info['browser_access'] = public_browser_policy(browser_policy(real_config, site))
            if info['applied']:
                info['effective_by_month'] = {m: filter_status(info['applied'], evidence=any(d.startswith(m + '-') for d in evidence_dates),
                    over_limits=m in info.get('capacity_fallback', {})) for m in info.get('totals', {})}
                latest = max(info.get('totals', {}), default='')
                info['effective'] = info['effective_by_month'].get(latest, filter_status(info['applied']))
                if info['effective'].get('verified_crawlers') == 'Active':
                    info['effective']['verified_crawlers'] = 'Active for covered requests'
            info['default_profile'] = defaults(APP, PERL, info.get('applied'))
        manifest['profiles'] = profiles
        atomic_json(run / 'manifest.json', manifest, gid=control_gid)
        decorate_generation(str(generated), manifest, apache_gid)
        # One retained report snapshot is inspectable from History. Avoid nested
        # copies of history and rewrite its local links to that frozen snapshot.
        history = generated / 'history'
        if history.exists():
            shutil.rmtree(str(history))
        history.mkdir(mode=0o750)
        historical = history / previous
        shutil.copytree(str(current.resolve()), str(historical), ignore=shutil.ignore_patterns('history'))
        for path in historical.glob('**/*.html'):
            text = path.read_text(encoding='utf-8').replace('/vstats/', '/vstats/history/' + previous + '/')
            if path.parent.name == 'filters' and path.name == 'index.html':
                text = text.replace('id="filters-main"', 'id="filters-main" data-historical="true"')
            path.write_text(text, encoding='utf-8')
        for directory, dirs, files in os.walk(str(generated)):
            os.chown(directory, 0, apache_gid); os.chmod(directory, 0o750)
            for name in files:
                os.chown(os.path.join(directory, name), 0, apache_gid); os.chmod(os.path.join(directory, name), 0o640)
        validate_report_links(str(generated))
        if request:
            site = request['site']
            result = {'profile_id': profiles[site]['profile_id'], 'coverage': scope,
                'before': PREVIEW_BASELINE.get(site, {}).get('totals'), 'after': profiles[site]['totals'],
                'capacity_fallback': profiles[site].get('capacity_fallback', {}), 'generation': token,
                'note': 'Same frozen input, evidence and rules. Unavailable baseline is not zero. Remaining visitors are not verified humans.'}
            atomic_json(state_root / 'jobs' / (request['id'] + '-result.json'), result, gid=control_gid)
            if request['action'] == 'preview':
                print(json.dumps({'status': 'PREVIEW READY', 'generation': token}), flush=True)
                return
        if options.trial:
            print(json.dumps({'status': 'TRIAL PASS', 'generation': token, 'published': False}), flush=True)
            return
        destination = Path(real_web) / 'generations' / token
        if request:
            # A policy change while a long rebuild runs must prevent publication.
            Control(settings).authorize(queued_user(request), request['site'], fresh=True)
        os.rename(str(generated), str(destination))
        subprocess.check_call(['/sbin/restorecon', '-R', str(destination)])
        # The profile/history manifest already exists. This is the sole public
        # commit point used by readers, the API and the next scheduled update.
        link = Path(real_web) / ('.current-' + token)
        os.symlink('generations/' + token, str(link))
        os.replace(str(link), str(current))
        descriptor = os.open(real_web, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        print(json.dumps({'status': 'SUCCESS', 'generation': token, 'profile_pair_committed': True}), flush=True)
        # Reports and mutable derived histories follow a two-generation retention
        # policy. Source corpus links and profile metadata are preserved. A filter
        # action never removes source data to meet a storage target.
        for directory in (Path(real_web) / 'generations').iterdir():
            if GENERATION.fullmatch(directory.name) and directory.name not in {token, previous} and directory.is_dir() and not directory.is_symlink():
                shutil.rmtree(str(directory))
        retained_runs = {token, previous}
        for base_reference in [manifest['private_base']] + ([read_json(previous_manifest_path)['private_base']] if previous_manifest_path.exists() else []):
            path = Path(base_reference)
            if path.name == 'base' and path.parent.parent == state_root / 'runs':
                retained_runs.add(path.parent.name)
        for old_run in (state_root / 'runs').iterdir():
            if not GENERATION.fullmatch(old_run.name) or old_run.name in retained_runs or old_run.is_symlink():
                continue
            for name in ['web', 'config', 'preflight']:
                path = old_run / name
                if path.is_dir() and not path.is_symlink():
                    shutil.rmtree(str(path))
            for name in ['data', 'data-verified', 'data-requests', 'data-behavior', 'input', 'work', 'crawler-evidence', 'supplements']:
                path = old_run / 'base' / name
                if path.is_dir() and not path.is_symlink():
                    shutil.rmtree(str(path))


if __name__ == '__main__':
    main()
