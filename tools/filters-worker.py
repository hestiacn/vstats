#!/usr/bin/env python3
"""Validate queued actions and run the fixed publisher outside the HTTP process."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vstats_filters import (Control, IDENTIFIER, atomic_json, identity, read_json,
                           utcnow, validate_profile, publish_browser_policy, queued_user)


def committed_generation(control, action_id):
    """Find this action in committed ancestry. Invalid ancestry raises: no status is written."""
    return next((m for m in control.committed_manifests()
                 if m.get('action_id') == action_id), None)


def process(control, request_path):
    action_id = request_path.stem
    if not IDENTIFIER.fullmatch(action_id):
        return
    output = control.state / 'jobs' / (action_id + '.json')
    if output.exists():
        return
    record = read_json(request_path)
    request, job = record['request'], record['queued']
    job = dict(job)
    gid = pwd.getpwnam(control.settings.get('api_user', 'vstats-control')).pw_gid
    try:
        if request['id'] != action_id or job['id'] != action_id:
            raise ValueError('Action identity mismatch')
        control.authorize(queued_user(request), request['site'], fresh=True)
        if request['action'] not in ['preview', 'apply']:
            raise ValueError('Unsupported queued action')
        profile = validate_profile(request['profile'], control.app, control.perl)
        if identity(profile) != identity(request['profile']):
            raise ValueError('Queued profile is not canonical')
        if request['base_generation'] != control.current()['generation']:
            raise ValueError('Reports changed; reload settings and submit a new action')
        frozen = control.state / 'jobs' / (action_id + '-request.json')
        atomic_json(frozen, request, gid=gid)
        job.update(status='Running', phase='Snapshotting input and rebuilding native reports', started_utc=utcnow())
        atomic_json(output, job, gid=gid)
        log_path = control.state / 'jobs' / (action_id + '.log')
        with open(str(log_path), 'xb') as log:
            os.chmod(str(log_path), 0o600)
            command = [sys.executable, '-I', str(Path(control.app) / 'tools/publish-static-reports.py'),
                       '--control-settings', control.settings['settings_path'], '--filter-job', str(frozen), '--verify-repeat']
            child = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                   env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'LANG': 'C',
                                        'PYTHONDONTWRITEBYTECODE': '1'}, timeout=2700)
        result_path = control.state / 'jobs' / (action_id + '-result.json')
        if child.returncode or not result_path.exists():
            raise RuntimeError('Rebuild failed validation; previous reports and settings remain applied')
        result = read_json(result_path)
        job.update(status='Completed', phase='Preview ready' if request['action'] == 'preview' else 'Reports published',
                   result=result, completed_utc=utcnow())
    except Exception as e:
        # A process may exit after the atomic report pointer moved. Reconcile it.
        committed = committed_generation(control, action_id) if request.get('action') == 'apply' else None
        if committed is not None:
            job.update(status='Completed', phase='Committed generation recovered',
                       generation=committed['generation'], completed_utc=utcnow())
        else:
            error = str(e) if isinstance(e, (ValueError, RuntimeError)) else 'Worker failed; consult private diagnostics'
            job.update(status='Failed', phase='No new report/profile pair published', error=error, completed_utc=utcnow())
            result_path = control.state / 'jobs' / (action_id + '-result.json')
            if result_path.exists():
                job['result'] = read_json(result_path)
    atomic_json(output, job, gid=gid)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--settings', required=True)
    parser.add_argument('--once', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('Run the queue worker as root; parsing is demoted by the publisher')
    settings = read_json(args.settings, root_owned=True)
    settings['settings_path'] = args.settings
    control = Control(settings)
    with open(str(control.state / 'worker.lock'), 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # A restarted worker must not silently replay an interrupted action.
        gid = pwd.getpwnam(settings.get('api_user', 'vstats-control')).pw_gid
        for path in (control.state / 'jobs').glob('*.json'):
            if not IDENTIFIER.fullmatch(path.stem):
                continue
            job = read_json(path)
            if job['status'] == 'Running':
                committed = committed_generation(control, job['id']) if job.get('action') == 'apply' else None
                job.update(status='Completed' if committed is not None else 'Failed',
                           phase='Committed generation recovered' if committed is not None else 'Worker restarted before publication',
                           completed_utc=utcnow())
                if committed is not None:
                    job['generation'] = committed['generation']
                atomic_json(path, job, gid=gid)
        while True:
            publish_browser_policy(settings, gid=gid)
            for path in sorted((control.state / 'requests').glob('*.json')):
                try:
                    process(control, path)
                except Exception:
                    # One corrupt spool entry cannot stop unrelated sites' jobs.
                    print('Invalid queue entry: ' + path.stem, file=sys.stderr, flush=True)
            if args.once:
                return
            time.sleep(3)


if __name__ == '__main__':
    main()
