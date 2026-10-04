#!/usr/bin/env python3
"""Validate the RPM installation and save only its authenticated files."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile
import veux_update_engine as e
import veux_release as release
import veux_config_compat as compat
import veux_device_fixes as fixes
import veux_rpm_fixes as rpm

SUITES = ('update_engine', 'release', 'device_fixes', 'config_compat',
          'source_transport', 'zip_install', 'diagnostic_retention', 'rpm_fixes')


def validate(archive, expected, head):
    e.require(e.git(e.REPO, 'rev-parse', 'HEAD') == head, 'checkout changed')
    e.require(e.digest(archive) == expected, 'installation ZIP changed')
    with zipfile.ZipFile(archive) as z:
        manifest = json.loads(z.read('INSTALL_MANIFEST.json'))
        e.require(manifest['schema'] == 1, 'installation manifest schema')
        files = manifest['files']
        for name, record in files.items():
            path = rpm.regular(e.REPO, name)
            e.require(e.digest(path) == record['after_sha256'], 'installed file changed: ' + name)
            e.require(hashlib.sha256(z.read(name)).hexdigest() == record['after_sha256'],
                      'ZIP member changed: ' + name)
    changed = set(e.git(e.REPO, 'diff', '--name-only', '-z', 'HEAD').split('\0')) - {''}
    added = set(e.git(e.REPO, 'ls-files', '--others', '--exclude-standard', '-z').split('\0')) - {''}
    e.require((changed | added) <= set(files), 'unrelated repository changes; refusing commit')
    e.git(e.REPO, 'diff', '--check')
    e.check_repo()
    compat.authenticate()
    fixes.expected('5.4.274')
    rpm.load()
    current = json.loads((e.REPO / release.CURRENT).read_text())
    e.require(release.snapshot_hashes(e.REPO / release.SOURCES) == current['source_sha256'],
              'existing component snapshot drift')
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    head = os.environ['GITHUB_SHA']
    e.require(re.fullmatch('[0-9a-f]{40}', head), 'invalid run commit')
    reports = Path(os.environ['RUNNER_TEMP']) / 'veux-rpm-reports'
    e.require(not reports.resolve().is_relative_to(e.REPO.resolve()), 'reports must be outside checkout')
    reports.mkdir(parents=True, exist_ok=True)
    files = validate(args.archive, args.sha256, head)
    rows = []
    for name in SUITES:
        result = subprocess.run([sys.executable, e.REPO / f'common/scripts/test_veux_{name}.py'],
                                cwd=e.REPO, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (reports / (name + '.log')).write_text(result.stdout)
        match = re.search(r'Ran (\d+) tests? in ', result.stdout)
        rows.append({'suite': name, 'returncode': result.returncode,
                     'tests': int(match[1]) if match else 0})
        e.write_json(reports / 'HOST-TESTS.json', rows)
        print(name + (': PASS' if result.returncode == 0 else ': FAIL'), flush=True)
        if result.returncode:
            print(result.stdout, flush=True)
            raise e.Blocked('host tests failed: ' + name)
        e.require(match is not None, 'test summary missing: ' + name)
    total = sum(row['tests'] for row in rows)
    e.require(total == 63, 'unexpected regression test count')
    validate(args.archive, args.sha256, head)
    # Recheck main immediately before writing; push is also fast-forward only.
    e.git(e.REPO, 'fetch', '--no-tags', 'origin', 'refs/heads/main')
    e.require(e.git(e.REPO, 'rev-parse', 'FETCH_HEAD') == head,
              'main moved; rerun from the current main commit')
    e.git(e.REPO, 'add', '--', *sorted(files))
    staged = e.git(e.REPO, 'diff', '--cached', '--name-only', '-z')
    e.require((set(staged.split('\0')) - {''}) <= set(files), 'unexpected staged files')
    if staged:
        e.git(e.REPO, 'config', 'user.name', 'github-actions[bot]')
        e.git(e.REPO, 'config', 'user.email', '41898282+github-actions[bot]@users.noreply.github.com')
        e.git(e.REPO, 'commit', '-m', 'Integrate verified VEUX RPM sleep-request fix [skip ci]')
        e.git(e.REPO, 'push', 'origin', 'HEAD:refs/heads/main')
    e.require(not e.git(e.REPO, 'status', '--porcelain'), 'checkout not clean after saving')
    commit = e.git(e.REPO, 'rev-parse', 'HEAD')
    e.write_json(reports / 'INSTALL-RESULT.json', {
        'status': 'PASS', 'host_tests': total, 'rpm_c_cases': 22,
        'commit': commit, 'base_commit': head, 'zip_sha256': args.sha256,
        'kernel_build': False, 'device_test': False,
        'changed_files': sorted(set(staged.split('\0')) - {''})})
    print(f'RPM_INSTALL=PASS; HOST_TESTS={total}; RPM_C_CASES=22; COMMIT={commit}; KERNEL_BUILD=NO')
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as summary:
            summary.write(f'RPM-Integration R1 gespeichert: `{commit}`.\n\n'
                          '63 Host-Regressionstests und 22 RPM-C-Faelle bestanden. '
                          'Kein Kernelbuild, kein Geraetetest.\n')


if __name__ == '__main__':
    try:
        main()
    except (e.Blocked, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print('BLOCKED: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
