#!/usr/bin/env python3
"""Fast read-only ReSukiSU/BakaSU compatibility gate for the VEUX kernel fleet.

Detect upstream changes and show blockers; NEVER bypass upstream $(error),
rewrite CURRENT_BUILD, approve a kernel, or change a component pin.
"""
from __future__ import annotations

import argparse
import ast
import base64
import binascii
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request

REPOSITORY = 'Chrizz100/veux-nongki-universal-kernel'
UPSTREAM = 'Baka-SU/BakaSU'
API_ROOT = 'https://api.github.com/repos/Baka-SU/BakaSU'
WORKER = 'common/scripts/veux_fleet_35217_nm21_r1.py'
RISK_PATHS = {
    'kernel/feature/selinux_hide.c',
    'kernel/selinux/sepolicy.c',
    'kernel/compat/kernel_compat.h',
    'kernel/tools/susfs_compat.mk',
    'kernel/Kbuild', 'kernel/Kconfig',
    'kernel/tools/kernel_compat.mk',
    'kernel/tools/static_export_check.mk',
    'uapi/supercall.h',
}
SHA_PATTERN = re.compile(r'[a-f0-9]{40}\Z')
BLOCKER_PATTERN = re.compile(r'^\s*\$\(\s*error\b', re.I | re.M)
UAPI_PATTERN = re.compile(r'\bKERNEL_SU_UAPI_VERSION\s*=\s*(\d+)\s*;')


class CheckBlocked(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CheckBlocked(message)


def fetch_json(url: str) -> dict:
    require(url.startswith(API_ROOT + '/'), 'Unapproved API hostname or URL')
    token = os.environ.get('GITHUB_TOKEN', '')
    headers = {
        'User-Agent': 'VEUX-BakaSU-FastGate-R1',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
    }
    if token:
        headers['Authorization'] = 'Bearer ' + token
    request = urllib.request.Request(url, headers=headers, method='GET')
    with urllib.request.urlopen(request, timeout=35) as stream:
        require(stream.status == 200, f'GitHub API HTTP {stream.status}')
        data = stream.read(3_000_001)
    require(len(data) <= 3_000_000, 'GitHub API response too large')
    obj = json.loads(data)
    require(isinstance(obj, dict), 'Invalid GitHub API JSON')
    return obj


def pinned_targets(worker_path: Path) -> dict:
    tree = ast.parse(worker_path.read_text(encoding='utf-8'), filename=str(worker_path))
    assignments = [node.value for node in tree.body
                   if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == 'TARGETS'
                           for target in node.targets)]
    require(len(assignments) == 1, 'Unique TARGETS literal not found')
    targets = ast.literal_eval(assignments[0])
    require(isinstance(targets, dict) and set(targets) == {'resukisu', 'susfs', 'nomount'},
            'Unexpected component targets')
    for item in targets.values():
        require(isinstance(item, dict) and isinstance(item.get('commit'), str)
                and SHA_PATTERN.fullmatch(item['commit']) is not None, 'Invalid pinned commit')
    return targets


def get_file(fetch, path: str, head: str) -> str:
    obj = fetch(f'{API_ROOT}/contents/{path}?ref={head}')
    require(obj.get('type') == 'file' and obj.get('encoding') == 'base64'
            and isinstance(obj.get('content'), str), f'Unexpected content: {path}')
    try:
        b = base64.b64decode(obj['content'], validate=False)
        require(len(b) < 500_000, f'Upstream source unexpectedly large: {path}')
        return b.decode('utf-8', errors='strict')
    except (UnicodeError, ValueError, binascii.Error) as exc:
        raise CheckBlocked('Invalid upstream source encoding: ' + path) from exc


def analyse(pin: str, head: str, compare: dict, compat: str, header: str) -> dict:
    require(SHA_PATTERN.fullmatch(pin) and SHA_PATTERN.fullmatch(head), 'Invalid SHA')
    require(compare.get('status') in ('ahead', 'identical')
            and isinstance(compare.get('ahead_by'), int) and compare['ahead_by'] >= 0
            and compare.get('behind_by') == 0 and
            compare.get('merge_base_commit', {}).get('sha') == pin,
            'UPSTREAM_HISTORY_REWRITE_OR_UNRELATED_COMMIT')
    entries = compare.get('files') or []
    require(isinstance(entries, list), 'Invalid compare files')
    changed = sorted({item['filename'] for item in entries
                      if isinstance(item, dict) and isinstance(item.get('filename'), str)})
    risky = sorted(set(changed) & RISK_PATHS)
    uapi = UAPI_PATTERN.search(header)
    require(uapi is not None, 'UAPI_VERSION_MISSING')
    uapi_v = int(uapi.group(1))
    blocker = bool(BLOCKER_PATTERN.search(compat))
    if blocker:
        state = 'BLOCKED_BY_UPSTREAM_SUSFS'
    elif uapi_v != 5:
        state = 'BLOCKED_UAPI_CHANGED'
    elif risky:
        state = 'REQUIRES_KERNEL_COMPATIBILITY_REVIEW'
    elif pin == head:
        state = 'NO_NEW_KERNEL_UPDATE'
    else:
        state = 'READY_FOR_SIX_KERNEL_PREFLIGHT_NOT_APPROVED'
    return {
        'schema': 1,
        'source': 'Baka-SU/BakaSU (migrated from ReSukiSU/ReSukiSU)',
        'previous_pinned_commit': pin,
        'upstream_main_commit': head,
        'commits_ahead': compare['ahead_by'],
        'upstream_history_fast_forward': True,
        'changed_files': changed,
        'critical_kernel_files_changed': risky,
        'uapi_version': uapi_v,
        'upstream_susfs_build_blocker': blocker,
        'status': state,
        'requires_review': bool(risky or blocker or uapi_v != 5),
        'build_approved': False,
        'kernel_compilation_performed': False,
        'repository_modified': False,
        'device_pass_inferred': False,
    }


def inspect(repo: Path, fetch=fetch_json) -> dict:
    repo = repo.resolve(strict=True)
    require(repo.is_dir() and (repo / '.git').is_dir(), 'Repository checkout missing')
    require(os.environ.get('GITHUB_REPOSITORY', REPOSITORY) == REPOSITORY,
            'Unexpected GitHub repository')
    targets = pinned_targets(repo / WORKER)
    pinned = targets['resukisu']['commit']
    branch = fetch(f'{API_ROOT}/branches/main')
    head = (branch.get('commit') or {}).get('sha')
    require(isinstance(head, str) and SHA_PATTERN.fullmatch(head),
            'Invalid upstream branch HEAD')
    compare = fetch(f'{API_ROOT}/compare/{pinned}...{head}')
    compat = get_file(fetch, 'kernel/tools/susfs_compat.mk', head)
    header = get_file(fetch, 'uapi/supercall.h', head)
    result = analyse(pinned, head, compare, compat, header)
    result['fleet_targets_unchanged'] = targets
    return result


def report_text(r: dict) -> str:
    risky = r['critical_kernel_files_changed']
    lines = [
        'VEUX BakaSU/ReSukiSU Fast Check R1',
        '================================',
        'STATUS: ' + r['status'],
        'PINNED: ' + r['previous_pinned_commit'],
        'LATEST: ' + r['upstream_main_commit'],
        'AHEAD: ' + str(r['commits_ahead']) + ' commits',
        'UAPI: ' + str(r['uapi_version']),
        'SUSFS_BUILD_BLOCKER: ' + ('YES' if r['upstream_susfs_build_blocker'] else 'NO'),
        'CRITICAL_KERNEL_FILES: ' + str(len(risky)),
    ]
    lines += [' - ' + p for p in risky]
    lines += ['', 'NO new kernel build and NO automatic version promotion.',
              'If a new critical upstream revision is found, review SUSFS compatibility',
              'and rerun source preflight for all six lineages BEFORE kernel builds.',
              'This report does NOT certify compatibility with the device.']
    return '\n'.join(lines) + '\n'


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--repo', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    options = ap.parse_args()
    try:
        repo = options.repo.resolve(strict=True)
        output = options.output.resolve()
        require(not output.is_relative_to(repo), 'Outputs must not modify repository')
        result = inspect(repo)
        output.mkdir(parents=True, exist_ok=True)
        (output / 'BAKASU_FASTCHECK.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
        summary = report_text(result)
        (output / 'BAKASU_FASTCHECK.txt').write_text(summary)
        print(summary, end='', flush=True)
        if result['upstream_susfs_build_blocker']:
            print('::warning title=Latest BakaSU not buildable with SUSFS::'
                  'Upstream explicitly blocks SUSFS builds. Keep 35217 pin; '
                  'do not run latest as a six-kernel compile.', flush=True)
        if os.environ.get('GITHUB_STEP_SUMMARY'):
            with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as stream:
                stream.write('## VEUX BakaSU/ResukiSU compatibility\n\n')
                stream.write('**' + result['status'] + '** · ' + str(result['commits_ahead']) + ' commits ahead\n\n')
                stream.write('SUSFS build blocker: **' + str(result['upstream_susfs_build_blocker']) + '**; UAPI: ' + str(result['uapi_version']) + '\n\n')
                stream.write('Build approved: **NO**. No kernel build or repository changes.\n')
        return 0
    except (CheckBlocked, OSError, ValueError, KeyError, UnicodeError,
            urllib.error.URLError, TimeoutError) as exc:
        print('FASTCHECK_FAILED: ' + str(exc), file=sys.stderr, flush=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())
