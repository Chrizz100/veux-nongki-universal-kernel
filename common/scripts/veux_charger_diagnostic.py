#!/usr/bin/env python3
"""Build one pinned charger experiment using the validated release gates."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import veux_update_engine as e
import veux_release as r

CONTRACT = 'common/diagnostics/charger-5.4.274/contract.json'


def authenticate():
    contract = json.loads((e.REPO / CONTRACT).read_text())
    e.require(contract['schema'] == 1 and contract['kernel'] == '5.4.274'
              and contract['id'] == 'ChargerDiag01', 'unsupported diagnostic contract')
    for name, expected in contract['pins'].items():
        e.require(e.digest(e.inside(e.REPO / name, e.REPO)) == expected,
                  f'diagnostic baseline drift: {name}')
    cfg, _ = e.check_repo()
    current = json.loads((e.REPO / r.CURRENT).read_text())
    e.require(current['targets'] == contract['components'], 'diagnostic component drift')
    for component in e.COMPONENTS:
        record = json.loads((e.REPO / f'common/upstream/{component}/current.json').read_text())
        e.require(record == contract['components'][component], f'component record drift: {component}')
    e.require(r.snapshot_hashes(e.REPO / r.SOURCES) == current['source_sha256'],
              'current component snapshot drift')
    overlay = e.REPO / r.OVERLAYS / contract['kernel'] / 'overlay.json'
    e.require(e.digest(overlay) == current['lineages'][contract['kernel']]['integration_overlay_sha256'],
              'current integration manifest drift')
    patch = contract['patch']
    e.require(e.digest(e.inside(e.REPO / patch['path'], e.REPO)) == patch['sha256'],
              'diagnostic patch drift')
    return contract, {
        'schema': 1, 'repository_sha': e.git(e.REPO, 'rev-parse', 'HEAD'),
        'golden_sha256': e.digest(e.REPO / cfg['golden_contract']),
        'lineages': [contract['kernel']], 'components': contract['components'],
    }


def apply_diagnostic(src, contract):
    spec = contract['patch']
    patch = e.inside(e.REPO / spec['path'], e.REPO)
    target = e.inside(src / spec['source'], src)
    e.require(not target.is_symlink(), 'diagnostic source is a symlink')
    e.require(e.digest(patch) == spec['sha256'], 'diagnostic patch drift')
    e.require(e.digest(target) == spec['before_sha256'], 'charger source preimage drift')
    expected = f"{spec['added_lines']}\t{spec['removed_lines']}\t{spec['source']}"
    e.require(e.run(['git', 'apply', '--numstat', patch], cwd=src) == expected,
              'diagnostic patch scope changed')
    e.run(['git', 'apply', '--check', patch], cwd=src)
    e.run(['git', 'apply', patch], cwd=src)
    e.require(e.digest(target) == spec['after_sha256'], 'charger source postimage drift')
    print('CHARGER PATCH=PASS; changed files=1; removed lines=5', flush=True)
    return dict(spec, applied=True)


def verify_checkout(expected_sha):
    e.require(e.git(e.REPO, 'rev-parse', 'HEAD') == expected_sha, 'repository HEAD changed')
    e.require(not e.git(e.REPO, 'status', '--porcelain'), 'repository is not clean')


def retain_evidence(work, diagnostics):
    diagnostics.mkdir(parents=True, exist_ok=True)
    for pattern in ('*.json', '*.log'):
        for p in work.glob(pattern):
            shutil.copy2(p, diagnostics / p.name)
    for name in ('AVB-VERIFY.txt', 'unpack-raw.log', 'unpack-decoded.log'):
        source = work / 'static' / name
        if source.is_file():
            shutil.copy2(source, diagnostics / name)


def build(work, public, diagnostics, jobs):
    e.require(jobs > 0, 'jobs must be positive')
    folders = [p.resolve() for p in (work, public, diagnostics)]
    for p in folders:
        e.require(not p.is_relative_to(e.REPO) and not e.REPO.is_relative_to(p),
                  'diagnostic directories must be outside the repository')
    e.require(all(not a.is_relative_to(b) and not b.is_relative_to(a)
                  for i, a in enumerate(folders) for b in folders[i + 1:]),
              'diagnostic directories must be disjoint')
    e.require(not any(p.exists() for p in folders), 'diagnostic directories must be new')
    contract, targets = authenticate()
    verify_checkout(targets['repository_sha'])
    work.mkdir(parents=True)
    try:
        e.write_json(work / 'targets.json', targets)
        e.write_json(work / 'diagnostic-contract.json', contract)
        state = e.materialize(contract['kernel'], work)
        state['dtb_reference'] = e.prepare_dtb_reference(contract['kernel'], state, work, jobs)
        src = Path(state['source'])
        # Replay only the already validated repository overlay; never resolve a moving head.
        e.require(r.replay_current(src, contract['kernel'], targets), 'pinned integration unavailable')
        applied = apply_diagnostic(src, contract)
        e.write_json(work / 'CHARGER-PATCH.json', applied)
        image, result = e.compile_kernel(contract['kernel'], state, targets, work, jobs)
        # Keep packages private until all existing compile, package and static gates pass.
        candidate = work / 'candidate'
        candidate.mkdir()
        e.package_kernel(image, targets, result, work, candidate)
        e.static_boot(image, result, work)
        stem = r.publish_files(result, work, candidate, targets) + '_' + contract['id']
        for key, suffix in (('package_file', '_AnyKernel.zip'), ('boot_file', '_boot.img')):
            (candidate / result[key]).rename(candidate / (stem + suffix))
            result[key] = stem + suffix
        e.require(e.digest(candidate / result['package_file']) == result['package_sha256'],
                  'diagnostic package copy mismatch')
        r.verify_boot(result, candidate)
        result.update(artifact_name=stem, repository_sha=targets['repository_sha'],
                      baseline_repository_sha=contract['baseline_repository_sha'],
                      baseline_run_id=contract['baseline_run_id'], targets=targets['components'],
                      diagnostic_id=contract['id'], charger_patch=applied,
                      device=False, repository_mutation=False)
        (candidate / 'PACKAGE-STATUS.json').unlink()
        e.write_json(candidate / 'RESULT.json', result)
        (candidate / 'SHA256SUMS.txt').write_text(''.join(
            f'{e.digest(p)}  {p.name}\n' for p in sorted(candidate.iterdir())))
        verify_checkout(targets['repository_sha'])
        authenticate()
        public.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(candidate, public)
        e.require(r.snapshot_hashes(public) == r.snapshot_hashes(candidate), 'public copy mismatch')
        e.write_json(work / 'RESULT.json', result)
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
                f.write('artifact_name=' + stem + '\n')
        print('DIAGNOSTIC BUILD=PASS; DEVICE_PASS=NO', flush=True)
    except Exception as exc:
        e.write_json(work / 'BLOCKED.json', {'reason': str(exc), 'device': False})
        raise
    finally:
        retain_evidence(work, diagnostics)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('check')
    worker = sub.add_parser('build')
    for name in ('work', 'public', 'diagnostics'):
        worker.add_argument('--' + name, type=Path, required=True)
    worker.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args()
    try:
        if args.command == 'check':
            authenticate()
            print('DIAGNOSTIC CONTRACT=PASS')
        else:
            build(args.work.resolve(), args.public.resolve(), args.diagnostics.resolve(), args.jobs)
    except (e.Blocked, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(f'BLOCKED: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
