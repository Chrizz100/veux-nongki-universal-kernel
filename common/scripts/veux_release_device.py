#!/usr/bin/env python3
"""Regular release entry point with mandatory per-lineage device fixes.

Keep the hash-pinned legacy engine and diagnostic runners reproducible. Reuse
their integration, compile, package, boot and promotion gates without modifying
them; this entry point adds the device-fix gate to the regular release pipeline.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import veux_update_engine as e
import veux_release as r
import veux_device_fixes as fixes
import veux_config_compat as compat
import veux_source_transport as transport


def preserve_device_diagnostics(work, public, diag):
    """Retain compact build evidence before deleting temporary source trees."""
    e.preserve_diagnostics(work, public, diag)
    paths = [*work.glob('*.log'), work / 'DEVICE-FIXES.json']
    # ConfigDiag10 writes the raw evidence below this directory. The legacy
    # preservation function only knows its own top-level JSON files.
    reports = work / 'config-reports'
    if reports.is_dir():
        paths.extend(reports.rglob('*'))
    paths.extend(work / rel for rel in (
        'static/AVB-VERIFY.txt', 'static/unpack-raw.log',
        'static/unpack-decoded.log', 'build/.config', 'build/Module.symvers',
        'build/System.map', 'build/include/config/kernel.release',
    ))
    for path in paths:
        e.require(not path.is_symlink(), 'linked diagnostic file: ' + str(path))
        if path.is_file():
            e.inside(path, work)
            target = diag / path.relative_to(work)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)


def worker(args):
    label, bundle, work, public = args.kernel, args.bundle, args.work, args.public
    cfg, _ = e.check_repo()
    targets = json.loads((bundle / 'targets.json').read_text())
    e.require(targets['repository_sha'] == e.git(e.REPO, 'rev-parse', 'HEAD'),
              'resolver/worker commit mismatch')
    e.require(e.digest(e.REPO / cfg['golden_contract']) == targets['golden_sha256'],
              'Golden contract changed')
    e.require(label in targets['lineages'], 'worker lineage not in resolver manifest')
    e.require(args.jobs > 0, 'jobs must be positive')
    e.require(work.name == label and not work.exists() and not public.exists(),
              'worker requires new build and output directories')
    work.mkdir(parents=True)
    public.mkdir(parents=True)
    try:
        state = transport.materialize(label, work)
        state['dtb_reference'] = e.prepare_dtb_reference(label, state, work, args.jobs)
        src = Path(state['source'])
        before = r.inventory(src)
        if not r.replay_current(src, label, targets):
            e.apply_update(src, state, bundle, work)
        overlay_hash = r.save_overlay(src, before, args.overlays / label, label, targets)
        # Required on BOTH repository replay and freshly resolved upstreams.
        proof = fixes.apply(src, label, work)
        fixes.verify_source(src, label, proof)
        image, result = compat.compile_kernel(label, state, targets, work, args.jobs)
        fixes.verify_source(src, label, proof)
        result['device_fixes'] = proof
        e.package_kernel(image, targets, result, work, public)
        e.static_boot(image, result, work)
        r.publish_files(result, work, public, targets)
        result.update(integration_overlay_sha256=overlay_hash,
                      repository_sha=targets['repository_sha'], targets=targets['components'],
                      target_manifest_sha256=e.digest(bundle / 'targets.json'), device=False)
        e.write_json(public / 'RESULT.json', result)
        (public / 'PACKAGE-STATUS.json').unlink()
        (public / 'SHA256SUMS.txt').write_text(''.join(
            f'{e.digest(p)}  {p.name}\n' for p in sorted(public.iterdir()) if p.is_file()))
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
                f.write('artifact_name=' + result['artifact_name'] + '\n')
    except Exception as exc:
        e.write_json(work / 'BLOCKED.json', {'kernel': label, 'reason': str(exc), 'device': False})
        raise
    finally:
        diag = work.parent / 'diagnostics' / label
        preserve_device_diagnostics(work, public, diag)
        shutil.rmtree(work)


def verify_results(args):
    targets = json.loads((args.bundle / 'targets.json').read_text())
    for label in targets['lineages']:
        row = json.loads((args.artifacts / label / 'RESULT.json').read_text())
        compat.verify_result(label, row)
        e.require(row.get('device_fixes') == fixes.expected(label),
                  'missing or outdated device fixes: ' + label)


def promote(args):
    # The old promotion preserves complete RESULT rows in CURRENT_BUILD.json.
    # Reject older successful builds which predate the required driver fixes.
    verify_results(args)
    r.promote(args)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    w = sub.add_parser('worker')
    for name in ('bundle', 'work', 'public', 'overlays'):
        w.add_argument('--' + name, type=Path, required=True)
    w.add_argument('--kernel', required=True)
    w.add_argument('--jobs', type=int, default=4)
    q = sub.add_parser('promote')
    for name in ('bundle', 'artifacts', 'overlays', 'output'):
        q.add_argument('--' + name, type=Path, required=True)
    args = p.parse_args()
    try:
        if args.command == 'worker':
            worker(args)
        else:
            promote(args)
    except (e.Blocked, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(f'BLOCKED: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
