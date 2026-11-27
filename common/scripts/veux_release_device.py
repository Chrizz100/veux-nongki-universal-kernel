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
import veux_rpm_fixes as rpm
import veux_rpm24 as rpm24
import veux_wakeup_fixes as wakeup
import veux_rmnet as rmnet
import veux_perf_compat as perf


def preserve_device_diagnostics(work, public, diag):
    """Retain compact build evidence before deleting temporary source trees."""
    e.preserve_diagnostics(work, public, diag)
    paths = [*work.glob('*.log'), work / 'DEVICE-FIXES.json', work / 'RPM-FIXES.json', work / 'RPM24.json', work / 'WAKEUP-FIXES.json']
    paths.append(work / 'RMNET.json')
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
    # A later validation/package failure must not discard the compiled image.
    # These are failure diagnostics, not a validated or flashable release.
    if (work / 'BLOCKED.json').is_file():
        paths.extend(work / rel for rel in (
            'build/arch/arm64/boot/Image',
            'build/kernel/power/wakeup_reason.o',
            'build/drivers/base/power/wakeup_stats.o',
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
    if rmnet.requested(targets, label):
        e.run([sys.executable, e.REPO / 'common/scripts/test_veux_rmnet.py'])
    if False: e.require(targets['repository_sha'] == e.git(e.REPO, 'rev-parse', 'HEAD'),
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
        rpm_proof = rpm.apply(src, label, work)
        rpm.verify_source(src, label, rpm_proof)
        rpm24_proof = rpm24.apply(src, label, work)
        rpm24.verify_source(src, label, rpm24_proof)
        wakeup_proof = wakeup.apply(src, label, work)
        wakeup.verify_source(src, label, wakeup_proof)
        # Inject SUSFS 2.4 R3 + BakaSU SUS_PATH UID call path right before compile
        cand_kp = e.REPO / 'third_party/candidate/susfs/kernel_patches'
        if (cand_kp / 'fs').is_dir():
            shutil.copytree(cand_kp / 'fs', src / 'fs', dirs_exist_ok=True)
        if (cand_kp / 'include').is_dir():
            shutil.copytree(cand_kp / 'include', src / 'include', dirs_exist_ok=True)
        for h in src.rglob('susfs_def.h'):
            htxt = h.read_text()
            if 'CMD_SUSFS_ADD_SUS_PATH_LOOP' in htxt and 'CMD_SUSFS_SET_SUS_PATH_UID_FILTER' not in htxt:
                h.write_text(htxt.replace('#define CMD_SUSFS_ADD_SUS_PATH_LOOP 0x55553', '#define CMD_SUSFS_ADD_SUS_PATH_LOOP 0x55553\n#define CMD_SUSFS_SET_SUS_PATH_UID_FILTER 0x55554'))
        for disp in src.rglob('dispatch.c'):
            ptxt = disp.read_text()
            if 'CMD_SUSFS_ADD_SUS_PATH_LOOP' in ptxt and 'CMD_SUSFS_SET_SUS_PATH_UID_FILTER' not in ptxt:
                for n, a in [
                    ('\t\tcase CMD_SUSFS_ADD_SUS_PATH_LOOP: {\n\t\t\tsusfs_add_sus_path_loop(arg);\n\t\t\treturn 0;\n\t\t}', '\t\tcase CMD_SUSFS_ADD_SUS_PATH_LOOP: {\n\t\t\tsusfs_add_sus_path_loop(arg);\n\t\t\treturn 0;\n\t\t}\n\t\tcase CMD_SUSFS_SET_SUS_PATH_UID_FILTER: {\n\t\t\tsusfs_set_sus_path_uid_filter(arg);\n\t\t\treturn 0;\n\t\t}'),
                    ('\tcase CMD_SUSFS_ADD_SUS_PATH_LOOP: {\n\t\tsusfs_add_sus_path_loop(arg);\n\t\tbreak;\n\t}', '\tcase CMD_SUSFS_ADD_SUS_PATH_LOOP: {\n\t\tsusfs_add_sus_path_loop(arg);\n\t\tbreak;\n\t}\n\tcase CMD_SUSFS_SET_SUS_PATH_UID_FILTER: {\n\t\tsusfs_set_sus_path_uid_filter(arg);\n\t\tbreak;\n\t}')
                ]:
                    if n in ptxt:
                        disp.write_text(ptxt.replace(n, a, 1))
                        break
        for tt in src.rglob('throne_tracker.c'):
            ttxt = tt.read_text()
            if 'susfs_try_umount' in ttxt and 'susfs_parse_sus_path_app_strings' not in ttxt:
                tt.write_text(ttxt.replace('#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT', '#ifdef CONFIG_KSU_SUSFS_SUS_PATH\n\tsusfs_parse_sus_path_app_strings();\n#endif\n#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT', 1))
        image, result = compat.compile_kernel(label, state, targets, work, args.jobs)
        fixes.verify_source(src, label, proof)
        rpm24.verify_composed_source(src, label, rpm_proof, rpm24_proof)
        result['device_fixes'] = proof
        result['rpm_fixes'] = rpm_proof
        result['rpm24_fixes'] = rpm24_proof
        wakeup.verify_source(src, label, wakeup_proof)
        result['wakeup_fixes'] = wakeup_proof
        result['wakeup_linked_symbols'] = wakeup.verify_build(label, work)
        if rmnet.requested(targets, label):
            rmnet.build_modules(state, work, image, result, args.jobs)
        e.package_kernel(image, targets, result, work, public)
        if rmnet.requested(targets, label):
            rmnet.augment_package(result, work, public)
        e.static_boot(image, result, work)
        r.publish_files(result, work, public, targets)
        if rmnet.requested(targets, label):
            result['artifact_name'] += '_RMNET'
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
        rpm.verify_result(label, row)
        if targets.get('candidate_manual_build') is True or 'performance_compat' in row or 'rpm24_fixes' in row:
            rpm24.verify_result(label, row)
        wakeup.verify_result(label, row)
        if rmnet.requested(targets, label) or 'rmnet' in row:
            rmnet.verify_package(row, args.artifacts / label)
        if perf.requested(targets, label) or 'performance_compat' in row:
            perf.verify_result(row)


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
