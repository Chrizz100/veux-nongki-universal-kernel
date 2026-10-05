#!/usr/bin/env python3
"""Reproduce the flashed VEUX component commits without resolving upstream HEADs."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

import veux_update_engine as e
import veux_current_components as current

CONTRACT = 'common/contracts/VEUX_STABILIZATION_R1.json'
CONTRACT_SHA256 = 'eaceb5c620adba6cb5fce34ee8e64b2f9ec1efa5707e8a7e3c1bf88d7f3df1b9'
REFERENCE = 'common/diagnostics/veux-stabilization-r1/REFERENCE_RESULT.json'


def load_contract(cfg):
    path = e.REPO / CONTRACT
    e.require(path.is_file() and not path.is_symlink(), 'component lock missing or linked')
    e.require(e.digest(path) == CONTRACT_SHA256, 'reviewed component lock changed')
    lock = json.loads(path.read_text())
    e.require(lock['schema'] == 1 and lock['kernel'] == '5.4.274'
              and lock['device_pass_inferred'] is False, 'invalid stabilization identity')
    e.require(cfg['lineages']['5.4.274']['blob'] == lock['source_recipe_blob'],
              'stabilization source recipe changed')
    e.require(set(lock['components']) == set(e.COMPONENTS), 'component lock incomplete')
    reference = e.REPO / REFERENCE
    e.require(reference.is_file() and not reference.is_symlink()
              and e.digest(reference) == lock['reference_result_sha256'],
              'flashed build reference changed')
    row = json.loads(reference.read_text())
    e.require(row['targets'] == lock['components'] and row['kernel'] == lock['kernel']
              and row['repository_sha'] == lock['reference_repository_sha']
              and row['image_sha256'] == lock['reference_image_sha256'],
              'component lock does not match flashed build reference')
    for name, entry in lock['components'].items():
        e.require(e.SHA.fullmatch(entry['commit']) and e.SHA.fullmatch(entry['base']),
                  'component lock needs full commit IDs: ' + name)
    return lock


def verify_donor(name, donor, entry):
    e.require(e.git(donor, 'rev-parse', 'HEAD') == entry['commit'],
              'frozen checkout identity mismatch: ' + name)
    e.require(not e.git(donor, 'status', '--porcelain'), 'modified frozen donor: ' + name)
    e.git(donor, 'merge-base', '--is-ancestor', entry['base'], entry['commit'])
    ahead = int(e.git(donor, 'rev-list', '--count', entry['base'] + '..' + entry['commit']))
    e.require(ahead == entry['ahead'], 'frozen ancestry mismatch: ' + name)
    if name == 'resukisu':
        count = int(e.git(donor, 'rev-list', '--count', entry['commit']))
        kbuild = (donor / 'kernel/Kbuild').read_text()
        e.require('expr 30000 + $(KSU_LOCAL_VERSION) + 700' in kbuild,
                  'ReSukiSU version formula changed')
        e.require(count == entry['local_version'] and str(30700 + count) == entry['version'],
                  'frozen ReSukiSU version mismatch')
        e.require(current.checked_uapi(donor) == entry['uapi'], 'frozen UAPI mismatch')
    else:
        path, pattern = (
            ('kernel_patches/include/linux/susfs.h', r'^#define SUSFS_VERSION "v?([^\"]+)"$')
            if name == 'susfs' else
            ('kernel/src/nomount.h', r'^#define NOMOUNT_VERSION "([^\"]+)"$'))
        versions = re.findall(pattern, (donor / path).read_text(), re.M)
        e.require(versions == [entry['version']], 'frozen version mismatch: ' + name)


def resolve(work):
    cfg, _ = e.check_repo()
    lock = load_contract(cfg)
    work.mkdir(parents=True, exist_ok=False)
    result = {'schema': 1, 'repository_sha': e.git(e.REPO, 'rev-parse', 'HEAD'),
              'golden_sha256': e.digest(e.REPO / cfg['golden_contract']),
              'lineages': [lock['kernel']], 'components': lock['components'],
              'component_lock': {'path': CONTRACT, 'sha256': CONTRACT_SHA256,
                                 'reference_run': lock['reference_run']}}
    for name in e.COMPONENTS:
        entry = lock['components'][name]
        donor = work / name
        # No ls-remote, branch-head resolution or fallback to a newer commit.
        e.checkout(entry['url'], entry['commit'], donor, full=True)
        verify_donor(name, donor, entry)
        print('FROZEN_COMPONENT ' + name + '=' + entry['commit'], flush=True)
    e.write_json(work / 'targets.json', result)
    return result


def verify_result(public, bundle):
    cfg, _ = e.check_repo()
    lock = load_contract(cfg)
    targets = json.loads((bundle / 'targets.json').read_text())
    row = json.loads((public / 'RESULT.json').read_text())
    e.require(targets['components'] == lock['components'], 'resolver component drift')
    e.require(targets['component_lock']['sha256'] == CONTRACT_SHA256,
              'resolver lock drift')
    e.require(targets['lineages'] == [lock['kernel']] and row['kernel'] == lock['kernel'],
              'unexpected stabilization kernel')
    e.require(row['targets'] == lock['components'], 'built component drift')
    e.require(row['repository_sha'] == targets['repository_sha']
              == e.git(e.REPO, 'rev-parse', 'HEAD'), 'build repository drift')
    e.require(row['target_manifest_sha256'] == e.digest(bundle / 'targets.json'),
              'build target manifest drift')
    e.require(all(row.get(k) is True for k in ('compile', 'package', 'static_boot'))
              and row.get('device') is False, 'incomplete build or inferred device PASS')
    # Reuse the regular release gates, including the source/config proofs.
    import veux_config_compat as compat
    import veux_device_fixes as fixes
    import veux_rpm_fixes as rpm
    import veux_wakeup_fixes as wakeup
    compat.verify_result(lock['kernel'], row)
    e.require(row.get('device_fixes') == fixes.expected(lock['kernel']),
              'missing stabilization device fixes')
    rpm.verify_result(lock['kernel'], row)
    wakeup.verify_result(lock['kernel'], row)
    print('FROZEN_BUILD=PASS; DEVICE_PASS=NO')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('check')
    resolver = commands.add_parser('resolve')
    resolver.add_argument('--work', type=Path, required=True)
    verifier = commands.add_parser('verify-result')
    verifier.add_argument('--public', type=Path, required=True)
    verifier.add_argument('--bundle', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == 'check':
            cfg, _ = e.check_repo()
            lock = load_contract(cfg)
            print('COMPONENT_LOCK=PASS; REFERENCE_RUN=' + str(lock['reference_run'])
                  + '; KERNEL_BUILD=NOT_RUN; DEVICE_PASS=NO')
        elif args.command == 'resolve':
            resolve(args.work)
        else:
            verify_result(args.public, args.bundle)
    except (e.Blocked, OSError, ValueError, KeyError, TypeError,
            subprocess.SubprocessError) as exc:
        print('BLOCKED: ' + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
