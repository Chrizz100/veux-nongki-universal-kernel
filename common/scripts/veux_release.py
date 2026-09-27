#!/usr/bin/env python3
"""Validated source snapshots and clean per-kernel release files."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import veux_update_engine as e

CURRENT = 'common/contracts/CURRENT_BUILD.json'
SOURCES = 'third_party/current'
OVERLAYS = 'common/update/current'


def snapshot_hashes(root):
    result = {}
    for p in root.rglob('*'):
        name = p.relative_to(root).as_posix()
        if p.is_symlink():
            e.inside(p, root)
            result[name] = 'link:' + hashlib.sha256(os.readlink(p).encode()).hexdigest()
        elif p.is_file():
            result[name] = e.digest(p)
    return result


def identity(label, components):
    values = [label] + [components[c]['version'] for c in e.COMPONENTS]
    for value in values:
        e.require(e.re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', value), 'unsafe release version')
    return f'Kernel_{values[0]}_ReSukiSU_{values[1]}_SUSFS_{values[2]}_NoMount_{values[3]}'


def inventory(src):
    vendor, mirrors = e.topology(src)
    roots = [src / 'fs', src / 'include', vendor / 'kernel', vendor / 'uapi', vendor / 'LICENSE', *mirrors]
    records = {}
    for root in roots:
        paths = [root] if root.is_file() else root.rglob('*')
        for p in paths:
            if '.git' in p.relative_to(src).parts:
                continue
            if p.is_symlink():
                e.inside(p, src)
                records[p.relative_to(src).as_posix()] = {'link': os.readlink(p)}
            elif p.is_file():
                e.inside(p, src)
                records[p.relative_to(src).as_posix()] = {'sha256': e.digest(p), 'mode': p.stat().st_mode & 0o777}
    return records


def save_overlay(src, before, destination, label, targets):
    after = inventory(src)
    destination.mkdir(parents=True, exist_ok=False)
    edits = {}
    for name in sorted(before.keys() | after.keys()):
        if before.get(name) == after.get(name):
            continue
        edits[name] = {'before': before.get(name), 'after': after.get(name)}
        if name in after and 'link' not in after[name]:
            p = destination / 'files' / name
            p.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src / name, p)
    e.write_json(destination / 'overlay.json', {'kernel': label,
        'recipe_blob': e.config()['lineages'][label]['blob'], 'targets': targets['components'], 'edits': edits})
    return e.digest(destination / 'overlay.json')


def replay_current(src, label, targets):
    current = e.REPO / CURRENT
    if not current.is_file():
        return False
    manifest = json.loads(current.read_text())
    # Base/ahead may change independently of the actual source identity.
    if any(manifest['targets'][c]['commit'] != targets['components'][c]['commit'] for c in e.COMPONENTS):
        return False
    e.require(snapshot_hashes(e.REPO / SOURCES) == manifest['source_sha256'], 'current component snapshot drift')
    folder = e.REPO / OVERLAYS / label
    expected = manifest['lineages'][label]['integration_overlay_sha256']
    e.require(e.digest(folder / 'overlay.json') == expected, 'current integration manifest drift')
    apply_overlay(src, folder, label, targets)
    print(f'INTEGRATION {label}=PASS; SOURCE=repository-current', flush=True)
    return True


def apply_overlay(src, folder, label, targets):
    overlay = json.loads((folder / 'overlay.json').read_text())
    e.require(overlay['kernel'] == label and overlay['recipe_blob'] == e.config()['lineages'][label]['blob'], 'overlay source mismatch')
    e.require(all(overlay['targets'][c]['commit'] == targets['components'][c]['commit'] for c in e.COMPONENTS), 'overlay target mismatch')
    actual = inventory(src)
    # Check every preimage and payload before writing any file.
    for name, edit in overlay['edits'].items():
        e.require(not Path(name).is_absolute() and '..' not in Path(name).parts, 'invalid overlay path')
        e.inside(src / name, src)
        e.require(actual.get(name) == edit['before'], f'overlay preimage drift: {name}')
        if edit['after'] and 'link' in edit['after']:
            target = edit['after']['link']
            e.require(not Path(target).is_absolute(), 'absolute integration symlink')
            e.inside((src / name).parent / target, src)
        elif edit['after']:
            payload = e.inside(folder / 'files' / name, folder)
            e.require(e.digest(payload) == edit['after']['sha256'], f'overlay payload drift: {name}')
    for name, edit in overlay['edits'].items():
        dest = src / name
        if dest.is_symlink():
            dest.unlink()
        if edit['after'] and 'link' in edit['after']:
            if dest.exists(): dest.unlink()
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.symlink_to(edit['after']['link'])
        elif edit['after']:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(folder / 'files' / name, dest)
            dest.chmod(edit['after']['mode'])
        elif dest.exists():
            dest.unlink()
    e.topology(src)


def publish_files(result, work, public, targets):
    stem = identity(result['kernel'], targets['components'])
    boot = work / 'static/boot.img'
    e.require(result['static_boot'] is True and e.digest(boot) == result['static_boot_sha256'], 'unverified boot image')
    name = stem + '_boot.img'
    shutil.copy2(boot, public / name)
    e.require(e.digest(public / name) == result['static_boot_sha256'], 'boot copy mismatch')
    result['boot_file'] = name
    result['artifact_name'] = stem
    return stem


def verify_boot(row, folder):
    name = row.get('boot_file', '')
    e.require(name and Path(name).name == name, 'missing or invalid boot filename')
    e.require(e.digest(folder / name) == row['static_boot_sha256'], 'promotion boot hash mismatch')


def run_worker(args):
    try:
        e.worker(args.kernel, args.bundle, args.work, args.public, args.jobs, args.overlays)
        result = json.loads((args.public / 'RESULT.json').read_text())
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
                f.write('artifact_name=' + result['artifact_name'] + '\n')
    finally:
        if args.work.exists():
            diag = args.work.parent / 'diagnostics' / args.kernel
            e.preserve_diagnostics(args.work, args.public, diag)
            for p in args.work.glob('*.log'):
                shutil.copy2(p, diag / p.name)
            # Build copies only; outputs and integration snapshots are siblings.
            e.require(args.work.name == args.kernel and args.work != e.REPO, 'invalid cleanup directory')
            shutil.rmtree(args.work)


def promote(args):
    e.require(e.git(e.REPO, 'branch', '--show-current') == 'main', 'promotion requires main')
    e.require(not e.git(e.REPO, 'status', '--porcelain'), 'promotion requires clean checkout')
    targets = json.loads((args.bundle / 'targets.json').read_text())
    base = targets['repository_sha']
    e.require(e.git(e.REPO, 'rev-parse', 'HEAD') == base, 'promotion base changed')
    e.prepare_promotion(args.bundle, args.artifacts, args.output)
    proof = json.loads((args.output / 'PROMOTION-READY.json').read_text())
    for label, row in proof['lineages'].items():
        verify_boot(row, args.artifacts / label)
        overlay = args.overlays / label / 'overlay.json'
        e.require(e.digest(overlay) == row['integration_overlay_sha256'], 'integration snapshot mismatch')
        data = json.loads(overlay.read_text())
        e.require(data['targets'] == targets['components'] and data['kernel'] == label, 'snapshot provenance mismatch')
        for name, edit in data['edits'].items():
            e.require(not Path(name).is_absolute() and '..' not in Path(name).parts, 'invalid snapshot path')
            if edit['after'] and 'link' not in edit['after']:
                e.require(e.digest(e.inside(overlay.parent / 'files' / name, overlay.parent)) == edit['after']['sha256'], 'snapshot payload mismatch')
    # Finish all preparation in a staging directory before mutating checkout.
    stage = args.output / 'repository'
    stage.mkdir()
    for component in e.COMPONENTS:
        donor = args.bundle / component
        entry = targets['components'][component]
        e.require(e.git(donor, 'rev-parse', 'HEAD') == entry['commit'] and not e.git(donor, 'status', '--porcelain'), 'promotion donor drift')
        dest = stage / SOURCES / component
        dest.parent.mkdir(parents=True, exist_ok=True)
        if component == 'resukisu':
            e.normalized_resukisu(donor, entry, dest)
        else:
            dest.mkdir()
            parts = ['kernel_patches', 'LICENSE'] if component == 'susfs' else ['kernel', 'LICENSE']
            for name in parts:
                p = donor / name
                if p.is_dir(): shutil.copytree(p, dest / name, symlinks=True)
                else: shutil.copy2(p, dest / name)
        e.write_json(stage / f'common/upstream/{component}/current.json', entry)
    shutil.copytree(args.overlays, stage / OVERLAYS)
    proof.update(status='compile-package-static-validated', repository_mutation=True,
                 source_directory=SOURCES, integration_directory=OVERLAYS,
                 run_id=os.environ.get('GITHUB_RUN_ID'), device_pass_inferred=False)
    proof['source_sha256'] = snapshot_hashes(stage / SOURCES)
    e.write_json(stage / CURRENT, proof)
    # Optimistic concurrency: never merge an update over a moved main.
    remote = e.git(e.REPO, 'ls-remote', 'origin', 'refs/heads/main').split()[0]
    e.require(remote == base, 'main moved during builds; artifacts retained, promotion blocked')
    for rel in (SOURCES, OVERLAYS):
        dest = e.REPO / rel
        if dest.exists(): shutil.rmtree(dest)
        shutil.copytree(stage / rel, dest, symlinks=True)
    for rel in [CURRENT] + [f'common/upstream/{c}/current.json' for c in e.COMPONENTS]:
        shutil.copy2(stage / rel, e.REPO / rel)
    e.require(e.digest(e.REPO / e.config()['golden_contract']) == targets['golden_sha256'], 'Golden changed')
    paths = [SOURCES, OVERLAYS, CURRENT] + [f'common/upstream/{c}/current.json' for c in e.COMPONENTS]
    e.git(e.REPO, 'add', '--', *paths)
    e.git(e.REPO, '-c', 'user.name=github-actions[bot]', '-c', 'user.email=41898282+github-actions[bot]@users.noreply.github.com',
          'commit', '-m', 'Update validated kernel sources and build references [skip ci]')
    # A regular fast-forward push rejects concurrent changes; no force push.
    e.git(e.REPO, 'push', 'origin', 'HEAD:refs/heads/main')
    print('REPOSITORY_UPDATE=PASS; DEVICE_PASS=NO', flush=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    w = sub.add_parser('worker')
    for name in ('bundle', 'work', 'public', 'overlays'): w.add_argument('--'+name, type=Path, required=True)
    w.add_argument('--kernel', required=True)
    w.add_argument('--jobs', type=int, default=4)
    q = sub.add_parser('promote')
    for name in ('bundle', 'artifacts', 'overlays', 'output'): q.add_argument('--'+name, type=Path, required=True)
    args = p.parse_args()
    try:
        if args.command == 'worker':
            e.require(args.jobs > 0, 'jobs must be positive')
            run_worker(args)
        else: promote(args)
    except (e.Blocked, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(f'BLOCKED: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
