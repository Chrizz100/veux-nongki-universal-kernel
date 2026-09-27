#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any

try:
    import yaml
except ImportError as exc:
    raise SystemExit('PyYAML is required') from exc

SHA40 = re.compile(r'^[0-9a-f]{40}$')
KERNEL_LABEL = re.compile(r'^5\.4\.\d+$')
EXPECTED_COMPONENTS = ('resukisu', 'susfs', 'nomount')
TEXT_SCAN_SUFFIXES = {'.c', '.h', '.cc', '.cpp', '.S', '.s', '.Kconfig', '.mk', '.txt', ''}
MAX_SCAN_BYTES = 2 * 1024 * 1024


def die(msg: str, code: int = 1) -> 'None':
    print(f'DETECTOR_ERROR: {msg}', file=sys.stderr)
    raise SystemExit(code)


def load_yaml(path: Path) -> dict[str, Any]:
    try:
        doc = yaml.safe_load(path.read_text(encoding='utf-8'))
    except Exception as exc:
        die(f'cannot parse {path}: {exc}')
    if not isinstance(doc, dict):
        die(f'{path} must contain a YAML mapping')
    return doc


def git(args: list[str], cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    p = subprocess.run(
        ['git', *args], cwd=str(cwd) if cwd else None, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if check and p.returncode:
        if p.stderr:
            print(p.stderr, file=sys.stderr, end='')
        die(f"git {' '.join(args)} failed rc={p.returncode}")
    return p


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def read_manifests(root: Path) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for comp in EXPECTED_COMPONENTS:
        p = root / 'common' / 'upstream' / comp / 'manifest.yml'
        if not p.is_file():
            die(f'missing upstream manifest: {p.relative_to(root)}')
        d = load_yaml(p)
        if d.get('schema') != 1 or d.get('component') != comp:
            die(f'invalid component manifest identity: {p.relative_to(root)}')
        stable = d.get('stable')
        track = d.get('track')
        sources = d.get('sources')
        if not isinstance(stable, dict) or not isinstance(track, dict) or not isinstance(sources, list) or not sources:
            die(f'invalid component manifest structure: {p.relative_to(root)}')
        commit = str(stable.get('commit', '')).lower()
        if not SHA40.fullmatch(commit):
            die(f'invalid stable commit in {p.relative_to(root)}')
        out[comp] = {
            'path': p.relative_to(root).as_posix(),
            'version': str(stable.get('version', '')),
            'commit': commit,
            'uapi': stable.get('uapi'),
            'track_ref': str(track.get('ref', '')),
            'sources': [str(x) for x in sources],
        }
    return out


def inventory_lineage(lineage_dir: Path) -> dict[str, Any]:
    files = sorted(p.name for p in lineage_dir.iterdir() if p.is_file())
    support = sorted(x for x in files if re.search(r'(PORT_SUPPORT|SOURCE_RESTORE).*\.zip$', x, re.I))
    local_targets = sorted(x for x in files if re.search(r'(^LOCAL_TARGET|INTEGRATE|GOLDEN_PORT).*\.py$', x, re.I))
    build_scripts = sorted(x for x in files if re.search(r'(BUILD|COMPILE).*\.sh$', x, re.I))

    # This is deliberately structural, not kernel-name based.
    if any('PORT_SUPPORT' in x.upper() for x in support):
        source_class = 'port-support-bundle'
    elif any('SOURCE_RESTORE' in x.upper() for x in support):
        source_class = 'source-restore-bundle'
    elif build_scripts or local_targets:
        source_class = 'lineage-local-tooling'
    else:
        source_class = 'authority-only'

    return {
        'source_class': source_class,
        'support_bundles': support,
        'local_integration_evidence': local_targets,
        'build_scripts': build_scripts,
        'all_top_level_files': files,
    }


def profile_row(root: Path, path: Path, manifests: dict[str, dict[str, Any]]) -> dict[str, Any]:
    d = load_yaml(path)
    kernel = str(d.get('kernel', ''))
    if not KERNEL_LABEL.fullmatch(kernel) or path.parent.name != kernel:
        die(f'invalid kernel identity: {path.relative_to(root)}')
    if d.get('enabled') is not True:
        die(f'{kernel}: detector V1 requires enabled=true')
    if d.get('device') != 'veux' or str(d.get('platform', '')).lower() != 'sm6375':
        die(f'{kernel}: unexpected device/platform')

    baseline = d.get('baseline')
    authority = d.get('legacy_authority')
    features = d.get('features')
    validation = d.get('validation')
    if not all(isinstance(x, dict) for x in (baseline, authority, features, validation)):
        die(f'{kernel}: malformed build profile')

    component_state: dict[str, Any] = {}
    for comp in EXPECTED_COMPONENTS:
        f = features.get(comp)
        if not isinstance(f, dict):
            die(f'{kernel}: missing feature {comp}')
        commit = str(f.get('commit', '')).lower()
        current = {
            'enabled': f.get('enabled') is True,
            'version': str(f.get('version', '')),
            'commit': commit,
        }
        if comp == 'resukisu':
            current['uapi'] = f.get('uapi')
        target = manifests[comp]
        aligned = (
            current['enabled']
            and current['version'] == target['version']
            and current['commit'] == target['commit']
            and (comp != 'resukisu' or current.get('uapi') == target.get('uapi'))
        )
        component_state[comp] = {**current, 'central_pin_aligned': aligned}

    authority_path = str(authority.get('workflow', ''))
    if not authority_path.startswith('.github/workflows/'):
        die(f'{kernel}: invalid legacy authority path')
    authority_exists = (root / authority_path).is_file()
    if not authority_exists:
        die(f'{kernel}: authority workflow missing: {authority_path}')

    inv = inventory_lineage(path.parent)
    role = str(baseline.get('role', ''))
    port_status = str(baseline.get('port_status', ''))
    device_pass = validation.get('device') is True

    return {
        'kernel': kernel,
        'profile_path': path.relative_to(root).as_posix(),
        'profile_git_blob': git(['hash-object', str(path)], cwd=root).stdout.strip() if (root / '.git').exists() else None,
        'baseline_role': role,
        'port_status': port_status,
        'authority_workflow': authority_path,
        'authority_present': authority_exists,
        'components': component_state,
        'validation': {
            'compile': validation.get('compile') is True,
            'package': validation.get('package') is True,
            'static_boot': validation.get('static_boot') is True,
            'device': device_pass,
        },
        'source_inventory': inv,
        # No per-kernel branch: same source inspection engine will decide after materialization.
        'next_engine': 'generic-source-inspector',
    }


def fleet_report(root: Path) -> dict[str, Any]:
    manifests = read_manifests(root)
    profiles = sorted(root.glob('lineages/*/build.yml'), key=lambda p: p.parent.name)
    if not profiles:
        die('no lineage profiles found')
    rows = [profile_row(root, p, manifests) for p in profiles]
    kernels = [r['kernel'] for r in rows]
    if len(kernels) != len(set(kernels)):
        die('duplicate kernel labels')

    component_alignment = {
        comp: all(r['components'][comp]['central_pin_aligned'] for r in rows)
        for comp in EXPECTED_COMPONENTS
    }
    head = None
    if (root / '.git').exists():
        p = git(['rev-parse', 'HEAD'], cwd=root, check=False)
        if p.returncode == 0:
            head = p.stdout.strip()

    return {
        'schema': 1,
        'mode': 'read-only-detector',
        'repository_head': head,
        'lineage_count': len(rows),
        'component_pins': manifests,
        'all_lineages_central_pin_aligned': all(component_alignment.values()),
        'component_alignment': component_alignment,
        'lineages': rows,
        'mutation_allowed': False,
        'integration_code_model': 'single-generic-engine',
    }


def parse_kernel_version(root: Path) -> str | None:
    makefile = root / 'Makefile'
    if not makefile.is_file():
        return None
    vals: dict[str, str] = {}
    for line in makefile.read_text(encoding='utf-8', errors='ignore').splitlines()[:120]:
        m = re.match(r'^\s*(VERSION|PATCHLEVEL|SUBLEVEL)\s*=\s*([0-9]+)\s*$', line)
        if m:
            vals[m.group(1)] = m.group(2)
    if all(k in vals for k in ('VERSION', 'PATCHLEVEL', 'SUBLEVEL')):
        return f"{vals['VERSION']}.{vals['PATCHLEVEL']}.{vals['SUBLEVEL']}"
    return None


def text_files(root: Path):
    skip = {'.git', 'out', 'out-kernel', 'dist'}
    for p in root.rglob('*'):
        if not p.is_file() or any(part in skip for part in p.parts):
            continue
        try:
            if p.stat().st_size > MAX_SCAN_BYTES:
                continue
        except OSError:
            continue
        if p.suffix in TEXT_SCAN_SUFFIXES or p.name in {'Kconfig', 'Kbuild', 'Makefile'}:
            yield p


def token_hits(root: Path, patterns: dict[str, re.Pattern[str]]) -> dict[str, list[str]]:
    hits = {k: [] for k in patterns}
    for p in text_files(root):
        try:
            s = p.read_text(encoding='utf-8', errors='ignore')
        except OSError:
            continue
        rel = p.relative_to(root).as_posix()
        for name, rx in patterns.items():
            if rx.search(s):
                hits[name].append(rel)
    for name in hits:
        hits[name] = sorted(set(hits[name]))
    return hits


def ksu_topology(root: Path) -> dict[str, Any]:
    candidates = []
    for rel in ('KernelSU/kernel', 'KernelSU', 'drivers/kernelsu', 'kernel/kernelsu'):
        p = root / rel
        if p.exists() or p.is_symlink():
            try:
                resolved = p.resolve(strict=True)
            except Exception:
                resolved = p.resolve(strict=False)
            candidates.append({
                'path': rel,
                'is_symlink': p.is_symlink(),
                'resolved': str(resolved),
            })

    # Prefer actual KSU roots and avoid double-counting parent KernelSU when KernelSU/kernel exists.
    logical = [x for x in candidates if x['path'] != 'KernelSU' or not (root / 'KernelSU/kernel').exists()]
    groups: dict[str, list[dict[str, Any]]] = {}
    for item in logical:
        groups.setdefault(item['resolved'], []).append(item)

    if not logical:
        topo = 'none'
    elif len(groups) == 1:
        topo = 'single-tree' if len(logical) == 1 else 'bound-aliases'
    else:
        topo = 'multiple-independent'

    return {
        'topology': topo,
        'safe_for_generic_refresh': topo in {'single-tree', 'bound-aliases'},
        'candidates': logical,
        'independent_tree_count': len(groups),
    }


def detect_defconfig(root: Path) -> dict[str, Any]:
    exact = root / 'arch/arm64/configs/veux_defconfig'
    if exact.is_file():
        return {'path': 'arch/arm64/configs/veux_defconfig', 'sha256': file_sha256(exact)}
    configs = root / 'arch/arm64/configs'
    matches = sorted(configs.glob('*veux*defconfig')) if configs.is_dir() else []
    return {
        'path': matches[0].relative_to(root).as_posix() if len(matches) == 1 else None,
        'candidate_count': len(matches),
    }


def source_report(root: Path) -> dict[str, Any]:
    if not root.is_dir():
        die(f'source root is not a directory: {root}')
    topology = ksu_topology(root)
    hits = token_hits(root, {
        'susfs': re.compile(r'CONFIG_KSU_SUSFS|\bsusfs_|\bSUSFS_'),
        'nomount': re.compile(r'\bNoMount\b|\bnomount[_A-Za-z0-9]*\b', re.I),
        'module_load_filter': re.compile(r'module_load_filter|ksu_block_modules|block_modules'),
    })
    susfs_core = [x for x in ('fs/susfs.c', 'include/linux/susfs.h', 'include/linux/susfs_def.h') if (root / x).exists()]

    report = {
        'schema': 1,
        'mode': 'source-read-only',
        'kernel_version': parse_kernel_version(root),
        'defconfig': detect_defconfig(root),
        'ksu': topology,
        'susfs': {
            'core_files': susfs_core,
            'symbol_files': hits['susfs'],
            'present': bool(susfs_core or hits['susfs']),
        },
        'nomount': {
            'symbol_files': hits['nomount'],
            'present': bool(hits['nomount']),
        },
        'excluded_module_load_filter': {
            'symbol_files': hits['module_load_filter'],
            'present': bool(hits['module_load_filter']),
        },
        'mutation_allowed': False,
    }

    blockers = []
    if topology['topology'] == 'multiple-independent':
        blockers.append('multiple-independent-ksu-trees')
    if report['excluded_module_load_filter']['present']:
        blockers.append('excluded-module-load-filter-present')
    if not report['defconfig'].get('path'):
        blockers.append('veux-defconfig-not-uniquely-detected')
    report['generic_update_blockers'] = blockers
    report['generic_update_ready'] = not blockers
    return report


def ls_remote(sources: list[str], ref: str) -> tuple[str, str]:
    errors = []
    for source in sources:
        p = git(['ls-remote', source, ref], check=False)
        if p.returncode != 0:
            errors.append(f'{source}: rc={p.returncode}')
            continue
        rows = [line.split() for line in p.stdout.splitlines() if line.strip()]
        rows = [r for r in rows if len(r) >= 2 and r[1] == ref and SHA40.fullmatch(r[0].lower())]
        if len(rows) == 1:
            return source, rows[0][0].lower()
        errors.append(f'{source}: exact ref resolution count={len(rows)}')
    die('all configured sources failed: ' + '; '.join(errors))


def resolve_upstreams(root: Path) -> dict[str, Any]:
    manifests = read_manifests(root)
    out: dict[str, Any] = {'schema': 1, 'components': {}, 'updates_found': False}
    for comp, m in manifests.items():
        source, head = ls_remote(m['sources'], m['track_ref'])
        changed = head != m['commit']
        out['updates_found'] = out['updates_found'] or changed
        out['components'][comp] = {
            'source': source,
            'track_ref': m['track_ref'],
            'current_version': m['version'],
            'current_commit': m['commit'],
            'remote_head': head,
            'update_available': changed,
        }
    return out


def write_json(obj: Any, report_path: str) -> None:
    text = json.dumps(obj, indent=2, sort_keys=True) + '\n'
    print(text, end='')
    if report_path:
        Path(report_path).write_text(text, encoding='utf-8')


def selftest() -> None:
    with tempfile.TemporaryDirectory(prefix='veux-detector-selftest-') as td:
        root = Path(td)
        # Source topology test: bound aliases.
        src = root / 'src-bound'
        (src / 'KernelSU/kernel').mkdir(parents=True)
        (src / 'drivers').mkdir(parents=True)
        os.symlink('../KernelSU/kernel', src / 'drivers/kernelsu')
        (src / 'arch/arm64/configs').mkdir(parents=True)
        (src / 'arch/arm64/configs/veux_defconfig').write_text('CONFIG_ARM64=y\n', encoding='utf-8')
        (src / 'Makefile').write_text('VERSION = 5\nPATCHLEVEL = 4\nSUBLEVEL = 300\n', encoding='utf-8')
        (src / 'fs').mkdir()
        (src / 'fs/susfs.c').write_text('/* susfs_ */\n', encoding='utf-8')
        (src / 'KernelSU/kernel/nomount.c').write_text('/* NoMount */\n', encoding='utf-8')
        r = source_report(src)
        if r['ksu']['topology'] != 'bound-aliases' or not r['generic_update_ready']:
            die('selftest bound-alias topology failed')

        # Independent-tree conflict must fail closed.
        src2 = root / 'src-conflict'
        (src2 / 'KernelSU/kernel').mkdir(parents=True)
        (src2 / 'drivers/kernelsu').mkdir(parents=True)
        (src2 / 'arch/arm64/configs').mkdir(parents=True)
        (src2 / 'arch/arm64/configs/veux_defconfig').write_text('CONFIG_ARM64=y\n', encoding='utf-8')
        (src2 / 'Makefile').write_text('VERSION = 5\nPATCHLEVEL = 4\nSUBLEVEL = 301\n', encoding='utf-8')
        r2 = source_report(src2)
        if r2['ksu']['topology'] != 'multiple-independent' or r2['generic_update_ready']:
            die('selftest independent-tree blocker failed')

        # Generic inventory classes: no kernel-name switch involved.
        d = root / 'lineage'
        d.mkdir()
        (d / 'OXX_PORT_SUPPORT_V1.zip').write_bytes(b'x')
        (d / 'LOCAL_TARGET_V1.py').write_text('', encoding='utf-8')
        inv = inventory_lineage(d)
        if inv['source_class'] != 'port-support-bundle':
            die('selftest inventory classification failed')

    print('VEUX_UPDATE_DETECTOR_SELFTEST=PASS')


def main() -> int:
    ap = argparse.ArgumentParser(description='VEUX single-engine all-in-one update detector (read-only V1)')
    sub = ap.add_subparsers(dest='cmd', required=True)
    sub.add_parser('selftest')

    p = sub.add_parser('fleet')
    p.add_argument('--repo-root', default='.')
    p.add_argument('--report', default='')
    p.add_argument('--require-six', action='store_true')

    p = sub.add_parser('source')
    p.add_argument('--source-root', required=True)
    p.add_argument('--report', default='')

    p = sub.add_parser('resolve')
    p.add_argument('--repo-root', default='.')
    p.add_argument('--report', default='')

    args = ap.parse_args()
    if args.cmd == 'selftest':
        selftest()
        return 0
    if args.cmd == 'fleet':
        report = fleet_report(Path(args.repo_root).resolve())
        if args.require_six and report['lineage_count'] != 6:
            die(f"expected six lineages, got {report['lineage_count']}")
        write_json(report, args.report)
        print('VEUX_FLEET_DETECTOR=PASS')
        return 0
    if args.cmd == 'source':
        report = source_report(Path(args.source_root).resolve())
        write_json(report, args.report)
        print('VEUX_SOURCE_DETECTOR=PASS')
        return 0
    if args.cmd == 'resolve':
        report = resolve_upstreams(Path(args.repo_root).resolve())
        write_json(report, args.report)
        print('VEUX_UPSTREAM_RESOLVE=PASS')
        return 0
    die('unknown command')


if __name__ == '__main__':
    raise SystemExit(main())
