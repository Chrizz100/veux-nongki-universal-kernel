#!/usr/bin/env python3
"""Authenticated Android wakeup diagnostic ABI for the stabilized 5.4.274 tree."""
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import tempfile
import veux_update_engine as e

KERNEL = '5.4.274'
PAYLOAD = 'common/device-fixes/5.4.274/wakeup-diag-r2'
MANIFEST_SHA256 = 'f7cbb70a09d42da700e303d695e23a6b1b9a3ee03d04200d4dc074103f1d38e8'
ABI_SYMBOLS = ('wakeup_reason_init', 'last_resume_reason_show', 'last_suspend_time_show')


def path_in(root, name, missing=False):
    rel = PurePosixPath(name)
    e.require(name and not rel.is_absolute() and '..' not in rel.parts
              and rel.as_posix() == name and '\\' not in name, 'invalid wakeup path')
    path = root.joinpath(*rel.parts)
    e.inside(path, root)
    for item in (path, *path.parents):
        e.require(not item.is_symlink(), 'linked wakeup path: ' + name)
        if item == root:
            break
    e.require(path.is_file() or (missing and not path.exists()),
              'wakeup path not a regular file: ' + name)
    return path


def load():
    folder = e.REPO / PAYLOAD
    manifest = path_in(folder, 'manifest.json')
    e.require(e.digest(manifest) == MANIFEST_SHA256, 'wakeup manifest drift')
    data = json.loads(manifest.read_text())
    e.require(data['schema'] == 1 and data['id'] == 'wakeup-diag-r2'
              and data['kernel'] == KERNEL, 'wakeup identity mismatch')
    e.require(data['recipe_blob'] == e.config()['lineages'][KERNEL]['blob'],
              'wakeup source recipe mismatch')
    for name, digest in data['assets'].items():
        e.require(e.digest(path_in(folder, name)) == digest, 'wakeup payload drift: ' + name)
    proof = dict(id=data['id'], manifest_sha256=MANIFEST_SHA256,
                 source_recipe_blob=data['recipe_blob'],
                 source_sha256={n:r['after_sha256'] for n,r in data['files'].items()},
                 host_tests=True, device_pass_inferred=False)
    return folder, data, proof


def expected(label):
    return [load()[2]] if label == KERNEL else []


def inventory(src, data):
    return {name:e.digest(p) if p.exists() else None for name in data['files']
            for p in [path_in(src, name, missing=True)]}


def apply(src, label, work):
    if label != KERNEL:
        return []
    folder, data, proof = load()
    before = inventory(src, data)
    original = {n:r['before_sha256'] for n,r in data['files'].items()}
    result = proof['source_sha256']
    e.require(before in (original, result), 'wakeup source drift or mixed patch state')
    with tempfile.TemporaryDirectory(prefix='wakeup-fix-', dir=work) as temporary:
        stage = Path(temporary)
        for name, digest in before.items():
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True)
            if digest is not None:
                shutil.copy2(src / name, target)
        if before != result:
            patch = folder / data['patch']
            e.run(['git', 'apply', '--check', '--whitespace=error', patch], cwd=stage)
            e.run(['git', 'apply', '--whitespace=error', patch], cwd=stage)
        e.require(inventory(stage, data) == result, 'wakeup postimage mismatch')
        e.run([sys.executable, folder / data['test'], stage], log=work / 'wakeup-host-tests.log')
        e.require(inventory(src, data) == before, 'wakeup source changed during tests')
        for name in result:
            target = src / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(stage / name, target)
    e.write_json(work / 'WAKEUP-FIXES.json', [proof])
    print('WAKEUP_FIXES=PASS; HOST_TESTS=PASS; DEVICE_PASS=NO', flush=True)
    return [proof]


def verify_source(src, label, proof):
    e.require(proof == expected(label), 'wakeup source proof mismatch')
    for item in proof:
        for name, digest in item['source_sha256'].items():
            e.require(e.digest(path_in(src, name)) == digest, 'wakeup source changed during build')


def verify_symbols(symbols):
    """Require function bodies, including the internal names in the R3 LTO build.

    Run 37335256954 contains name$<32 hex digits> for these static functions.
    A .cfi body is also valid, but a .cfi_jt jump-table entry alone is not proof
    that the corresponding implementation was linked.
    """
    for name in ABI_SYMBOLS:
        pattern = (r'^[0-9a-fA-F]+[ \t]+[tT][ \t]+' + re.escape(name)
                   + r'(?:\$[0-9a-fA-F]{32})?(?:\.cfi)?[ \t]*$')
        e.require(re.search(pattern, symbols, re.M) is not None,
                  'wakeup symbol not linked: ' + name)
    return list(ABI_SYMBOLS)


def verify_build(label, work):
    if label != KERNEL:
        return []
    for name in ('build/kernel/power/wakeup_reason.o',
                 'build/drivers/base/power/wakeup_stats.o'):
        obj = path_in(work, name)
        e.require(obj.stat().st_size > 0, 'wakeup object empty: ' + name)
    symbols = path_in(work, 'build/System.map').read_text()
    return verify_symbols(symbols)


def verify_result(label, row):
    e.require(row.get('wakeup_fixes', []) == expected(label),
              'missing or outdated wakeup fix proof: ' + label)
    wanted = list(ABI_SYMBOLS) if label == KERNEL else []
    e.require(row.get('wakeup_linked_symbols', []) == wanted, 'wakeup link proof missing: ' + label)
