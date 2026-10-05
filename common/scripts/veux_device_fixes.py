#!/usr/bin/env python3
"""Authenticated device patches, separate from replaceable upstream overlays."""
import json
from pathlib import Path
import shutil
import sys
import tempfile
import veux_update_engine as e


PATCHSETS = {'5.4.274': 'common/device-fixes/5.4.274/charger-pm-r1'}


def authenticate_payload(folder, name, digest):
    e.require(name not in ('', '.', '..') and Path(name).name == name,
              'invalid device payload path')
    path = folder / name
    e.require(path.is_file() and not path.is_symlink(), 'device payload must be a regular file')
    e.require(e.digest(path) == digest, 'device payload drift: ' + name)


def host_tests(row):
    return [row] + row.get('extra_tests', [])


def load(label):
    if label not in PATCHSETS:
        return None
    folder = e.REPO / PATCHSETS[label]
    manifest = folder / 'manifest.json'
    data = json.loads(manifest.read_text())
    e.require(data['schema'] == 1 and data['kernel'] == label, 'device patch identity mismatch')
    e.require(data['recipe_blob'] == e.config()['lineages'][label]['blob'], 'device patch recipe mismatch')
    names = set()
    for row in data['files']:
        name = row['source']
        e.require(not Path(name).is_absolute() and '..' not in Path(name).parts,
                  'invalid device source path')
        e.require(name not in names, 'duplicate device source path')
        names.add(name)
        authenticate_payload(folder, row['patch'], row['patch_sha256'])
        for test in host_tests(row):
            authenticate_payload(folder, test['test'], test['test_sha256'])
            for asset in test.get('assets', []):
                authenticate_payload(folder, asset['file'], asset['sha256'])
    e.require(names, 'empty device patchset')
    proof = {'id': data['id'], 'manifest_sha256': e.digest(manifest),
             'reference_run': data['reference_run'],
             'source_sha256': {r['source']: r['after_sha256'] for r in data['files']},
             'host_tests': True}
    return folder, data, proof


def expected(label):
    loaded = load(label)
    return [] if loaded is None else [loaded[2]]


def apply(src, label, work):
    loaded = load(label)
    if loaded is None:
        return []
    folder, data, proof = loaded
    # Validate every source before touching any of them. Accept only the exact
    # original or the exact proven result, never a best-effort fuzzy rebase.
    for row in data['files']:
        e.require(not (src / row['source']).is_symlink(), 'device source must be a regular file')
        path = e.inside(src / row['source'], src)
        e.require(e.digest(path) in (row['before_sha256'], row['after_sha256']),
                  'device source drift: ' + row['source'])
    with tempfile.TemporaryDirectory(prefix='device-fixes-', dir=work) as tmp:
        stage = Path(tmp)
        for row in data['files']:
            dest = stage / row['source']
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src / row['source'], dest)
            if e.digest(dest) != row['after_sha256']:
                e.run(['git', 'apply', '--check', folder / row['patch']], cwd=stage)
                e.run(['git', 'apply', folder / row['patch']], cwd=stage)
            e.require(e.digest(dest) == row['after_sha256'], 'device patch postimage mismatch')
        header = 'drivers/power/supply/qcom/bq2589x_reg.h'
        shutil.copy2(e.inside(src / header, src), stage / header)
        for row in data['files']:
            for test in host_tests(row):
                e.run([sys.executable, folder / test['test'], stage / row['source']],
                      log=work / (test['test'] + '.log'))
        for row in data['files']:
            shutil.copy2(stage / row['source'], src / row['source'])
    e.write_json(work / 'DEVICE-FIXES.json', [proof])
    print(f'DEVICE_FIXES {label}={data["id"]}; SOURCE_AND_HOST_TESTS=PASS', flush=True)
    return [proof]


def verify_source(src, label, proof):
    e.require(proof == expected(label), 'device patch proof mismatch')
    for entry in proof:
        for name, digest in entry['source_sha256'].items():
            e.require(e.digest(e.inside(src / name, src)) == digest,
                      'device source changed during build: ' + name)
