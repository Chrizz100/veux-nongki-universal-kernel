#!/usr/bin/env python3
"""Keep unsent VEUX 5.4.274 RPM sleep requests pending on transport failure."""
import json
from pathlib import Path, PurePosixPath
import shutil
import sys
import tempfile
import veux_update_engine as e

KERNEL = '5.4.274'
PAYLOAD = 'common/device-fixes/5.4.274/rpm-sleep-r1'
MANIFEST_SHA256 = 'e530b5df0fc78f90a867dd2e15fb85f4a63cb2a4f4f287d67ba1e35e976645d7'


def regular(root, name):
    relative = PurePosixPath(name)
    e.require(not relative.is_absolute() and '..' not in relative.parts
              and relative.as_posix() == name and '\\' not in name,
              'invalid RPM path: ' + name)
    path = root.joinpath(*relative.parts)
    e.inside(path, root)
    e.require(path.is_file() and not path.is_symlink(), 'RPM file missing or linked: ' + name)
    for parent in path.parents:
        e.require(not parent.is_symlink(), 'linked RPM parent: ' + str(parent))
        if parent == root:
            break
    return path


def load():
    folder = e.REPO / PAYLOAD
    manifest = regular(folder, 'manifest.json')
    e.require(e.digest(manifest) == MANIFEST_SHA256, 'RPM manifest drift')
    data = json.loads(manifest.read_text())
    e.require(data['kernel'] == KERNEL and data['id'] == 'rpm-sleep-r1',
              'RPM payload identity mismatch')
    e.require(data['recipe_blob'] == e.config()['lineages'][KERNEL]['blob'],
              'RPM source recipe mismatch')
    for name, expected in data['assets'].items():
        e.require(e.digest(regular(folder, name)) == expected, 'RPM payload drift: ' + name)
    proof = {'id': data['id'], 'manifest_sha256': MANIFEST_SHA256,
             'source_recipe_blob': data['recipe_blob'],
             'source_sha256': {data['source']: data['after_sha256']},
             'host_cases': data['host_cases'], 'host_tests': True,
             'device_pass_inferred': False}
    return folder, data, proof


def expected(label):
    return [load()[2]] if label == KERNEL else []


def apply(src, label, work):
    if label != KERNEL:
        return []
    folder, data, proof = load()
    source = regular(src, data['source'])
    before = e.digest(source)
    e.require(before in (data['before_sha256'], data['after_sha256']), 'RPM source drift')
    with tempfile.TemporaryDirectory(prefix='rpm-fix-', dir=work) as temporary:
        stage = Path(temporary)
        target = stage / data['source']
        target.parent.mkdir(parents=True)
        shutil.copy2(source, target)
        if before == data['before_sha256']:
            e.run(['git', 'apply', '--check', folder / data['patch']], cwd=stage)
            e.run(['git', 'apply', folder / data['patch']], cwd=stage)
        e.require(e.digest(target) == data['after_sha256'], 'RPM patch postimage mismatch')
        e.run([sys.executable, folder / data['test'], target], log=work / 'rpm-host-tests.log')
        # Do not modify the build source until patch and actual-C tests passed.
        e.require(e.digest(source) == before, 'RPM source changed while testing')
        shutil.copy2(target, source)
    e.write_json(work / 'RPM-FIXES.json', [proof])
    print('RPM_FIXES 5.4.274=rpm-sleep-r1; HOST_CASES=22; DEVICE_PASS=NO', flush=True)
    return [proof]


def verify_source(src, label, proof):
    e.require(proof == expected(label), 'RPM source proof mismatch')
    for entry in proof:
        for name, digest in entry['source_sha256'].items():
            e.require(e.digest(regular(src, name)) == digest, 'RPM source changed during build')


def verify_result(label, row):
    e.require(row.get('rpm_fixes', []) == expected(label), 'missing or outdated RPM fix proof: ' + label)
