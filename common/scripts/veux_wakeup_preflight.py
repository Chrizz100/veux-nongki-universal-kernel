#!/usr/bin/env python3
"""Reconstruct exact recipe preimages, then test the wakeup patch without a build."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import shutil
import subprocess
import sys
from urllib.request import urlopen
import zipfile
import veux_update_engine as e
import veux_wakeup_fixes as wakeup
import veux_frozen_components as frozen


def check(work, source=None):
    cfg, _ = e.check_repo()
    frozen.load_contract(cfg)
    folder, data, _ = wakeup.load()
    work.mkdir(parents=True, exist_ok=False)
    stage = work / 'source'
    def fetch(item):
        name, row = item
        if row['vendor_sha256'] is None:
            return
        target = stage / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if source is None:
            url = data['vendor_url'] + data['vendor_commit'] + '/' + name
            with urlopen(url, timeout=60) as response:
                target.write_bytes(response.read())
        else:
            shutil.copyfile(source / name, target)
        e.require(e.digest(target) == row['vendor_sha256'], 'wakeup vendor drift: ' + name)
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(fetch, data['files'].items()))
    archive = wakeup.path_in(e.REPO, data['restore']['archive'])
    e.require(e.digest(archive) == data['restore']['sha256'], 'wakeup restore kit drift')
    includes = ['--include=' + n for n,r in data['files'].items() if r['vendor_sha256'] is not None]
    with zipfile.ZipFile(archive) as z:
        for i, (name, digest) in enumerate(data['restore']['patches'].items()):
            patch = work / ('restore-' + str(i) + '.patch')
            patch.write_bytes(z.read(name))
            e.require(e.digest(patch) == digest, 'wakeup restore patch drift')
            e.run(['git', 'apply', '--check', '--whitespace=error', *includes, patch], cwd=stage)
            e.run(['git', 'apply', '--whitespace=error', *includes, patch], cwd=stage)
    expected = {n:r['before_sha256'] for n,r in data['files'].items()}
    e.require(wakeup.inventory(stage, data) == expected, 'wakeup recipe preimage mismatch')
    proof = wakeup.apply(stage, wakeup.KERNEL, work)
    wakeup.verify_source(stage, wakeup.KERNEL, proof)
    e.require(wakeup.apply(stage, wakeup.KERNEL, work) == proof, 'wakeup reapply changed proof')
    wakeup.verify_source(stage, wakeup.KERNEL, proof)
    e.write_json(work / 'PREFLIGHT.json', dict(schema=1, wakeup_fixes=proof,
                 source_recipe=True, reapply=True, kernel_build=False, device=False))
    print('WAKEUP_PREFLIGHT=PASS; REAPPLY=PASS; KERNEL_BUILD=NOT_RUN; DEVICE_PASS=NO')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--work',type=Path,required=True)
    p.add_argument('--source',type=Path,help='local raw vendor files; hashes remain mandatory')
    args=p.parse_args()
    try:
        check(args.work,args.source)
    except (e.Blocked,OSError,ValueError,KeyError,subprocess.SubprocessError) as exc:
        print('BLOCKED: '+str(exc),file=sys.stderr)
        return 1
    return 0

if __name__=='__main__':
    raise SystemExit(main())
