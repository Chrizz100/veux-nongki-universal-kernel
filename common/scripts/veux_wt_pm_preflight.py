#!/usr/bin/env python3
"""Apply and host-test the cumulative WT PM repair on authenticated vendor files."""
import argparse
from pathlib import Path
import shutil
import subprocess
import sys
from urllib.request import urlopen

import veux_update_engine as e
import veux_device_fixes as fixes
import veux_frozen_components as frozen

SOURCE_COMMIT = 'b2b7a3bbc36d120ee523ebc8d68e0f13a97df632'
SOURCE_URL = 'https://raw.githubusercontent.com/dereference23/kernel_xiaomi_sm6375/' + SOURCE_COMMIT + '/'
HEADER = 'drivers/power/supply/qcom/bq2589x_reg.h'
HEADER_SHA256 = '117e931c2c82d5772ba1435b1ab5243fc5be7e5684ef498bb81648aa8cc3a24d'


def check(work, source=None):
    cfg, _ = e.check_repo()
    frozen.load_contract(cfg)
    _, manifest, _ = fixes.load('5.4.274')
    e.require(manifest['id'] == 'charger-pm-r1', 'wrong WT PM patchset')
    work.mkdir(parents=True, exist_ok=False)
    stage = work / 'source'
    inputs = {r['source']: r['before_sha256'] for r in manifest['files']}
    inputs[HEADER] = HEADER_SHA256
    for name, digest in inputs.items():
        target = stage / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if source is None:
            with urlopen(SOURCE_URL + name, timeout=60) as response:
                target.write_bytes(response.read())
        else:
            shutil.copyfile(source / name, target)
        e.require(e.digest(target) == digest, 'vendor source changed: ' + name)
    proof = fixes.apply(stage, '5.4.274', work)
    fixes.verify_source(stage, '5.4.274', proof)
    # The installer and worker must also accept the exact already-patched result.
    repeated = fixes.apply(stage, '5.4.274', work)
    e.require(repeated == proof, 'repeated application changed proof')
    fixes.verify_source(stage, '5.4.274', repeated)
    e.write_json(work / 'PREFLIGHT.json', dict(
        schema=1, patchset='charger-pm-r1', source_commit=SOURCE_COMMIT,
        source_and_host_tests=True, repeated_application=True, device_fixes=proof,
        kernel_build=False, device=False))
    print('WT_PM_PREFLIGHT=PASS; REAPPLY=PASS; KERNEL_BUILD=NOT_RUN; DEVICE_PASS=NO')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--source', type=Path, help='optional local vendor source; hashes remain mandatory')
    args = parser.parse_args()
    try:
        check(args.work, args.source)
    except (e.Blocked, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print('BLOCKED: ' + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
