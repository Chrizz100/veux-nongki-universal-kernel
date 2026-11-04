#!/usr/bin/env python3
"""R60 targeted runner fix: execute authenticated R58 tests with the installed venv.

No kernel, sources, component pins, archive hashes, or flash rules are changed.
Strictly guards the exact GitHub workflow from run 41787370004 / commit b814b104.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import sys

WORKFLOW = Path('.github/workflows/VEUX_R60_NATIVE54_CASS_BUILD_NOFLASH.yml')
EXPECTED_ORIGINAL_BLOB = '5778ffae561dc06a5cb55f5505f1e3935b8d2b1f'
EXPECTED_PATCHED_BLOB = 'bc7eef083ae21b1d16dc7190aae717a367c391f1'
OLD_LINE = '        python3 -B -m unittest discover -s "$RUNNER_TEMP/veux-r58-payload/tests" -p \'test_*.py\' -v\n'
NEW_LINE = '        "$R5S2_PY" -B -m unittest discover -s "$RUNNER_TEMP/veux-r58-payload/tests" -p \'test_*.py\' -v\n'


def git_blob_sha(blob: bytes) -> str:
    return hashlib.sha1(b'blob ' + str(len(blob)).encode() + b'\0' + blob).hexdigest()


def apply(data: bytes) -> bytes:
    if git_blob_sha(data) != EXPECTED_ORIGINAL_BLOB:
        raise ValueError('WRONG_GITHUB_WORKFLOW_VERSION; no changes made')
    raw = data.decode('utf-8')
    if raw.count(OLD_LINE) != 1 or raw.count(NEW_LINE) != 0:
        raise ValueError('UNEXPECTED_R58_TEST_RUNNER_ANCHOR; no changes made')
    patched = raw.replace(OLD_LINE, NEW_LINE, 1).encode('utf-8')
    if git_blob_sha(patched) != EXPECTED_PATCHED_BLOB:
        raise ValueError('PATCHED_GIT_BLOB_MISMATCH; no changes made')
    return patched


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', default=str(WORKFLOW), type=Path,
                        help='Original repository workflow (default: .github/workflows/...)')
    parser.add_argument('--output', type=Path, help='Patched output path, default: *_VENV_FIXED.yml next to input')
    parser.add_argument('--in-place', action='store_true', help='Replace exact original after saving .bak backup')
    ns = parser.parse_args()
    if ns.in_place and ns.output is not None:
        parser.error('--output and --in-place cannot be combined')
    source = ns.input.read_bytes()
    old_sha = git_blob_sha(source)
    if old_sha == EXPECTED_PATCHED_BLOB:
        print('ALREADY_PATCHED=PASS; no changes made')
        return
    result = apply(source)
    dest = ns.input if ns.in_place else (ns.output or ns.input.with_name(ns.input.stem + '_VENV_FIXED.yml'))
    if ns.in_place:
        backup = ns.input.with_name(ns.input.name + '.bak')
        if backup.exists() or backup.is_symlink():
            parser.error('Backup file already exists; refusing overwrite')
        backup.write_bytes(source)
    elif dest.exists() or dest.is_symlink():
        parser.error('Output file exists; refusing overwrite')
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(result)
    print('RUNNER_IMPORT_FIX=PASS')
    print('ORIGINAL_GIT_BLOB=' + EXPECTED_ORIGINAL_BLOB)
    print('PATCHED_GIT_BLOB=' + git_blob_sha(result))
    print('PATCHED_SHA256=' + hashlib.sha256(result).hexdigest())
    print('KERNEL_SOURCE_CHANGED=NO')
    print('FLASH_ALLOWED=NO')
    print('OUTPUT=' + str(dest))
    print('NOTE=Static patch only; updated full native54 compiler has not run')


if __name__ == '__main__':
    main()
