#!/usr/bin/env python3
"""Prepare a separate, NOT flashable SWEET candidate. No network, make, or repo writes.

Usage: python3 common/scripts/sweet/prepare_candidate_r5.py \
  --source /path/to/pristine/sweet_k6a-r-oss --output /path/to/new/candidate
Requires Python 3.10+ and Git. The input is never modified.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
LOCK = ROOT / 'lineages/sweet/candidates/r5.json'


def digest_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def git_object(kind: bytes, data: bytes) -> bytes:
    return hashlib.sha1(kind + b' ' + str(len(data)).encode('ascii') + b'\0' + data).digest()


def tree_identity(root: Path) -> tuple[str, dict[str, dict[str, str]]]:
    """Hash the complete working tree, excluding only root .git; never follow links."""
    files: dict[str, dict[str, str]] = {}
    def visit(directory: Path) -> bytes:
        entries = []
        for p in directory.iterdir():
            if directory == root and p.name == '.git':
                continue
            st = p.lstat()
            if stat.S_ISLNK(st.st_mode):
                mode = '120000'; sha = git_object(b'blob', os.fsencode(os.readlink(p)))
            elif stat.S_ISDIR(st.st_mode):
                entries.append((os.fsencode(p.name) + b'/', b'40000 ' + os.fsencode(p.name) + b'\0' + visit(p)))
                continue
            elif stat.S_ISREG(st.st_mode):
                mode = '100755' if st.st_mode & stat.S_IXUSR else '100644'
                h = hashlib.sha1(b'blob ' + str(st.st_size).encode('ascii') + b'\0')
                with p.open('rb') as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                        h.update(chunk)
                sha = h.digest()
            else:
                raise ValueError(f'Unsupported filesystem object: {p}')
            files[p.relative_to(root).as_posix()] = {'mode': mode, 'git_blob': sha.hex()}
            entries.append((os.fsencode(p.name), mode.encode() + b' ' + os.fsencode(p.name) + b'\0' + sha))
        return git_object(b'tree', b''.join(value for _, value in sorted(entries)))
    result = visit(root).hex()
    return result, files


def prepare(source: Path, output: Path, lock: dict[str, Any], root: Path = ROOT) -> dict[str, Any]:
    source = source.resolve(); output = output.resolve()
    if not source.is_dir():
        raise ValueError('Input source directory does not exist')
    if output.exists() or output.is_relative_to(source):
        raise ValueError('Output must be a NEW directory outside the input source')
    print('Verifying complete OEM tree...', file=sys.stderr, flush=True)
    identity, original_files = tree_identity(source)
    if identity != lock['base_tree']:
        raise ValueError(f'Input is not the pristine pinned OEM tree: {identity}')
    # Verify every package input before creating the candidate.
    patches = []
    for item in lock['patches']:
        patch = (root / item['path']).resolve()
        if not patch.is_relative_to(root.resolve()) or digest_file(patch) != item['sha256']:
            raise ValueError(f'Patch integrity mismatch: {item["path"]}')
        patches.append(patch)
    def ignore(directory: str, names: list[str]) -> list[str]:
        return ['.git'] if Path(directory).resolve() == source and '.git' in names else []
    print('Copying to a new working directory...', file=sys.stderr, flush=True)
    shutil.copytree(source, output, symlinks=True, ignore=ignore)
    print('Applying verified patch series...', file=sys.stderr, flush=True)
    for patch in patches:
        subprocess.run(['git', 'apply', '--check', str(patch)], cwd=output, check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        subprocess.run(['git', 'apply', '--whitespace=nowarn', str(patch)], cwd=output, check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    print('Verifying entire candidate tree...', file=sys.stderr, flush=True)
    candidate_tree, candidate_files = tree_identity(output)
    changed = sorted(p for p in original_files.keys() | candidate_files.keys()
                     if original_files.get(p) != candidate_files.get(p))
    expected = sorted(m['path'] for m in lock['changed_files'])
    if changed != expected:
        raise ValueError(f'Unexpected changed-file set: {changed}')
    for item in lock['changed_files']:
        if digest_file(output / item['path']) != item['after_sha256']:
            raise ValueError(f'Candidate content mismatch: {item["path"]}')
    print('Rechecking original tree...', file=sys.stderr, flush=True)
    after_tree, _ = tree_identity(source)
    if after_tree != identity:
        raise ValueError('Original source changed during preparation')
    return {'base_commit': lock['base_commit'], 'base_tree': identity,
            'candidate_tree_before_make': candidate_tree, 'changed_files': changed,
            'original_unchanged': True, 'source_preparation_passed': True,
            'kernel_built': False, 'flashable': False,
            'note': 'This prepares source only. Missing MILLET/UFS/MIUI parts remain blockers.'}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--source', required=True, type=Path)
    ap.add_argument('--output', required=True, type=Path)
    a = ap.parse_args()
    try:
        lock = json.loads(LOCK.read_text(encoding='utf-8'))
        result = prepare(a.source, a.output, lock)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
            print(exc.stderr.decode(errors='replace'), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
