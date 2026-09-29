#!/usr/bin/env python3
"""Source-recipe entry point with an exact clang-r547379 download fallback."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import veux_update_engine as e


PIN = {
    'url': 'https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86/+archive/d19c99c180cfa21504426915d765b5e7adf878b6/clang-r547379.tar.gz',
    'repo': 'https://github.com/msft-mirror-aosp/platform.prebuilts.clang.host.linux-x86.git',
    'commit': 'd19c99c180cfa21504426915d765b5e7adf878b6',
    'root_tree': 'bbded716da5e381be98b773ed70608f1e6ca4edb',
    'subdir': 'clang-r547379',
    'subtree': '87fc9823e3f7d1adb0433de49a5331bc6404d03b',
}


def materialize(label, work):
    # The frozen materializer uses HERE only to select the make/curl shim
    # entry point. Keep its source, REPO, recipe hashes and build capture intact.
    previous = e.HERE
    try:
        e.HERE = Path(__file__).resolve()
        return e.materialize(label, work)
    finally:
        e.HERE = previous


def primary_download(args):
    try:
        return subprocess.run(['/usr/bin/curl', *args], timeout=180).returncode == 0
    except subprocess.TimeoutExpired:
        return False


def transport_curl(args):
    if PIN['url'] not in args:
        # In particular, retain the already authenticated r416183b fallback.
        return e.transport_curl(args)
    outputs = [args[i + 1] for i, arg in enumerate(args[:-1]) if arg in ('-o', '--output')]
    e.require(len(outputs) == 1, 'clang-r547379 request needs one explicit output')
    output = Path(outputs[0]).resolve()
    roots = [Path(os.environ[k]).resolve() for k in ('VEUX_SOURCE_WORK', 'VEUX_TRANSPORT_WORK')]
    e.require(any(output.is_relative_to(root) for root in roots), 'clang output escapes temporary workspace')
    if primary_download(args):
        return
    # Export only the exact subtree from the exact historical commit. A moving
    # branch, a different compiler release or BUILD_INFO alone is insufficient.
    print('CLANG_PRIMARY_FAILED=r547379; trying pinned GitHub mirror', flush=True)
    with tempfile.TemporaryDirectory(prefix='clang-r547379-', dir=roots[1]) as tmp:
        mirror = Path(tmp)
        e.git(mirror, 'init', '-q')
        e.git(mirror, 'remote', 'add', 'origin', PIN['repo'])
        e.git(mirror, 'config', 'remote.origin.promisor', 'true')
        e.git(mirror, 'config', 'remote.origin.partialclonefilter', 'blob:none')
        e.run(['git', '-C', mirror, 'fetch', '--quiet', '--depth=1', '--filter=blob:none',
               'origin', PIN['commit']], timeout=600)
        e.require(e.git(mirror, 'rev-parse', 'FETCH_HEAD') == PIN['commit'], 'clang mirror commit mismatch')
        e.require(e.git(mirror, 'rev-parse', 'FETCH_HEAD^{tree}') == PIN['root_tree'], 'clang mirror root tree mismatch')
        e.require(e.git(mirror, 'rev-parse', 'FETCH_HEAD:' + PIN['subdir']) == PIN['subtree'],
                  'clang mirror subtree mismatch')
        e.git(mirror, 'sparse-checkout', 'init', '--cone')
        e.git(mirror, 'sparse-checkout', 'set', PIN['subdir'])
        e.git(mirror, 'checkout', '--quiet', '--detach', 'FETCH_HEAD')
        archive = mirror / 'clang.tar.gz'
        e.git(mirror, 'archive', '--format=tar.gz', '--output=' + str(archive),
              PIN['commit'] + ':' + PIN['subdir'])
        e.require(archive.stat().st_size > 0, 'empty clang mirror archive')
        archive.replace(output)
    print(f'CLANG_TRANSPORT=AUTHENTICATED_GITHUB_MIRROR; compiler=r547379; commit={PIN["commit"]}', flush=True)


def main():
    command, *args = sys.argv[1:]
    if args[:1] == ['--']:
        args = args[1:]
    if command == 'capture-make':
        e.capture_make(args)
    elif command == 'transport-curl':
        transport_curl(args)
    else:
        raise e.Blocked('unsupported source entry point: ' + command)


if __name__ == '__main__':
    try:
        main()
    except (e.Blocked, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(f'BLOCKED: {exc}', file=sys.stderr)
        raise SystemExit(1)
