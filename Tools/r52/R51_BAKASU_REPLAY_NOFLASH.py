#!/usr/bin/env python3
"""VEUX R51: isolated 5-commit BakaSU replay; no device/boot/kernel build.

Real source modification occurs *only* in the explicitly supplied new sandbox
--output, never in --local-port or --upstream. Commit identities are pinned.
An exit code of 0 indicates only a reproducible source replay, NOT a build gate.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

MAIN_HEAD = '516d3e87fbc986ccefdde2c2765f1700612441a9'
OFFICIAL_BASE = 'd5e9e025b8b49155f8014684d64c91742b465f65'
LOCAL_FIRST = '2cbbcc2363aa8d4b6286fc2266a338063b2b77a7'
LOCAL_SECOND = 'd2537b13ab15fce72e8c0d99e7788805f071aeb4'
R41_SHA256 = 'e9ea57fc1feb8d4d0e840a61b21174ad1d83d496216794bd9285b40f17026bff'
UPSTREAM_SEQUENCE = [
    '5785bdb8091304322f597f67d50e0b79f9815cb2',
    'f98b7a5b909910e1830cae8a2f9c78a61f1f6c2a',
    'e5473cdf25ce0285fcb4977396a9c0585a0e2d91',
    '01c11c70b4a49a756f7fa4b2ec13f2dbbe6f6abb',
    MAIN_HEAD,
]
# ALL 11 upstream-delta paths; VEUX's five local modifications are protected separately.
EXPECTED_CHANGE_PATHS = {
    '.github/workflows/build-manager.yml',
    'kernel/Kbuild', 'kernel/core/init.c', 'kernel/infra/btf_parser.c',
    'kernel/infra/btf_parser.h', 'kernel/infra/file_wrapper.c',
    'kernel/selinux/inode.c', 'kernel/selinux/selinux.h',
    'scripts/ksubot.py', 'userspace/ksud/src/boot_patch.rs',
    'userspace/ksuinit/src/init.rs',
}
PROTECTED_PORT_FILES = (
    'kernel/feature/selinux_hide.c',
    'kernel/feature/sucompat.c',
    'kernel/feature/sucompat.h',
    'kernel/manager/throne_tracker.c',
    'kernel/supercall/dispatch.c',
)

class GateError(RuntimeError):
    pass

def must(value, message):
    if not value:
        raise GateError(message)

def sha256(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for part in iter(lambda: stream.read(1024*1024), b''):
            h.update(part)
    return h.hexdigest()

def run(cwd, *args, env=None, allow_fail=False):
    result = subprocess.run(['git', '-C', str(cwd), *args], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    if result.returncode and not allow_fail:
        raise GateError('GIT_STEP_FAILED:'+str(args[0])+':'+(result.stderr[-700:] or str(result.returncode)))
    return result

def output(cwd, *args):
    return run(cwd, *args).stdout.strip()

def blob(cwd, rev, path):
    r=run(cwd, 'show', rev+':'+path)
    return r.stdout.encode('utf-8')

def inspect_history(local, upstream, pins):
    base, first, second, new, sequence=pins
    for path in (local,upstream):
        must(path.is_dir() and not path.is_symlink(), 'MISSING_GIT_DIRECTORY')
        must(output(path, 'rev-parse', '--is-inside-work-tree')=='true', 'NOT_GIT_WORKTREE')
        must(output(path, 'rev-parse', '--is-shallow-repository')=='false', 'SHALLOW_HISTORY_NOT_ALLOWED')
        must(not output(path,'status','--porcelain','--untracked-files=all'), 'DIRTY_SOURCE_REFUSED')
    must(output(local,'rev-parse','HEAD')==second, 'R13_LOCAL_PORT_NOT_EXACT')
    if pins[2]==LOCAL_SECOND:
        must(output(local,'rev-list','--count','HEAD')=='4554', 'R13_LOCAL_PORT_COUNT_CHANGED')
    must(output(local,'rev-parse','HEAD^')==first, 'R13_LOCAL_PARENT_MISMATCH')
    must(output(local,'rev-parse','HEAD^^')==base, 'R13_LOCAL_GRANDPARENT_MISMATCH')
    must(output(upstream,'rev-parse','HEAD')==new,'BAKASU_UPSTREAM_HEAD_CHANGED')
    must(output(local,'rev-parse','--is-shallow-repository')=='false', 'R13_SHALLOW_CHECKOUT')
    must(run(upstream,'merge-base','--is-ancestor',base,new,allow_fail=True).returncode==0,
         'BAKASU_UPSTREAM_REWROTE_BASE')
    commits=output(upstream,'rev-list','--reverse',base+'..'+new).splitlines()
    must(commits==sequence, 'BAKASU_FIVE_COMMITS_CHANGED_OR_REORDERED')
    # Local preservation is provable as exact blobs, not by grepping for hooks.
    protected={p:output(local,'rev-parse',second+':'+p) for p in PROTECTED_PORT_FILES}
    must(all(len(x)==40 for x in protected.values()), 'MISSING_LOCAL_PORT_BLOB')
    return protected

def replay(local:Path, upstream:Path, destination:Path, r41:Path,
           pins=(OFFICIAL_BASE,LOCAL_FIRST,LOCAL_SECOND,MAIN_HEAD,UPSTREAM_SEQUENCE),
           allow_test_only=False):
    must(r41.is_file() and not r41.is_symlink(), 'R41_PACKAGE_MISSING_OR_LINKED')
    if not allow_test_only:
        must(sha256(r41)==R41_SHA256,'R41_SOURCE_HASH_MISMATCH')
    protected=inspect_history(local,upstream,pins)
    base, first, second, new, sequence=pins
    must(not destination.exists() and not destination.is_symlink(),'OUTPUT_EXISTS_NO_OVERWRITE')
    must(destination.parent.is_dir() and not destination.parent.is_symlink(), 'OUTPUT_PARENT_INVALID')
    must(not any(destination.resolve().is_relative_to(x.resolve()) for x in (local,upstream)),
         'OUTPUT_INSIDE_SOURCE_ROOT')
    # no git object sharing: this is a *new* worktree, never the original R13.
    run(local,'clone','--quiet','--no-hardlinks','--no-checkout',str(local),str(destination))
    try:
        # Clone subcommand above has `-C local`, but creates only destination.
        run(destination,'fetch','--no-tags','--quiet',str(upstream),new)
        must(output(destination,'rev-parse','FETCH_HEAD')==new,'UPSTREAM_FETCH_SHA_MISMATCH')
        run(destination,'checkout','--quiet','--detach',new)
        env=dict(os.environ)
        env.update({'GIT_COMMITTER_NAME':'VEUX source replay',
                    'GIT_COMMITTER_EMAIL':'veux-replay@localhost.invalid',
                    'GIT_COMMITTER_DATE':'2026-11-01T00:00:00+00:00'})
        # Cherry-pick retains the original author; the SHA/tree is reported below.
        for c in (first,second):
            run(destination,'cherry-pick','-x','--no-gpg-sign',c,env=env)
        must(output(destination,'rev-list','--count',new+'..HEAD')=='2',
             'BAKASU_LOCAL_PORT_COMMIT_COUNT_CHANGED')
        must(not output(destination,'status','--porcelain','--untracked-files=all'),
             'BAKASU_SOURCE_NOT_CLEAN')
        for path,blob_sha in protected.items():
            must(output(destination,'rev-parse','HEAD:'+path)==blob_sha,
                 'VEUX_PROTECTED_LOCAL_PORT_CHANGED:'+path)
        new_files=set(output(destination,'diff','--name-only',second+'..HEAD').splitlines())
        if not allow_test_only:
            must(new_files==EXPECTED_CHANGE_PATHS,
                 'UNEXPECTED_BAKASU_DELTA_PATHS:'+repr(sorted(new_files^EXPECTED_CHANGE_PATHS)))
        if not allow_test_only:
            # Upstream BTF fix targets 6.6 modules; ensure a built-in 5.4 fallback
            # remains in source. This is a source guard, NOT a compile proof.
            inode=(destination/'kernel/selinux/inode.c').read_text()
            header=(destination/'kernel/selinux/selinux.h').read_text()
            init=(destination/'kernel/core/init.c').read_text()
            wrapper=(destination/'kernel/infra/file_wrapper.c').read_text()
            must('#if defined(MODULE) && defined(CONFIG_DEBUG_INFO_BTF)' in inode and
                 'return selinux_inode(inode);' in inode,
                 'NATIVE54_BUILTIN_SELINUX_FALLBACK_MISSING')
            must('#if defined(MODULE) && defined(CONFIG_DEBUG_INFO_BTF)' in header,
                 'NATIVE54_BTF_HEADER_GUARD_MISSING')
            must('ksu_selinux_inode_init()' in init and 'ksu_selinux_inode(' in wrapper,
                 'BTF_UPSTREAM_SOURCE_INCOMPLETE')
        # Verify the 5 upstream commits and the 2 local changes form the history.
        ancestry=output(destination,'rev-list','--reverse',base+'..HEAD').splitlines()
        must(ancestry[:len(sequence)]==sequence and len(ancestry)==len(sequence)+2,
             'REPLAY_ANCESTRY_INVALID')
        version_count=int(output(destination,'rev-list','--count','HEAD'))
        if not allow_test_only:
            must(version_count==4559, 'BAKASU_REPLAY_GIT_COUNT_CHANGED')
        proof={'schema':'VEUX_R51_BAKASU_REPLAY_NOFLASH_V1',
             'status':'BAKASU_ISOLATED_REPLAY_PASS__KERNEL_NOT_BUILT__SUSFS_NOT_MERGED__NO_FLASH',
             'original_port':second,'new_official_head':new,
             'applied_official_commits':sequence,
             'local_port_commits_replayed':[first,second],
             'result_commit':output(destination,'rev-parse','HEAD'),
             'result_tree':output(destination,'rev-parse','HEAD^{tree}'),
             'genuine_git_commit_count':version_count,
             'calculated_source_version':30700+version_count,
             'protected_port_blobs':protected,'changed_paths':sorted(new_files),
             'source_directory':str(destination),
             'kernel_compiled':False,'flash_allowed':False,'susfs_native54_merged':False}
        # Place receipt OUTSIDE Git worktree to keep identity/cleanliness preserved.
        return proof
    except Exception:
        # Intentionally preserve failed directory for offline review; never touch local/upstream.
        raise

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--local-port',type=Path,required=True)
    p.add_argument('--upstream',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--r41',type=Path,required=True)
    p.add_argument('--receipt',type=Path,required=True)
    a=p.parse_args()
    try:
        must(a.receipt.parent.is_dir() and not a.receipt.exists(), 'RECEIPT_ALREADY_EXISTS')
        must(not any(a.receipt.resolve().is_relative_to(x.resolve()) for x in
                     (a.local_port,a.upstream,a.output)),
             'RECEIPT_CANNOT_CHANGE_SOURCE_OR_CANDIDATE')
        proof=replay(a.local_port,a.upstream,a.output,a.r41)
        a.receipt.write_text(json.dumps(proof,sort_keys=True,indent=2)+'\n')
        print(proof['status'])
    except (GateError,OSError,ValueError) as exc:
        print('R51_BAKASU_REPLAY_BLOCKED: '+str(exc),file=sys.stderr)
        return 2
    return 0

if __name__=='__main__':
    sys.exit(main())
