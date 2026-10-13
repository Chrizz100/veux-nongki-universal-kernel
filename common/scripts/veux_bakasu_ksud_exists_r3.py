#!/usr/bin/env python3
"""VEUX source-only, exact-identity BakaSU execve/ksud fix (64814408).

This is NOT a BakaSU HEAD upgrade. Keep base BakaSU 35222, fa12/R4 SELinux,
Unhook R1, SUSFS 2.3.0 and NoMount21. The upstream commit touches only
sucompat.c, and the tiny port drops its now-unused `struct path kpath;`
from the affected function to keep kernel builds warning-clean.

No repo changes, no pin changes, no GitHub writes, no compiled/device approval.
Only the disposable Linux 5.4.274 kernel sources are modified.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import subprocess

PIN = '5b76b884c75f729a220bb317aa4a4fc78f0e0e9c'
COMMIT = '648144087efd32f5fe68982e8cbf5efc1576038a'
PARENT = 'f4435f007b16f61705089ff982e3f981a6017979'
REL = 'kernel/feature/sucompat.c'
SRC = 'KernelSU/' + REL
BASE_BLOB = '8dbbd847a0e059397f96351e4fef124b775b169c'
UPSTREAM_BLOB = '42e01ebfffe1ff3f40579b8053767ecb5777c0fb'
R4_UNHOOK_BLOB_SHA256 = 'be787e0cab3c366c3a8f8dc4662a711370a9e50a137adbdb753ab65b11067f88'
R4_UNHOOK = 'KernelSU/kernel/feature/selinux_hide.c'
BLOCKER = b'$(error Please wait susfs update.)'
FUNC_START = b'static inline int do_ksu_handle_execveat_sucompat('
FUNC_END = b'\n// fd, filename, argv, envp, flags and retval'
UNUSED = b'    struct path kpath;\n'

class SafetyStop(RuntimeError):
    pass

def check(ok: bool, reason: str) -> None:
    if not ok:
        raise SafetyStop(reason)

def git_blob(data: bytes) -> str:
    return hashlib.sha1(b'blob '+str(len(data)).encode()+b'\x00'+data).hexdigest()

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def git(donor: Path, *args: str, binary: bool = False) -> bytes | str:
    cmd=['git','-C',str(donor),*args]
    p=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120,check=False)
    check(p.returncode == 0, 'GIT_SOURCE_PROOF_FAILED '+ ' '.join(args[:2]) + ' rc='+str(p.returncode))
    return p.stdout if binary else p.stdout.decode().strip()

def verify_upstream(donor: Path) -> tuple[bytes, bytes, dict]:
    check(donor.is_dir() and (donor/'.git').exists(),'SOURCE_DONOR_MISSING')
    check(git(donor,'rev-parse','HEAD') == PIN,'FROZEN_BAKASU_PIN_DRIFT')
    check(not git(donor,'status','--porcelain'),'SOURCE_DONOR_DIRTY')
    check(git(donor,'rev-parse',COMMIT+'^') == PARENT,'COMMIT_648_PARENT_DRIFT')
    git(donor,'merge-base','--is-ancestor',PIN,COMMIT)
    names=git(donor,'diff-tree','--no-commit-id','--name-only','-r',COMMIT).splitlines()
    check(names == [REL], 'COMMIT_648_UNEXPECTED_SCOPE '+repr(names))
    old=git(donor,'show',PIN+':'+REL,binary=True)
    new=git(donor,'show',COMMIT+':'+REL,binary=True)
    check(git_blob(old)==BASE_BLOB,'BAKASU_35222_SUCOMPAT_BLOB_DRIFT')
    check(git_blob(new)==UPSTREAM_BLOB,'BAKASU_648_SUCOMPAT_BLOB_DRIFT')
    base_compat=git(donor,'show',PIN+':kernel/tools/susfs_compat.mk',binary=True)
    new_compat=git(donor,'show',COMMIT+':kernel/tools/susfs_compat.mk',binary=True)
    check(BLOCKER not in base_compat and BLOCKER in new_compat,
          'UPSTREAM_SUSFS_BUILD_SUSPENSION_PROVENANCE_DRIFT')
    return old,new,{'frozen_base_commit':PIN,'isolated_upstream_commit':COMMIT,
                    'commit_parent':PARENT,'changed_upstream_paths':[REL],
                    'base_git_blob':BASE_BLOB,'upstream_git_blob':UPSTREAM_BLOB,
                    'upstream_susfs_build_suspension_retained_at_head':True,
                    'upstream_susfs_build_suspension_not_mutated':True}

def func(data: bytes) -> bytes:
    check(data.count(FUNC_START)==1 and data.count(FUNC_END)==1,
          'SUCOMPAT_EXEC_FUNCTION_BOUNDARY_CHANGED')
    return data.split(FUNC_START,1)[1].split(FUNC_END,1)[0]

def rewrite_exact(old: bytes,new: bytes,*,verify_blobs:bool=True) -> tuple[bytes,dict]:
    if verify_blobs:
        check(git_blob(old)==BASE_BLOB,'SUCOMPAT_REAL_35222_SOURCE_DRIFT')
        check(git_blob(new)==UPSTREAM_BLOB,'SUCOMPAT_REAL_648_UPSTREAM_DRIFT')
    before=func(old);after=func(new)
    check(before!=after and len(before)>300 and len(after)>300,
          'SUCOMPAT_FUNCTION_DELTA_MISSING')
    check(before.count(UNUSED)==1 and after.count(UNUSED)==1,
          'UPSTREAM_UNUSED_PATH_VARIABLE_DRIFT')
    # Confirm that the complete upstream change is strictly this one function.
    old_prefix,old_suffix=old.split(FUNC_START,1)
    new_prefix,new_suffix=new.split(FUNC_START,1)
    check(old_prefix == new_prefix,'SUCOMPAT_UNRELATED_PREAMBLE_CHANGE')
    check(old_suffix.split(FUNC_END,1)[1]==new_suffix.split(FUNC_END,1)[1],
          'SUCOMPAT_UNRELATED_TRAILER_CHANGE')
    check(b'override_creds(ksu_cred)' in after and b'is_ksud_exists()' in after
          and b'revert_creds(old_cred)' in after,
          'SUCOMPAT_MISSING_CREDENTIAL_CHECK')
    check(after.count(b'revert_creds(old_cred)')==2,
          'SUCOMPAT_CREDENTIAL_BALANCE_DRIFT')
    check(after.find(b'return -EINVAL;') < after.find(b'escape_with_root_profile()')
          and after.find(b'is_ksud_exists()') < after.find(b'escape_with_root_profile()'),
          'SUCOMPAT_ESCALATION_BEFORE_KSUD_CHECK')
    check(b'fallback to /system/bin/sh' in before and
          b'fallback to /system/bin/sh' not in after and
          b'memcpy((void *)filename, ksud_path' in after,
          'SUCOMPAT_DAEMON_FALLBACK_NOT_REMOVED')
    # One upstream-unused local (kpath) is removed; all other 648 C source
    # content is preserved byte-for-byte from the official commit.
    clean=after.replace(UNUSED,b'',1)
    check(UNUSED not in clean,'SUCOMPAT_KPATH_DECL_REMAINS')
    out=new.replace(FUNC_START+after,FUNC_START+clean,1)
    check(out.count(FUNC_START)==1 and func(out)==clean and out!=old,
          'SUCOMPAT_PORT_NOT_EXACT')
    check(out.replace(FUNC_START+clean,FUNC_START+after,1)==new,
          'SUCOMPAT_ADAPTATION_NOT_RECONSTRUCTIBLE')
    return out,{'source_only':True,'modified_kernel_paths':[SRC],
                'before_sha256':sha256(old),'upstream_post_sha256':sha256(new),
                'after_sha256':sha256(out),'official_upstream_function_restorable':True,
                'unused_upstream_kpath_decl_removed':True,
                'ksud_absent_does_not_redirect_to_root_shell':True,
                'credentials_reverted_on_both_paths':True,
                'no_kernel_build':True,'no_device_pass':True,
                'no_version_or_susfs_pin_promotion':True}

def apply_648_source_only(src:Path,donor:Path,report:Path) -> dict:
    """Only run on ephemeral VEUX 5.4.274 workspace after R4 SELinux guard."""
    src=src.resolve(strict=True)
    donor=donor.resolve(strict=True)
    check(src.name=='kernel','BAKASU_PORT_UNSUPPORTED_WORKSPACE')
    mk=src/'Makefile'
    check(mk.is_file() and not mk.is_symlink(),'BAKASU_PORT_KERNEL_MAKEFILE_MISSING')
    mktext=mk.read_text()
    check(re.search(r'(?m)^VERSION\s*=\s*5\s*$',mktext) is not None and
          re.search(r'(?m)^PATCHLEVEL\s*=\s*4\s*$',mktext) is not None,
          'BAKASU_PORT_KERNEL_MUST_BE_5_4')
    build=src/'drivers/kernelsu';vendor=src/'KernelSU/kernel'
    check(build.exists() and vendor.is_dir() and
          build.resolve(strict=True)==vendor.resolve(strict=True),
          'BAKASU_PORT_KERNEL_SOURCE_LAYOUT_DRIFT')
    hook=src/R4_UNHOOK
    check(hook.is_file() and not hook.is_symlink() and
          sha256(hook.read_bytes())==R4_UNHOOK_BLOB_SHA256,
          'BAKASU_PORT_R4_UNHOOK_MISSING')
    path=src/SRC
    check(path.is_file() and not path.is_symlink() and
          path.resolve(strict=True).is_relative_to(src),
          'BAKASU_PORT_SOURCE_PATH_UNSAFE')
    check(not report.exists() and not report.is_symlink() and
          not report.resolve().is_relative_to(src) and
          not report.resolve().is_relative_to(donor),
          'BAKASU_PORT_REPORT_PATH_UNSAFE')
    pinned,new,provenance=verify_upstream(donor)
    current=path.read_bytes()
    check(current==pinned,'BAKASU_PORT_EFFECTIVE_35222_SOURCE_DIFFERS_FROM_GIT')
    out,proof=rewrite_exact(current,new)
    proof['provenance']=provenance
    check(path.read_bytes()==current,'BAKASU_PORT_SOURCE_RACED')
    try:
        path.write_bytes(out)
        check(path.read_bytes()==out,'BAKASU_PORT_WRITE_VALIDATION_FAILED')
        report.parent.mkdir(parents=True,exist_ok=True)
        report.write_text(json.dumps(proof,indent=2,sort_keys=True)+'\n')
    except Exception:
        if path.exists() and path.read_bytes()!=current:
            path.write_bytes(current)
        raise
    print('VEUX_BAKASU_648_SUCOMPAT_SOURCE=PASS; KSUD_ABSENCE_FIX=STAGED; '
          'PIN_PROMOTION=NO; KERNEL_BUILD=NO; DEVICE_PASS=NO',flush=True)
    return proof
