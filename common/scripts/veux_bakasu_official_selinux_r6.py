#!/usr/bin/env python3
"""VEUX R6: restore exact upstream BakaSU d7260ca1 SELinux code.

This is *not* a new SELinux implementation. It replaces the temporary R4/R5
source edits with the unchanged, hash-authenticated source from official
BakaSU commit d7260ca1. The frozen 35222 SUSFS pin stays untouched.
All mutations are limited to a disposable CI kernel source workspace.
"""
from __future__ import annotations
import hashlib
import json
import re
import subprocess
from pathlib import Path

SOURCE_PIN = '5b76b884c75f729a220bb317aa4a4fc78f0e0e9c'
UPSTREAM_COMMIT = 'd7260ca1e5c128061122924d0d48754e361e135c'
UPSTREAM_PARENT = '648144087efd32f5fe68982e8cbf5efc1576038a'
HOOK_REL = 'kernel/feature/selinux_hide.c'
HOOK_PATH = 'KernelSU/' + HOOK_REL
OFFICIAL_HOOK_GIT_BLOB = '9864c9cf5171311769564b682a42cc7eecc8a801'
OFFICIAL_COMPAT_GIT_BLOB = '2023956a3faa701198e6e9efcd84300db84d488c'
OFFICIAL_SUCOMPAT_GIT_BLOB = '42e01ebfffe1ff3f40579b8053767ecb5777c0fb'
# R5 real compiled source: genuine run 38518865530, proven with build audit.
R5_EFFECTIVE_SHA256 = '41aa4ff6f3c452cb90fe293ebc7076c3770c58d8bdbbc8b150a4d82b9d81ea71'
R5_COMPAT_SHA256 = '0045b59d0689d1cc4e3cef669622ec3443ea4e0d5f9099ac151625e602fc1983'
R5_SUCOMPAT_SHA256 = '1cd5e5b249d1d144b3231f7a08d3b09eb9b7ab9483cf34b0ffda03097f6b4665'
SUSFS_PIN_GIT_BLOB = '904bad1c251314c5addca6dec944f586a9c602e1'

class SafetyStop(RuntimeError):
    pass

def require(valid: bool, reason: str) -> None:
    if not valid:
        raise SafetyStop(reason)

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def git_blob(data: bytes) -> str:
    return hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()

def git(donor: Path, *args: str, binary: bool = False) -> str | bytes:
    p = subprocess.run(['git','-C',str(donor),*args], capture_output=True,
                       timeout=120, check=False)
    require(p.returncode == 0,
            'R6_UPSTREAM_GIT_ERROR '+str(p.returncode)+':'+p.stderr.decode(errors='replace')[-450:])
    return p.stdout if binary else p.stdout.decode().strip()

def upstream_verified(donor: Path) -> tuple[bytes, dict]:
    donor = donor.resolve(strict=True)
    require((donor/'.git').is_dir(), 'R6_DONOR_GIT_MISSING')
    require(git(donor,'rev-parse','HEAD') == SOURCE_PIN, 'R6_DONOR_PIN_DRIFT')
    require(not git(donor,'status','--porcelain'), 'R6_DONOR_DIRTY')
    require(git(donor,'rev-parse',UPSTREAM_COMMIT+'^') == UPSTREAM_PARENT,
            'R6_OFFICIAL_COMMIT_PARENT_DRIFT')
    git(donor,'merge-base','--is-ancestor',SOURCE_PIN,UPSTREAM_COMMIT)
    changed=set(git(donor,'diff-tree','--no-commit-id','--name-only','-r',UPSTREAM_COMMIT).splitlines())
    require(changed == {HOOK_REL, 'kernel/tools/kernel_compat.mk'},
            'R6_OFFICIAL_COMMIT_SCOPE_DRIFT:'+repr(changed))
    blob=git(donor,'show',UPSTREAM_COMMIT+':'+HOOK_REL,binary=True)
    require(git_blob(blob)==OFFICIAL_HOOK_GIT_BLOB, 'R6_OFFICIAL_SELINUX_BLOB_DRIFT')
    for name,expected in (
        ('kernel/feature/sucompat.c',OFFICIAL_SUCOMPAT_GIT_BLOB),
        ('kernel/tools/kernel_compat.mk',OFFICIAL_COMPAT_GIT_BLOB),
    ):
        data=git(donor,'show',UPSTREAM_COMMIT+':'+name,binary=True)
        require(git_blob(data)==expected,'R6_OFFICIAL_DEPENDENCY_BLOB_DRIFT:'+name)
    require(b'$(error Please wait susfs update.)' in
            git(donor,'show',UPSTREAM_COMMIT+':kernel/tools/susfs_compat.mk',binary=True),
            'R6_UPSTREAM_SUSFS_BLOCKER_PROVENANCE_DRIFT')
    require(git_blob(git(donor,'show',SOURCE_PIN+':kernel/tools/susfs_compat.mk',binary=True))==SUSFS_PIN_GIT_BLOB,
            'R6_PINNED_SUSFS_BASE_DRIFT')
    return blob,{'source_pin':SOURCE_PIN, 'upstream_commit':UPSTREAM_COMMIT,
                 'upstream_parent':UPSTREAM_PARENT, 'official_git_blob':OFFICIAL_HOOK_GIT_BLOB,
                 'official_changed_paths':sorted(changed)}

def validate_exact_source(before: bytes, official: bytes, *, pinned: bool = True) -> dict:
    if pinned:
        require(sha256(before)==R5_EFFECTIVE_SHA256,
                'R6_R5_PREIMAGE_DRIFT expected='+R5_EFFECTIVE_SHA256+' actual='+sha256(before))
        require(git_blob(official)==OFFICIAL_HOOK_GIT_BLOB,
                'R6_OFFICIAL_HOOK_BLOB_NOT_VERIFIED')
    require(before!=official, 'R6_OFFICIAL_SOURCE_ALREADY_INSTALLED')
    for label, content in (('previous',before),('upstream',official)):
        require(b'ksu_handle_selinux_setprocattr(' in content,
                'R6_SETPROCATTR_MISSING:'+label)
        require(b'ksu_security_context_to_sid(' in content,
                'R6_SID_TRANSLATOR_MISSING:'+label)
        require(content.count(b'context_add_hash(policydb, &context)')==1 and
                content.count(b'context_add_hash(orig_policydb, &orig_context)')==1,
                'R6_D726_HASH_FIX_ABSENT:'+label)
        require(b'ksu_selinux_hide_unhook()' in content,
                'R6_SELINUX_UNHOOK_MISSING:'+label)
    # The R5 replacement removed the *R4 comment*, not just the behavior.
    # An exact pinned R5 SHA prevents accepting any earlier R4-only source.
    require(b'VEUX 5.4 source-only parity candidate' in before,
            'R6_EXPECTED_R5_PRESCREEN_NOT_PRESENT')
    require(b'VEUX 5.4: preserve the stock' not in official and
            b'VEUX 5.4 source-only parity candidate' not in official,
            'R6_NONUPSTREAM_SELINUX_WORKAROUND_REMAINS')
    require(b'    commit_creds(new);' in official,
            'R6_UPSTREAM_MANUAL_CREDENTIAL_PATH_NOT_PRESENT')
    return {
        'before_sha256':sha256(before),'after_sha256':sha256(official),
        'upstream_git_blob':git_blob(official),
        'source_matches_official_bakasu_d726_byte_for_byte':True,
        'r4_setprocattr_adapter_not_in_compiled_source':True,
        'r5_backup_policy_prescreen_not_in_compiled_source':True,
        'local_unhook_adapter_not_in_compiled_source':True,
        'd726_context_hash_preserved':True,
        'kernel_build':False,'device_pass':False,'detector_pass':False,
        'susfs_pin_unchanged':True,'upstream_build_blocker_not_patched':True,
        'no_repository_write':True,
    }

def apply_official_source(src: Path, donor: Path, report: Path) -> dict:
    src=src.resolve(strict=True);donor=donor.resolve(strict=True)
    require(src.name=='kernel' and src!=donor, 'R6_INVALID_DISPOSABLE_SOURCE')
    mk=src/'Makefile'
    require(mk.is_file() and not mk.is_symlink(), 'R6_KERNEL_MAKEFILE_UNSAFE')
    txt=mk.read_text()
    require(re.search(r'(?m)^VERSION\s*=\s*5\s*$',txt) is not None and
            re.search(r'(?m)^PATCHLEVEL\s*=\s*4\s*$',txt) is not None,
            'R6_KERNEL_5_4_REQUIRED')
    vendor=src/'KernelSU/kernel';build=src/'drivers/kernelsu'
    require(vendor.is_dir() and build.exists() and
            build.resolve(strict=True)==vendor.resolve(strict=True),
            'R6_KSU_BUILD_SOURCE_LAYOUT_DRIFT')
    target=src/HOOK_PATH
    compat=src/'KernelSU/kernel/tools/kernel_compat.mk'
    sucompat=src/'KernelSU/kernel/feature/sucompat.c'
    susfs=src/'KernelSU/kernel/tools/susfs_compat.mk'
    for path in (target,compat,sucompat,susfs):
        require(path.is_file() and not path.is_symlink() and
                path.resolve(strict=True).is_relative_to(src),
                'R6_SOURCE_FILE_UNSAFE:'+str(path))
    require(not report.exists() and not report.is_symlink() and
            not report.resolve().is_relative_to(src) and
            not report.resolve().is_relative_to(donor),
            'R6_REPORT_PATH_UNSAFE')
    require(sha256(compat.read_bytes()) == R5_COMPAT_SHA256,
            'R6_EFFECTIVE_COMPAT_SHA_DRIFT')
    require(sha256(sucompat.read_bytes()) == R5_SUCOMPAT_SHA256,
            'R6_EFFECTIVE_SUCOMPAT_SHA_DRIFT')
    require(git_blob(susfs.read_bytes()) == SUSFS_PIN_GIT_BLOB,
            'R6_SUSFS_BASE_PIN_MISMATCH')
    official,provenance=upstream_verified(donor)
    previous=target.read_bytes()
    proof=validate_exact_source(previous,official)
    proof['source_provenance']=provenance
    proof['changed_paths']=[HOOK_PATH]
    require(target.read_bytes()==previous, 'R6_CONCURRENT_SOURCE_MUTATION')
    try:
        target.write_bytes(official)
        require(target.read_bytes()==official, 'R6_UPSTREAM_SOURCE_WRITEBACK_FAILED')
        report.parent.mkdir(parents=True,exist_ok=True)
        report.write_text(json.dumps(proof,indent=2,sort_keys=True)+'\n')
    except BaseException:
        if target.is_file() and target.read_bytes()!=previous:
            target.write_bytes(previous)
        raise
    print('VEUX_BAKASU_R6_OFFICIAL_D726=PASS; EXACT_UPSTREAM_SELINUX_C=YES; '
          'R4_R5_RUNTIME_MODS_IN_COMPILED_SOURCE=NO; D726_HASH=YES; '
          'SUSFS_PIN_UNCHANGED; DEVICE_PASS=NO',flush=True)
    return proof
