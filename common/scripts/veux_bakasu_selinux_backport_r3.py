#!/usr/bin/env python3
"""Audited, fail-closed, temporary-source backport of BakaSU fa12ffde.

The backport is applied to the *already integrated* 35222 VEUX source in an
uncommitted GitHub Actions workspace. No upstream SUSFS build prohibition is
removed, no moving git ref is compiled, and no real-device result is inferred.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

SOURCE_PIN = '5b76b884c75f729a220bb317aa4a4fc78f0e0e9c'
BACKPORT_COMMIT = 'fa12ffde8244008e9afdb7ac0c1bb1bc1b06b95a'
BACKPORT_PARENT = '9097b1a1c6c889756201bbc5713a84a9b23f7908'
# Exact git blob identities: GitHub API, same audited upstream commit.
# These five files are the ENTIRE BakaSU fa12ffde kernel change set.
FILE_BLOBS = {
    'kernel/compat/kernel_compat.h': ('79cc9ff06741b45562c7898890fa50daa157e581', '931179d158c05300045b5775180dcf56f045e5b2'),
    'kernel/feature/selinux_hide.c': ('612de60f9a9fefced88c904025769de941547986', '17e1b61fbd3e85c9c879f678d17fddffa4014734'),
    'kernel/selinux/sepolicy.c': ('0f095801a2a71af3b5cfe8242da5c3b844866a83', '288d55b01ce5c62229843c2ec780b95956eac58c'),
    'kernel/tools/kernel_compat.mk': ('57504d06a3c2b8d8d740a1125c8087213604e3d6', 'dc87d993df5d7e965b5665ecb55758ff2552e70f'),
    'kernel/tools/static_export_check.mk': ('693b21a7d61d58245d8c3eb903d5c54163420f16', 'b2230d6c0043b07ebb634550752fb73fab1f5c55'),
}
KNOWN_SUSFS_35222_BLOB = '904bad1c251314c5addca6dec944f586a9c602e1'
KNOWN_UAPI5_BLOB = '9ba813dc4294fa9633e2a68234b3cf62ab9b514c'

class UnsafeBackport(RuntimeError):
    pass

def checked(ok: bool, explanation: str):
    if not ok:
        raise UnsafeBackport(explanation)

def git_blob(data: bytes) -> str:
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()

def cmd(*args: str, binary: bool = False, timeout: int = 120):
    p = subprocess.run([str(x) for x in args], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=timeout, check=False)
    checked(p.returncode == 0, 'GIT_COMMAND_FAILED rc=' + str(p.returncode) +
            ' stderr=' + p.stderr.decode(errors='replace')[-900:])
    return p.stdout if binary else p.stdout.decode().strip()

def read_commit_blob(donor: Path, sha: str, path: str, expected: str) -> bytes:
    checked(bool(re.fullmatch('[0-9a-f]{40}', sha)), 'INVALID_COMMIT')
    checked(path in FILE_BLOBS, 'UNAPPROVED_KERNEL_FILE ' + path)
    data = cmd('git', '-C', str(donor), 'show', sha + ':' + path, binary=True)
    checked(git_blob(data) == expected, 'UPSTREAM_BLOB_DRIFT ' + path)
    return data

def verify_donor(donor: Path) -> dict:
    donor = donor.resolve(strict=True)
    checked((donor / '.git').exists(), 'DONOR_GIT_MISSING')
    checked(cmd('git','-C',str(donor),'rev-parse','HEAD') == SOURCE_PIN,
            'SOURCE_PIN_MISMATCH')
    checked(not cmd('git','-C',str(donor),'status','--porcelain'), 'DIRTY_SOURCE_DONOR')
    checked(cmd('git','-C',str(donor),'rev-parse',BACKPORT_COMMIT+'^') == BACKPORT_PARENT,
            'UNEXPECTED_BACKPORT_PARENT')
    cmd('git','-C',str(donor),'merge-base','--is-ancestor', SOURCE_PIN, BACKPORT_COMMIT)
    changed = set(cmd('git','-C',str(donor),'diff-tree','--no-commit-id','--name-only','-r',BACKPORT_COMMIT).splitlines())
    checked(changed == set(FILE_BLOBS), 'BACKPORT_SCOPE_DRIFT '+str(sorted(changed)))
    for name, (before, after) in FILE_BLOBS.items():
        read_commit_blob(donor, SOURCE_PIN, name, before)
        read_commit_blob(donor, BACKPORT_COMMIT, name, after)
    for name, expected in (
        ('kernel/tools/susfs_compat.mk',KNOWN_SUSFS_35222_BLOB),
        ('uapi/supercall.h',KNOWN_UAPI5_BLOB),
    ):
        data = cmd('git','-C',str(donor),'show',SOURCE_PIN+':'+name,binary=True)
        checked(git_blob(data)==expected,'PINNED_INTERFACE_DRIFT '+name)
        if name.endswith('susfs_compat.mk'):
            checked(b'$(error Please wait susfs update.)' not in data,
                    'UPSTREAM_SUSFS_STOPPER_MUST_NOT_BE_REMOVED')
    # The later upstream makefile HAS an explicit blocker: prove it remains
    # absent only because this candidate never integrates the 35223 commit.
    future_guard = cmd('git','-C',str(donor),'show',BACKPORT_COMMIT+':kernel/tools/susfs_compat.mk',binary=True)
    checked(b'$(error Please wait susfs update.)' in future_guard,
            'UPSTREAM_BLOCKER_PROVENANCE_CHANGED')
    return {'source_pin':SOURCE_PIN,'isolated_backport':BACKPORT_COMMIT,
            'parent':BACKPORT_PARENT,'files':{n:{'before':a,'after':b} for n,(a,b) in FILE_BLOBS.items()},
            'guard_not_integrated':True,'test_build_required':True}

def apply_source_backport(src: Path, donor: Path, report: Path) -> dict:
    """Validate ALL five source preimages first; then apply only pinned files.

    src is the materialized, temporary VEUX kernel source, never the repo.
    No file is modified if any precondition or upstream identity check fails.
    """
    src=src.resolve(strict=True)
    donor=donor.resolve(strict=True)
    checked(src.name=='kernel' and (src / 'drivers/kernelsu').exists(),
            'UNKNOWN_INTEGRATED_KERNEL_LAYOUT')
    checked(not report.exists(), 'BACKPORT_REPORT_ALREADY_EXISTS')
    checked(src != donor and not donor.is_relative_to(src) and not src.is_relative_to(donor),
            'WORKSPACE_OVERLAP')
    proof=verify_donor(donor)
    vendor=src/'KernelSU'
    checked(vendor.is_dir() and (vendor/'kernel').is_dir(), 'KERNELSU_VENDOR_TREE_MISSING')
    real_vendor=(vendor/'kernel').resolve(strict=True)
    bound=(src/'drivers/kernelsu').resolve(strict=True)
    checked(bound==real_vendor,'KERNELSU_BUILT_TREE_NOT_VENDOR')
    checked(not (src/'drivers/kernelsu').is_symlink() or bound.is_relative_to(src),
            'LINK_ESCAPE')
    stage=[]
    for relative,(before,after) in FILE_BLOBS.items():
        target=vendor/relative
        checked(target.is_file() and not target.is_symlink(),
                'SOURCE_FILE_MISSING_OR_SYMLINK '+relative)
        checked(target.resolve().is_relative_to(src), 'PATH_ESCAPE '+relative)
        original=target.read_bytes()
        checked(git_blob(original)==before, 'VEUX_SOURCE_PREIMAGE_DRIFT '+relative+
                ' observed='+git_blob(original))
        replacement=read_commit_blob(donor, BACKPORT_COMMIT, relative, after)
        stage.append((target, original, replacement,after))
    # All preconditions passed.  Mutation is limited to the temporary kernel
    # source and fails closed if another process modifies a staged preimage.
    try:
        for target,before,replacement,expected in stage:
            checked(target.read_bytes()==before, 'CONCURRENT_SOURCE_CHANGE '+str(target))
            target.write_bytes(replacement)
            checked(git_blob(target.read_bytes())==expected,'BACKPORT_POSTIMAGE_DRIFT '+str(target))
    except Exception:
        for target,before,_,_ in stage:
            if target.exists(): target.write_bytes(before)
        raise
    proof['source_directory']=str(src)
    proof['changed_kernel_paths']=list(FILE_BLOBS)
    proof['device_pass']=False
    proof['kernel_build']=False
    proof['susfs_version']='2.3.0'
    proof['effective_version_label']='35222+fa12-security-backport (NOT official 35225)'
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(proof,sort_keys=True,indent=2)+'\n')
    print('BAKASU_R3_PINNED_SELINUX_BACKPORT=PASS; CHANGED=5; NO_SUSFS_GUARD_REMOVED',flush=True)
    return proof

# Inject after the existing protected AWINIC wrapper: this preserves the exact
# trusted AWINIC change without modifying any committed release worker code.
ANCHOR = '''        if not r.replay_current(src, label, targets):
            e.apply_update(src, state, bundle, work)
'''
INSERT = ANCHOR + '''        from veux_bakasu_selinux_backport_r3 import apply_source_backport
        selinux_backport_r3 = apply_source_backport(
            src, bundle / "resukisu", work / "BAKASU-SELINUX-R3.json")
'''
RESULT_ANCHOR='''        image, result = compat.compile_kernel(label, state, targets, work, args.jobs)
'''
RESULT_INSERT=RESULT_ANCHOR+'''        result['selinux_backport_r3'] = selinux_backport_r3
'''

def inject_worker(original: Path, destination: Path) -> dict:
    checked(original.is_file() and not original.is_symlink(),'WORKER_SOURCE_MISSING')
    checked(not destination.exists(),'WORKER_DEST_ALREADY_EXISTS')
    data=original.read_text()
    checked(data.count(ANCHOR)==1,'WORKER_UPDATE_ANCHOR_DRIFT')
    checked(data.count(RESULT_ANCHOR)==1,'WORKER_COMPILE_ANCHOR_DRIFT')
    checked('BAKASU-SELINUX-R3.json' not in data,'WORKER_ALREADY_PATCHED')
    modified=data.replace(ANCHOR,INSERT,1).replace(RESULT_ANCHOR,RESULT_INSERT,1)
    import ast
    ast.parse(modified,filename=str(destination))
    destination.write_text(modified)
    return {'original_sha256':hashlib.sha256(data.encode()).hexdigest(),
            'patched_sha256':hashlib.sha256(modified.encode()).hexdigest(),
            'source':str(original),'destination':str(destination)}
