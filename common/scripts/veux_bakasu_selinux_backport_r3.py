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

# Device-reported regression: Linux 5.4.274 R3 fa12 runtime prevented normal
# execve (/system/bin/sh, BakaSU libksud.so) while R2 35222 worked. The fa12
# handler changes app SELinux current via new manual SID/cred mutation. Android
# Zygote invokes setcontext AFTER switching from root to an app UID.
# Keep the exact security fix as upstream for >= 5.10, but route this *single*
# older-kernel hook to Linux's original, already working setprocattr callback.
# This does NOT relax SELinux and does NOT claim fa12 side-channel protection
# for this one legacy interface. No SUSFS or NoMount pin is changed.
LEGACY_54_SETPROCATTR_PATH = 'kernel/feature/selinux_hide.c'
LEGACY_54_GUARD_ANCHOR = '''    if (strcmp(name, "current")) {
        goto call_orig;
    }

    struct ksu_task_security_struct *tsec;
'''
LEGACY_54_GUARD = '''    if (strcmp(name, "current")) {
        goto call_orig;
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
    /* VEUX 5.4: preserve the stock, enforcing SELinux process SID transition.
     * The fa12 manual SID/credential path regressed Android app execve on VEUX.
     * This fallback is limited to the legacy kernel; no allow/deny is bypassed.
     */
    goto call_orig;
#endif

    struct ksu_task_security_struct *tsec;
'''


def stage_legacy_54_setprocattr_guard(fa12_data: bytes) -> tuple[bytes, dict]:
    """Pure, fail-closed adapter of exactly the pinned fa12 C source.

    No device source or donor commit is touched. Production call is gated by
    stage_legacy_selinux_exports(src), requiring kernel 5.4 and SELinux state.
    """
    expected = FILE_BLOBS[LEGACY_54_SETPROCATTR_PATH][1]
    checked(git_blob(fa12_data) == expected,
            'LEGACY_SETPROCATTR_EXPECTED_FA12_POSTIMAGE_MISSING')
    original = fa12_data.decode('utf-8', errors='strict')
    checked(original.count(LEGACY_54_GUARD_ANCHOR) == 1,
            'LEGACY_SETPROCATTR_ANCHOR_DRIFT')
    checked(original.count('int __nocfi ksu_handle_selinux_setprocattr(') == 2,
            'LEGACY_SETPROCATTR_PROTOTYPE_DRIFT')
    checked(original.count('    return ksu_orig_setprocattr(name, value, size);') == 1,
            'LEGACY_SETPROCATTR_ORIGINAL_CALL_NOT_FOUND')
    checked(original.count('call_orig:') == 1,
            'LEGACY_SETPROCATTR_CALL_ORIG_DRIFT')
    updated = original.replace(LEGACY_54_GUARD_ANCHOR, LEGACY_54_GUARD, 1)
    checked(updated.replace(LEGACY_54_GUARD, LEGACY_54_GUARD_ANCHOR, 1) == original,
            'LEGACY_SETPROCATTR_UNRELATED_CHANGE')
    checked(updated.count('#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)') >= 1,
            'LEGACY_SETPROCATTR_MISSING_VERSION_GUARD')
    result = updated.encode('utf-8')
    proof = {
        'kernel_version_scope': '5.4 (source Makefile gate); 5.4.274 (R3 fleet target)',
        'source_relative': LEGACY_54_SETPROCATTR_PATH,
        'official_fa12_git_blob': expected,
        'effective_git_blob': git_blob(result),
        'effective_sha256': hashlib.sha256(result).hexdigest(),
        'insertions': 1,
        'other_fa12_code_unchanged': True,
        'legacy_setprocattr': 'original_stock_kernel_callback',
        'selinux_enforcing_not_changed': True,
        'sidechannel_fix_at_legacy_setprocattr': 'not_claimed',
        'device_runtime_pass': False,
    }
    return result, proof


# Targeted host-kernel export for the fa12 SELinux code on Linux 5.4.
# The BakaSU static_export_check.mk for fa12 requires these two functions to
# have external linkage with CONFIG_KALLSYMS_ALL disabled.  Do not disable the
# check, touch the ELF module ABI, or change the functions' implementations.
LEGACY_SELINUX_EXPORTS = (
    'security_dump_masked_av',
    'context_struct_compute_av',
)


def stage_legacy_selinux_exports(src: Path) -> tuple[Path, bytes, bytes, dict]:
    """Stage exact `static`-qualifier removals, without writing to the source.

    Only the 5.4 SELinux-state layout is supported. This deliberately rejects
    unfamiliar source signatures, instead of masking an upstream ABI change.
    """
    src = src.resolve(strict=True)
    makefile = src / 'Makefile'
    security = src / 'security/selinux/include/security.h'
    path = src / 'security/selinux/ss/services.c'
    for item in (makefile, security, path):
        checked(item.is_file() and not item.is_symlink() and
                item.resolve().is_relative_to(src),
                'SELINUX_HOST_FILE_MISSING_OR_SYMLINK ' + str(item.relative_to(src)))
    mk = makefile.read_text()
    checked(bool(re.search(r'^VERSION[ \t]*=[ \t]*5[ \t]*$', mk, re.M)) and
            bool(re.search(r'^PATCHLEVEL[ \t]*=[ \t]*4[ \t]*$', mk, re.M)),
            'HOST_EXPORT_REQUIRES_LINUX_5_4')
    checked(bool(re.search(r'\bstruct\s+selinux_state\b',security.read_text())),
            'HOST_EXPORT_REQUIRES_SELINUX_STATE')

    original = path.read_bytes()
    before = original.decode('utf-8')
    updated = before
    counts = {}
    for symbol in LEGACY_SELINUX_EXPORTS:
        pattern = re.compile(r'(?m)^(?P<indent>[ \t]*)static[ \t]+void[ \t]+'
                             + re.escape(symbol) + r'(?=[ \t]*\()')
        found = list(pattern.finditer(updated))
        # A forward declaration + definition is normal for context_struct_compute_av.
        allowed = (1,) if symbol == 'security_dump_masked_av' else (1, 2)
        checked(len(found) in allowed, 'HOST_EXPORT_UNEXPECTED_STATIC_COUNT '
                + symbol + ' count=' + str(len(found)))
        for match in found:
            next_text = updated[match.end():match.end()+180]
            checked(bool(re.match(r'\s*\(\s*struct\s+policydb\s*\*\s*policydb\b', next_text)),
                    'HOST_EXPORT_SIGNATURE_CHANGED ' + symbol)
        updated, replacements = pattern.subn(
            lambda m: m.group('indent') + 'void ' + symbol, updated)
        checked(replacements == len(found), 'HOST_EXPORT_REPLACEMENT_COUNT ' + symbol)
        checked(not pattern.search(updated), 'HOST_EXPORT_STATIC_SURVIVED ' + symbol)
        counts[symbol] = replacements
    checked(updated != before, 'HOST_EXPORT_NO_EFFECT')
    proof = {
        'host_kernel': '5.4',
        'source_file': 'security/selinux/ss/services.c',
        'before_sha256': hashlib.sha256(original).hexdigest(),
        'after_sha256': hashlib.sha256(updated.encode()).hexdigest(),
        'symbols': counts,
        'new_export_symbol_macros': False,
        'changed_function_bodies': False,
        'config_kallsyms_all_was_not_changed': True,
        'config_modversions_was_not_changed': True,
    }
    return path, original, updated.encode(), proof


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
        if relative == LEGACY_54_SETPROCATTR_PATH:
            replacement, legacy_54_proof = stage_legacy_54_setprocattr_guard(replacement)
        stage.append((target, original, replacement, git_blob(replacement)))
    # Preflight the host export as well, BEFORE altering any BakaSU source.
    host_path, host_before, host_after, host_proof = stage_legacy_selinux_exports(src)
    stage.append((host_path, host_before, host_after, git_blob(host_after)))
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
    proof['host_kernel_symbol_exports']=host_proof
    proof['legacy_54_setprocattr_runtime_compat']=legacy_54_proof
    proof['device_pass']=False
    proof['kernel_build']=False
    proof['susfs_version']='2.3.0'
    proof['effective_version_label']='35222+fa12-5.4-setprocattr-runtime-compat (NOT official 35225)'
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(proof,sort_keys=True,indent=2)+'\n')
    print('BAKASU_R3_PINNED_SELINUX_BACKPORT=PASS; CHANGED=5; HOST_EXPORTS=2; LEGACY_54_SETPROCATTR_FALLBACK=PASS; NO_SUSFS_GUARD_REMOVED',flush=True)
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
