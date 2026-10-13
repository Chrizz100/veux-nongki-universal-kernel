#!/usr/bin/env python3
"""Audited *source-only* 5.4.274 SUSFS hook port feasibility probe.

Checks the exact two original simonpunk GitLab commits (the clean donor was
cloned/pinned by the proven R3 fleet). Attempts ONLY IN MEMORY to rebase the
changed GKI-5.10 host hunks against the already integrated R4 5.4 kernel
sources. No sources, official donors, pinned manifests, or working repo are
modified. Reports conflicts rather than pretending the new patches are 5.4-ready.

NO COMPILE, NO ZIP, NO FLASH, NO UPSTREAM SUSFS GUARD REMOVAL.
"""
from __future__ import annotations
import argparse
from dataclasses import dataclass
import difflib
import hashlib
import json
from pathlib import Path
import re
import subprocess

OLD = '5326e21a7eb232f9e21debdd5164e99bee3d1e2f'
MID = '2837d10b68bacbd7f06758d301237e8f8b363adb'
NEW = '14c45388ec8cb3ca72f2ac8bf83097b9285a8418'
R4_HOOK_BLOB = 'a2ef78981d1a1e39ab45649a3658367da770eba7'
CORE_BLOBS = {
    'kernel_patches/fs/susfs.c': '1e70f7f2487d1a4c3072f861c7725f733eb59d46',
    'kernel_patches/include/linux/susfs.h': '1e0ae04060839e1adba1db19b4d07638eaae0f95',
    'kernel_patches/include/linux/susfs_def.h': 'a021078ceaaaf6dc098dfdbed592c268c81f85b3',
}
HOST_PATCH = 'kernel_patches/50_add_susfs_in_gki-android13-5.10.patch'
ALTERNATIVE_PATCH = 'kernel_patches/KernelSU/10_enable_susfs_for_ksu.patch'
PATCH_BLOBS = {
    HOST_PATCH: ('cd0932731641bdc2f086834805be5842df2d4615',
                 '264dcb05a5a424191719cba610360437f3c6996a'),
    ALTERNATIVE_PATCH: ('cc84f6a16b12182bc9966fe047da23ae8958377a',
                        '7ebb9d5ef3a15682470236ae14ec53d9c17b5767'),
}

# Audited, full real 5.10 patch-image diff on identical Git object IDs.
# (number of modified postimages, number with modified original preimage)
KNOWN_HOST_HUNK_DELTA = {
    'fs/exec.c': (1, 0),
    'security/selinux/hooks.c': (2, 2),
    'security/selinux/selinuxfs.c': (5, 5),
}

class PortError(ValueError):
    pass


def demand(ok: bool, error: str) -> None:
    if not ok:
        raise PortError(error)


def blob(content: bytes) -> str:
    return hashlib.sha1(b'blob '+str(len(content)).encode()+b'\x00'+content).hexdigest()


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def git(donor: Path, *args: str) -> str:
    proc = subprocess.run(['git','-C',str(donor),*args], capture_output=True,
                          text=True, timeout=70, check=False)
    demand(proc.returncode == 0, 'GIT_READ_FAILED '+str(args[:2])+' '+proc.stderr[-220:])
    return proc.stdout.strip()


@dataclass(frozen=True)
class SourcePins:
    old: str = OLD
    mid: str = MID
    new: str = NEW
    r4_hook_blob: str = R4_HOOK_BLOB
    core: dict[str,str] | None = None
    patches: dict[str,tuple[str,str]] | None = None


def verify_git_scope(donor: Path, pins: SourcePins) -> dict:
    """Read-only immutable provenance check: five files and two commits."""
    demand(donor.is_dir() and not donor.is_symlink(), 'SUSFS_DONOR_UNSAFE')
    donor = donor.resolve(strict=True)
    demand(git(donor,'rev-parse','--show-toplevel') == str(donor), 'SUSFS_DONOR_NOT_GIT_TOP')
    demand(git(donor,'rev-parse','HEAD') == pins.old, 'SUSFS_BUILD_PIN_CHANGED')
    demand(not git(donor,'status','--porcelain','--untracked-files=all'), 'SUSFS_DONOR_DIRTY')
    demand(git(donor,'rev-parse',pins.mid+'^') == pins.old, 'SUSFS_FIRST_PARENT_DRIFT')
    demand(git(donor,'rev-parse',pins.new+'^') == pins.mid, 'SUSFS_SECOND_PARENT_DRIFT')
    changes = git(donor,'diff','--name-only',pins.old,pins.new).splitlines()
    demand(set(changes) == set(pins.patches), 'SUSFS_UNREVIEWED_PATH_CHANGE '+str(changes))
    demand(git(donor,'rev-list','--reverse',pins.old+'..'+pins.new).splitlines()
           == [pins.mid,pins.new], 'SUSFS_COMMIT_CHAIN_DRIFT')
    for path,check in pins.core.items():
        demand(git(donor,'rev-parse',pins.old+':'+path) == check,
               'SUSFS_CORE_BASE_DRIFT '+path)
        demand(git(donor,'rev-parse',pins.new+':'+path) == check,
               'SUSFS_CORE_UPDATE_DRIFT '+path)
    for path,(before,after) in pins.patches.items():
        demand(git(donor,'rev-parse',pins.old+':'+path) == before,
               'SUSFS_PATCH_BASE_DRIFT '+path)
        demand(git(donor,'rev-parse',pins.new+':'+path) == after,
               'SUSFS_PATCH_UPDATE_DRIFT '+path)
    header = git(donor,'show',pins.new+':kernel_patches/include/linux/susfs.h')
    demand(re.search(r'^#define\s+SUSFS_VERSION\s+"v?2\.3\.0"',header,re.M) is not None,
           'SUSFS_DECLARED_VERSION_CHANGED')
    return {'git_object_chain_checked': True,
            'old':pins.old,'first_change':pins.mid,'new':pins.new,
            'kernel_core_unchanged': True,'changed_paths':sorted(changes)}


def images(patch: str) -> dict[str,list[dict[str,list[str]]]]:
    """Parse patch hunk images, matching the proven VEUX updater's semantics."""
    result={}
    current=None
    hunk=None
    for line in patch.splitlines(keepends=True):
        if line.startswith('diff --git '):
            cols=line.split()
            demand(len(cols)==4 and cols[2].startswith('a/') and
                   cols[3].startswith('b/'), 'UNEXPECTED_PATCH_PATH_DECLARATION')
            current=cols[3][2:]
            demand(current not in result and current==cols[2][2:],
                   'PATCH_RENAMES_OR_DUPLICATES_FORBIDDEN '+current)
            demand(current and not Path(current).is_absolute() and
                   '..' not in Path(current).parts, 'PATCH_PATH_TRAVERSAL')
            result[current]=[]
            hunk=None
        elif line.startswith('@@ '):
            demand(current is not None,'PATCH_HUNK_WITHOUT_PATH')
            hunk={'before':[],'after':[]}
            result[current].append(hunk)
        elif hunk is not None and line[:1] in (' ','+','-'):
            if line[0] in (' ','-'):
                hunk['before'].append(line[1:])
            if line[0] in (' ','+'):
                hunk['after'].append(line[1:])
    demand(bool(result) and all(result.values()),'EMPTY_OR_MALFORMED_HOST_PATCH')
    return result


def stage_text(text: str, old: list[str], new: list[str]) -> tuple[str,int]:
    """Return staged 5.4 text in memory, never write the original source."""
    edits=[]
    for tag,a,b,c,d in difflib.SequenceMatcher(None,old,new,autojunk=False).get_opcodes():
        if tag=='equal':
            continue
        before=''.join(old[a:b]); after=''.join(new[c:d])
        if not before:
            demand(a>0 and b<len(old),'UNANCHORED_HUNK_INSERTION')
            before=old[a-1]+old[b]
            after=old[a-1]+after+old[b]
        demand(text.count(before)==1,'MISSING_OR_AMBIGUOUS_5_4_CONTEXT '+repr(before[:85]))
        start=text.index(before)
        edits.append((start,start+len(before),after))
    edits.sort()
    demand(all(a[1]<=b[0] for a,b in zip(edits,edits[1:])),
           'OVERLAPPING_HUNK_PORT_EDITS')
    for start,end,after in reversed(edits):
        text=text[:start]+after+text[end:]
    return text,len(edits)


# The final 14c45388 change to GKI-5.10 fs/exec.c removes only this
# unused declaration. Absence in the real 5.4 source is a NO-OP, not a
# reason to edit the kernel or rebuild it. Require both pinned patch images.
UNUSED_EXEC_DECL = 'extern bool __ksu_is_allow_uid_for_current(uid_t uid);\n'


def is_upstream_unused_decl_cleanup(path: str, before: list[str],
                                     after: list[str], text: str) -> bool:
    if path != 'fs/exec.c' or UNUSED_EXEC_DECL not in before:
        return False
    old_only = [x for x in before if x not in after]
    new_only = [x for x in after if x not in before]
    # Reject widened upstream changes, duplicated prototypes, or local uses.
    return (old_only == [UNUSED_EXEC_DECL] and not new_only and
            '__ksu_is_allow_uid_for_current' not in text)


def inspect_host_5_4_selinux(src: Path) -> dict:
    """Read-only evidence about 5.4 hook layout; never a patch or PASS.

    GKI 5.10 moved wrapper logic into native SELinux functions. The 5.4
    implementation must be inspected, rather than mechanically rebased.
    These checks intentionally distinguish absence of wrapper *names* from
    proof of equivalent runtime protection (which this cannot establish).
    """
    checks = {
        'fs/exec.c': ('__ksu_is_allow_uid_for_current',),
        'security/selinux/hooks.c': (
            'my_setprocattr', 'selinux_setprocattr',
            'ksu_selinux_hide_running', 'security_context_to_sid',
            'LSM_HOOK_INIT(setprocattr',
        ),
        'security/selinux/selinuxfs.c': (
            'my_sel_open_handle_status', 'my_write_context', 'my_write_access',
            'sel_open_handle_status', 'sel_write_context', 'sel_write_access',
            'ksu_selinux_hide_running', 'ksu_selinux_hide_enabled',
            'fake_status_initialize_key',
        ),
        'KernelSU/kernel/feature/selinux_hide.c': (
            'my_sel_open_handle_status', 'my_write_context', 'my_write_access',
            'ksu_handle_selinux_setprocattr', 'orig_sel_open_handle_status',
            'orig_context_write', 'orig_access_write',
            'kfree(canon)', 'kfree(tcon)', 'kfree(scon)',
            'fake_status_initialize_key', 'ksu_selinux_hide_running',
            'KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE',
        ),
    }
    result = {}
    for relative, needles in checks.items():
        path=src/relative
        if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(src):
            result[relative]={'status':'SOURCE_NOT_PRESENT_OR_UNSAFE',
                              'review_required':True}
            continue
        data=path.read_bytes()
        try:
            value=data.decode('utf-8')
        except UnicodeDecodeError:
            result[relative]={'status':'NON_UTF8_SOURCE',
                              'review_required':True,
                              'sha256':sha256(data)}
            continue
        refs={symbol:len(re.findall(re.escape(symbol),value)) for symbol in needles}
        if relative=='fs/exec.c':
            status=('UNUSED_EXTERN_NOT_PRESENT' if refs[needles[0]]==0
                    else 'SYMBOL_PRESENT_REVIEW_CALLERS')
            needs=refs[needles[0]]!=0
        else:
            wrappers=[name for name in needles if name.startswith('my_') and refs[name]>0]
            if relative.startswith('KernelSU/'):
                status=('BAKASU_R4_LEGACY_WRAPPERS_REVIEW_RUNTIME_SEMANTICS' if wrappers
                        else 'BAKASU_R4_HOOK_LAYOUT_UNVERIFIED')
            else:
                status=('LEGACY_WRAPPERS_PRESENT_REVIEW_ORIGINAL_CLEANUP' if wrappers
                        else 'NO_NAMED_GKI_WRAPPERS_FOUND_EQUIVALENCE_UNPROVEN')
            needs=True  # No evidence of functional parity/SELinux leak safety.
        result[relative]={
            'status':status,'review_required':needs,
            'sha256':sha256(data),'symbols':refs,
            'reason':('Presence/absence of names does not prove equivalent '
                      'policy handling, memory lifetime or device behavior'),
        }
        demand(path.read_bytes()==data,
               'PORT_PROBE_CHANGED_READ_ONLY_HOST_FILE '+relative)
    return {'source_paths':result,
            'actual_5_4_host_sources_read_only':True,
            'no_semantic_port_or_runtime_approval':True,
            'selinux_cleanup_requires_code_review':True}


def classify_host(src: Path, old_patch: str, new_patch: str) -> dict:
    old=images(old_patch); new=images(new_patch)
    demand(old.keys()==new.keys(),'SUSFS_HOST_PATCH_CHANGED_PATH_SET')
    findings=[]
    for path in old:
        left=old[path];right=new[path]
        entry={'path':path,'hunks_baseline':len(left),'hunks_candidate':len(right),
               'candidate_hunks_different':0,'staged_edits':0}
        findings.append(entry)
        if len(left)!=len(right):
            entry['result']='HUNK_TOPOLOGY_CHANGED';continue
        differing=[(a,b) for a,b in zip(left,right) if a['after']!=b['after']]
        entry['candidate_hunks_different']=len(differing)
        entry['upstream_original_contexts_changed'] = sum(
            a['before'] != b['before'] for a,b in zip(left,right))
        if not differing:
            entry['result']='NO_SEMANTIC_CHANGE';continue
        # A changed upstream 5.10 preimage cannot be installed unreviewed on 5.4.
        if any(a['before']!=b['before'] for a,b in zip(left,right)):
            entry['result']='UPSTREAM_GKI_BASE_CHANGED';continue
        local=src/path
        if not local.is_file() or local.is_symlink() or not local.resolve().is_relative_to(src):
            entry['result']='HOST_5_4_FILE_MISSING_OR_UNSAFE';continue
        orig=local.read_bytes()
        try:
            staging=orig.decode('utf-8')
            # GKI-5.10's final commit removed one declaration unused by 5.4.
            # Recognize a no-op on the real source only with exact scoped edit.
            if (path=='fs/exec.c' and len(differing)==1 and
                is_upstream_unused_decl_cleanup(path, differing[0][0]['after'],
                                                differing[0][1]['after'], staging)):
                entry['result']='UPSTREAM_UNUSED_DECL_ALREADY_ABSENT_IN_5_4'
                entry['original_sha256']=sha256(orig)
                entry['candidate_sha256']=sha256(orig)
                demand(local.read_bytes()==orig,'PORT_PROBE_MUTATED_REAL_5_4_SOURCE '+path)
                continue
            for a,b in differing:
                staging,n=stage_text(staging,a['after'],b['after'])
                entry['staged_edits']+=n
        except (PortError,UnicodeDecodeError) as exc:
            entry['result']='NEEDS_MANUAL_5_4_REBASE'
            entry['reason']=str(exc)[:260]
            continue
        entry['result']='IN_MEMORY_STAGE_ONLY_NOT_APPROVED'
        entry['original_sha256']=sha256(orig)
        entry['candidate_sha256']=sha256(staging.encode('utf-8'))
        # Critical guarantee: never modify the materialized working kernel.
        demand(local.read_bytes()==orig,'PORT_PROBE_MUTATED_REAL_5_4_SOURCE '+path)
    return {'host_paths_examined':len(findings),
            'host_paths_with_changed_hunks':sum(x['candidate_hunks_different']>0 for x in findings),
            'host_paths_stageable_in_memory':sum(x['result']=='IN_MEMORY_STAGE_ONLY_NOT_APPROVED' for x in findings),
            'host_paths_requiring_manual_port':sum(x['result'] not in
                ('NO_SEMANTIC_CHANGE','IN_MEMORY_STAGE_ONLY_NOT_APPROVED',
                 'UPSTREAM_UNUSED_DECL_ALREADY_ABSENT_IN_5_4') for x in findings),
            'findings':findings}


def probe(src: Path, donor: Path, output: Path, pins: SourcePins | None = None) -> dict:
    """Do not touch `src` or `donor`. Only write one evidence JSON into a report dir."""
    pins=pins or SourcePins(core=CORE_BLOBS, patches=PATCH_BLOBS)
    src=src.resolve(strict=True)
    donor=donor.resolve(strict=True)
    demand(src.name=='kernel' and donor.name=='susfs','UNKNOWN_VEUX_WORKSPACE_LAYOUT')
    demand(not src.is_relative_to(donor) and not donor.is_relative_to(src),
           'SOURCE_DONOR_WORKSPACE_OVERLAP')
    demand(not output.exists() and not output.is_symlink() and
           not output.resolve().is_relative_to(src) and
           not output.resolve().is_relative_to(donor),
           'PORT_PROBE_REPORT_CANNOT_MUTATE_SOURCE')
    makefile=src/'Makefile'
    demand(makefile.is_file() and not makefile.is_symlink() and
           bool(re.search(r'^VERSION\s*=\s*5$',makefile.read_text(),re.M)) and
           bool(re.search(r'^PATCHLEVEL\s*=\s*4$',makefile.read_text(),re.M)),
           'PORT_PROBE_REQUIRES_KERNEL_5_4')
    hook=src/'KernelSU/kernel/feature/selinux_hide.c'
    demand(hook.is_file() and not hook.is_symlink() and blob(hook.read_bytes())==pins.r4_hook_blob,
           'R4_RUNTIME_FIXED_SELINUX_HOOK_REQUIRED')
    scope=verify_git_scope(donor,pins)
    old_text=git(donor,'show',pins.old+':'+HOST_PATCH)+'\n'
    new_text=git(donor,'show',pins.new+':'+HOST_PATCH)+'\n'
    result=classify_host(src,old_text,new_text)
    original_layout=inspect_host_5_4_selinux(src)
    if pins.old == OLD and pins.new == NEW:
        observed = {
            f['path']: (f['candidate_hunks_different'],
                        f['upstream_original_contexts_changed'])
            for f in result['findings'] if f['candidate_hunks_different']
        }
        demand(observed == KNOWN_HOST_HUNK_DELTA,
               'OFFICIAL_SUSFS_5_10_HUNK_SCOPE_DRIFT ' + repr(observed))
    alt_old=git(donor,'show',pins.old+':'+ALTERNATIVE_PATCH)
    alt_new=git(donor,'show',pins.new+':'+ALTERNATIVE_PATCH)
    a=lambda t:[s for s in t.splitlines() if s.startswith('+') and not s.startswith('+++')]
    alternative_changed=a(alt_old)!=a(alt_new)
    demand(alternative_changed,'EXPECTED_KERNELSU_INTERFACE_DELTA_MISSING')
    report={'schema':1,
            'status':'PROBE_COMPLETED_PORT_NOT_APPROVED',
            'official_commits':scope,
            'host_5_4':result,
            'real_5_4_selinux_layout':original_layout,
            'alternative_KernelSU_patch_additions_changed':alternative_changed,
            'security':{
                'source_only_no_kernel_compilation':True,
                'all_host_staging_only_in_memory':True,
                'no_source_or_repo_mutations':True,
                'no_pin_update':True,
                'no_flash_artifact':True,
                'R4_setprocattr_runtime_fix_preserved':True,
                'SELinux_Enforcing_not_disabled':True,
                'SUSFS_2_3_0_core_identical':True,
                'automatic_promotion_blocked':True},
            'decision':'MANUAL_REVIEW_5_4_HOOKS_REQUIRED',
            'baseline_kernel':'5.4.274',
            'baseline_bakasu':'35222+fa12+R4_runtime_fix',
            'baseline_susfs_pin':pins.old,
            'new_susfs_head_only_under_review':pins.new}
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print('VEUX_SUSFS_54_PORT_PROBE=FINISHED; '
          f"HOST_CHANGED={result['host_paths_with_changed_hunks']}; "
          f"STAGED_IN_MEMORY={result['host_paths_stageable_in_memory']}; "
          f"NEEDS_MANUAL_5_4_PORT={result['host_paths_requiring_manual_port']}; "
          'PIN_PROMOTION=BLOCKED; DEVICE_PASS=NO; NO_KERNEL_BUILD; '
          'SELINUX_5_4_PARITY=UNPROVEN',flush=True)
    return report


def main()->int:
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--src',required=True,type=Path)
    cli.add_argument('--susfs-donor',required=True,type=Path)
    cli.add_argument('--report',required=True,type=Path)
    args=cli.parse_args()
    try:
        probe(args.src,args.susfs_donor,args.report)
        return 0
    except (PortError, OSError, subprocess.SubprocessError) as exc:
        print('VEUX_SUSFS_54_PORT_PROBE=BLOCKED '+str(exc))
        return 1

if __name__=='__main__':
    raise SystemExit(main())
