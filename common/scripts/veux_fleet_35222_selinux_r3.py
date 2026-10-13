#!/usr/bin/env python3
"""VEUX experimental R3: proven 35222 plus the isolated fa12 SELinux security backport.

The official upstream 35223+ SUSFS-blocking commit is NOT integrated and NOT
removed. The five changed SELinux files are independently hash-pinned, and
source is the frozen 35222 release plus that one isolated security change.
Device status is never inferred from a CI pass. Restrict R3 to kernel 5.4.274.

Base evidence: V4 6/6 run 37745338419, with 5.4.274 extended evidence from
RPM24-R4 + RMNET + AWINIC-R3 run 38131689108.  The candidate adds exactly five BakaSU commits before the upstream SUSFS build blocker.
All remaining kernel ingredients stay on proven hashes. Neither this tool nor
its workflow promotes source changes or infers a device PASS.

Do not confuse the historical CURRENT_BUILD (35203 / NM20) with this build's
validated 35217 / NM21 source base. Candidate 35222 still requires full CI and device testing.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from types import SimpleNamespace
import veux_bakasu_selinux_backport_r3 as selinux_r3

REPO_NAME = 'Chrizz100/veux-nongki-universal-kernel'
EXPECTED_KERNEL_R3 = '5.4.274'
BASELINE_35222_IMAGE_SHA256 = 'a8915b449fc26786e50ba075430435b997d1bcbe4ce9dcd2ae51eaad4c14b5df'
PROVEN_35217_NM21_FLEET_RUN = 38159736741
BAKASU_35222_PRE_BLOCKER_COMMIT = '5b76b884c75f729a220bb317aa4a4fc78f0e0e9c'
BAKASU_35217_DEVICE_BASE_COMMIT = 'c9246641b9eee8b9986050e8bf1832f88da880c2'
SUSFS_COMPAT_VERIFIED_BLOB = '904bad1c251314c5addca6dec944f586a9c602e1'
UAPI_VERIFIED_BLOB = '9ba813dc4294fa9633e2a68234b3cf62ab9b514c'
SELINUX_HIDE_VERIFIED_BLOB = '612de60f9a9fefced88c904025769de941547986'
KERNELS = ('5.4.274','5.4.292','5.4.293','5.4.300','5.4.301','5.4.302')
GOOD_SIX_RUN = 37745338419
GOOD_274_RUN = 38131689108
GOOD_274_IMAGE_SHA256 = 'a55edc3f13f7cb663b055d99cb2636e2e41259e8031d688840f4d1032e64172a'
GOOD_274_RESULT_TARGETS_SHA256 = '848bc5a760e29ba7bf41b40a6b2f84b028c701fd38c1b61179623ca1d2f62237'
# Committed software pins; NO CURRENT_BUILD base/ahead/current_fleet fallback.
TARGETS = {
    'resukisu': {
        'url':'https://github.com/Baka-SU/BakaSU.git',
        'ref':'refs/heads/main',
        'commit':'5b76b884c75f729a220bb317aa4a4fc78f0e0e9c',
        'version':'35222','local_version':4522,'tag':'v4.2.0-rc3','uapi':5,
    },
    'susfs': {
        'url':'https://gitlab.com/simonpunk/susfs4ksu.git',
        'ref':'refs/heads/gki-android13-5.10',
        'commit':'5326e21a7eb232f9e21debdd5164e99bee3d1e2f',
        'version':'2.3.0',
    },
    'nomount': {
        'url':'https://github.com/maxsteeel/nomount.git',
        'ref':'refs/heads/master',
        'commit':'1ded61dc908c511072162fa0bee44e6ccdb7b4c7',
        'version':'21','version_kind':'base-version-dynamic-commit-count',
    },
}
BUILT_NOMOUNT21 = 'c7f63e3feb4125d591b6969a33aac04feb40f8ba'
# Frozen, statically audited host tools already used in successful 11 October run.
CODE_BLOBS = {
    'common/scripts/veux_update_engine.py':'1b59c48392fa63af9640dce47b111057ab237b31',
    'common/scripts/veux_release_device.py':'6401eda65d26f047e8cb2ce836c12fbfeadbd80f',
    'common/scripts/veux_rpm24.py':'e08344b581c2aa6e7933552e3bb1a1811021c909',
    'common/scripts/test_veux_rpm24.py':'f8e5d6dfdfaf5892a4b6050411bcf8715f58b0b8',
}
AWINIC_POST_SHA256 = 'f44881388908c8002b96383356104b00f8c823ca11193106d87dc1f8601378b4'
AWINIC_PATCH_SHA256 = '5c00ebcf5ceb1f9e2c8988a16d538e0048f7b4bb28298de875d6b4f0e854e7a2'

# Exact pinned GitLab transport only. Never fall back to an unverified mirror,
# switch to a floating HEAD, or hide a history/commit mismatch.
SUSFS_GITLAB_URL = 'https://gitlab.com/simonpunk/susfs4ksu.git'
SUSFS_GITLAB_REF = 'refs/heads/gki-android13-5.10'
SUSFS_GITLAB_PIN = '5326e21a7eb232f9e21debdd5164e99bee3d1e2f'
SUSFS_GITLAB_RETRY_DELAYS = (5, 15, 30, 45)  # five total attempts
GITLAB_OVERLOAD_MARKERS = (
    'gitlab is currently unable to handle this request due to load',
    'the requested url returned error: 503',
    'the requested url returned error: 502',
    'the requested url returned error: 504',
    'the requested url returned error: 429',
    '503 service unavailable',
    '502 bad gateway',
    '504 gateway timeout',
    '429 too many requests',
)


class FleetBlocked(RuntimeError):
    pass


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise FleetBlocked(reason)


def run(*args: object, timeout: int = 240, cwd: Path | None = None) -> str:
    proc = subprocess.run([str(x) for x in args],cwd=cwd,stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE,text=True,timeout=timeout,
                          env={**os.environ,'GIT_TERMINAL_PROMPT':'0'})
    require(proc.returncode==0,
            'COMMAND_FAILURE '+str(args[0])+' rc='+str(proc.returncode)+': '+proc.stderr[-1250:])
    return proc.stdout.strip()


def gitlab_is_transient(exc: BaseException) -> bool:
    """Only overload/rate-limit transport errors are retried, never identity errors."""
    msg = str(exc).lower()
    return any(marker in msg for marker in GITLAB_OVERLOAD_MARKERS)


def _write_gitlab_retry_log(folder: Path | None, stage: str, rows: list[dict], status: str) -> None:
    if folder is None:
        return
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / ('SUSFS_GITLAB_' + stage.upper().replace('-', '_') + '.json')
    require(not target.is_symlink(), 'UNSAFE_GITLAB_RETRY_LOG')
    target.write_text(json.dumps({
        'component': 'susfs', 'source_url': SUSFS_GITLAB_URL,
        'ref': SUSFS_GITLAB_REF, 'pinned_commit': SUSFS_GITLAB_PIN,
        'stage': stage, 'status': status, 'attempts': rows,
        'head_is_not_a_build_pin': True, 'fallback_mirror_used': False,
    }, indent=2, sort_keys=True) + '\n')


def retry_susfs_gitlab(stage: str, operation, *, audit: Path | None = None,
                       cleanup=None):
    """Bounded retry for the exact GitLab overload seen in two failed runs.

    Non-transport, verification and source-identity errors fail immediately.
    GitLab's frozen commit and source URL never change.
    """
    require(stage in ('head', 'clone'), 'UNEXPECTED_GITLAB_RETRY_STAGE')
    attempts = []
    for index in range(len(SUSFS_GITLAB_RETRY_DELAYS) + 1):
        number = index + 1
        try:
            result = operation()
        except Exception as exc:
            if not gitlab_is_transient(exc):
                raise
            if cleanup is not None:
                cleanup()
            exhausted = index == len(SUSFS_GITLAB_RETRY_DELAYS)
            attempts.append({'attempt': number, 'result': 'TRANSIENT_GITLAB_OVERLOAD'})
            _write_gitlab_retry_log(audit, stage, attempts, 'EXHAUSTED' if exhausted else 'RETRYING')
            if exhausted:
                raise FleetBlocked('SUSFS_GITLAB_OVERLOAD_RETRY_EXHAUSTED ' + stage +
                                   ': official GitLab server overloaded; pin unchanged') from exc
            delay = SUSFS_GITLAB_RETRY_DELAYS[index]
            print(f'SUSFS_GITLAB_{stage.upper()}_OVERLOAD_RETRY={number}; '
                  f'waiting={delay}s; official pinned source unchanged', flush=True)
            time.sleep(delay)
        else:
            attempts.append({'attempt': number, 'result': 'PASS'})
            _write_gitlab_retry_log(audit, stage, attempts, 'PASS')
            return result
    raise FleetBlocked('UNREACHABLE_GITLAB_RETRY_STATE')


def _remove_partial_susfs_checkout(donor: Path) -> None:
    """Remove ONLY a failed temporary SUSFS clone, never any existing checkout."""
    require(donor.name == 'susfs' and donor.parent.name == 'bundle',
            'SUSFS_PARTIAL_CHECKOUT_SCOPE_CHANGED')
    require(not donor.is_symlink(), 'SUSFS_PARTIAL_CHECKOUT_SYMLINK')
    if donor.exists():
        require(donor.is_dir(), 'SUSFS_PARTIAL_CHECKOUT_NOT_DIRECTORY')
        shutil.rmtree(donor)


def checkout_exact_susfs_with_retry(engine, entry: dict, donor: Path, *, audit: Path | None = None) -> None:
    """Clone from the official GitLab URL at a fixed, authenticated SHA."""
    require(entry['url'] == SUSFS_GITLAB_URL and entry['ref'] == SUSFS_GITLAB_REF
            and entry['commit'] == SUSFS_GITLAB_PIN,
            'SUSFS_SOURCE_PIN_OR_URL_CHANGED')
    require(donor.name == 'susfs' and donor.parent.name == 'bundle' and
            not donor.exists() and not donor.is_symlink(),
            'SUSFS_CHECKOUT_DESTINATION_UNSAFE')
    retry_susfs_gitlab('clone',
                       lambda: engine.checkout(entry['url'], entry['commit'], donor, full=True),
                       audit=audit, cleanup=lambda: _remove_partial_susfs_checkout(donor))
    require(donor.is_dir() and not donor.is_symlink(), 'SUSFS_CHECKOUT_NOT_REAL_DIRECTORY')


def git_blob(blob: bytes) -> str:
    return hashlib.sha1(b'blob '+str(len(blob)).encode()+b'\0'+blob).hexdigest()


def sha256(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def ensure_project(repo: Path) -> str:
    repo=repo.resolve(strict=True)
    require(os.environ.get('GITHUB_REPOSITORY',REPO_NAME)==REPO_NAME,'WRONG_REPOSITORY')
    require(repo.is_dir() and (repo/'.git').exists(),'PROJECT_CHECKOUT_MISSING')
    head=run('git','-C',repo,'rev-parse','HEAD')
    require(bool(re.fullmatch(r'[0-9a-f]{40}',head)),'INVALID_REPOSITORY_HEAD')
    require(os.environ.get('GITHUB_SHA',head)==head,'STALE_CHECKOUT_SHA')
    require(not run('git','-C',repo,'status','--porcelain','--untracked-files=all'),
            'REPOSITORY_DIRTY')
    # All previously validated device-specific fixes and source recipes stay.
    for name,expected in CODE_BLOBS.items():
        path=repo/name
        require(path.is_file() and not path.is_symlink(),'SOURCE_FILE_MISSING '+name)
        actual=git_blob(path.read_bytes())
        require(actual==expected,'SOURCE_FILE_DRIFT '+name+' actual='+actual)
    contract=json.loads((repo/'common/contracts/CURRENT_BUILD.json').read_text())
    require(contract.get('status')=='compile-package-static-validated',
            'HISTORICAL_CURRENT_BUILD_UNVALIDATED')
    require(contract.get('device_pass_inferred') is False,
            'HISTORICAL_DEVICE_PASS_INCORRECT')
    require(set(contract.get('lineages',{}))==set(KERNELS),'FLEET_RECIPE_SET_CHANGED')
    # The historical CURRENT_BUILD is NOT the source base for this candidate.
    return head


def validate_wire_abi(reference_header: str, new_header: str) -> dict[str,str]:
    """Compare kernel/userspace wire declarations, not private VFS structures."""
    expressions = {
        'enum':r'enum\s*\{\s*NM_CMD_UNSPEC\s*=\s*0,[\s\S]*?\};',
        'nm_payload':r'\bstruct\s+nm_payload\s*\{[\s\S]*?\}\s*__attribute__\s*\(\(packed\)\)\s*;',
        'nm_rule_hdr':r'\bstruct\s+nm_rule_hdr\s*\{[\s\S]*?\}\s*__attribute__\s*\(\(packed\)\)\s*;',
        'nm_del_hdr':r'\bstruct\s+nm_del_hdr\s*\{[\s\S]*?\}\s*__attribute__\s*\(\(packed\)\)\s*;',
    }
    def canonical(s: str) -> str:
        s=re.sub(r'/\*.*?\*/|//[^\n]*','',s,flags=re.S)
        return ' '.join(re.findall(r'[A-Za-z_][A-Za-z_0-9]*|\d+|[^\s]',s))
    result={}
    for key,pat in expressions.items():
        a=re.findall(pat,reference_header,flags=re.S)
        b=re.findall(pat,new_header,flags=re.S)
        require(len(a)==len(b)==1,'WIRE_DECLARATION_MISSING_OR_DUPLICATED '+key)
        require(canonical(a[0])==canonical(b[0]),'WIRE_ABI_CHANGED '+key)
        result[key]='IDENTICAL'
    for which,data in (('reference',reference_header),('candidate',new_header)):
        require(bool(re.search(r'^\s*#define\s+NOMOUNT_BASE_VERSION\s+"21"',data,re.M)),
                'NOT_NOMOUNT_21_'+which)
    return result


def safe_symlinks(donor: Path) -> list[dict[str,str]]:
    root=donor.resolve(strict=True)
    found=[]
    for item in donor.rglob('*'):
        if not item.is_symlink():
            continue
        relative=item.relative_to(donor).as_posix()
        raw=Path(os.readlink(item))
        require(not raw.is_absolute(),'ABSOLUTE_UPSTREAM_SYMLINK '+relative)
        try:
            resolved=item.resolve(strict=True)
        except (OSError,RuntimeError) as exc:
            raise FleetBlocked('BROKEN_OR_CYCLIC_SYMLINK '+relative) from exc
        require(resolved.is_relative_to(root),'ESCAPING_UPSTREAM_SYMLINK '+relative)
        found.append({'path':relative,'target':str(raw)})
    return found


def remote_head(url: str, ref: str) -> str:
    require(url.startswith(('https://github.com/','https://gitlab.com/')),'UNKNOWN_SOURCE_HOST')
    require(bool(re.fullmatch(r'refs/heads/[A-Za-z0-9_./-]+',ref)),'INVALID_TRACKED_REF')
    lines=run('git','ls-remote','--exit-code','--refs',url,ref).splitlines()
    require(len(lines)==1,'AMBIGUOUS_UPSTREAM_REF '+ref)
    cols=lines[0].split()
    require(len(cols)==2 and cols[1]==ref and bool(re.fullmatch(r'[0-9a-f]{40}',cols[0])),
            'INVALID_UPSTREAM_REF '+ref)
    return cols[0]


def verify_35222_interface_pins(donor: Path) -> dict[str,str]:
    """Prove that this candidate has the audited UAPI, SELinux and SUSFS files.

    The upstream build blocker on BakaSU 35223+ must NEVER be patched out.
    Any changed source must be reviewed, re-pinned and re-tested as a NEW R3.
    """
    root = donor.resolve(strict=True)
    expected = {
        'kernel/tools/susfs_compat.mk': SUSFS_COMPAT_VERIFIED_BLOB,
        'uapi/supercall.h': UAPI_VERIFIED_BLOB,
        'kernel/feature/selinux_hide.c': SELINUX_HIDE_VERIFIED_BLOB,
    }
    checked: dict[str,str] = {}
    for relative, digest in expected.items():
        file = root / relative
        require(file.is_file() and not file.is_symlink(),
                'BAKASU_INTERFACE_MISSING_OR_SYMLINK ' + relative)
        actual = git_blob(file.read_bytes())
        require(actual == digest, 'BAKASU_INTERFACE_DRIFT ' + relative +
                ' expected=' + digest + ' actual=' + actual)
        checked[relative] = actual
    compat = (root / 'kernel/tools/susfs_compat.mk').read_text()
    require('$(error Please wait susfs update.)' not in compat,
            'EXPLICIT_UPSTREAM_SUSFS_BUILD_BLOCKER')
    header = (root / 'uapi/supercall.h').read_text()
    require('KERNEL_SU_UAPI_VERSION = 5;' in header,
            'BAKASU_UAPI5_MISSING')
    return checked


def audit_frozen_upstream(donor: Path, component: str,
                          pinned: str, observed: str) -> dict:
    """Allow a moved branch tip ONLY when it descends from the frozen source pin.

    A moved tip is NOT compiled, installed, or automatically promoted.  The
    checkout remains detached at pinned; a rewritten/unknown tip is rejected.
    Git graph proof is performed against the just-cloned complete upstream.
    """
    require(component in ('susfs','nomount'),'INVALID_FROZEN_COMPONENT')
    require(all(re.fullmatch(r'[0-9a-f]{40}', v) for v in (pinned,observed)),
            'INVALID_FROZEN_UPSTREAM_SHA '+component)
    require(run('git','-C',donor,'rev-parse','HEAD')==pinned,
            'PINNED_DONOR_IDENTITY_MISMATCH '+component)
    require(run('git','-C',donor,'cat-file','-t',observed)=='commit',
            'UNKNOWN_UPSTREAM_TIP '+component)
    try:
        run('git','-C',donor,'merge-base','--is-ancestor',pinned,observed,
            timeout=90)
    except FleetBlocked as exc:
        raise FleetBlocked('UPSTREAM_NON_FAST_FORWARD '+component+
                           ': source must be reviewed before changing the pin') from exc
    count=int(run('git','-C',donor,'rev-list','--count',pinned+'..'+observed))
    require(count>=0,'NEGATIVE_UPSTREAM_DISTANCE '+component)
    return {
        'source_component':component,
        'frozen_build_commit':pinned,
        'observed_branch_head':observed,
        'commits_ahead_not_integrated':count,
        'upstream_advanced':observed!=pinned,
        'needs_review_before_integrating_new_head':observed!=pinned,
        'candidate_uses_only_frozen_commit':True,
    }


def prepare(repo: Path, root: Path, kernel: str) -> dict:
    repo=repo.resolve(strict=True)
    require(kernel == EXPECTED_KERNEL_R3,'R3_IS_SINGLE_KERNEL_CANDIDATE')
    require(not root.exists() and not root.is_symlink(),'WORKDIR_NOT_NEW')
    require(not root.resolve().is_relative_to(repo),'WORKDIR_IN_REPOSITORY')
    head=ensure_project(repo)
    root.mkdir(parents=True)
    dest=root/'bundle';dest.mkdir()
    sys.path.insert(0,str(repo/'common/scripts'))
    import veux_update_engine as e
    import veux_current_components as reviewed
    cfg,_=e.check_repo()
    report={
      'schema':1,'kernel':kernel,'main_sha':head,
      'isolated_backport_commit':selinux_r3.BACKPORT_COMMIT,
      'note':'R3 backports five SELinux files only; does not import SUSFS build blocker.',
      'baseline':'35217-NoMount21-six-fleet-run-38159736741;candidate-35222-is-UNTESTED',
      'base_run':GOOD_SIX_RUN,'extended_274_run':GOOD_274_RUN,
      'proven_35217_nm21_fleet_run':PROVEN_35217_NM21_FLEET_RUN,
      'extended_274_image_sha256':GOOD_274_IMAGE_SHA256,
      'new_components':TARGETS,'updates_from_nomount_commit':BUILT_NOMOUNT21,
      'only_update':'resukisu','compile':False,'package':False,
      'device_pass':False,'promotion':False,
    }
    heads={}
    links={}
    for comp in ('resukisu','susfs','nomount'):
        entry=TARGETS[comp]
        if comp == 'susfs':
            require(entry['url'] == SUSFS_GITLAB_URL and entry['ref'] == SUSFS_GITLAB_REF
                    and entry['commit'] == SUSFS_GITLAB_PIN,
                    'SUSFS_SOURCE_PIN_OR_URL_CHANGED')
            newhead=retry_susfs_gitlab(
                'head', lambda: remote_head(entry['url'], entry['ref']),
                audit=root/'report')
        else:
            newhead=remote_head(entry['url'],entry['ref'])
        heads[comp]=newhead
        # Never integrate a floating HEAD.  Source is always the frozen pin;
        # for SUSFS and NoMount, verify ancestry after fetching full history.
        # Upstream drift is recorded and requires review before updating pins.
        # Freeze audited BakaSU 35222 BEFORE the upstream SUSFS build blocker.
        # Newer branch heads are never silently integrated.
        donor=dest/comp
        if comp == 'susfs':
            checkout_exact_susfs_with_retry(e, entry, donor, audit=root/'report')
        else:
            e.checkout(entry['url'],entry['commit'],donor,full=True)
        require(e.git(donor,'rev-parse','HEAD')==entry['commit'],
                'PINNED_DONOR_IDENTITY_MISMATCH '+comp)
        require(not e.git(donor,'status','--porcelain'),'DIRTY_UPSTREAM_DONOR '+comp)
        if comp in ('susfs','nomount'):
            report.setdefault('frozen_upstream_audit',{})[comp] = audit_frozen_upstream(
                donor,comp,entry['commit'],newhead)
            if newhead!=entry['commit']:
                print('FROZEN_'+comp.upper()+'_PIN=PASS; HEAD_ADVANCED_NOT_INTEGRATED',
                      flush=True)
        if comp=='resukisu':
            require(reviewed.checked_uapi(donor)==5,'RESUKISU_UAPI5_REVIEW_MISMATCH')
            # The pre-blocker commit is the LAST fully pinned candidate with the
            # historical SUSFS compatibility makefile. Never bypass the upstream
            # SUSFS blocker or apply a floating Git HEAD to a flashable build.
            verify_35222_interface_pins(donor)
            report['selinux_backport_source_review'] = selinux_r3.verify_donor(donor)
            compat=donor/'kernel/tools/susfs_compat.mk'
            require(not compat.exists() or '$(error Please wait susfs update.)' not in compat.read_text(),
                    'BAKASU_35222_SUSFS_BLOCKER_PRESENT')
        if comp=='nomount':
            require(run('git','-C',donor,'merge-base','--is-ancestor',BUILT_NOMOUNT21,entry['commit'])=='',
                    'NOMOUNT21_NOT_FAST_FORWARD')
            old=run('git','-C',donor,'show',BUILT_NOMOUNT21+':kernel/src/nomount.h')
            new=(donor/'kernel/src/nomount.h').read_text()
            report['nomount_wire_abi']=validate_wire_abi(old,new)
            require({p.name for p in (donor/'kernel/src').iterdir()}==
                    {'Kconfig','Makefile','nomount.c','nomount.h'},'NOMOUNT21_KERNEL_LAYOUT_CHANGED')
        links[comp]=safe_symlinks(donor)
    require(run('git','-C',dest/'resukisu','merge-base','--is-ancestor',
                TARGETS['resukisu']['commit'],heads['resukisu'])=='',
            'RESUKISU_UPSTREAM_REWOUND')
    result={'schema':1,'repository_sha':head,
            'golden_sha256':e.digest(repo/cfg['golden_contract']),
            'lineages':[kernel], 'components':TARGETS,
            'candidate_manual_build':True, 'device_pass_inferred':False,
            'performance_required':['5.4.274'], 'rmnet_required':['5.4.274'],
            'fleet_candidate_provenance':{'six_run':GOOD_SIX_RUN,'274_run':GOOD_274_RUN,
                'proven_35217_nm21_run':PROVEN_35217_NM21_FLEET_RUN,
                'nomount21_previous':BUILT_NOMOUNT21},
            'no_promotion':True}
    e.write_json(dest/'targets.json',result)
    report['heads_at_checkout']=heads
    report['upstream_heads_not_used_as_source']=True
    report['review_new_upstream_commits_before_integration']=any(
        h!=TARGETS[c]['commit'] for c,h in heads.items())
    report['upstream_symlinks']=links
    report['proven_274_requires_awinic_r3']=kernel=='5.4.274'
    report['retained_device_fixes']=True
    report['source_bundle_ready']=True
    (root/'prepare.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print('FLEET_35222_NOMOUNT21_BUNDLE=PASS; KERNEL='+kernel,flush=True)
    return report


def awinic_assets(repo: Path, root: Path) -> Path:
    sys.path.insert(0,str(repo/'common/scripts'))
    import veux_fleet_awinic_r1 as awinic_payload
    out=root/'awinic-r3'
    hashes=awinic_payload.extract(out)
    require(hashes['VEUX_AWINIC_R2_GETTER_CANDIDATE.patch']==AWINIC_PATCH_SHA256,
            'AWINIC_PATCH_CHANGED')
    return out


def check_src(repo: Path, root: Path, kernel: str) -> dict:
    require(kernel == EXPECTED_KERNEL_R3,'R3_IS_SINGLE_KERNEL_CANDIDATE')
    sys.path.insert(0,str(repo/'common/scripts'))
    import veux_update_engine as e
    import veux_source_transport as transport
    import veux_device_fixes as fixes
    import veux_rpm_fixes as rpm
    import veux_rpm24 as rpm24
    import veux_wakeup_fixes as wakeup
    from pathlib import Path
    work=root/'source-audit'/kernel
    work.mkdir(parents=True,exist_ok=False)
    bundle=root/'bundle'
    status={'kernel':kernel,'source_preflight':False,'device_pass':False,
            'kernel_build':False,'repository_write':False,
            'targets':TARGETS,'provenance_runs':[GOOD_SIX_RUN,GOOD_274_RUN]}
    try:
        state=transport.materialize(kernel,work)
        src=Path(state['source'])
        e.apply_update(src,state,bundle,work)
        selinux_proof = selinux_r3.apply_source_backport(
            src, bundle/'resukisu', work/'BAKASU-SELINUX-R3.json')
        status['selinux_backport_r3'] = {
            'commit': selinux_proof['isolated_backport'],
            'file_count': len(selinux_proof['changed_kernel_paths']),
            'verified': True,
        }
        # Verify and stage the pinned R4 5.4 unhook guard in THIS disposable
        # source-only tree, even when workflow_dispatch.enable_build=false.
        # The normal build worker independently repeats the same source guard.
        # Any SHA/source/ABI drift fails closed before a kernel can compile.
        from veux_bakasu_unhook_guard_r1 import apply_source_guard
        unhook_proof = apply_source_guard(
            src, root/'report/BAKASU-UNHOOK-R1.json')
        require(unhook_proof.get('r4_effective_source_pinned') is True and
                unhook_proof.get('setprocattr_r4_fallback_unchanged') is True and
                unhook_proof.get('protects_original_pointers_after_restore_error') is True,
                'UNHOOK_R1_SOURCE_PROOF_INCOMPLETE')
        status['unhook_guard_r1'] = {
            'verified': True,
            'source_only_staged': True,
            'input_sha256': unhook_proof['before_sha256'],
            'output_sha256': unhook_proof['after_sha256'],
            'report': 'report/BAKASU-UNHOOK-R1.json',
            'kernel_build': False,
            'device_pass': False,
        }
        # Isolated 64814408 upstream ksud-absence fix.  Pinned 35222 remains
        # the donor build base; never import the upstream SUSFS build stopper.
        from veux_bakasu_ksud_exists_r3 import apply_648_source_only
        sucompat_648_proof = apply_648_source_only(
            src, bundle/'resukisu', root/'report/BAKASU-SUCOMPAT-648-R3.json')
        require(sucompat_648_proof['official_upstream_function_restorable'] is True and
                sucompat_648_proof['ksud_absent_does_not_redirect_to_root_shell'] is True and
                sucompat_648_proof['no_version_or_susfs_pin_promotion'] is True,
                'BAKASU_SUCOMPAT_648_PROOF_INCOMPLETE')
        status['bakasu_sucompat_648'] = {
            'commit': '648144087efd32f5fe68982e8cbf5efc1576038a',
            'source_only_verified': True,
            'after_sha256': sucompat_648_proof['after_sha256'],
            'report': 'report/BAKASU-SUCOMPAT-648-R3.json',
            'device_pass': False,
        }
        fixes_proof=fixes.apply(src,kernel,work)
        fixes.verify_source(src,kernel,fixes_proof)
        rpm_proof=rpm.apply(src,kernel,work)
        rpm.verify_source(src,kernel,rpm_proof)
        rpm24_proof=rpm24.apply(src,kernel,work)
        rpm24.verify_source(src,kernel,rpm24_proof)
        wakeup_proof=wakeup.apply(src,kernel,work)
        wakeup.verify_source(src,kernel,wakeup_proof)
        if kernel=='5.4.274':
            stage=awinic_assets(repo,root)
            sys.path.insert(0,str(stage))
            import awinic_candidate
            proof=awinic_candidate.apply(src,kernel,work)
            require(proof['source_after_sha256']==AWINIC_POST_SHA256,
                    'AWINIC_SOURCE_POST_SHA256_CHANGED')
            status['awinic_r3_source_verified']=True
            status['rpm24_r4_required']=True
            status['rmnet_required']=True
            status['performance_required']=True
        else:
            status['awinic_r3_source_verified']='not-applicable-to-lineage'
        # R3 SOURCE-ONLY SUSFS 5.4 port probe.  Read-only against both kernel
        # and pinned official GitLab donor; writes an audit JSON outside source.
        # A 5.10 hook delta is not a 5.4 implementation approval.
        from veux_susfs_54_port_probe_r3 import probe as susfs_54_port_probe
        status['susfs_54_port_probe'] = susfs_54_port_probe(
            src, bundle/'susfs', root/'report/SUSFS_54_PORT_PROBE_R1.json',
            unhook_proof=unhook_proof)
        # The R4/SUSFS compatibility probe above consumes the exact
        # R4+Unhook source identity. Apply the isolated d726 hash fix ONLY
        # after that read-only probe and prove both postimages independently.
        from veux_bakasu_context_hash_r3 import apply_context_hash_5_4
        hash_d726_proof = apply_context_hash_5_4(
            src, bundle/'resukisu', root/'report/BAKASU-CONTEXT-HASH-D726-R3.json')
        require(hash_d726_proof['upstream_patch_reconstructed_exactly'] is True and
                hash_d726_proof['R4_unhook_and_setprocattr_guards_preserved'] is True and
                hash_d726_proof['host']['context_add_hash_nonstatic'] is True,
                'BAKASU_D726_CONTEXT_HASH_PROOF_INCOMPLETE')
        status['bakasu_context_hash_d726'] = {
            'commit': 'd7260ca1e5c128061122924d0d48754e361e135c',
            'source_only_verified': True,
            'after_hook_sha256': hash_d726_proof['after_hook_sha256'],
            'after_mk_sha256': hash_d726_proof['after_mk_sha256'],
            'report': 'report/BAKASU-CONTEXT-HASH-D726-R3.json',
            'device_pass': False,
        }
        status['source_preflight']=True
        status['device_fixes_verified']=True
        status['rpm24_source_verified']=True
        status['wakeup_source_verified']=True
        status['status']='SOURCE_PREFLIGHT_PASS'
        print('FLEET_'+kernel+'_SOURCE_PREFLIGHT=PASS; NO_KERNEL_BUILD',flush=True)
    except Exception as exc:
        status['status']='BLOCKED'
        status['reason']=str(exc)
        raise
    finally:
        destination=root/'report'
        destination.mkdir(exist_ok=True)
        (destination/('FLEET_'+kernel+'.json')).write_text(
            json.dumps(status,sort_keys=True,indent=2)+'\n')
    return status


def build(repo: Path, root: Path, kernel: str, jobs: int) -> dict:
    require(kernel == EXPECTED_KERNEL_R3,'R3_IS_SINGLE_KERNEL_CANDIDATE')
    require(jobs>0 and jobs<=32,'INVALID_BUILD_JOBS')
    sys.path.insert(0,str(repo/'common/scripts'))
    import veux_update_engine as e
    import veux_release_device as release
    from pathlib import Path
    work=root/'builds'/kernel
    public=root/'public'/kernel
    overlays=root/'overlays'
    work.parent.mkdir(parents=True,exist_ok=True)
    public.parent.mkdir(parents=True,exist_ok=True)
    overlays.mkdir(parents=True,exist_ok=True)
    python=sys.executable
    worker=repo/'common/scripts/veux_release_device.py'
    env=os.environ.copy()
    if kernel=='5.4.274':
        assets=root/'awinic-r3'
        if not assets.is_dir():
            assets=awinic_assets(repo,root)
        env['PYTHONPATH']=os.pathsep.join([str(assets),str(repo/'common/scripts'),env.get('PYTHONPATH','')])
        run(python,assets/'inject_worker.py',worker,root/'release_worker_awinic.py')
        worker=root/'release_worker_awinic.py'
        r3_worker=root/'release_worker_selinux_r3.py'
        selinux_r3.inject_worker(worker,r3_worker)
        worker=r3_worker
        require(git_blob((repo/'common/scripts/veux_release_device.py').read_bytes())==
                CODE_BLOBS['common/scripts/veux_release_device.py'],
                'PROVEN_WORKER_SOURCE_CHANGED')
        # Host tests of the original two-getter patch, unchanged since good run.
        test=subprocess.run([python,'-m','unittest','-v','test_awinic_candidate'],
                            cwd=assets,env=env,timeout=120,check=False)
        require(test.returncode==0,'AWINIC_R3_HOST_TESTS_FAILED')
    cmd=[python,'-u',worker,'worker','--kernel',kernel,
         '--bundle',root/'bundle','--work',work,'--public',public,
         '--overlays',overlays,'--jobs',str(jobs)]
    p=subprocess.run(list(map(str,cmd)),cwd=repo,env=env,timeout=10800,
                     text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    buildlog=root/'report'/('BUILD_'+kernel+'.log')
    buildlog.write_text(p.stdout[-500000:]+'\n')
    require(p.returncode==0,'FLEET_KERNEL_WORKER_FAILED '+kernel+'; see '+str(buildlog))
    row=json.loads((public/'RESULT.json').read_text())
    backport_data=row.get('selinux_backport_r3') or {}
    require(backport_data.get('isolated_backport')==selinux_r3.BACKPORT_COMMIT,
            'BACKPORT_PROOF_MISSING_IN_PUBLISHED_RESULT')
    require(backport_data.get('changed_kernel_paths')==list(selinux_r3.FILE_BLOBS),
            'BACKPORT_SCOPE_MISSING_IN_PUBLISHED_RESULT')
    require(row.get('image_sha256') != BASELINE_35222_IMAGE_SHA256,
            'BACKPORT_IMAGE_IDENTICAL_TO_35222_REFERENCE')
    require(all(row.get(k) is True for k in ('compile','package','static_boot')),
            'INCOMPLETE_BUILD_GATES '+kernel)
    require(row.get('device') is False and row.get('targets')==TARGETS,
            'COMPONENT_OR_DEVICE_PASS_MISMATCH '+kernel)
    require(row.get('repository_sha')==run('git','-C',repo,'rev-parse','HEAD'),
            'WRONG_BUILD_REPOSITORY_COMMIT '+kernel)
    release.verify_results(SimpleNamespace(bundle=root/'bundle',
                                           artifacts=root/'public'))
    if kernel=='5.4.274':
        sys.path.insert(0,str(root/'awinic-r3'))
        import awinic_candidate
        proof=awinic_candidate.verify_published(public)
        require(proof['source_after_sha256']==AWINIC_POST_SHA256,
                'AWINIC_R3_FAILED_TO_SURVIVE_BUILD')
        require('rmnet' in row or 'RMNET' in row.get('package_file',''),
                'RMNET_PACKAGE_MISSING')
        require('performance_compat' in row and 'rpm24_fixes' in row,
                'RPM24_OR_PERFORMANCE_PROOF_DROPPED')
    report={'status':'BUILD_VALIDATED','kernel':kernel,'run_base':GOOD_SIX_RUN,
            'isolated_backport_commit':selinux_r3.BACKPORT_COMMIT,
            'official_35225_not_claimed':True,
            'extended_274':GOOD_274_RUN,'targets':TARGETS,
            'image_sha256':row['image_sha256'],'artifact_name':row['artifact_name'],
            'compile':True,'package':True,'static_boot':True,
            'device_pass':False,'promotion':False,'repository_written':False}
    (root/'report'/('BUILD_'+kernel+'.json')).write_text(
        json.dumps(report,sort_keys=True,indent=2)+'\n')
    print('VEUX_FLEET_R3_'+kernel+'_BUILD_PACKAGE_STATIC=PASS; SELINUX_BACKPORT='+selinux_r3.BACKPORT_COMMIT[:8]+'; DEVICE_PASS=NO',flush=True)
    return report


def main() -> int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('operation',choices=('prepare','preflight','build'))
    ap.add_argument('--repo',required=True,type=Path)
    ap.add_argument('--work',required=True,type=Path)
    ap.add_argument('--kernel',required=True,choices=KERNELS)
    ap.add_argument('--jobs',type=int,default=4)
    args=ap.parse_args()
    try:
        repo=args.repo.resolve(strict=True)
        work=args.work
        if args.operation=='prepare':
            prepare(repo,work,args.kernel)
        elif args.operation=='preflight':
            require(work.is_dir() and (work/'bundle/targets.json').is_file(),
                    'MISSING_BUNDLE_FOR_PREFLIGHT')
            check_src(repo,work,args.kernel)
        else:
            require(work.is_dir() and (work/'bundle/targets.json').is_file(),
                    'MISSING_BUNDLE_FOR_BUILD')
            build(repo,work,args.kernel,args.jobs)
        return 0
    except (FleetBlocked,selinux_r3.UnsafeBackport,OSError,ValueError,KeyError,ImportError,TimeoutError,
            subprocess.SubprocessError) as exc:
        print('VEUX_FLEET_R3_BLOCKED: '+str(exc),file=sys.stderr,flush=True)
        return 1


if __name__=='__main__':
    sys.exit(main())
