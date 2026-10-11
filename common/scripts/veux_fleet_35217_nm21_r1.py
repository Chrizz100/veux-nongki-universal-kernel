#!/usr/bin/env python3
"""VEUX six-lineage fleet candidate, using proven 35217 / NoMount21 source IDs.

Base evidence: V4 6/6 run 37745338419, with 5.4.274 extended evidence from
RPM24-R4 + RMNET + AWINIC-R3 run 38131689108.  The ONLY new kernel source
revision is the NoMount21 master commit below.  Neither this tool nor its
workflow promotes source changes to GitHub or infers a device PASS.

Do not confuse the historical CURRENT_BUILD (35203 / NM20) with this build's
validated 35217 / NM21 source base.
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
from types import SimpleNamespace

REPO_NAME = 'Chrizz100/veux-nongki-universal-kernel'
KERNELS = ('5.4.274','5.4.292','5.4.293','5.4.300','5.4.301','5.4.302')
GOOD_SIX_RUN = 37745338419
GOOD_274_RUN = 38131689108
GOOD_274_IMAGE_SHA256 = 'a55edc3f13f7cb663b055d99cb2636e2e41259e8031d688840f4d1032e64172a'
GOOD_274_RESULT_TARGETS_SHA256 = '848bc5a760e29ba7bf41b40a6b2f84b028c701fd38c1b61179623ca1d2f62237'
# Committed software pins; NO CURRENT_BUILD base/ahead/current_fleet fallback.
TARGETS = {
    'resukisu': {
        'url':'https://github.com/ReSukiSU/ReSukiSU.git',
        'ref':'refs/heads/main',
        'commit':'c9246641b9eee8b9986050e8bf1832f88da880c2',
        'version':'35217','local_version':4517,'tag':'v4.2.0-rc3','uapi':5,
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


def prepare(repo: Path, root: Path, kernel: str) -> dict:
    repo=repo.resolve(strict=True)
    require(kernel in KERNELS,'UNKNOWN_KERNEL')
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
      'baseline':'verified-six-fleet-build-37745338419;five-four-274-rpm24-awinic-run-38131689108',
      'base_run':GOOD_SIX_RUN,'extended_274_run':GOOD_274_RUN,
      'extended_274_image_sha256':GOOD_274_IMAGE_SHA256,
      'new_components':TARGETS,'updates_from_nomount_commit':BUILT_NOMOUNT21,
      'only_update':'nomount','compile':False,'package':False,
      'device_pass':False,'promotion':False,
    }
    heads={}
    links={}
    for comp in ('resukisu','susfs','nomount'):
        entry=TARGETS[comp]
        newhead=remote_head(entry['url'],entry['ref'])
        heads[comp]=newhead
        if comp=='nomount':
            require(newhead==entry['commit'],
                    'NOMOUNT_HEAD_CHANGED: review latest head before updating pin')
        elif comp=='susfs':
            require(newhead==entry['commit'],
                    'SUSFS_HEAD_CHANGED: audit compatibility/backports before compiling')
        # We intentionally freeze ReSukiSU 35217 even if main advanced.
        donor=dest/comp
        e.checkout(entry['url'],entry['commit'],donor,full=True)
        require(e.git(donor,'rev-parse','HEAD')==entry['commit'],
                'PINNED_DONOR_IDENTITY_MISMATCH '+comp)
        require(not e.git(donor,'status','--porcelain'),'DIRTY_UPSTREAM_DONOR '+comp)
        if comp=='resukisu':
            require(reviewed.checked_uapi(donor)==5,'RESUKISU_UAPI5_REVIEW_MISMATCH')
            compat=donor/'kernel/tools/susfs_compat.mk'
            require(not compat.exists() or '$(error Please wait susfs update.)' not in compat.read_text(),
                    'RESUKISU_35217_SUSFS_BLOCKER_PRESENT')
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
                'nomount21_previous':BUILT_NOMOUNT21},
            'no_promotion':True}
    e.write_json(dest/'targets.json',result)
    report['heads_at_checkout']=heads
    report['upstream_symlinks']=links
    report['proven_274_requires_awinic_r3']=kernel=='5.4.274'
    report['retained_device_fixes']=True
    report['source_bundle_ready']=True
    (root/'prepare.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print('FLEET_35217_NOMOUNT21_BUNDLE=PASS; KERNEL='+kernel,flush=True)
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
    require(kernel in KERNELS,'UNKNOWN_KERNEL')
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
    require(kernel in KERNELS,'UNKNOWN_KERNEL')
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
            'extended_274':GOOD_274_RUN,'targets':TARGETS,
            'image_sha256':row['image_sha256'],'artifact_name':row['artifact_name'],
            'compile':True,'package':True,'static_boot':True,
            'device_pass':False,'promotion':False,'repository_written':False}
    (root/'report'/('BUILD_'+kernel+'.json')).write_text(
        json.dumps(report,sort_keys=True,indent=2)+'\n')
    print('VEUX_FLEET_'+kernel+'_BUILD_PACKAGE_STATIC=PASS; DEVICE_PASS=NO',flush=True)
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
    except (FleetBlocked,OSError,ValueError,KeyError,ImportError,TimeoutError,
            subprocess.SubprocessError) as exc:
        print('VEUX_FLEET_R1_BLOCKED: '+str(exc),file=sys.stderr,flush=True)
        return 1


if __name__=='__main__':
    sys.exit(main())
