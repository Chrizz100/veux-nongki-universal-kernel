#!/usr/bin/env python3
"""VEUX R3 source-only BakaSU d7260ca1 sidtab context-hash backport.

Isolate upstream's two-file commit only on the disposable Linux 5.4.274
source. Preserve BakaSU 35222+fa12+R4+Unhook R1, SUSFS 2.3.0 and NoMount21.
This gate is NOT a BakaSU HEAD upgrade, compiled kernel, or device pass.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import subprocess

PIN='5b76b884c75f729a220bb317aa4a4fc78f0e0e9c'
BASE='fa12ffde8244008e9afdb7ac0c1bb1bc1b06b95a'
UPSTREAM='d7260ca1e5c128061122924d0d48754e361e135c'
PARENT='648144087efd32f5fe68982e8cbf5efc1576038a'
HOOK_REL='kernel/feature/selinux_hide.c'
COMPAT_REL='kernel/tools/kernel_compat.mk'
HOOK_PATH='KernelSU/'+HOOK_REL
COMPAT_PATH='KernelSU/'+COMPAT_REL
HOOK_OLD_GIT='17e1b61fbd3e85c9c879f678d17fddffa4014734'
HOOK_NEW_GIT='9864c9cf5171311769564b682a42cc7eecc8a801'
COMPAT_OLD_GIT='dc87d993df5d7e965b5665ecb55758ff2552e70f'
COMPAT_NEW_GIT='2023956a3faa701198e6e9efcd84300db84d488c'
EFFECTIVE_R4_UNHOOK_SHA256='be787e0cab3c366c3a8f8dc4662a711370a9e50a137adbdb753ab65b11067f88'
HOST_SERVICES_GIT='08b8700be4bd0699987cd38f48070997e1d47dac' # frozen base before source work
HOST_SERVICES_H_GIT='fc40640a972577cb271f2b917decef403825acef'
BLOCKER=b'$(error Please wait susfs update.)'

OLD_CONTEXT=b'''    if (!rc) {
        rc = sidtab_context_to_sid(sidtab, &context, sid);
        // rc should not be frozen
        context_destroy(&context);
        // removed: if (rc == -ESTALE)
        if (!orig_rc) {
            // sync to global sidtab
            orig_rc = sidtab_context_to_sid(orig_sidtab, &orig_context, &orig_sid);
            if (orig_sid_p)
                *orig_sid_p = orig_sid;
            context_destroy(&orig_context);
        }
    }
'''
NEW_CONTEXT=b'''    if (!rc) {
#ifdef KSU_COMPAT_HAS_CONTEXT_ADD_HASH
        rc = context_add_hash(policydb, &context);
#endif
        if (!rc)
            rc = sidtab_context_to_sid(sidtab, &context, sid);
        // rc should not be frozen
        context_destroy(&context);
        // removed: if (rc == -ESTALE)
        if (!orig_rc) {
#ifdef KSU_COMPAT_HAS_CONTEXT_ADD_HASH
            orig_rc = context_add_hash(orig_policydb, &orig_context);
#endif
            if (!orig_rc) {
                // sync to global sidtab
                orig_rc = sidtab_context_to_sid(orig_sidtab, &orig_context, &orig_sid);
                if (orig_sid_p)
                    *orig_sid_p = orig_sid;
            }
            context_destroy(&orig_context);
        }
    }
'''
COMPAT_APPEND=b'''\n# Google's backport
# https://android-review.googlesource.com/q/Iead2a1d90731ae24fefec2a40af5ffdc457ac916
ifeq ($(shell grep -q "^int context_add_hash" $(srctree)/security/selinux/ss/services.c 2>/dev/null; echo $$?),0)
$(info -- $(REPO_NAME)/compat: found hash indexed sidtab)
ccflags-y += -DKSU_COMPAT_HAS_CONTEXT_ADD_HASH
endif
'''

class SafetyStop(RuntimeError): pass

def check(v:bool,reason:str)->None:
    if not v:raise SafetyStop(reason)

def blob(data:bytes)->str:
    return hashlib.sha1(b'blob '+str(len(data)).encode()+b'\x00'+data).hexdigest()

def sha(data:bytes)->str:
    return hashlib.sha256(data).hexdigest()

def git(donor:Path,*args,binary=False):
    p=subprocess.run(['git','-C',str(donor),*args],capture_output=True,check=False,timeout=120)
    check(p.returncode==0,'UPSTREAM_CONTEXT_HASH_GIT_FAILURE '+ ' '.join(args[:2]))
    return p.stdout if binary else p.stdout.decode().strip()

def verify_upstream(donor:Path)->tuple[bytes,bytes,bytes,bytes,dict]:
    check(donor.is_dir() and (donor/'.git').exists(),'CONTEXT_HASH_DONOR_MISSING')
    check(git(donor,'rev-parse','HEAD')==PIN,'CONTEXT_HASH_FROZEN_PIN_DRIFT')
    check(not git(donor,'status','--porcelain'),'CONTEXT_HASH_DONOR_DIRTY')
    check(git(donor,'rev-parse',UPSTREAM+'^')==PARENT,'CONTEXT_HASH_UPSTREAM_PARENT_DRIFT')
    git(donor,'merge-base','--is-ancestor',PIN,UPSTREAM)
    changed=set(git(donor,'diff-tree','--no-commit-id','--name-only','-r',UPSTREAM).splitlines())
    check(changed=={HOOK_REL,COMPAT_REL},'CONTEXT_HASH_UPSTREAM_UNEXPECTED_SCOPE '+repr(changed))
    old_h=git(donor,'show',BASE+':'+HOOK_REL,binary=True)
    new_h=git(donor,'show',UPSTREAM+':'+HOOK_REL,binary=True)
    old_m=git(donor,'show',BASE+':'+COMPAT_REL,binary=True)
    new_m=git(donor,'show',UPSTREAM+':'+COMPAT_REL,binary=True)
    check(blob(old_h)==HOOK_OLD_GIT and blob(new_h)==HOOK_NEW_GIT,
          'CONTEXT_HASH_UPSTREAM_HOOK_BLOB_DRIFT')
    check(blob(old_m)==COMPAT_OLD_GIT and blob(new_m)==COMPAT_NEW_GIT,
          'CONTEXT_HASH_UPSTREAM_MAKE_BLOB_DRIFT')
    head_m=git(donor,'show',UPSTREAM+':kernel/tools/susfs_compat.mk',binary=True)
    pin_m=git(donor,'show',PIN+':kernel/tools/susfs_compat.mk',binary=True)
    check(BLOCKER in head_m and BLOCKER not in pin_m,'CONTEXT_HASH_SUSFS_STOPPER_PROVENANCE_DRIFT')
    return old_h,new_h,old_m,new_m,{
        'pin':PIN,'upstream_commit':UPSTREAM,'upstream_parent':PARENT,
        'base_selinux_commit':BASE,
        'verified_changed_paths':sorted(changed),'susfs_build_blocker_intact_upstream':True,
        'no_full_head_integration':True}

def verify_host(src:Path)->dict:
    p=src/'security/selinux/ss/services.c'
    h=src/'security/selinux/ss/services.h'
    check(p.is_file() and h.is_file() and not p.is_symlink() and not h.is_symlink(),
          'HOST_CONTEXT_HASH_FILES_MISSING')
    data=p.read_bytes();header=h.read_bytes()
    # The earlier R4 fa12 backport changes linkage on unrelated services.c
    # exports.  Require the actual hash implementation and declaration, not
    # the original whole-file hash which is expected to differ after that.
    check(bool(re.search(rb'(?m)^int context_add_hash\(struct policydb \*policydb,',data)),
          'HOST_5_4_CONTEXT_ADD_HASH_MISSING')
    check(b'context->hash = context_compute_hash' in data and
          b'return sidtab_context_to_sid(sidtab, context, sid);' in data,
          'HOST_5_4_CONTEXT_HASH_IMPLEMENTATION_DRIFT')
    check(bool(re.search(rb'int context_add_hash\(struct policydb \*policydb,\s*struct context \*context\);',header)),
          'HOST_5_4_CONTEXT_HASH_HEADER_UNDECLARED')
    return {'services_c_sha256':sha(data),'services_h_sha256':sha(header),
            'context_add_hash_nonstatic':True,'context_hash_before_sidtab_in_stock_kernel':True}

def rewrite_exact(effective_h:bytes,old_h:bytes,new_h:bytes,effective_m:bytes,
                  old_m:bytes,new_m:bytes,*,pinned:bool=True)->tuple[bytes,bytes,dict]:
    if pinned:
        check(sha(effective_h)==EFFECTIVE_R4_UNHOOK_SHA256,
              'R4_UNHOOK_CONTEXT_HASH_PREIMAGE_DRIFT')
        check(blob(old_h)==HOOK_OLD_GIT and blob(new_h)==HOOK_NEW_GIT,
              'CONTEXT_HASH_HOOK_COMMIT_DRIFT')
        check(blob(old_m)==COMPAT_OLD_GIT and blob(new_m)==COMPAT_NEW_GIT,
              'CONTEXT_HASH_MK_COMMIT_DRIFT')
        check(blob(effective_m)==COMPAT_OLD_GIT,'CONTEXT_HASH_EFFECTIVE_MK_PREIMAGE_DRIFT')
    # The upstream delta is *only* this exact localized SELinux function block.
    check(old_h.count(OLD_CONTEXT)==1 and new_h.count(NEW_CONTEXT)==1,
          'CONTEXT_HASH_UPSTREAM_FUNCTION_ANCHOR_DRIFT')
    check(old_h.replace(OLD_CONTEXT,NEW_CONTEXT,1)==new_h,
          'CONTEXT_HASH_UPSTREAM_OUTSIDE_SCOPE_CHANGED')
    check(effective_h.count(OLD_CONTEXT)==1 and effective_h.count(NEW_CONTEXT)==0,
          'R4_CONTEXT_HASH_FUNCTION_ANCHOR_DRIFT')
    check(new_m==old_m+COMPAT_APPEND and effective_m==old_m,
          'CONTEXT_HASH_UPSTREAM_MK_NOT_PURE_APPEND')
    after_h=effective_h.replace(OLD_CONTEXT,NEW_CONTEXT,1)
    after_m=new_m
    check(after_h.replace(NEW_CONTEXT,OLD_CONTEXT,1)==effective_h,
          'CONTEXT_HASH_R4_HOOK_INVERSE_FAILED')
    check(b'VEUX 5.4: preserve the stock' in after_h,
          'CONTEXT_HASH_R4_SETPROCATTR_FALLBACK_LOST')
    check(after_h.count(b'context_add_hash(policydb, &context);')==1 and
          after_h.count(b'context_add_hash(orig_policydb, &orig_context);')==1,
          'CONTEXT_HASH_CALLSITE_SCOPE_DRIFT')
    return after_h,after_m,{
        'before_hook_sha256':sha(effective_h),'after_hook_sha256':sha(after_h),
        'before_mk_sha256':sha(effective_m),'after_mk_sha256':sha(after_m),
        'changed_paths':[HOOK_PATH,COMPAT_PATH],
        'upstream_patch_reconstructed_exactly':True,
        'R4_unhook_and_setprocattr_guards_preserved':True,
        'context_hash_call_sites':2,'macro_detection_enabled':True,
        'kernel_build':False,'device_pass':False,'pin_promotion':False}

def apply_context_hash_5_4(src:Path,donor:Path,report:Path)->dict:
    src=src.resolve(strict=True);donor=donor.resolve(strict=True)
    check(src.name=='kernel','CONTEXT_HASH_INVALID_WORKSPACE')
    mk=src/'Makefile'
    check(mk.is_file() and not mk.is_symlink(),'CONTEXT_HASH_MAKEFILE_MISSING')
    make=mk.read_text()
    check(re.search(r'(?m)^VERSION\s*=\s*5\s*$',make) is not None and
          re.search(r'(?m)^PATCHLEVEL\s*=\s*4\s*$',make) is not None,
          'CONTEXT_HASH_REQUIRES_LINUX_5_4')
    build=src/'drivers/kernelsu';vendor=src/'KernelSU/kernel'
    check(build.exists() and vendor.is_dir() and
          build.resolve(strict=True)==vendor.resolve(strict=True),
          'CONTEXT_HASH_DIVERGENT_KERNELSU_LAYOUT')
    dest_h=src/HOOK_PATH;dest_m=src/COMPAT_PATH
    check(all(p.is_file() and not p.is_symlink() and
              p.resolve(strict=True).is_relative_to(src) for p in (dest_h,dest_m)),
          'CONTEXT_HASH_HOST_SOURCE_UNSAFE')
    check(not report.exists() and not report.is_symlink() and
          not report.resolve().is_relative_to(src) and
          not report.resolve().is_relative_to(donor),
          'CONTEXT_HASH_REPORT_PATH_UNSAFE')
    host=verify_host(src)
    old_h,new_h,old_m,new_m,source=verify_upstream(donor)
    before_h=dest_h.read_bytes();before_m=dest_m.read_bytes()
    new_h,new_m,proof=rewrite_exact(before_h,old_h,new_h,before_m,old_m,new_m)
    proof['source_provenance']=source;proof['host']=host
    check(dest_h.read_bytes()==before_h and dest_m.read_bytes()==before_m,
          'CONTEXT_HASH_SOURCE_CHANGED_BEFORE_APPLY')
    try:
        dest_h.write_bytes(new_h)
        dest_m.write_bytes(new_m)
        check(dest_h.read_bytes()==new_h and dest_m.read_bytes()==new_m,
              'CONTEXT_HASH_WRITE_VERIFY_FAILED')
        report.parent.mkdir(parents=True,exist_ok=True)
        report.write_text(json.dumps(proof,sort_keys=True,indent=2)+'\n')
    except Exception:
        if dest_h.exists() and dest_h.read_bytes()!=before_h:dest_h.write_bytes(before_h)
        if dest_m.exists() and dest_m.read_bytes()!=before_m:dest_m.write_bytes(before_m)
        raise
    print('VEUX_BAKASU_D726_CONTEXT_HASH_SOURCE=PASS; HOST_CONTEXT_ADD_HASH=YES; '
          'SELINUX_R4_PRESERVED=YES; NO_KERNEL_BUILD; DEVICE_PASS=NO',flush=True)
    return proof
