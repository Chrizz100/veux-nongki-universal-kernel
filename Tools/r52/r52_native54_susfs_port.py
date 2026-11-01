#!/usr/bin/env python3
"""R52: derive an auditable *partial* native 5.4 SUSFS candidate from pinned source.

NEVER writes the input repository or R41 archive.  No build or flash output.
The new SELinux/KernelSU host hooks are NOT ported; exit status 2 denotes
successful, intentionally BLOCKED partial source work.
"""
from __future__ import annotations
import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import zipfile

R41_SHA256 = 'e9ea57fc1feb8d4d0e840a61b21174ad1d83d496216794bd9285b40f17026bff'
NATIVE_54_SHA256 = '4d6f73641fba90b422a0f3d787a5c220829ad6b99807bec843ba24e7f1d73172'
UPSTREAM_HEAD = '937232ce8c4bdcbe4216e99a1b3d7b5cf633f7c6'
PINNED_BLOBS = {
 'kernel_patches/fs/susfs.c':'8f7be592bfab5967314f3495113e2d75cbd617c6',
 'kernel_patches/include/linux/susfs.h':'58128c796967308f412c0c9740253a1dce875f56',
 'kernel_patches/include/linux/susfs_def.h':'432f596d6043c335e459b02d7551a35a2facc34f',
 'kernel_patches/50_add_susfs_in_gki-android13-5.10.patch':'5744645d92644dd2a9d0cc69673a7c21c79919c0',
 'kernel_patches/KernelSU/10_enable_susfs_for_ksu.patch':'83fc32b4100a20f8b0d3cde64a97e112dd8a1b9b',
}
CANDIDATE_BLOCK_START = 'static DEFINE_MUTEX(susfs_mutex_lock_sus_type);'
FUNCTIONS = ('susfs_add_sus_type', 'susfs_is_sus_type_rcu',
             'susfs_add_sus_avd_allowed_by_type', 'susfs_spoof_avd_allowed_rcu')
BLOCK_END = '/*\n * Switches the selinux domain of the current process to the KernelSU one, so'
MISSING_HOST = ('security/selinux/avc.c', 'security/selinux/hooks.c')
MISSING_KSU = ('susfs_add_sus_type', 'susfs_add_sus_avd_allowed_by_type')

class Rejected(RuntimeError): pass

def require(ok, message):
    if not ok: raise Rejected(message)

def sha(data:bytes)->str: return hashlib.sha256(data).hexdigest()
def git_blob(data:bytes)->str:
    return hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()

def verified_file(path:Path)->bytes:
    require(path.is_file() and not path.is_symlink(), 'MISSING_OR_LINKED_FILE:'+str(path))
    require(stat.S_ISREG(path.lstat().st_mode), 'NONREGULAR_FILE:'+str(path))
    return path.read_bytes()

def verify_payload(r41:Path, repository:Path):
    require(repository.is_dir() and not repository.is_symlink(), 'REPOSITORY_MISSING_OR_LINKED')
    require(sha(verified_file(r41))==R41_SHA256, 'R41_SHA256_MISMATCH')
    with zipfile.ZipFile(r41) as archive:
        require(archive.testzip() is None, 'R41_ZIP_CRC_ERROR')
        original = archive.read('r11/evidence/susfs/after/fs/susfs.c')
    require(sha(original)==NATIVE_54_SHA256, 'NATIVE_54_PREIMAGE_HASH_MISMATCH')
    info=json.loads(verified_file(repository/'common/upstream/susfs/candidate.json'))
    require(info.get('commit')==UPSTREAM_HEAD and info.get('version')=='2.3.0',
            'SUSFS_UPSTREAM_PIN_MISMATCH')
    require(info.get('fast_forward_from_current') is True and
            info.get('snapshot_complete') is True, 'SUSFS_UNVERIFIED_SNAPSHOT')
    root=repository/'third_party/candidate/susfs'
    data={}
    for rel,expected in PINNED_BLOBS.items():
        p=root/rel
        require(p.resolve().is_relative_to(root.resolve()), 'SOURCE_ESCAPE')
        b=verified_file(p)
        require(git_blob(b)==expected,'SUSFS_GIT_BLOB_CHANGED:'+rel)
        data[rel]={'bytes':len(b),'sha256':sha(b),'git_blob_sha1':expected}
    return original, (root/'kernel_patches/fs/susfs.c').read_bytes(), {
        'metadata':info, 'snapshots':data,
        'host_patch':(root/'kernel_patches/50_add_susfs_in_gki-android13-5.10.patch').read_text(),
        'ksu_patch':(root/'kernel_patches/KernelSU/10_enable_susfs_for_ksu.patch').read_text(),
        'header':(root/'kernel_patches/include/linux/susfs.h').read_text(),
        'defs':(root/'kernel_patches/include/linux/susfs_def.h').read_text(),
    }

def derive_partial(native:str, upstream:str)->tuple[str,str]:
    require(native.count(BLOCK_END)==1, 'NATIVE_INSERT_ANCHOR_MISSING_OR_DUPLICATE')
    require(upstream.count(CANDIDATE_BLOCK_START)==1 and upstream.count(BLOCK_END)==1,
            'UPSTREAM_ANCHOR_MISSING_OR_DUPLICATE')
    require(native.count('/* sus_path */')==1, 'NATIVE_EXISTING_SOURCE_DRIFT')
    require('#include <linux/string.h>\n' in native, 'NATIVE_INCLUDE_ANCHOR_MISSING')
    require('#include <linux/hash.h>' not in native, 'NATIVE_HASH_HEADER_ALREADY_EXISTS_REVIEW')
    require(all(name not in native for name in FUNCTIONS), 'FEATURE_ALREADY_PRESENT_NO_DOUBLE_PORT')
    for symbol in ('susfs_set_priority_uid_filter', 'susfs_parse_priority_app_strings',
                   'susfs_is_priority_uid_filtered'):
        require(symbol in native and symbol in upstream, 'EXISTING_NATIVE54_FEATURE_MISSING:'+symbol)
    begin=upstream.index(CANDIDATE_BLOCK_START)
    end=upstream.index(BLOCK_END,begin)
    block=upstream[begin:end]
    require(len(block)<16000 and len(block)>1600 and block.endswith('\n\n'),
            'UPSTREAM_BLOCK_BOUNDARY_INVALID')
    for symbol in FUNCTIONS+('susfs_av_rule_hash', 'SUS_TYPE_HLIST','SUS_AVD_ALLOWED_HLIST'):
        require(symbol in block, 'MISSING_NEW_UPSTREAM_FUNCTION:'+symbol)
    require('susfs_switch_to_ksu_domain(' not in block, 'DUPLICATE_CREDENTIAL_HELPER')
    merged=native.replace('#include <linux/string.h>\n',
                          '#include <linux/string.h>\n#include <linux/hash.h>\n',1)
    merged=merged.replace(BLOCK_END,block+BLOCK_END,1)
    require(merged.count('susfs_set_priority_uid_filter')==native.count('susfs_set_priority_uid_filter'),
            'DUPLICATE_EXISTING_PRIORITY_UID_FILTER')
    require(merged.replace(block,'',1).replace('#include <linux/hash.h>\n','',1)==native,
            'NATIVE54_BASE_CHANGED_OUTSIDE_AUTHORIZED_INSERTIONS')
    return merged,block

def dependency_gate(context:dict)->dict:
    host=context['host_patch']; ksu=context['ksu_patch']; hdr=context['header']; defs=context['defs']
    require(all(name in host for name in MISSING_HOST), 'UPSTREAM_HOST_HOOKS_ABSENT')
    require(all(name in ksu for name in MISSING_KSU),'UPSTREAM_KERNELSU_DEPENDENCIES_ABSENT')
    require('susfs_is_sus_type_rcu' in host and 'susfs_spoof_avd_allowed_rcu' in host,
            'SELINUX_HOST_CALLS_MISSING')
    require('CMD_SUSFS_SET_PRIORITY_UID_FILTER' in defs,'SUSFS_UAPI_NOT_PINNED')
    require('susfs_set_priority_uid_filter' in hdr,'SUSFS_HEADER_NOT_PINNED')
    return {'kernel_54_selinux_avc_hooks_ported':False,
            'kernel_54_selinux_hooks_ported':False,
            'native_54_susfs_h_and_def_h_ported':False,
            'kernel_54_ksu_dispatch_hooks_ported':False,
            'compiled_new_native_54_susfs_object':False,
            'vendor_abi_validated':False,
            'build_allowed':False,'flash_allowed':False}

def main(argv=None)->int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--r41',type=Path,required=True)
    parser.add_argument('--repository',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True,
                        help='New empty output path outside input repository')
    args=parser.parse_args(argv)
    try:
        require(args.output.parent.is_dir() and not args.output.parent.is_symlink(),
                'OUTPUT_PARENT_NOT_REGULAR')
        require(not args.output.exists() and not args.output.is_symlink(),
                'OUTPUT_ALREADY_EXISTS_NO_OVERWRITE')
        require(not args.output.resolve().is_relative_to(args.repository.resolve()),
                'OUTPUT_INSIDE_SOURCE_REJECTED')
        original,official,context=verify_payload(args.r41,args.repository)
        native=original.decode('utf-8')
        candidate,inserted=derive_partial(native,official.decode('utf-8'))
        blockers=dependency_gate(context)
        patched=candidate.encode('utf-8')
        diff=''.join(difflib.unified_diff(native.splitlines(keepends=True),
                candidate.splitlines(keepends=True),
                fromfile='a/fs/susfs.c',tofile='b/fs/susfs.c',n=5))
        require(diff.startswith('--- a/fs/susfs.c\n+++ b/fs/susfs.c\n'), 'PATCH_FORMAT_BAD')
        report={
           'schema':'VEUX_R52_SUSFS_PARTIAL_NATIVE54_PORT_V1',
           'status':'PINNED_SOURCE_PARTIAL_NATIVE54_PORT_PASS__SELINUX_HOST_GATES_BLOCKED__NO_BUILD_NO_FLASH',
           'r41_sha256':R41_SHA256,'official_head':UPSTREAM_HEAD,
           'native54_preimage_sha256':NATIVE_54_SHA256,
           'native54_partial_candidate_sha256':sha(patched),
           'new_block_sha256':sha(inserted.encode()),
           'new_block_lines':len(inserted.splitlines()),
           'added_features':list(FUNCTIONS),
           'existing_native54_priority_uid_filter_preserved':True,
           'new_full_5_10_host_patch_applied':False,
           'source_provenance':context['snapshots'],
           'gates':blockers,
           'device_modified':False,'kernel_build_performed':False,'boot_images_created':False,
        }
        args.output.mkdir(mode=0o700)
        (args.output/'NOT_BUILD_READY_susfs.c').write_bytes(patched)
        (args.output/'NOT_BUILD_READY_susfs.c.patch').write_text(diff)
        (args.output/'R52_SOURCE_RECEIPT.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
        (args.output/'R52_BLOCKERS.txt').write_text(
          'NO BUILD / NO FLASH. This is a partial fs/susfs.c source candidate ONLY.\n'
          'Unported native 5.4 source: security/selinux/avc.c, security/selinux/hooks.c,\n'
          'include/linux/susfs.h, include/linux/susfs_def.h, KernelSU dispatch and\n'
          'associated 5.4 compile/ABI tests. Never upload candidate as kernel build.\n')
        print(report['status'])
        return 2  # expected partial-completion gate, NOT all-green
    except (Rejected,OSError,ValueError,KeyError,UnicodeError,zipfile.BadZipFile) as exc:
        print('R52_SOURCE_REJECTED='+str(exc),file=sys.stderr)
        return 3
if __name__=='__main__': sys.exit(main())
