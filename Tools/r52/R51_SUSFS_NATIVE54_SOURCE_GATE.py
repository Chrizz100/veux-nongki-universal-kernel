#!/usr/bin/env python3
"""R51 read-only SUSFS verification: fail closed until a genuine 5.4 port exists.

The copied 5.10 source is reference evidence, NOT a drop-in patch for Linux 5.4.
The script never modifies any repository, kernel source or Android device.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys
import zipfile

R41_SHA = 'e9ea57fc1feb8d4d0e840a61b21174ad1d83d496216794bd9285b40f17026bff'
SUSFS_UPSTREAM = '937232ce8c4bdcbe4216e99a1b3d7b5cf633f7c6'
OLD_PORT = 'a9bc1852785cc5288b587169752c74353b2110d6'
R13_NATIVE54_SHA = '4d6f73641fba90b422a0f3d787a5c220829ad6b99807bec843ba24e7f1d73172'
# Verifiable Git blob SHA1 values from the exact stored candidate tree.
PINS = {
 'kernel_patches/fs/susfs.c':'8f7be592bfab5967314f3495113e2d75cbd617c6',
 'kernel_patches/include/linux/susfs.h':'58128c796967308f412c0c9740253a1dce875f56',
 'kernel_patches/include/linux/susfs_def.h':'432f596d6043c335e459b02d7551a35a2facc34f',
 'kernel_patches/50_add_susfs_in_gki-android13-5.10.patch':'5744645d92644dd2a9d0cc69673a7c21c79919c0',
 'kernel_patches/KernelSU/10_enable_susfs_for_ksu.patch':'83fc32b4100a20f8b0d3cde64a97e112dd8a1b9b',
}
REQUIRED_OLD = ('susfs_set_priority_uid_filter', 'susfs_parse_priority_app_strings',
                'susfs_is_priority_uid_filtered')
REQUIRED_NEW = ('susfs_add_sus_type', 'susfs_is_sus_type_rcu', 'susfs_spoof_avd_allowed_rcu')

class GateError(RuntimeError):pass

def req(c, reason):
 if not c:raise GateError(reason)

def sha256(x):return hashlib.sha256(x).hexdigest()
def git_blob(data):return hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()

def audit_payload(z, candidate, metadata):
 req(metadata.get('commit')==SUSFS_UPSTREAM, 'SUSFS_UNEXPECTED_COMMIT')
 req(metadata.get('version')=='2.3.0', 'SUSFS_VERSION_MISMATCH')
 req(metadata.get('fast_forward_from_current') is True, 'SUSFS_HISTORY_NOT_FAST_FORWARD')
 baseline=z.read('r11/evidence/susfs/after/fs/susfs.c')
 req(sha256(baseline)==R13_NATIVE54_SHA, 'NATIVE54_ORIGINAL_PREIMAGE_CHANGED')
 a=baseline.decode()
 data={}
 for rel,expect in PINS.items():
  path=candidate/rel
  req(path.is_file() and not path.is_symlink(),'UPSTREAM_SOURCE_NOT_REGULAR:'+rel)
  raw=path.read_bytes()
  req(git_blob(raw)==expect, 'SUSFS_CAPTURE_GIT_BLOB_MISMATCH:'+rel)
  data[rel]={'git_blob_sha1':expect,'sha256':sha256(raw),'bytes':len(raw)}
 src=(candidate/'kernel_patches/fs/susfs.c').read_text()
 kernel=(candidate/'kernel_patches/50_add_susfs_in_gki-android13-5.10.patch').read_text()
 ksu=(candidate/'kernel_patches/KernelSU/10_enable_susfs_for_ksu.patch').read_text()
 req(all(s in a and s in src for s in REQUIRED_OLD), 'LOST_PRIORITY_UID_FILTER')
 req(all(s not in a and s in src for s in REQUIRED_NEW), 'SELINUX_NEW_FEATURE_SET_UNEXPECTED')
 req('security/selinux/avc.c' in kernel and 'security/selinux/hooks.c' in kernel,
     'SELINUX_HOST_HOOK_REFERENCES_MISSING')
 req(all(x in ksu for x in ('susfs_add_sus_type','susfs_add_sus_avd_allowed_by_type')),
     'KSU_NEW_DISPATCH_DEPENDENCIES_MISSING')
 return {'schema':'VEUX_R51_SUSFS_NATIVE54_GATE_V1',
         'status':'SUSFS_UPSTREAM_CAPTURE_PASS__NATIVE54_AVC_PORT_MISSING__NO_KERNEL_BUILD__NO_FLASH',
         'upstream_commit':SUSFS_UPSTREAM,'existing_port_upstream':OLD_PORT,
         'existing_native54_fs_susfs_sha256':R13_NATIVE54_SHA,
         'upstream_capture':data, 'already_present_on_5_4':list(REQUIRED_OLD),
         'new_missing_on_5_4':list(REQUIRED_NEW),
         'new_selinux_hooks_needed':['security/selinux/avc.c','security/selinux/hooks.c'],
         'cannot_copy_android_13_5_10_host_patch_to_5_4':True,
         'native54_backport_completed':False,'build_allowed':False,'flash_allowed':False}

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--r41',type=Path,required=True)
 p.add_argument('--repository',type=Path,required=True,
                help='GitHub repository checkout with third_party/candidate/susfs')
 p.add_argument('--report',type=Path,required=True)
 a=p.parse_args()
 try:
  req(a.r41.is_file() and not a.r41.is_symlink(),'R41_ARCHIVE_NOT_REGULAR')
  req(sha256(a.r41.read_bytes())==R41_SHA,'R41_ZIP_HASH_CHANGED')
  req(a.repository.is_dir(),'GITHUB_REPOSITORY_NOT_FOUND')
  req(a.report.parent.is_dir() and not a.report.exists(),'REPORT_EXISTS_OR_PARENT_MISSING')
  metadata=json.loads((a.repository/'common/upstream/susfs/candidate.json').read_text())
  with zipfile.ZipFile(a.r41) as z:
   req(z.testzip() is None, 'R41_ARCHIVE_CRC_FAIL')
   proof=audit_payload(z,a.repository/'third_party/candidate/susfs',metadata)
  a.report.write_text(json.dumps(proof,sort_keys=True,indent=2)+'\n')
  print(proof['status'])
  return 2 # deliberately remains build-blocked
 except (OSError,ValueError,GateError,zipfile.BadZipFile) as e:
  print('R51_SUSFS_GATE_REJECTED:'+str(e),file=sys.stderr)
  return 3
if __name__=='__main__':sys.exit(main())
