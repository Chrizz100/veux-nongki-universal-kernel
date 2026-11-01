#!/usr/bin/env python3
"""Host-only, synthetic Git-replay regression checks for R51."""
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parent
R41_FOR_TEST=Path(os.environ.get('R51_R41_PACKAGE','/mnt/data/files/VEUX_R41_NOMOUNT_SOURCE_MAIN.zip'))
sys.path.insert(0,str(ROOT))
import R51_BAKASU_REPLAY_NOFLASH as br
import R51_SUSFS_NATIVE54_SOURCE_GATE as sg


def git(root,*args):
 p=subprocess.run(['git','-C',str(root),*args],capture_output=True,text=True)
 if p.returncode:raise RuntimeError(repr(args)+':'+p.stderr[-1000:])
 return p.stdout.strip()


def write(root,path,body):
 f=root/path
 f.parent.mkdir(parents=True,exist_ok=True)
 f.write_text(body)


def commit(root,msg):
 git(root,'add','-A')
 git(root,'-c','user.name=R51 synthetic','-c','user.email=synthetic@local.invalid','commit','-qm',msg)
 return git(root,'rev-parse','HEAD')


def fixture(td):
 td=Path(td)
 upstream=td/'official'
 upstream.mkdir()
 git(upstream,'init','-q')
 for f in br.PROTECTED_PORT_FILES:write(upstream,f,'protected baseline\n')
 write(upstream,'kernel/Kbuild','kernel baseline\n')
 base=commit(upstream,'upstream old baseline')
 local=td/'local-r13'
 git(td,'clone','--quiet',str(upstream),str(local))
 write(local,'kernel/feature/sucompat.c','protected customized VEUX\n')
 write(local,'kernel/feature/sucompat.h','protected VEUX header\n')
 write(local,'kernel/manager/throne_tracker.c','protected VEUX tracker\n')
 write(local,'kernel/supercall/dispatch.c','protected VEUX supercall\n')
 first=commit(local,'VEUX five protected port changes')
 write(local,'kernel/feature/selinux_hide.c','VEUX native54 SELinux protected\n')
 second=commit(local,'VEUX native54 selinux source fix')
 # Five official commits touching only the eleven proven upstream paths.
 write(upstream,'userspace/ksud/src/boot_patch.rs','originos blocklist fix\n')
 write(upstream,'userspace/ksuinit/src/init.rs','originos blocklist fix\n')
 sha1=commit(upstream,'originos userspace')
 for path in ('kernel/Kbuild','kernel/core/init.c','kernel/infra/btf_parser.c',
              'kernel/infra/btf_parser.h','kernel/infra/file_wrapper.c',
              'kernel/selinux/inode.c','kernel/selinux/selinux.h'):
  write(upstream,path,'BTF code for 6.6 compatibility\n')
 sha2=commit(upstream,'BTF patch')
 write(upstream,'kernel/selinux/selinux.h','BTF define tweak\n')
 sha3=commit(upstream,'BTF init guard patch')
 write(upstream,'.github/workflows/build-manager.yml','no spoofed manager build\n')
 write(upstream,'scripts/ksubot.py','normal manager only\n')
 sha4=commit(upstream,'manager CI')
 write(upstream,'userspace/ksuinit/src/init.rs','originos blocklist formatting\n')
 sha5=commit(upstream,'formatting')
 return local,upstream,(base,first,second,sha5,[sha1,sha2,sha3,sha4,sha5])

class Replay(unittest.TestCase):
 def setUp(self):
  self.temporary=tempfile.TemporaryDirectory(prefix='r51-synth-')
  self.addCleanup(self.temporary.cleanup)
  self.base=Path(self.temporary.name)
  self.local,self.upstream,self.pins=fixture(self.base)
  self.r41=self.base/'R41_TEST_FAKE.zip';self.r41.write_bytes(b'not a real package')

 def replay(self,name='replay',pins=None):
  return br.replay(self.local,self.upstream,self.base/name,self.r41,
                   self.pins if pins is None else pins, allow_test_only=True)

 def test_01_real_git_replay_and_preserved_ports(self):
  proof=self.replay()
  self.assertTrue(proof['status'].startswith('BAKASU_ISOLATED_REPLAY_PASS'))
  self.assertEqual(set(proof['changed_paths']),br.EXPECTED_CHANGE_PATHS)
  self.assertEqual(proof['genuine_git_commit_count'],8)
  self.assertEqual(len(proof['protected_port_blobs']),5)
  self.assertEqual(git(self.local,'rev-parse','HEAD'),self.pins[2])
  self.assertEqual(git(self.upstream,'rev-parse','HEAD'),self.pins[3])

 def test_02_wrong_current_upstream_commit_rejected(self):
  bad=list(self.pins);bad[3]=self.pins[0]
  with self.assertRaisesRegex(br.GateError,'HEAD_CHANGED'):
   self.replay(pins=tuple(bad))

 def test_03_missing_upstream_commit_rejected(self):
  bad=list(self.pins);bad[4]=bad[4][:-1]
  with self.assertRaisesRegex(br.GateError,'FIVE_COMMITS_CHANGED'):
   self.replay(pins=tuple(bad))

 def test_04_dirty_local_rejected(self):
  write(self.local,'DANGER.txt','dirty\n')
  with self.assertRaisesRegex(br.GateError,'DIRTY_SOURCE'):
   self.replay()

 def test_05_dirty_official_rejected(self):
  write(self.upstream,'DANGER.txt','dirty\n')
  with self.assertRaisesRegex(br.GateError,'DIRTY_SOURCE'):
   self.replay()

 def test_06_existing_output_never_overwritten(self):
  dest=self.base/'replay';dest.mkdir()
  sentinel=dest/'sentinel';sentinel.write_text('unchanged')
  with self.assertRaisesRegex(br.GateError,'OUTPUT_EXISTS'):
   self.replay()
  self.assertEqual(sentinel.read_text(),'unchanged')

 def test_07_output_inside_original_repo_rejected(self):
  with self.assertRaisesRegex(br.GateError,'OUTPUT_INSIDE_SOURCE_ROOT'):
   br.replay(self.local,self.upstream,self.local/'subdir',self.r41,
             self.pins,allow_test_only=True)

 def test_08_no_source_replaced_and_reportable_git_tree(self):
  p1=self.replay('one')
  p2=self.replay('two')
  self.assertEqual(p1['result_tree'],p2['result_tree'])
  self.assertEqual(p1['protected_port_blobs'],p2['protected_port_blobs'])
  self.assertTrue((self.base/'two/kernel/selinux/inode.c').is_file())

 def test_09_symlink_source_path_rejected(self):
  other=self.base/'link'
  other.symlink_to(self.local,target_is_directory=True)
  with self.assertRaisesRegex(br.GateError,'MISSING_GIT_DIRECTORY'):
   br.replay(other,self.upstream,self.base/'out',self.r41,self.pins,True)

 def test_10_invalid_r41_hash_fails_closed(self):
  with self.assertRaisesRegex(br.GateError,'R41_SOURCE_HASH_MISMATCH'):
   br.replay(self.local,self.upstream,self.base/'out',self.r41,self.pins,False)

 def test_11_unprotected_official_new_feature_stays_in_diff(self):
  p=self.replay()
  self.assertIn('kernel/selinux/inode.c',p['changed_paths'])
  self.assertFalse(p['susfs_native54_merged'])
  self.assertFalse(p['kernel_compiled'])
  self.assertFalse(p['flash_allowed'])

 def test_12_local_port_parent_diff_is_real(self):
  self.assertEqual(git(self.local,'rev-parse','HEAD^'),self.pins[1])
  self.assertEqual(git(self.local,'rev-parse','HEAD^^'),self.pins[0])

class SUSFS(unittest.TestCase):
 def _fake_candidate(self):
  td=tempfile.TemporaryDirectory(prefix='r51-susfs-')
  self.addCleanup(td.cleanup)
  source=Path(td.name)
  root=source/'kernel_patches'
  mockcontents={
    'fs/susfs.c':'susfs_set_priority_uid_filter susfs_parse_priority_app_strings susfs_is_priority_uid_filtered susfs_add_sus_type susfs_is_sus_type_rcu susfs_spoof_avd_allowed_rcu',
    'include/linux/susfs.h':'stub',
    'include/linux/susfs_def.h':'stub',
    '50_add_susfs_in_gki-android13-5.10.patch':'security/selinux/avc.c security/selinux/hooks.c',
    'KernelSU/10_enable_susfs_for_ksu.patch':'susfs_add_sus_type susfs_add_sus_avd_allowed_by_type',
  }
  fakepins={}
  for suffix,content in mockcontents.items():
   write(root,suffix,content)
   fakepins['kernel_patches/'+suffix]=sg.git_blob(content.encode())
  return source,fakepins

 def _audit(self,source):
  import zipfile
  z=zipfile.ZipFile(R41_FOR_TEST)
  with z:
   return sg.audit_payload(z,source,{'commit':sg.SUSFS_UPSTREAM,
                                    'version':'2.3.0','fast_forward_from_current':True})

 def test_13_valid_pinned_feature_capture_remains_blocked(self):
  src,pins=self._fake_candidate()
  with mock.patch.object(sg,'PINS',pins):
   result=self._audit(src)
  self.assertFalse(result['build_allowed'])
  self.assertFalse(result['native54_backport_completed'])
  self.assertIn('NATIVE54_AVC_PORT_MISSING',result['status'])

 def test_14_modified_susfs_blob_rejected(self):
  src,pins=self._fake_candidate()
  (src/'kernel_patches/fs/susfs.c').write_text('unexpected mutation')
  with mock.patch.object(sg,'PINS',pins):
   with self.assertRaisesRegex(sg.GateError,'SUSFS_CAPTURE_GIT_BLOB_MISMATCH'):
    self._audit(src)

 def test_15_missing_selinux_hook_rejected(self):
  src,pins=self._fake_candidate()
  (src/'kernel_patches/50_add_susfs_in_gki-android13-5.10.patch').write_text('avc only')
  pins['kernel_patches/50_add_susfs_in_gki-android13-5.10.patch']=sg.git_blob(b'avc only')
  with mock.patch.object(sg,'PINS',pins):
   with self.assertRaisesRegex(sg.GateError,'SELINUX_HOST_HOOK_REFERENCES_MISSING'):
    self._audit(src)

 def test_16_wrong_source_commit_rejected(self):
  src,pins=self._fake_candidate()
  import zipfile
  with zipfile.ZipFile(R41_FOR_TEST) as z:
   with self.assertRaisesRegex(sg.GateError,'SUSFS_UNEXPECTED_COMMIT'):
    sg.audit_payload(z,src,{'commit':'0'*40,'version':'2.3.0'})

 def test_13_git_blob_sha1_is_git_canonical(self):
  payload=b'abc\n';target=b'blob 4\0abc\n'
  self.assertEqual(sg.git_blob(payload),hashlib.sha1(target).hexdigest())
 def test_14_exact_reference_contains_priority_filter(self):
  import zipfile
  z=zipfile.ZipFile(R41_FOR_TEST)
  b=z.read('r11/evidence/susfs/after/fs/susfs.c')
  self.assertEqual(hashlib.sha256(b).hexdigest(),sg.R13_NATIVE54_SHA)
  self.assertTrue(all(name in b.decode() for name in sg.REQUIRED_OLD))
  self.assertTrue(all(name not in b.decode() for name in sg.REQUIRED_NEW))
 def test_15_no_explicit_flash_pass_possible(self):
  self.assertEqual(sg.SUSFS_UPSTREAM,'937232ce8c4bdcbe4216e99a1b3d7b5cf633f7c6')
  self.assertEqual(len(sg.PINS),5)

if __name__=='__main__':unittest.main(verbosity=2)
