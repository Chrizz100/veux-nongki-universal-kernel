#!/usr/bin/env python3
import importlib.util
import json
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from zipfile import ZipFile

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('r52',ROOT/'tools/r52/r52_native54_susfs_port.py')
r52=importlib.util.module_from_spec(spec); spec.loader.exec_module(r52)
import os
R41=Path(os.environ.get('R52_R41_PATH','/mnt/data/files/VEUX_R41_NOMOUNT_SOURCE_MAIN.zip'))
ORIGINAL=ZipFile(R41).read('r11/evidence/susfs/after/fs/susfs.c').decode()

# Fixture contains source-shaped code but is not represented as official GitLab bytes.
B=('static DEFINE_MUTEX(susfs_mutex_lock_sus_type);\n'
   'static DEFINE_HASHTABLE(SUS_TYPE_HLIST, 10);\n'
   'static DEFINE_HASHTABLE(SUS_AVD_ALLOWED_HLIST, 18);\n'
   'static unsigned int susfs_av_rule_hash(int a, int b) {return a^b;}\n'
   'int susfs_add_sus_type(int a, int b) {return a+b;}\n'
   'int susfs_is_sus_type_rcu(int a) {return a;}\n'
   'int susfs_add_sus_avd_allowed_by_type(int a) {return a;}\n'
   'int susfs_spoof_avd_allowed_rcu(int a) {return a;}\n'
   + ('/* source fixture: diagnostic only, never compiler-tested */\n'*42)+'\n')

UPSTREAM=ORIGINAL.replace(r52.BLOCK_END,B+r52.BLOCK_END,1)

class Native54(unittest.TestCase):
    def test_01_real_original_SHA(self):
        self.assertEqual(r52.sha(ORIGINAL.encode()),r52.NATIVE_54_SHA256)
    def test_02_original_R41_SHA(self):
        self.assertEqual(r52.sha(R41.read_bytes()),r52.R41_SHA256)
    def test_03_merge_preserves_entire_preimage(self):
        new,b=r52.derive_partial(ORIGINAL,UPSTREAM)
        self.assertEqual(b,B)
        self.assertEqual(new.replace(B,'',1).replace('#include <linux/hash.h>\n','',1),ORIGINAL)
    def test_04_priority_uid_filter_preserved(self):
        new,_=r52.derive_partial(ORIGINAL,UPSTREAM)
        self.assertEqual(new.count('susfs_set_priority_uid_filter'),ORIGINAL.count('susfs_set_priority_uid_filter'))
    def test_05_duplicate_feature_rejected(self):
        fake=ORIGINAL.replace(r52.BLOCK_END,'susfs_add_sus_type();\n'+r52.BLOCK_END,1)
        with self.assertRaises(r52.Rejected):r52.derive_partial(fake,UPSTREAM)
    def test_06_missing_native_anchor_rejected(self):
        with self.assertRaises(r52.Rejected):r52.derive_partial(ORIGINAL.replace(r52.BLOCK_END,'',1),UPSTREAM)
    def test_07_missing_upstream_feature_rejected(self):
        with self.assertRaises(r52.Rejected):r52.derive_partial(ORIGINAL,UPSTREAM.replace('susfs_spoof_avd_allowed_rcu','missing_function'))
    def test_08_missing_priority_uid_filter_rejected(self):
        with self.assertRaises(r52.Rejected):r52.derive_partial(ORIGINAL.replace('susfs_set_priority_uid_filter','gone'),UPSTREAM)
    def test_09_dupe_upstream_anchor_rejected(self):
        with self.assertRaises(r52.Rejected):r52.derive_partial(ORIGINAL,UPSTREAM+r52.BLOCK_END)
    def test_10_modified_upstream_block_limit_rejected(self):
        with self.assertRaises(r52.Rejected):r52.derive_partial(ORIGINAL,UPSTREAM.replace(B,B+('X'*16500),1))
    def test_11_missing_hash_include_anchor_rejected(self):
        with self.assertRaises(r52.Rejected):r52.derive_partial(ORIGINAL.replace('#include <linux/string.h>',''),UPSTREAM)
    def test_12_missing_source_hooks_rejected(self):
        with self.assertRaises(r52.Rejected):r52.dependency_gate({'host_patch':'none','ksu_patch':'none','header':'','defs':''})
    def test_13_valid_dependency_source_still_blocked(self):
        j=r52.dependency_gate({'host_patch':'security/selinux/avc.c security/selinux/hooks.c susfs_is_sus_type_rcu susfs_spoof_avd_allowed_rcu',
        'ksu_patch':'susfs_add_sus_type susfs_add_sus_avd_allowed_by_type',
        'header':'susfs_set_priority_uid_filter','defs':'CMD_SUSFS_SET_PRIORITY_UID_FILTER'})
        self.assertEqual(j['build_allowed'],False)
        self.assertFalse(j['flash_allowed'])
        self.assertFalse(j['kernel_54_ksu_dispatch_hooks_ported'])
    def test_14_git_blob_matches_git_hash_object(self):
        a=b'R52 test bytes\n'
        with tempfile.TemporaryDirectory() as t:
            q=Path(t)/'x';q.write_bytes(a)
            subprocess.run(['git','init','-q',t],check=True)
            p=subprocess.run(['git','-C',t,'hash-object','x'],text=True,capture_output=True,check=True).stdout.strip()
            self.assertEqual(r52.git_blob(a),p)
    def test_15_diff_patch_roundtrip(self):
        new,_=r52.derive_partial(ORIGINAL,UPSTREAM)
        import difflib
        diff=''.join(difflib.unified_diff(ORIGINAL.splitlines(keepends=True),new.splitlines(keepends=True),
                 fromfile='a/fs/susfs.c',tofile='b/fs/susfs.c',n=5))
        with tempfile.TemporaryDirectory() as t:
            f=Path(t)/'fs/susfs.c';f.parent.mkdir(parents=True);f.write_text(ORIGINAL)
            patch=Path(t)/'x.patch';patch.write_text(diff)
            p=subprocess.run(['patch','-s','-p1','-i',str(patch)],cwd=t,capture_output=True,text=True)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertEqual(f.read_text(),new)
    def test_16_truncated_r41_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            fake=Path(t)/'r41.zip';fake.write_bytes(R41.read_bytes()[:400])
            self.assertNotEqual(r52.sha(fake.read_bytes()),r52.R41_SHA256)
    def test_17_source_manifest_pin_changes_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            fake=Path(t)/'x';fake.write_text('changed')
            self.assertNotEqual(r52.git_blob(fake.read_bytes()),r52.PINNED_BLOBS['kernel_patches/fs/susfs.c'])
    def test_18_no_bootflash_generated_by_patch(self):
        new,_=r52.derive_partial(ORIGINAL,UPSTREAM)
        self.assertNotIn('mkbootimg',new)
    def test_19_orig_source_bytes_unmodified_in_memory(self):
        before=hashlib.sha256(ORIGINAL.encode()).hexdigest()
        r52.derive_partial(ORIGINAL,UPSTREAM)
        self.assertEqual(hashlib.sha256(ORIGINAL.encode()).hexdigest(),before)
    def test_20_source_patch_expected_minimal_sections(self):
        new,_=r52.derive_partial(ORIGINAL,UPSTREAM)
        import difflib
        D=''.join(difflib.unified_diff(ORIGINAL.splitlines(True),new.splitlines(True)))
        self.assertEqual(D.count('@@'),4)
    def test_21_r51_integrity_not_modified(self):
        src=ROOT/'tools/r52/R51_BAKASU_REPLAY_NOFLASH.py'
        self.assertTrue(src.is_file())
        self.assertIn('BAKASU_UPSTREAM_HEAD_CHANGED',src.read_text())
    def test_22_source_parent_identity_refusal(self):
        with tempfile.TemporaryDirectory() as t:
            f=Path(t)/'symlink';f.symlink_to(R41)
            with self.assertRaises(r52.Rejected):r52.verified_file(f)

if __name__=='__main__':unittest.main(verbosity=2)
