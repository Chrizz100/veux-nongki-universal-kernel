#!/usr/bin/env python3
"""Fail-closed verification of R6 official BakaSU d726 SELinux source selection."""
from __future__ import annotations
import ast
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
SCRIPTS=ROOT/'common/scripts'
SPEC=importlib.util.spec_from_file_location('veux_bakasu_official_selinux_r6',
                                           SCRIPTS/'veux_bakasu_official_selinux_r6.py')
mod=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)

SHARED=b'''#include <stdint.h>
static int ksu_selinux_hide_unhook(){return 0;}
static int ksu_security_context_to_sid(){return 0;}
static int ksu_handle_selinux_setprocattr(){return 0;}
void stub(void){
    context_add_hash(policydb, &context);
    context_add_hash(orig_policydb, &orig_context);
    commit_creds(new);
}
'''
R5=SHARED+b'''/* VEUX 5.4 source-only parity candidate */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
    goto call_orig;
#endif
'''
OFFICIAL=SHARED+b'''/* official BakaSU d7260ca1 */
    return ksu_handle_selinux_setprocattr();
'''
SUSFS_BASE=b'# baseline SUSFS old compatible base\n'
SUSFS_FUTURE=SUSFS_BASE+b'$(error Please wait susfs update.)\n'
COMPAT_OLD=b'# original compat mk\n'
COMPAT_NEW=COMPAT_OLD+b'ccflags-y += -DKSU_COMPAT_HAS_CONTEXT_ADD_HASH\n'
SUCOMPAT=b'// official sucompat 648\n'

def git(folder,*args):
    p=subprocess.run(['git','-C',str(folder),*args],check=False,
                     text=True,capture_output=True,timeout=25)
    if p.returncode:raise AssertionError(str(args)+':'+p.stderr)
    return p.stdout.strip()

class Fixture:
    def __init__(self,dir):
        self.root=Path(dir);self.donor=self.root/'donor';self.donor.mkdir()
        git(self.donor,'init','-q');git(self.donor,'config','user.name','Test');git(self.donor,'config','user.email','t@example.invalid')
        self._put('kernel/feature/selinux_hide.c',SHARED)
        self._put('kernel/feature/sucompat.c',SUCOMPAT)
        self._put('kernel/tools/kernel_compat.mk',COMPAT_OLD)
        self._put('kernel/tools/susfs_compat.mk',SUSFS_BASE)
        git(self.donor,'add','.');git(self.donor,'commit','-qm','baseline')
        self.base=git(self.donor,'rev-parse','HEAD')
        self._put('kernel/tools/susfs_compat.mk',SUSFS_FUTURE)
        git(self.donor,'add','.');git(self.donor,'commit','-qm','upstream guard')
        self.parent=git(self.donor,'rev-parse','HEAD')
        self._put('kernel/feature/selinux_hide.c',OFFICIAL)
        self._put('kernel/tools/kernel_compat.mk',COMPAT_NEW)
        git(self.donor,'add','.');git(self.donor,'commit','-qm','official source with sidtab fix')
        self.commit=git(self.donor,'rev-parse','HEAD')
        git(self.donor,'checkout','--quiet','--detach',self.base)
        self.src=self.root/'worker'/'kernel';self.src.mkdir(parents=True)
        (self.src/'Makefile').write_text('VERSION = 5\nPATCHLEVEL = 4\nSUBLEVEL = 274\n')
        target=self.src/'KernelSU/kernel/feature/selinux_hide.c'
        target.parent.mkdir(parents=True)
        target.write_bytes(R5)
        self.target=target
        (self.src/'KernelSU/kernel/tools').mkdir(parents=True)
        (self.src/'KernelSU/kernel/tools/kernel_compat.mk').write_bytes(COMPAT_NEW)
        (self.src/'KernelSU/kernel/tools/susfs_compat.mk').write_bytes(SUSFS_BASE)
        (self.src/'KernelSU/kernel/feature/sucompat.c').write_bytes(SUCOMPAT)
        (self.src/'drivers').mkdir()
        (self.src/'drivers/kernelsu').symlink_to('../KernelSU/kernel')
        self.report=self.root/'report'/'R6.json'
        keys={
            'SOURCE_PIN':self.base,'UPSTREAM_COMMIT':self.commit,'UPSTREAM_PARENT':self.parent,
            'OFFICIAL_HOOK_GIT_BLOB':mod.git_blob(OFFICIAL),
            'OFFICIAL_COMPAT_GIT_BLOB':mod.git_blob(COMPAT_NEW),
            'OFFICIAL_SUCOMPAT_GIT_BLOB':mod.git_blob(SUCOMPAT),
            'SUSFS_PIN_GIT_BLOB':mod.git_blob(SUSFS_BASE),
            'R5_EFFECTIVE_SHA256':mod.sha256(R5),
            'R5_COMPAT_SHA256':mod.sha256(COMPAT_NEW),
            'R5_SUCOMPAT_SHA256':mod.sha256(SUCOMPAT),
        }
        self.patchers=[patch.object(mod,key,value) for key,value in keys.items()]
        for patcher in self.patchers:patcher.start()
    def _put(self,path,data):
        f=self.donor/path;f.parent.mkdir(parents=True,exist_ok=True);f.write_bytes(data)
    def close(self):
        for p in reversed(self.patchers):p.stop()

class RealPinnedContract(unittest.TestCase):
    def test_exact_upstream_commit_and_git_blob_pins(self):
        self.assertEqual(mod.UPSTREAM_COMMIT,'d7260ca1e5c128061122924d0d48754e361e135c')
        self.assertEqual(mod.UPSTREAM_PARENT,'648144087efd32f5fe68982e8cbf5efc1576038a')
        self.assertEqual(mod.OFFICIAL_HOOK_GIT_BLOB,'9864c9cf5171311769564b682a42cc7eecc8a801')
        self.assertEqual(mod.SUSFS_PIN_GIT_BLOB,'904bad1c251314c5addca6dec944f586a9c602e1')
    def test_pinned_build_report_r5_is_exact(self):
        self.assertEqual(mod.R5_EFFECTIVE_SHA256,
                         '41aa4ff6f3c452cb90fe293ebc7076c3770c58d8bdbbc8b150a4d82b9d81ea71')
        self.assertEqual(mod.R5_COMPAT_SHA256,
                         '0045b59d0689d1cc4e3cef669622ec3443ea4e0d5f9099ac151625e602fc1983')
        self.assertEqual(mod.R5_SUCOMPAT_SHA256,
                         '1cd5e5b249d1d144b3231f7a08d3b09eb9b7ab9483cf34b0ffda03097f6b4665')
    def test_python_syntax_and_worker_integration(self):
        for path in ('veux_bakasu_official_selinux_r6.py','veux_fleet_35222_selinux_r3.py',
                     'veux_bakasu_selinux_backport_r3.py'):
            ast.parse((SCRIPTS/path).read_text(),filename=path)
        fleet=(SCRIPTS/'veux_fleet_35222_selinux_r3.py').read_text()
        wrapper=(SCRIPTS/'veux_bakasu_selinux_backport_r3.py').read_text()
        self.assertEqual(fleet.count('official_r6 = apply_official_source('),1)
        self.assertGreater(fleet.index('official_r6 = apply_official_source('),
                           fleet.index('parity54_proof = apply_legacy_policy_parity('))
        self.assertLess(fleet.index('official_r6 = apply_official_source('),
                        fleet.index("status['source_preflight']=True"))
        self.assertEqual(wrapper.count('bakasu_official_r6 = apply_official_source('),1)
        self.assertGreater(wrapper.index('bakasu_official_r6 = apply_official_source('),
                           wrapper.index('selinux54_parity_r3 = apply_legacy_policy_parity('))
        self.assertLess(wrapper.index('bakasu_official_r6 = apply_official_source('),
                        wrapper.index("RESULT_ANCHOR="))
        self.assertEqual(wrapper.count("result['bakasu_official_r6'] = bakasu_official_r6"),1)
        self.assertIn('R6_OFFICIAL_SELINUX_SOURCE_NOT_IN_PUBLISHED_KERNEL',fleet)
        self.assertIn('R6_WORKER_AND_PUBLIC_PROOFS_DISAGREE',fleet)
        self.assertIn("'VEUX_FLEET_R6_'",fleet)
        self.assertIn('OFFICIAL_D726_BUILD_PACKAGE_STATIC=PASS',fleet)
    def test_frozen_susfs_blocker_does_not_get_deleted(self):
        script=(SCRIPTS/'veux_bakasu_official_selinux_r6.py').read_text()
        self.assertIn("'R6_UPSTREAM_SUSFS_BLOCKER_PROVENANCE_DRIFT'",script)
        self.assertIn('SUSFS_PIN_GIT_BLOB',script)
        self.assertNotIn('git reset --hard',script)
        self.assertNotIn('git checkout ',script)

class SourceGuard(unittest.TestCase):
    def test_full_git_object_roundtrip_and_one_file_only(self):
        with tempfile.TemporaryDirectory() as d:
            a=Fixture(d)
            try:
                before=a.target.read_bytes()
                proof=mod.apply_official_source(a.src,a.donor,a.report)
                self.assertEqual(a.target.read_bytes(),OFFICIAL)
                self.assertNotEqual(a.target.read_bytes(),before)
                self.assertEqual(proof['changed_paths'],['KernelSU/kernel/feature/selinux_hide.c'])
                self.assertTrue(proof['source_matches_official_bakasu_d726_byte_for_byte'])
                self.assertFalse(proof['device_pass'])
                self.assertFalse(proof['detector_pass'])
                self.assertTrue(proof['susfs_pin_unchanged'])
                self.assertEqual(json.loads(a.report.read_text())['after_sha256'],mod.sha256(OFFICIAL))
                self.assertEqual((a.src/'KernelSU/kernel/tools/susfs_compat.mk').read_bytes(),SUSFS_BASE)
                self.assertEqual((a.src/'KernelSU/kernel/tools/kernel_compat.mk').read_bytes(),COMPAT_NEW)
                self.assertEqual((a.src/'KernelSU/kernel/feature/sucompat.c').read_bytes(),SUCOMPAT)
                self.assertEqual(git(a.donor,'rev-parse','HEAD'),a.base)
            finally:a.close()
    def test_double_application_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            a=Fixture(d)
            try:
                mod.apply_official_source(a.src,a.donor,a.report)
                with self.assertRaises(mod.SafetyStop):
                    mod.apply_official_source(a.src,a.donor,a.report)
            finally:a.close()
    def test_bad_preimage_hash_fails_before_writes(self):
        with tempfile.TemporaryDirectory() as d:
            a=Fixture(d)
            try:
                a.target.write_bytes(R5+b'unsafe')
                with self.assertRaisesRegex(mod.SafetyStop,'R6_R5_PREIMAGE_DRIFT'):
                    mod.apply_official_source(a.src,a.donor,a.report)
                self.assertEqual(a.target.read_bytes(),R5+b'unsafe')
                self.assertFalse(a.report.exists())
            finally:a.close()
    def test_dirty_donor_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            a=Fixture(d)
            try:
                (a.donor/'kernel/feature/selinux_hide.c').write_bytes(b'dirty')
                with self.assertRaisesRegex(mod.SafetyStop,'R6_DONOR_DIRTY'):
                    mod.apply_official_source(a.src,a.donor,a.report)
                self.assertEqual(a.target.read_bytes(),R5)
            finally:a.close()
    def test_wrong_upstream_blob_blocks(self):
        with tempfile.TemporaryDirectory() as d:
            a=Fixture(d)
            try:
                with patch.object(mod,'OFFICIAL_HOOK_GIT_BLOB','0'*40):
                    with self.assertRaisesRegex(mod.SafetyStop,'R6_OFFICIAL_SELINUX_BLOB_DRIFT'):
                        mod.apply_official_source(a.src,a.donor,a.report)
                self.assertEqual(a.target.read_bytes(),R5)
            finally:a.close()
    def test_unknown_kernel_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            a=Fixture(d)
            try:
                (a.src/'Makefile').write_text('VERSION = 5\nPATCHLEVEL = 10\n')
                with self.assertRaisesRegex(mod.SafetyStop,'R6_KERNEL_5_4_REQUIRED'):
                    mod.apply_official_source(a.src,a.donor,a.report)
            finally:a.close()
    def test_symlink_target_escape_blocks(self):
        with tempfile.TemporaryDirectory() as d:
            a=Fixture(d)
            try:
                a.target.unlink()
                outside=a.root/'evil';outside.write_bytes(R5)
                a.target.symlink_to(outside)
                with self.assertRaisesRegex(mod.SafetyStop,'R6_SOURCE_FILE_UNSAFE'):
                    mod.apply_official_source(a.src,a.donor,a.report)
                self.assertEqual(outside.read_bytes(),R5)
            finally:a.close()
    def test_compat_and_sucompat_version_drift_block(self):
        for path,reason in (('kernel/tools/kernel_compat.mk','R6_EFFECTIVE_COMPAT_SHA_DRIFT'),
                            ('kernel/feature/sucompat.c','R6_EFFECTIVE_SUCOMPAT_SHA_DRIFT')):
            with tempfile.TemporaryDirectory() as d:
                a=Fixture(d)
                try:
                    (a.src/'KernelSU'/path).write_bytes(b'other')
                    with self.assertRaisesRegex(mod.SafetyStop,reason):
                        mod.apply_official_source(a.src,a.donor,a.report)
                    self.assertEqual(a.target.read_bytes(),R5)
                finally:a.close()
    def test_susfs_pin_mismatch_block(self):
        with tempfile.TemporaryDirectory() as d:
            a=Fixture(d)
            try:
                (a.src/'KernelSU/kernel/tools/susfs_compat.mk').write_bytes(SUSFS_FUTURE)
                with self.assertRaisesRegex(mod.SafetyStop,'R6_SUSFS_BASE_PIN_MISMATCH'):
                    mod.apply_official_source(a.src,a.donor,a.report)
                self.assertEqual(a.target.read_bytes(),R5)
            finally:a.close()
    def test_report_failed_write_rolls_back(self):
        with tempfile.TemporaryDirectory() as d:
            a=Fixture(d)
            try:
                bad=a.root/'file';bad.write_text('not-dir')
                with self.assertRaises(OSError):
                    mod.apply_official_source(a.src,a.donor,bad/'report.json')
                self.assertEqual(a.target.read_bytes(),R5)
            finally:a.close()
    def test_fake_official_source_with_original_workaround_rejected(self):
        with self.assertRaisesRegex(mod.SafetyStop,'R6_NONUPSTREAM_SELINUX_WORKAROUND_REMAINS'):
            mod.validate_exact_source(R5,OFFICIAL+b'VEUX 5.4 source-only parity candidate',pinned=False)
    def test_missing_sid_hash_or_manual_commit_rejected(self):
        for new,pattern in ((OFFICIAL.replace(b'context_add_hash(',b'unknown_hash('),
                             'R6_D726_HASH_FIX_ABSENT'),
                            (OFFICIAL.replace(b'commit_creds(new)',b'disabled_creds(new)'),
                             'R6_UPSTREAM_MANUAL_CREDENTIAL_PATH_NOT_PRESENT')):
            with self.assertRaisesRegex(mod.SafetyStop,pattern):
                mod.validate_exact_source(R5,new,pinned=False)
    def test_pinned_sha_is_not_bypassed(self):
        with self.assertRaisesRegex(mod.SafetyStop,'R6_R5_PREIMAGE_DRIFT'):
            mod.validate_exact_source(R5,OFFICIAL,pinned=True)
    def test_status_files_have_no_device_pass_claim(self):
        with tempfile.TemporaryDirectory() as d:
            a=Fixture(d)
            try:
                p=mod.apply_official_source(a.src,a.donor,a.report)
                self.assertFalse(p['kernel_build'])
                self.assertFalse(p['device_pass'])
                self.assertFalse(p['detector_pass'])
                self.assertFalse(p['no_repository_write'] is False)
            finally:a.close()

if __name__=='__main__':unittest.main()
