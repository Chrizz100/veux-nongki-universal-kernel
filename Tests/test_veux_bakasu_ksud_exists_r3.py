#!/usr/bin/env python3
"""R3 workflow-collected tests for exact BakaSU 64814408 isolated port."""
from __future__ import annotations
import ast
from contextlib import contextmanager
from pathlib import Path
from unittest import mock
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(REPO/'common/scripts'))
import veux_bakasu_ksud_exists_r3 as b
import veux_bakasu_selinux_backport_r3 as backport

OLD_FUNC='''static inline int do_ksu_handle_execveat_sucompat(int *fd, const char *filename, struct user_arg_ptr *argv)
{
    struct ksu_sulog_pending_event *pending_sucompat = NULL;
    struct path kpath;
    bool is_allowed = ksu_is_allow_uid_for_current(ksu_get_uid_t(current_uid()));
    if (!ksu_su_compat_enabled) return -EINVAL;
    if (!is_allowed) return -EINVAL;
    if (memcmp(filename, su_path, sizeof(su_path))) return -EINVAL;
    pr_info("do_execveat_common su found\\n");
    escape_with_root_profile();
    pending_sucompat = ksu_sulog_capture_sucompat_manual(filename, *argv, GFP_KERNEL);
    // We are only check ksud exists
    // In manual hook, we can't try exec ksud, and detect exec success or not
    if (kern_path(KSUD_PATH, LOOKUP_FOLLOW, &kpath)) {
        pr_info("sucompat: /data/adb/ksud not found, fallback to /system/bin/sh");
        memcpy((void *)filename, sh_path, sizeof(sh_path));
        goto out;
    }
    path_put(&kpath);
    memcpy((void *)filename, ksud_path, sizeof(ksud_path));
out:
    ksu_sulog_emit_pending(pending_sucompat, 0, GFP_KERNEL);
    set_thread_flag(TIF_PROC_IN_KSU_EXECVE);
    return 0;
}
'''
NEW_FUNC='''static inline int do_ksu_handle_execveat_sucompat(int *fd, const char *filename, struct user_arg_ptr *argv)
{
    const struct cred *old_cred;
    struct ksu_sulog_pending_event *pending_sucompat = NULL;
    struct path kpath;
    bool is_allowed = ksu_is_allow_uid_for_current(ksu_get_uid_t(current_uid()));
    if (!ksu_su_compat_enabled) return -EINVAL;
    if (!is_allowed) return -EINVAL;
    if (memcmp(filename, su_path, sizeof(su_path))) return -EINVAL;
    pr_info("do_execveat_common su found\\n");
    old_cred = override_creds(ksu_cred);
    if (is_ksud_exists()) {
        pr_info("%s su->sh!\\n", __func__);
    } else {
        pr_info("no ksud found, don't process execve for su!");
        revert_creds(old_cred);
        return -EINVAL;
    }
    revert_creds(old_cred);
    pending_sucompat = ksu_sulog_capture_sucompat_manual(filename, *argv, GFP_KERNEL);
    escape_with_root_profile();
    memcpy((void *)filename, ksud_path, sizeof(ksud_path));
    ksu_sulog_emit_pending(pending_sucompat, 0, GFP_KERNEL);
    set_thread_flag(TIF_PROC_IN_KSU_EXECVE);
    return 0;
}
'''
PRE=b'/* preserved includes and unrelated functions */\n'
SUF=b'\n// fd, filename, argv, envp, flags and retval were NOT provided in bprm_committed_creds\nint not_touched=42;\n'
OLD=PRE+OLD_FUNC.encode()+SUF
NEW=PRE+NEW_FUNC.encode()+SUF

def git_runner(*args,cwd=None):
    p=subprocess.run(['git',*args],cwd=cwd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
    return p.stdout.decode().strip()

@contextmanager
def fake_repo(extra_path:bool=False):
    with tempfile.TemporaryDirectory(prefix='veux-baka648-') as td:
        root=Path(td);donor=root/'donor';donor.mkdir()
        git_runner('init','-q',str(donor))
        git_runner('config','user.name','Test',cwd=donor)
        git_runner('config','user.email','test@example.test',cwd=donor)
        path=donor/b.REL;path.parent.mkdir(parents=True)
        compat=donor/'kernel/tools/susfs_compat.mk';compat.parent.mkdir(parents=True)
        path.write_bytes(OLD);compat.write_text('obj-y += kernel.o\n')
        git_runner('add','.',cwd=donor);git_runner('commit','-qm','pinned base',cwd=donor)
        pin=git_runner('rev-parse','HEAD',cwd=donor)
        path.write_bytes(NEW);compat.write_text('obj-y += kernel.o\n$(error Please wait susfs update.)\n')
        # This changes an extra file too, as upstream blocker was added by
        # an earlier commit. Commit blocker separately, then the 648-only fix.
        path.write_bytes(OLD)
        git_runner('add','.',cwd=donor);git_runner('commit','-qm','blocker',cwd=donor)
        prev=git_runner('rev-parse','HEAD',cwd=donor)
        path.write_bytes(NEW)
        if extra_path:
            (donor/'unexpected').write_text('change')
        git_runner('add','.',cwd=donor);git_runner('commit','-qm','648 candidate',cwd=donor)
        head=git_runner('rev-parse','HEAD',cwd=donor)
        git_runner('checkout','-q',pin,cwd=donor)
        src=root/'kernel';src.mkdir();(src/'Makefile').write_text('VERSION = 5\nPATCHLEVEL = 4\n')
        k=src/'KernelSU/kernel/feature';k.mkdir(parents=True)
        (k/'sucompat.c').write_bytes(OLD)
        (k/'selinux_hide.c').write_bytes(b'R4 effective unhook fixture\n')
        build=src/'drivers';build.mkdir()
        (build/'kernelsu').symlink_to(Path('../KernelSU/kernel'))
        with mock.patch.multiple(b,PIN=pin,PARENT=prev,COMMIT=head,
             BASE_BLOB=b.git_blob(OLD),UPSTREAM_BLOB=b.git_blob(NEW),
             R4_UNHOOK_BLOB_SHA256=b.sha256(b'R4 effective unhook fixture\n')):
            yield root,src,donor,root/'audit/BAKASU-648.json'

class SourceOnly648Tests(unittest.TestCase):
    def test_exact_pinned_production_constants(self):
        self.assertEqual(b.PIN,'5b76b884c75f729a220bb317aa4a4fc78f0e0e9c')
        self.assertEqual(b.COMMIT,'648144087efd32f5fe68982e8cbf5efc1576038a')
        self.assertEqual(b.BASE_BLOB,'8dbbd847a0e059397f96351e4fef124b775b169c')
        self.assertEqual(b.UPSTREAM_BLOB,'42e01ebfffe1ff3f40579b8053767ecb5777c0fb')
        self.assertEqual(b.SRC,'KernelSU/kernel/feature/sucompat.c')

    def test_git_blob_empty_is_correct(self):
        self.assertEqual(b.git_blob(b''),'e69de29bb2d1d6434b8b29ae775ad8c2e48c5391')

    def test_transform_safely_removes_unused_upstream_local(self):
        payload,proof=b.rewrite_exact(OLD,NEW,verify_blobs=False)
        self.assertEqual(payload,NEW.replace(b.UNUSED,b'',1))
        self.assertTrue(proof['official_upstream_function_restorable'])
        self.assertNotIn(b'fallback to /system/bin/sh',payload)
        self.assertNotIn(b'    struct path kpath;',b.func(payload))
        self.assertEqual(payload.replace(b.FUNC_START+b.func(payload),b.FUNC_START+b.func(NEW),1),NEW)

    def test_reject_any_added_unrelated_header_change(self):
        with self.assertRaisesRegex(b.SafetyStop,'UNRELATED_PREAMBLE'):
            b.rewrite_exact(OLD,b'x'+NEW,verify_blobs=False)

    def test_reject_any_added_unrelated_tail_change(self):
        with self.assertRaisesRegex(b.SafetyStop,'UNRELATED_TRAILER'):
            b.rewrite_exact(OLD,NEW+b'x',verify_blobs=False)

    def test_reject_missing_credential_revert(self):
        with self.assertRaisesRegex(b.SafetyStop,'CREDENTIAL_BALANCE'):
            b.rewrite_exact(OLD,NEW.replace(b'revert_creds(old_cred);',b'/* gone */',1),verify_blobs=False)

    def test_reject_upstream_ignored_ksud_check(self):
        data=NEW.replace(b'is_ksud_exists()',b'no_ksud_check()')
        with self.assertRaisesRegex(b.SafetyStop,'CREDENTIAL_CHECK'):
            b.rewrite_exact(OLD,data,verify_blobs=False)

    def test_reject_wrong_original_git_blob(self):
        with self.assertRaisesRegex(b.SafetyStop,'REAL_35222_SOURCE_DRIFT'):
            b.rewrite_exact(b'x'+OLD,NEW)

    def test_upstream_scope_and_exact_commit_file(self):
        with fake_repo() as (_,src,donor,report):
            old,new,proof=b.verify_upstream(donor)
            self.assertEqual(old,OLD)
            self.assertEqual(new,NEW)
            self.assertEqual(proof['changed_upstream_paths'],[b.REL])
            self.assertTrue(proof['upstream_susfs_build_suspension_retained_at_head'])
            self.assertEqual((donor/b.REL).read_bytes(),OLD)

    def test_refuses_additional_modified_commit_path(self):
        with fake_repo(extra_path=True) as (_,src,donor,report):
            with self.assertRaisesRegex(b.SafetyStop,'UNEXPECTED_SCOPE'):
                b.verify_upstream(donor)

    def test_source_only_full_roundtrip(self):
        with fake_repo() as (_,src,donor,report):
            proof=b.apply_648_source_only(src,donor,report)
            self.assertEqual((src/b.SRC).read_bytes(),NEW.replace(b.UNUSED,b'',1))
            self.assertEqual(json.loads(report.read_text())['after_sha256'],proof['after_sha256'])
            self.assertEqual((donor/b.REL).read_bytes(),OLD)
            self.assertTrue(proof['no_device_pass'])

    def test_double_application_fails_closed(self):
        with fake_repo() as (_,src,donor,report):
            b.apply_648_source_only(src,donor,report)
            with self.assertRaisesRegex(b.SafetyStop,'SOURCE_DIFFERS_FROM_GIT'):
                b.apply_648_source_only(src,donor,report.parent/'again.json')

    def test_wrong_kernel_major_fails(self):
        with fake_repo() as (_,src,donor,report):
            (src/'Makefile').write_text('VERSION = 5\nPATCHLEVEL = 10\n')
            with self.assertRaisesRegex(b.SafetyStop,'MUST_BE_5_4'):
                b.apply_648_source_only(src,donor,report)

    def test_without_r4_unhook_fails(self):
        with fake_repo() as (_,src,donor,report):
            (src/b.R4_UNHOOK).write_text('wrong')
            with self.assertRaisesRegex(b.SafetyStop,'R4_UNHOOK_MISSING'):
                b.apply_648_source_only(src,donor,report)

    def test_dirty_donor_fails(self):
        with fake_repo() as (_,src,donor,report):
            (donor/'dirtyfile').write_text('untracked')
            with self.assertRaisesRegex(b.SafetyStop,'SOURCE_DONOR_DIRTY'):
                b.apply_648_source_only(src,donor,report)
            self.assertEqual((src/b.SRC).read_bytes(),OLD)

    def test_report_must_be_outside_source(self):
        with fake_repo() as (_,src,donor,report):
            with self.assertRaisesRegex(b.SafetyStop,'REPORT_PATH_UNSAFE'):
                b.apply_648_source_only(src,donor,src/'proof.json')
            self.assertEqual((src/b.SRC).read_bytes(),OLD)

    def test_symlink_escape_blocked(self):
        with fake_repo() as (root,src,donor,report):
            p=src/b.SRC;p.unlink();p.symlink_to(root/'outside')
            (root/'outside').write_bytes(OLD)
            with self.assertRaisesRegex(b.SafetyStop,'SOURCE_PATH_UNSAFE'):
                b.apply_648_source_only(src,donor,report)

    def test_existing_report_blocks_before_writes(self):
        with fake_repo() as (_,src,donor,report):
            report.parent.mkdir();report.write_text('existing')
            with self.assertRaisesRegex(b.SafetyStop,'REPORT_PATH_UNSAFE'):
                b.apply_648_source_only(src,donor,report)
            self.assertEqual((src/b.SRC).read_bytes(),OLD)

    def test_injected_writer_error_rolls_back_kernel_file(self):
        with fake_repo() as (_,src,donor,report):
            real=Path.write_text
            def bad_write(path,*args,**kwargs):
                if path == report: raise OSError('report read-only')
                return real(path,*args,**kwargs)
            with mock.patch.object(Path,'write_text',bad_write):
                with self.assertRaisesRegex(OSError,'report read-only'):
                    b.apply_648_source_only(src,donor,report)
            self.assertEqual((src/b.SRC).read_bytes(),OLD)

    def test_preflight_order_source_only(self):
        source=(REPO/'common/scripts/veux_fleet_35222_selinux_r3.py').read_text()
        section=source.split('def check_src(',1)[1].split('\ndef build(',1)[0]
        self.assertEqual(section.count('apply_648_source_only('),1)
        self.assertLess(section.find('apply_source_guard('),section.find('apply_648_source_only('))
        self.assertLess(section.find('apply_648_source_only('),section.find('fixes.apply(src,kernel,work)'))
        self.assertLess(section.find('apply_648_source_only('),section.find('susfs_54_port_probe('))
        self.assertIn("root/'report/BAKASU-SUCOMPAT-648-R3.json'",section)
        self.assertIn("status['bakasu_sucompat_648']",section)
        self.assertIn("status['source_preflight']=True",section)
        self.assertNotRegex(section, r'(?m)^\s*(?:if|elif)\b[^\n]*enable_build')

    def test_worker_injection_after_unhook(self):
        self.assertEqual(backport.INSERT.count('apply_648_source_only('),1)
        self.assertLess(backport.INSERT.index('apply_source_backport('),backport.INSERT.index('apply_source_guard('))
        self.assertLess(backport.INSERT.index('apply_source_guard('),backport.INSERT.index('apply_648_source_only('))
        self.assertIn("result['bakasu_sucompat_648'] = sucompat_648",backport.RESULT_INSERT)
        ast.parse('def fake_build():\n'+backport.INSERT)

    def test_existing_yaml_unchanged_and_build_off_gate(self):
        f=REPO/'.github/workflows/VEUX_V4_BakaSU_35222_SELinux_Backport_R3.yml'
        self.assertEqual(hashlib.sha256(f.read_bytes()).hexdigest(),
                         'ff171df9661d7edb311930e9f94966b85e8d50377b04d1686d55c2d6c0323317')
        self.assertIn("if: ${{ inputs.enable_build }}",f.read_text())
        self.assertIn("-p 'test_veux_*r3.py'",f.read_text())

    def test_repo_pins_not_promoted(self):
        source=(REPO/'common/scripts/veux_fleet_35222_selinux_r3.py').read_text()
        self.assertIn("'version':'35222'",source)
        self.assertIn("'commit':'5b76b884c75f729a220bb317aa4a4fc78f0e0e9c'",source)
        self.assertIn("'version':'2.3.0'",source)
        self.assertIn("'version':'21'",source)

    def test_C_missing_ksud_branch_does_not_escalate(self):
        compilers=[x for x in ('clang','gcc') if shutil.which(x)]
        if not compilers:self.skipTest('no C compiler')
        harness=r'''
#include <stdio.h>
#include <errno.h>
#include <string.h>
static int have_daemon=0, overrides=0,reverts=0, roots=0,rewrites=0, flags=0;
static int is_ksud_exists(void){return have_daemon;}
static int override_creds(void){overrides++;return 123;}
static void revert_creds(int old){(void)old;reverts++;}
static void escape_with_root_profile(void){roots++;}
static int run_su(void){
    int old_cred=override_creds();
    if(is_ksud_exists()){}
    else {revert_creds(old_cred);return -EINVAL;}
    revert_creds(old_cred);
    escape_with_root_profile();
    rewrites++;
    flags++;
    return 0;
}
int main(void){
  have_daemon=0;
  if(run_su()!=-EINVAL || roots || rewrites || flags || overrides!=1 || reverts!=1)return 11;
  have_daemon=1;
  if(run_su()!=0 || roots!=1 || rewrites!=1 || flags!=1 || overrides!=2 || reverts!=2)return 12;
  return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            src=Path(tmp)/'test.c';exe=Path(tmp)/'test';src.write_text(harness)
            for cc in compilers:
                with self.subTest(compiler=cc):
                    subprocess.run([cc,'-Wall','-Wextra','-Werror',str(src),'-o',str(exe)],check=True,capture_output=True)
                    subprocess.run([str(exe)],check=True,capture_output=True)

if __name__=='__main__': unittest.main()
