#!/usr/bin/env python3
"""VEUX source-only R1 unhook regression and deliberate failure injection."""
from __future__ import annotations
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(REPO/'common/scripts'))
import veux_bakasu_unhook_guard_r1 as g
import veux_bakasu_selinux_backport_r3 as bp


def fixture() -> bytes:
    old=[row[0] for row in g.REPLACEMENTS]
    # Verbatim anchors from pinned BakaSU-R4 error paths; filler is a minimal
    # host fixture only, and never misrepresented as the real full kernel C.
    source = '''/* VEUX 5.4: preserve the stock, enforcing SELinux process SID transition. */
/* goto call_orig; */
#ifndef KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE
''' + old[0] + '''
    if (orig_context_write) {
        ret = ksu_patch_text(context_write, &orig_context_write, sizeof(orig_context_write), 1);
''' + old[1] + '''
    }
    if (orig_access_write) {
        ret = ksu_patch_text(access_write, &orig_access_write, sizeof(orig_access_write), 1);
''' + old[2] + '''
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    ksu_lsm_unhook(&selinux_setprocattr_hook);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
    if (ksu_orig_setprocattr) {
        ret = ksu_patch_text((void *)selinux_setprocattr_hook_ptr, &ksu_orig_setprocattr,
                             sizeof(ksu_orig_setprocattr), 1);
''' + old[3] + '''
    }
#else
    stop_machine(ksu_unregister_setprocattr_lsm_hook, NULL, NULL);
''' + old[4] + '''

static int ksu_selinux_hide_enable(void)
{
    int ret = 0;
    goto out;
out:
    return 0;
#ifndef KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE
''' + old[5] + '''
}
''' + old[6] + '''
''' + old[7] + '''
''' + old[8] + '''
    mutex_lock(ksu_selinux_status_lock);
    if (fake_status)
        __free_page(fake_status);
    fake_status = NULL;
    mutex_unlock(ksu_selinux_status_lock);
}
'''
    return source.encode('utf-8')


def tree(tmp:Path, source:bytes, *, version='5.4'):
    root=tmp/'kernel'
    vendor=root/'KernelSU/kernel/feature'
    vendor.mkdir(parents=True)
    (root/'drivers').mkdir()
    (root/'drivers/kernelsu').symlink_to('../KernelSU/kernel')
    ma,mi=version.split('.')
    (root/'Makefile').write_text(f'VERSION = {ma}\nPATCHLEVEL = {mi}\n')
    target=vendor/'selinux_hide.c'
    target.write_bytes(source)
    return root,target


def extract_unhook(c: str) -> str:
    s='static int ksu_selinux_hide_unhook()'
    a=c.index(s);b=c.index('\n\nextern void ksu_register_setprocattr_lsm_hook();',a)
    return c[a:b]


class SourceGuardTests(unittest.TestCase):
    def test_exact_preimage_pin(self):
        self.assertEqual(g.R4_EFFECTIVE_BAKASU_SHA256,
                         '5e40cb29c74fbca6b2b15072e395fb971932894eebe9f846f970a7de139c0a8f')
        self.assertEqual(g.RELATIVE,'KernelSU/kernel/feature/selinux_hide.c')

    def test_scope_and_kernel_pins_preserved(self):
        p=(REPO/'common/scripts/veux_bakasu_selinux_backport_r3.py').read_text()
        self.assertIn("SOURCE_PIN = '5b76b884c75f729a220bb317aa4a4fc78f0e0e9c'",p)
        self.assertIn("BACKPORT_COMMIT = 'fa12ffde8244008e9afdb7ac0c1bb1bc1b06b95a'",p)
        self.assertIn('NO_SUSFS_GUARD_REMOVED',p)
        self.assertEqual(len(g.REPLACEMENTS),9)

    def test_lifetime_error_correction_is_reversible(self):
        src=fixture()
        patched,proof=g.rewrite_effective_r4(src,enforce_sha=False)
        self.assertEqual(len(proof['changed_sections']),9)
        self.assertNotEqual(src,patched)
        text=patched.decode('utf-8')
        for old,new,_ in g.REPLACEMENTS:
            self.assertNotIn(old,text)
            self.assertIn(new,text)
        self.assertIn('goto call_orig;',text)
        self.assertIn('ksu_selinux_hide_running || previously_enabled',text)
        self.assertIn('if (restore_error)',text)
        self.assertFalse(proof['device_pass'])

    def test_second_apply_must_reject(self):
        changed,_=g.rewrite_effective_r4(fixture(),enforce_sha=False)
        with self.assertRaisesRegex(g.UnsafeSource,'EXPECTED_LEGACY_54_UNHOOK_NOT_UNIQUE'):
            g.rewrite_effective_r4(changed,enforce_sha=False)

    def test_unknown_real_source_rejected_before_changes(self):
        with self.assertRaisesRegex(g.UnsafeSource,'R4_BAKASU_EFFECTIVE_SOURCE_DRIFT'):
            g.rewrite_effective_r4(fixture())

    def test_missing_c_anchor_rejected(self):
        src=fixture().replace(b'orig_access_write = NULL;',b'orig_access_write = 0;',1)
        with self.assertRaisesRegex(g.UnsafeSource,'UNHOOK_SOURCE_ANCHOR_DRIFT access_write_restore'):
            g.rewrite_effective_r4(src,enforce_sha=False)

    def test_double_restore_block_rejected(self):
        src=fixture()+b'\n'+g.REPLACEMENTS[1][0].encode()+b'\n'
        with self.assertRaisesRegex(g.UnsafeSource,'UNHOOK_SOURCE_ANCHOR_DRIFT context_write_restore'):
            g.rewrite_effective_r4(src,enforce_sha=False)

    def test_missing_r4_setprocattr_guard_rejected(self):
        src=fixture().replace(b'VEUX 5.4: preserve the stock',b'VEUX 5.4: missing stock')
        with self.assertRaisesRegex(g.UnsafeSource,'R4_5_4_SETPROCATTR_FALLBACK_NOT_PRESENT'):
            g.rewrite_effective_r4(src,enforce_sha=False)

    def test_invalid_utf8_rejected(self):
        with self.assertRaisesRegex(g.UnsafeSource,'R4_BAKASU_NOT_UTF8'):
            g.rewrite_effective_r4(fixture()+b'\xff',enforce_sha=False)

    def test_worker_integration_after_pinned_backport(self):
        script=bp.INSERT
        self.assertLess(script.index('apply_source_backport('),script.index('apply_source_guard('))
        self.assertIn("result['unhook_guard_r1'] = unhook_guard_r1",bp.RESULT_INSERT)
        self.assertEqual(script.count('apply_source_guard('),1)

    def test_temporary_source_and_readonly_pinning(self):
        with tempfile.TemporaryDirectory() as td:
            tmp=Path(td);src,t=tree(tmp,fixture())
            proof=tmp/'proof.json'
            with patch.object(g,'R4_EFFECTIVE_BAKASU_SHA256',g.sha(fixture())):
                p=g.apply_source_guard(src,proof)
            self.assertEqual(g.sha(t.read_bytes()),p['after_sha256'])
            self.assertEqual(json.loads(proof.read_text()),p)
            self.assertEqual(len(p['changed_sections']),9)
            self.assertNotIn('$(error Please wait susfs update.)',t.read_text())

    def test_misplaced_source_tree_refused(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/'not_kernel';root.mkdir()
            with self.assertRaisesRegex(g.UnsafeSource,'NOT_A_DISPOSABLE_KERNEL_SOURCE'):
                g.apply_source_guard(root,Path(td)/'proof.json')

    def test_non_5_4_target_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            tmp=Path(td);src,t=tree(tmp,fixture(),version='5.10')
            with self.assertRaisesRegex(g.UnsafeSource,'NON_5_4_KERNEL_BLOCKED'):
                g.apply_source_guard(src,tmp/'p.json')

    def test_symlink_source_file_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            tmp=Path(td);src,t=tree(tmp,fixture());copy=tmp/'copy.c';copy.write_bytes(fixture())
            t.unlink();t.symlink_to(copy)
            with self.assertRaisesRegex(g.UnsafeSource,'BAKASU_SOURCE_MISSING_OR_UNSAFE'):
                g.apply_source_guard(src,tmp/'p.json')

    def test_bad_kernelsu_link_blocks(self):
        with tempfile.TemporaryDirectory() as td:
            tmp=Path(td);src,t=tree(tmp,fixture())
            (src/'drivers/kernelsu').unlink()
            (src/'drivers/kernelsu').symlink_to('/tmp')
            with self.assertRaisesRegex(g.UnsafeSource,'INTEGRATED_KERNELSU_TREE_MISMATCH'):
                g.apply_source_guard(src,tmp/'p.json')

    def test_existing_report_does_not_write(self):
        with tempfile.TemporaryDirectory() as td:
            tmp=Path(td);src,t=tree(tmp,fixture());p=tmp/'p.json';p.write_text('existing')
            old=t.read_bytes()
            with self.assertRaisesRegex(g.UnsafeSource,'REPORT_MUST_BE_OUTSIDE_KERNEL_TREE'):
                g.apply_source_guard(src,p)
            self.assertEqual(t.read_bytes(),old)

    def test_report_inside_source_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            tmp=Path(td);src,t=tree(tmp,fixture());old=t.read_bytes()
            with self.assertRaisesRegex(g.UnsafeSource,'REPORT_MUST_BE_OUTSIDE_KERNEL_TREE'):
                g.apply_source_guard(src,src/'report.json')
            self.assertEqual(t.read_bytes(),old)

    def test_simulated_source_writer_failure_rolls_back(self):
        with tempfile.TemporaryDirectory() as td:
            tmp=Path(td);src,t=tree(tmp,fixture());prev=t.read_bytes()
            orig=Path.write_bytes
            count=[0]
            def bad_writer(obj,data):
                if obj==t and data != prev and count[0]==0:
                    count[0]+=1
                    orig(obj,b'truncated')
                    raise OSError('intentional failure')
                return orig(obj,data)
            with patch.object(g,'R4_EFFECTIVE_BAKASU_SHA256',g.sha(prev)):
                with patch.object(Path,'write_bytes',bad_writer):
                    with self.assertRaisesRegex(OSError,'intentional failure'):
                        g.apply_source_guard(src,tmp/'p.json')
            self.assertEqual(t.read_bytes(),prev)
            self.assertFalse((tmp/'p.json').exists())

    def test_python_ast_and_workflow_unchanged(self):
        import ast
        for p in (REPO/'common/scripts/veux_bakasu_unhook_guard_r1.py',
                  REPO/'common/scripts/veux_bakasu_selinux_backport_r3.py'):
            ast.parse(p.read_text())
        wf=(REPO/'.github/workflows/VEUX_V4_BakaSU_35222_SELinux_Backport_R3.yml').read_bytes()
        self.assertEqual(len(wf),12346)  # unchanged from live GitHub main

    def test_c_hook_restore_error_injection_clang(self):
        self._run_hook_c('clang')

    def test_c_hook_restore_error_injection_gcc(self):
        self._run_hook_c('gcc')

    def _run_hook_c(self,compiler):
        cc=shutil.which(compiler)
        if not cc:self.skipTest(compiler+' not installed')
        changed,_=g.rewrite_effective_r4(fixture(),enforce_sha=False)
        fn=extract_unhook(changed.decode())
        c=r'''
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#define LINUX_VERSION_CODE 328704
#define KERNEL_VERSION(a,b,c) (((a)<<16)|((b)<<8)|(c))
#define KSU_PATCH_TEXT_FLUSH_DCACHE 1
#define pr_err(...) do {} while(0)
typedef int (*write_op_fn)(void);
typedef int (*setprocattr_fn)(void);
static int original(void) {return 42;}
static int hooked(void) {return -1;}
static write_op_fn ctx_slot, access_slot;
static write_op_fn *context_write=&ctx_slot,*access_write=&access_slot;
static write_op_fn orig_context_write,orig_access_write;
static setprocattr_fn ksu_orig_setprocattr,proc_slot;
static uintptr_t selinux_setprocattr_hook_ptr;
static int fail_at,attempts;
static int ksu_patch_text(void *dst,void *src,size_t len,int flags)
{
    (void)flags;
    attempts++;
    if (attempts==fail_at) return -77;
    memcpy(dst,src,len);
    return 0;
}
''' + fn + r'''
static int run_case(int fail)
{
    int rc;
    ctx_slot=hooked; access_slot=hooked; proc_slot=hooked;
    orig_context_write=original; orig_access_write=original;
    ksu_orig_setprocattr=original;
    selinux_setprocattr_hook_ptr=(uintptr_t)&proc_slot;
    attempts=0;fail_at=fail;
    rc=ksu_selinux_hide_unhook();
    if (fail) {
        if (rc!=-77 || attempts!=fail) return 11;
        if (fail>=1 && fail<=3) {
            if (fail==1 && (!orig_context_write || ctx_slot!=hooked))return 12;
            if (fail==2 && (!orig_access_write || access_slot!=hooked))return 13;
            if (fail==3 && (!ksu_orig_setprocattr || proc_slot!=hooked))return 14;
        }
        fail_at=0;attempts=0;
        rc=ksu_selinux_hide_unhook();
    }
    if (rc!=0 || orig_context_write || orig_access_write || ksu_orig_setprocattr)
        return 15;
    if (ctx_slot!=original || access_slot!=original || proc_slot!=original)
        return 16;
    return 0;
}
int main(void)
{
    int i, rc;
    for(i=0;i<=3;i++){
        rc=run_case(i);
        if(rc){fprintf(stderr,"case=%d rc=%d\n",i,rc);return rc;}
    }
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);source=root/'check.c';exe=root/'check'
            source.write_text(c)
            build=subprocess.run([cc,'-std=gnu11','-Wall','-Wextra','-Werror',str(source),'-o',str(exe)],capture_output=True,text=True,timeout=18)
            self.assertEqual(build.returncode,0,build.stderr)
            run=subprocess.run([str(exe)],capture_output=True,text=True,timeout=5)
            self.assertEqual(run.returncode,0,run.stderr)

    def test_c_feature_state_and_exit_clang(self):
        self._run_feature_c('clang')

    def test_c_feature_state_and_exit_gcc(self):
        self._run_feature_c('gcc')

    def _run_feature_c(self, compiler):
        cc = shutil.which(compiler)
        if not cc:
            self.skipTest(compiler + ' not installed')
        source, _ = g.rewrite_effective_r4(fixture(), enforce_sha=False)
        src = source.decode()
        feature = g.REPLACEMENTS[7][1]
        self.assertIn(feature, src)
        # The first part of the exit body is pinned by REPLACEMENTS; add only
        # the original cleanup suffix, which remains unchanged in production.
        exit_func = g.REPLACEMENTS[8][1] + r'''
    mutex_lock(ksu_selinux_status_lock);
    if (fake_status)
        __free_page(fake_status);
    fake_status = NULL;
    mutex_unlock(ksu_selinux_status_lock);
}
'''
        c = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
typedef uint64_t u64;
#define __exit
#define KSU_FEATURE_SELINUX_HIDE 4
#define pr_err(...) do {} while(0)
#define pr_info(...) do {} while(0)
static bool ksu_selinux_hide_running,ksu_selinux_hide_enabled;
static int enable_result,disable_result,unregistered,freed;
static int selinux_hide_mutex, fake_status_lock;
static int *ksu_selinux_status_lock=&fake_status_lock;
static void *fake_status=(void*)123;
static void mutex_lock(int *p){(void)p;}
static void mutex_unlock(int *p){(void)p;}
static int ksu_selinux_hide_enable(void){return enable_result;}
static int ksu_selinux_hide_disable(void){return disable_result;}
static void ksu_unregister_feature_handler(int x){(void)x;unregistered++;}
static void __free_page(void *p){(void)p;freed++;}
''' + feature + '\n' + exit_func + r'''
int main(void)
{
    int r;
    ksu_selinux_hide_running=false;ksu_selinux_hide_enabled=false;
    enable_result=0;
    r=selinux_hide_feature_set(1);
    if(r||!ksu_selinux_hide_running||!ksu_selinux_hide_enabled) return 10;
    disable_result=-77;
    r=selinux_hide_feature_set(0);
    if(r!=-77||!ksu_selinux_hide_running||!ksu_selinux_hide_enabled) return 11;
    ksu_selinux_hide_exit();
    if(unregistered||freed||!fake_status||!ksu_selinux_hide_running) return 12;
    disable_result=0;
    r=selinux_hide_feature_set(0);
    if(r||ksu_selinux_hide_running||ksu_selinux_hide_enabled)return 13;
    ksu_selinux_hide_exit();
    if(unregistered!=1||freed!=1||fake_status)return 14;
    ksu_selinux_hide_running=false;ksu_selinux_hide_enabled=false;
    enable_result=-5;
    r=selinux_hide_feature_set(1);
    if(r!=-5||ksu_selinux_hide_running||ksu_selinux_hide_enabled)return 15;
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as td:
            top=Path(td);cs=top/'model.c';exe=top/'model';cs.write_text(c)
            build=subprocess.run([cc,'-std=gnu11','-Wall','-Wextra','-Werror',str(cs),'-o',str(exe)],capture_output=True,text=True,timeout=18)
            self.assertEqual(build.returncode,0,build.stderr)
            run=subprocess.run([str(exe)],capture_output=True,text=True,timeout=5)
            self.assertEqual(run.returncode,0,run.stderr)

if __name__=='__main__':unittest.main(verbosity=2)
