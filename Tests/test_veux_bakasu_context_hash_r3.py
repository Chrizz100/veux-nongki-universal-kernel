#!/usr/bin/env python3
"""Fail-closed tests for the isolated upstream BakaSU d726 context-hash fix."""
from __future__ import annotations
from contextlib import contextmanager
from pathlib import Path
from unittest import mock
import ast
import json
import hashlib
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(REPO/'common/scripts'))
import veux_bakasu_context_hash_r3 as g
import veux_bakasu_selinux_backport_r3 as backport

OLD_H=b'''/* BakaSU legacy SELinux, unaffected prefix */
#include <ss/services.h>
/* VEUX 5.4: preserve the stock, enforcing SELinux process SID transition. */
static int ksu_security_context_to_sid(void) {
    int rc = 0;
    int orig_rc = 0;
'''+g.OLD_CONTEXT+b'''    return rc;
}
/* unaffected suffix */
'''
NEW_H=OLD_H.replace(g.OLD_CONTEXT,g.NEW_CONTEXT,1)
OLD_M=b'# BakaSU 5.4 flags\nccflags-y += -DCOMPAT_TEST\n'
NEW_M=OLD_M+g.COMPAT_APPEND

def git(*params,cwd=None):
    p=subprocess.run(['git',*params],cwd=cwd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
    return p.stdout.decode().strip()

@contextmanager
def fake_repo(change_extra_file:bool=False,break_host:bool=False,old_hook=None):
    with tempfile.TemporaryDirectory(prefix='veux-d726-') as td:
        tmp=Path(td);repo=tmp/'upstream';repo.mkdir();git('init','-q',str(repo))
        git('config','user.email','test@example.test',cwd=repo)
        git('config','user.name','Test',cwd=repo)
        h=repo/g.HOOK_REL;h.parent.mkdir(parents=True)
        m=repo/g.COMPAT_REL;m.parent.mkdir(parents=True)
        s=repo/'kernel/tools/susfs_compat.mk'
        h.write_bytes(OLD_H);m.write_bytes(OLD_M);s.write_bytes(b'no build stopper yet\n')
        git('add','.',cwd=repo);git('commit','-qm','frozen',cwd=repo)
        pin=git('rev-parse','HEAD',cwd=repo)
        # Fa12 inherited, marker commit between pinned and new HEAD.
        (repo/'fa12_marker').write_text('existing SELinux backport')
        git('add','.',cwd=repo);git('commit','-qm','fa12 source',cwd=repo)
        base=git('rev-parse','HEAD',cwd=repo)
        s.write_bytes(b'$(error Please wait susfs update.)\n')
        git('add','.',cwd=repo);git('commit','-qm','SUSFS stop',cwd=repo)
        (repo/'ksud_marker').write_text('648 source')
        git('add','.',cwd=repo);git('commit','-qm','648 source',cwd=repo)
        parent=git('rev-parse','HEAD',cwd=repo)
        h.write_bytes(NEW_H);m.write_bytes(NEW_M)
        if change_extra_file:(repo/'extra').write_text('bad extra scope')
        git('add','.',cwd=repo);git('commit','-qm','d726 scoped commit',cwd=repo)
        commit=git('rev-parse','HEAD',cwd=repo)
        git('checkout','-q',pin,cwd=repo)
        src=tmp/'kernel';src.mkdir();(src/'Makefile').write_text('VERSION = 5\nPATCHLEVEL = 4\n')
        src_h=src/g.HOOK_PATH;src_h.parent.mkdir(parents=True)
        src_h.write_bytes(old_hook if old_hook is not None else OLD_H)
        src_m=src/g.COMPAT_PATH;src_m.parent.mkdir(parents=True)
        src_m.write_bytes(OLD_M)
        fs=src/'security/selinux/ss';fs.mkdir(parents=True)
        (fs/'services.c').write_bytes(b'int context_add_hash(struct policydb *policydb,\n  struct context *context) { context->hash = context_compute_hash(context->str); return 0; }\nreturn sidtab_context_to_sid(sidtab, context, sid);\n' if not break_host else b'no hash function\n')
        (fs/'services.h').write_text('int context_add_hash(struct policydb *policydb, struct context *context);\n')
        (src/'drivers').mkdir()
        (src/'drivers/kernelsu').symlink_to(Path('../KernelSU/kernel'))
        with mock.patch.multiple(g,PIN=pin,BASE=base,PARENT=parent,UPSTREAM=commit,
           HOOK_OLD_GIT=g.blob(OLD_H),HOOK_NEW_GIT=g.blob(NEW_H),
           COMPAT_OLD_GIT=g.blob(OLD_M),COMPAT_NEW_GIT=g.blob(NEW_M),
           EFFECTIVE_R4_UNHOOK_SHA256=g.sha(OLD_H)):
            yield tmp,src,repo,tmp/'report/BAKASU-CONTEXT-HASH-D726-R3.json'

class ContextHashR3Tests(unittest.TestCase):
    def test_pinned_real_commit_and_exact_blob_identities(self):
        self.assertEqual(g.PIN,'5b76b884c75f729a220bb317aa4a4fc78f0e0e9c')
        self.assertEqual(g.BASE,'fa12ffde8244008e9afdb7ac0c1bb1bc1b06b95a')
        self.assertEqual(g.UPSTREAM,'d7260ca1e5c128061122924d0d48754e361e135c')
        self.assertEqual(g.HOOK_OLD_GIT,'17e1b61fbd3e85c9c879f678d17fddffa4014734')
        self.assertEqual(g.HOOK_NEW_GIT,'9864c9cf5171311769564b682a42cc7eecc8a801')
        self.assertEqual(g.COMPAT_OLD_GIT,'dc87d993df5d7e965b5665ecb55758ff2552e70f')
        self.assertEqual(g.COMPAT_NEW_GIT,'2023956a3faa701198e6e9efcd84300db84d488c')

    def test_upstream_makes_only_scoped_delta(self):
        with fake_repo() as (_,src,repo,report):
            o,n,om,nm,proof=g.verify_upstream(repo)
            self.assertEqual((o,n,om,nm),(OLD_H,NEW_H,OLD_M,NEW_M))
            self.assertEqual(proof['verified_changed_paths'],[g.HOOK_REL,g.COMPAT_REL])

    def test_rejects_unexpected_upstream_commit_path(self):
        with fake_repo(change_extra_file=True) as (_,src,repo,report):
            with self.assertRaisesRegex(g.SafetyStop,'UNEXPECTED_SCOPE'):
                g.verify_upstream(repo)

    def test_exact_source_transform_only_two_files(self):
        out_h,out_m,proof=g.rewrite_exact(OLD_H,OLD_H,NEW_H,OLD_M,OLD_M,NEW_M,pinned=False)
        self.assertEqual(out_h,NEW_H)
        self.assertEqual(out_m,NEW_M)
        self.assertEqual(proof['changed_paths'],[g.HOOK_PATH,g.COMPAT_PATH])
        self.assertTrue(proof['R4_unhook_and_setprocattr_guards_preserved'])

    def test_scope_change_in_upstream_hook_rejected(self):
        with self.assertRaisesRegex(g.SafetyStop,'OUTSIDE_SCOPE_CHANGED'):
            g.rewrite_exact(OLD_H,OLD_H,NEW_H+b'unrelated change',OLD_M,OLD_M,NEW_M,pinned=False)

    def test_scope_change_in_makefile_rejected(self):
        with self.assertRaisesRegex(g.SafetyStop,'NOT_PURE_APPEND'):
            g.rewrite_exact(OLD_H,OLD_H,NEW_H,OLD_M,OLD_M,NEW_M+b'bad',pinned=False)

    def test_duplicated_function_anchor_rejected(self):
        with self.assertRaisesRegex(g.SafetyStop,'FUNCTION_ANCHOR_DRIFT'):
            g.rewrite_exact(OLD_H+g.OLD_CONTEXT,OLD_H,NEW_H,OLD_M,OLD_M,NEW_M,pinned=False)

    def test_no_r4_fallback_is_rejected(self):
        with self.assertRaisesRegex(g.SafetyStop,'SETPROCATTR_FALLBACK_LOST'):
            g.rewrite_exact(OLD_H.replace(b'VEUX 5.4:',b'MISSING:'),OLD_H,NEW_H,OLD_M,OLD_M,NEW_M,pinned=False)

    def test_real_host_context_hash_verified(self):
        with fake_repo() as (_,src,repo,report):
            self.assertTrue(g.verify_host(src)['context_add_hash_nonstatic'])

    def test_host_without_context_hash_fail_closed(self):
        with fake_repo(break_host=True) as (_,src,repo,report):
            with self.assertRaisesRegex(g.SafetyStop,'HOST_5_4_CONTEXT_ADD_HASH_MISSING'):
                g.apply_context_hash_5_4(src,repo,report)
            self.assertEqual((src/g.HOOK_PATH).read_bytes(),OLD_H)

    def test_source_only_integration_two_files(self):
        with fake_repo() as (_,src,repo,report):
            proof=g.apply_context_hash_5_4(src,repo,report)
            self.assertEqual((src/g.HOOK_PATH).read_bytes(),NEW_H)
            self.assertEqual((src/g.COMPAT_PATH).read_bytes(),NEW_M)
            self.assertEqual(json.loads(report.read_text())['after_hook_sha256'],proof['after_hook_sha256'])
            self.assertEqual((repo/g.HOOK_REL).read_bytes(),OLD_H)

    def test_double_apply_refused(self):
        with fake_repo() as (_,src,repo,report):
            g.apply_context_hash_5_4(src,repo,report)
            with self.assertRaisesRegex(g.SafetyStop,'UNHOOK_CONTEXT_HASH_PREIMAGE_DRIFT'):
                g.apply_context_hash_5_4(src,repo,report.parent/'again.json')

    def test_wrong_kernel_blocked(self):
        with fake_repo() as (_,src,repo,report):
            (src/'Makefile').write_text('VERSION = 5\nPATCHLEVEL = 10\n')
            with self.assertRaisesRegex(g.SafetyStop,'REQUIRES_LINUX_5_4'):
                g.apply_context_hash_5_4(src,repo,report)

    def test_no_report_inside_kernel_tree(self):
        with fake_repo() as (_,src,repo,report):
            with self.assertRaisesRegex(g.SafetyStop,'REPORT_PATH_UNSAFE'):
                g.apply_context_hash_5_4(src,repo,src/'proof.json')

    def test_dirty_donor_blocked(self):
        with fake_repo() as (_,src,repo,report):
            (repo/'extra-dirty').write_text('bad')
            with self.assertRaisesRegex(g.SafetyStop,'DONOR_DIRTY'):
                g.apply_context_hash_5_4(src,repo,report)

    def test_reject_different_file_before_writes(self):
        with fake_repo() as (_,src,repo,report):
            (src/g.COMPAT_PATH).write_text('unexpected compat build options')
            with self.assertRaisesRegex(g.SafetyStop,'PREIMAGE_DRIFT'):
                g.apply_context_hash_5_4(src,repo,report)
            self.assertEqual((src/g.HOOK_PATH).read_bytes(),OLD_H)

    def test_rolls_back_both_files_if_report_fails(self):
        with fake_repo() as (_,src,repo,report):
            real=Path.write_text
            def bad_write(p,*args,**kwargs):
                if p==report:raise OSError('writer blocked')
                return real(p,*args,**kwargs)
            with mock.patch.object(Path,'write_text',bad_write):
                with self.assertRaisesRegex(OSError,'writer blocked'):
                    g.apply_context_hash_5_4(src,repo,report)
            self.assertEqual((src/g.HOOK_PATH).read_bytes(),OLD_H)
            self.assertEqual((src/g.COMPAT_PATH).read_bytes(),OLD_M)

    def test_symlink_in_kernel_file_blocked(self):
        with fake_repo() as (tmp,src,repo,report):
            p=src/g.HOOK_PATH;p.unlink();p.symlink_to(tmp/'outside')
            (tmp/'outside').write_bytes(OLD_H)
            with self.assertRaisesRegex(g.SafetyStop,'HOST_SOURCE_UNSAFE'):
                g.apply_context_hash_5_4(src,repo,report)

    def test_preflight_after_read_only_susfs_probe(self):
        txt=(REPO/'common/scripts/veux_fleet_35222_selinux_r3.py').read_text()
        body=txt[txt.index('def check_src('):txt.index('def build(',txt.index('def check_src('))]
        self.assertEqual(body.count('apply_context_hash_5_4('),1)
        self.assertLess(body.index('apply_648_source_only('),body.index('susfs_54_port_probe('))
        self.assertLess(body.index('susfs_54_port_probe('),body.index('apply_context_hash_5_4('))
        self.assertLess(body.index('apply_context_hash_5_4('),body.index("status['source_preflight']=True"))
        self.assertIn("root/'report/BAKASU-CONTEXT-HASH-D726-R3.json'",body)
        self.assertIn("status['bakasu_context_hash_d726']",body)

    def test_kernel_worker_after_r4_unhook_and_648(self):
        ins=backport.INSERT
        self.assertEqual(ins.count('apply_context_hash_5_4('),1)
        self.assertLess(ins.index('apply_source_guard('),ins.index('apply_648_source_only('))
        self.assertLess(ins.index('apply_648_source_only('),ins.index('apply_context_hash_5_4('))
        self.assertIn("result['bakasu_context_hash_d726'] = context_hash_d726",backport.RESULT_INSERT)
        ast.parse('def stage():\n'+ins)

    def test_c_stubs_both_compilers_with_macro_off_on(self):
        compilers=[c for c in ('clang','gcc') if shutil.which(c)]
        if not compilers:self.skipTest('no C compiler')
        code=r'''
#include <errno.h>
struct context{int hash;};
static int sid_calls=0,hash_calls=0;
static int context_add_hash(struct context *c){c->hash=17;hash_calls++;return 0;}
static int sidtab_context_to_sid(struct context *c){sid_calls++;return c->hash == 17 ? 0 : -EINVAL;}
static int transform(void){struct context c={0}; int rc=0;
#ifdef KSU_COMPAT_HAS_CONTEXT_ADD_HASH
  rc=context_add_hash(&c);
#endif
  if(!rc)rc=sidtab_context_to_sid(&c);
  return rc;
}
int main(void){int ret=transform();
#ifdef KSU_COMPAT_HAS_CONTEXT_ADD_HASH
 if(ret || hash_calls!=1 || sid_calls!=1)return 1;
#else
 if(ret!=-EINVAL || hash_calls!=0 || sid_calls!=1)return 2;
#endif
return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'smoke.c';exe=Path(tmp)/'smoke';p.write_text(code)
            for cc in compilers:
                for enabled in (False,True):
                    with self.subTest(compiler=cc,hash_flag=enabled):
                        args=[cc,'-Wall','-Wextra','-Werror','-Wno-unused-function']
                        if enabled:args+=['-DKSU_COMPAT_HAS_CONTEXT_ADD_HASH']
                        args += [str(p),'-o',str(exe)]
                        subprocess.run(args,check=True,capture_output=True)
                        subprocess.run([str(exe)],check=True,capture_output=True)

if __name__=='__main__':unittest.main()
