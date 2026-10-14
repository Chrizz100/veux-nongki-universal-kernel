#!/usr/bin/env python3
"""Source-only 5.4 SELinux parity tests. No detector spoofing or device claims."""
import ast
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT/'common/scripts/veux_bakasu_selinux54_policy_parity_r3.py'
spec=importlib.util.spec_from_file_location('veux_bakasu_selinux54_policy_parity_r3',SCRIPT)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# Miniature body including pinned source identifiers: exact_sha=False only.
FIXTURE='''int ksu_security_context_to_sid(struct policydb *a, struct sidtab *b,
struct policydb *c, struct sidtab *d, const char *s, size_t n,
u32 *sid, u32 def, int flags, void *other, void *err);
static int ksu_selinux_hide_unhook() {return 0;}
int ksu_handle_selinux_setprocattr(const char *name, void *value, size_t size) {
    if (uid < 10000 || strcmp(name, "current")) goto call_orig;
'''+mod.OLD+'''
call_orig: return ksu_orig_setprocattr(name,value,size);
}
void example(void){ context_add_hash(&policydb, &context); commit_creds(new); }
'''

class SourceValidation(unittest.TestCase):
    def test_python_ast(self):
        for file in (SCRIPT,ROOT/'common/scripts/veux_fleet_35222_selinux_r3.py',
                     ROOT/'common/scripts/veux_bakasu_selinux_backport_r3.py'):
            ast.parse(file.read_text(),filename=str(file))

    def test_r4_guard_original_exact(self):
        self.assertIn('    goto call_orig;\n#endif',mod.OLD)
        self.assertIn('5.4',mod.OLD)
        self.assertIn('stock, enforcing SELinux',mod.OLD)

    def test_only_one_source_hunk(self):
        output,proof=mod.rewrite(FIXTURE.encode(),exact_pin=False)
        self.assertEqual(proof['paths_changed'],[mod.TARGET])
        self.assertEqual(output.decode().replace(mod.NEW,mod.OLD),FIXTURE)
        self.assertEqual(output.decode().count('context_add_hash('),1)
        self.assertIn('goto call_orig;',output.decode())
        self.assertEqual(proof['kernel_build'],False)
        self.assertEqual(proof['device_pass'],False)
        self.assertEqual(proof['detector_pass_claimed'],False)

    def test_unaltered_source_not_pretended_to_be_correct_sha(self):
        with self.assertRaisesRegex(mod.ParityBlocked,'D726_EFFECTIVE_HOOK_SHA_DRIFT'):
            mod.rewrite(FIXTURE.encode(),exact_pin=True)

    def test_d726_exact_ci_report_pin(self):
        self.assertEqual(mod.PINNED_D726_HOOK_SHA256,
            '0bcacdecd4579dd48c3dcde89fd9c5c9b9afcf422df6c840ad6116a0b06cd3b8')

    def test_baseline_no_fa12_blocked(self):
        with self.assertRaisesRegex(mod.ParityBlocked,'FA12_BACKUP_POLICY_PARSER_NOT_PRESENT'):
            mod.rewrite(FIXTURE.replace('ksu_security_context_to_sid(', 'old_parser(').encode(),exact_pin=False)

    def test_unhook_absent_blocked(self):
        with self.assertRaisesRegex(mod.ParityBlocked,'UNHOOK_R1_FIX_NOT_PRESENT'):
            mod.rewrite(FIXTURE.replace('static int ksu_selinux_hide_unhook()', 'static void ksu_selinux_hide_unhook()').encode(),exact_pin=False)

    def test_hash_absent_blocked(self):
        with self.assertRaisesRegex(mod.ParityBlocked,'D726_CONTEXT_ADD_HASH_FIX_NOT_PRESENT'):
            mod.rewrite(FIXTURE.replace('context_add_hash(', 'context_bare(').encode(),exact_pin=False)

    def test_double_application_rejected(self):
        out,_=mod.rewrite(FIXTURE.encode(),exact_pin=False)
        with self.assertRaisesRegex(mod.ParityBlocked,'R4_LEGACY_FALLBACK_NOT_UNIQUE_OR_MISSING'):
            mod.rewrite(out,exact_pin=False)

    def test_missing_guard_rejected(self):
        with self.assertRaisesRegex(mod.ParityBlocked,'R4_LEGACY_FALLBACK_NOT_UNIQUE_OR_MISSING'):
            mod.rewrite(FIXTURE.replace(mod.OLD,'/* gone */').encode(),exact_pin=False)

    def test_doubled_guard_rejected(self):
        with self.assertRaisesRegex(mod.ParityBlocked,'R4_LEGACY_FALLBACK_NOT_UNIQUE_OR_MISSING'):
            mod.rewrite((FIXTURE+mod.OLD).encode(),exact_pin=False)

    def test_non_utf8_rejected(self):
        with self.assertRaisesRegex(mod.ParityBlocked,'NON_UTF8_BAKASU_SOURCE'):
            mod.rewrite(b'\xff'+FIXTURE.encode(),exact_pin=False)

    def test_newline_and_permission_semantics_present(self):
        for expected in ('backup_policydb', 'backup_sidtab', 'ksu_security_context_to_sid(',
                         'ksu_avc_has_perm_compat(', 'validation_error',
                         'return permission_error ? permission_error : validation_error;',
                         'goto call_orig;', 'check_size--', "str[check_size - 1] = '\\0'"):
            self.assertIn(expected,mod.NEW)
        self.assertNotIn('prepare_creds(',mod.NEW)
        self.assertNotIn('commit_creds(',mod.NEW)

    def test_stock_transition_not_replaced(self):
        self.assertIn('goto call_orig;',mod.NEW)
        self.assertIn('ksu_orig_setprocattr(',FIXTURE)

    def test_workflow_yaml_not_changed(self):
        bundle=ROOT/'common/scripts/veux_bakasu_selinux_backport_r3.py'
        txt=bundle.read_text()
        self.assertIn('selinux54_parity_r3 = apply_legacy_policy_parity(',txt)
        self.assertIn("result['selinux54_policy_parity_r3'] = selinux54_parity_r3",txt)
        self.assertEqual(txt.count('selinux54_parity_r3 = apply_legacy_policy_parity('),1)

    def test_preflight_and_worker_order(self):
        fleet=(ROOT/'common/scripts/veux_fleet_35222_selinux_r3.py').read_text()
        worker=(ROOT/'common/scripts/veux_bakasu_selinux_backport_r3.py').read_text()
        self.assertGreater(fleet.index('parity54_proof = apply_legacy_policy_parity('),
                           fleet.index('hash_d726_proof = apply_context_hash_5_4('))
        self.assertLess(fleet.index('parity54_proof = apply_legacy_policy_parity('),
                        fleet.index("status['source_preflight']=True"))
        self.assertGreater(worker.index('selinux54_parity_r3 = apply_legacy_policy_parity('),
                           worker.index('context_hash_d726 = apply_context_hash_5_4('))
        self.assertLess(worker.index('selinux54_parity_r3 = apply_legacy_policy_parity('),
                        worker.index("RESULT_ANCHOR="))

    def test_kernel_major_mismatch_fail(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'kernel';root.mkdir();(root/'Makefile').write_text('VERSION = 5\nPATCHLEVEL = 10\n')
            with self.assertRaisesRegex(mod.ParityBlocked,'KERNEL_NOT_5_4'):
                mod.apply_legacy_policy_parity(root,Path(d)/'proof.json')

    def test_staged_wrong_pin_atomic(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'kernel';root.mkdir();(root/'Makefile').write_text('VERSION = 5\nPATCHLEVEL = 4\n')
            f=root/mod.TARGET;f.parent.mkdir(parents=True);f.write_text(FIXTURE)
            report=Path(d)/'proof.json'
            with self.assertRaisesRegex(mod.ParityBlocked,'D726_EFFECTIVE_HOOK_SHA_DRIFT'):
                mod.apply_legacy_policy_parity(root,report)
            self.assertEqual(f.read_text(),FIXTURE)
            self.assertFalse(report.exists())

    def test_source_symlink_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'kernel';root.mkdir();(root/'Makefile').write_text('VERSION = 5\nPATCHLEVEL = 4\n')
            external=Path(d)/'x.c';external.write_text(FIXTURE)
            f=root/mod.TARGET;f.parent.mkdir(parents=True);f.symlink_to(external)
            with self.assertRaisesRegex(mod.ParityBlocked,'UNSAFE_OR_MISSING_BAKASU_SOURCE'):
                mod.apply_legacy_policy_parity(root,Path(d)/'proof.json')

class StubRuntimeSemantics(unittest.TestCase):
    def test_compilers_and_5_4_or_5_10_paths(self):
        # The production kernel source is not available locally; this only
        # tests the extracted exact 5.4 C hunk with typed stub policy API.
        harness=r'''
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
struct policydb{int x;}; struct sidtab{int x;};
typedef unsigned int u32;
#define GFP_KERNEL 1
#define SECSID_NULL 0
#define SECCLASS_PROCESS 1
#define PROCESS__SETCURRENT 3
#define KSU_COMPAT_USE_SELINUX_STATE 1
#define KERNEL_VERSION(a,b,c) ((a)*65536+(b)*256+(c))
#define LINUX_VERSION_CODE KERNEL_VERSION(5,4,274)
struct state_ss {struct policydb policydb; struct sidtab *sidtab;};
struct state {struct state_ss *ss;};
static struct policydb backupdb={0};static struct sidtab backuptab={0};
static struct sidtab live_tab={0}; static struct state_ss ss={ {0}, &live_tab};
static struct state selinux_state={&ss};
#define backup_policydb (&backupdb)
#define backup_sidtab (&backuptab)
static int cur_uid=10234, permission=0, nstock=0, npolicy=0;
static u32 current_sid(void){return 123;}
static int ksu_avc_has_perm_compat(u32 a,u32 b,int c,int p,void *audit){
(void)a;(void)b;(void)c;(void)p;(void)audit;return permission;}
static int ksu_security_context_to_sid(struct policydb *db,struct sidtab *st,
  struct policydb *bdb,struct sidtab *bst,const char *str,size_t len,
  u32 *sid,u32 def,int flags,void *osid,void *err){
 (void)db;(void)st;(void)bdb;(void)bst;(void)len;(void)def;
 (void)flags;(void)osid;(void)err; npolicy++; *sid=12;
 return strstr(str,"ksu")?-EINVAL:0;
}
static int ksu_orig_setprocattr(const char *name, void *value, size_t size){
 (void)name;(void)value;(void)size;nstock++;return 1234;}
static int hook(const char *name,void *value,size_t size){
 if(cur_uid<10000)goto call_orig;
 if(strcmp(name,"current"))goto call_orig;
'''+mod.NEW+r'''
call_orig: return ksu_orig_setprocattr(name,value,size);
}
int main(void){
 char hidden[]="u:r:ksu:s0";char normal[]="u:r:untrusted_app:s0";
 char hiddennewline[]="u:r:ksu:s0\n";
 int rc;
 permission=0;nstock=0;npolicy=0;
 rc=hook("current",hidden,sizeof(hidden)-1);
 if(rc!=-EINVAL || nstock!=0 || npolicy!=1)return 1;
 permission=-EACCES;nstock=0;npolicy=0;
 rc=hook("current",hidden,sizeof(hidden)-1);
 if(rc!=-EACCES || nstock!=0 || npolicy!=1)return 2;
 permission=0;nstock=0;npolicy=0;
 rc=hook("current",normal,sizeof(normal)-1);
 if(rc!=1234 || nstock!=1 || npolicy!=1)return 3;
 nstock=0;npolicy=0;rc=hook("exec",hidden,sizeof(hidden)-1);
 if(rc!=1234 || nstock!=1 || npolicy!=0)return 4;
 cur_uid=0;nstock=0;npolicy=0;rc=hook("current",hidden,sizeof(hidden)-1);
 if(rc!=1234 || nstock!=1 || npolicy!=0)return 5;
 cur_uid=10234;nstock=0;npolicy=0;
 rc=hook("current",hiddennewline,sizeof(hiddennewline)-1);
 if(rc!=-EINVAL || nstock!=0 || npolicy!=1)return 6;
 puts("LEGACY_POLICY_PRESCREEN_STOCK_SETPROCATTR=PASS");return 0;}
'''
        available=[c for c in ('gcc','clang') if shutil.which(c)]
        self.assertGreater(len(available),0,'Need GCC or Clang for the host fixture')
        with tempfile.TemporaryDirectory() as td:
            s=Path(td)/'harness.c';s.write_text(harness)
            for cc in available:
                exe=Path(td)/('harness_'+cc)
                p=subprocess.run([cc,'-std=gnu11','-O1','-Wall','-Wextra','-Werror',str(s),'-o',str(exe)],capture_output=True,text=True)
                self.assertEqual(p.returncode,0,p.stdout+'\n'+p.stderr)
                run=subprocess.run([str(exe)],capture_output=True,text=True)
                self.assertEqual(run.returncode,0,f'{cc}: '+run.stdout+'\n'+run.stderr)
                self.assertIn('LEGACY_POLICY_PRESCREEN_STOCK_SETPROCATTR=PASS',run.stdout)

if __name__=='__main__':unittest.main()
