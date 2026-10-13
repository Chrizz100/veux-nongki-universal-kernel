#!/usr/bin/env python3
"""Isolated local tests for the source-only VEUX Linux 5.4 SUSFS port probe.

All tests execute with generated local Git commit chains, no network, device,
source rebuild, root, permissions changes, or repository writes.
"""
from __future__ import annotations
import contextlib
from dataclasses import replace
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT=Path(__file__).resolve().parents[1]/'common/scripts/veux_susfs_54_port_probe_r3.py'
spec=importlib.util.spec_from_file_location('veux_susfs_54_port_probe_r3',SCRIPT)
port=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=port
spec.loader.exec_module(port)


def command(root,*args):
    return subprocess.check_output(['git','-C',str(root),*args],
                                   stderr=subprocess.PIPE,text=True).strip()

def sample_patch(what:str, source:str)->str:
    if what=='host':
        return ('diff --git a/security/selinux/hooks.c b/security/selinux/hooks.c\n'
                '--- a/security/selinux/hooks.c\n'
                '+++ b/security/selinux/hooks.c\n'
                '@@ -1,1 +1,2 @@\n'
                ' int check(void)\n'
                f'+ {source}_hook();\n')
    return ('diff --git a/kernel/Kbuild b/kernel/Kbuild\n'
            '--- a/kernel/Kbuild\n'
            '+++ b/kernel/Kbuild\n'
            '@@ -1,1 +1,2 @@\n'
            ' int stage(void)\n'
            f'+ {source}_api();\n')


@contextlib.contextmanager
def sample_workspace(*,source='5.4',hook_text='old',patch_context_changed=False,
                     extra=False,changed_core=False,alt_same=False):
    with tempfile.TemporaryDirectory() as dir:
        top=Path(dir);donor=top/'bundle/susfs';donor.mkdir(parents=True)
        command(donor,'init','-q');command(donor,'config','user.name','SUSFS 5.4 probe fixture')
        command(donor,'config','user.email','fixture@example.invalid')
        core={
          'kernel_patches/fs/susfs.c':'void susfs(void){}\n',
          'kernel_patches/include/linux/susfs.h':'#define SUSFS_VERSION "v2.3.0"\n',
          'kernel_patches/include/linux/susfs_def.h':'#define SUSFS_FEATURES 9\n'
        }
        for f,text in core.items():
            p=donor/f;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
        p1=donor/port.HOST_PATCH;p1.parent.mkdir(parents=True,exist_ok=True)
        p2=donor/port.ALTERNATIVE_PATCH;p2.parent.mkdir(parents=True,exist_ok=True)
        p1.write_text(sample_patch('host','old'))
        p2.write_text(sample_patch('alternative','old'))
        command(donor,'add','.');command(donor,'commit','-qm','old PIN')
        old=command(donor,'rev-parse','HEAD');core_blobs={p:command(donor,'rev-parse',old+':'+p) for p in core}
        old_blobs={p:command(donor,'rev-parse',old+':'+p) for p in [port.HOST_PATCH,port.ALTERNATIVE_PATCH]}
        p1.write_text(sample_patch('host','middle'))
        command(donor,'commit','-qam','middle 5.10 update')
        mid=command(donor,'rev-parse','HEAD')
        if patch_context_changed:
            modified=sample_patch('host','new').replace(' int check(void)', ' int another(void)')
        else:
            modified=sample_patch('host','new')
        p1.write_text(modified)
        if not alt_same:p2.write_text(sample_patch('alternative','new'))
        if extra:
            p=donor/'extra_unreviewed.txt';p.write_text('unreviewed\n')
        if changed_core:
            (donor/'kernel_patches/fs/susfs.c').write_text('int drift(void);\n')
        command(donor,'add','.');command(donor,'commit','-qm','new 5.10 update')
        new=command(donor,'rev-parse','HEAD')
        new_blobs={p:command(donor,'rev-parse',new+':'+p) for p in [port.HOST_PATCH,port.ALTERNATIVE_PATCH]}
        command(donor,'checkout','--quiet','--detach',old)
        src=top/'source/kernel';src.mkdir(parents=True)
        (src/'Makefile').write_text('VERSION = 5\nPATCHLEVEL = '+source.split('.')[-1]+'\nSUBLEVEL = 274\n')
        hook=src/'KernelSU/kernel/feature/selinux_hide.c';hook.parent.mkdir(parents=True)
        hook.write_text('known R4 compatible legacy handler\n')
        sf=src/'security/selinux/hooks.c';sf.parent.mkdir(parents=True)
        sf.write_text('int check(void)\n '+hook_text+'_hook();\n\n')
        pin=port.SourcePins(old,mid,new,port.blob(hook.read_bytes()),core_blobs,
                            {p:(old_blobs[p],new_blobs[p]) for p in old_blobs})
        report=top/'report/PORT.json'
        yield top,src,donor,report,pin


class GitAndScopeTests(unittest.TestCase):
    def test_exact_git_scope_and_two_commits(self):
        with sample_workspace() as (_,src,donor,report,pin):
            result=port.verify_git_scope(donor,pin)
            self.assertTrue(result['kernel_core_unchanged'])
            self.assertEqual(result['old'],pin.old)
            self.assertEqual(result['new'],pin.new)
            self.assertEqual(len(result['changed_paths']),2)

    def test_original_pin_and_commit_ids_are_frozen(self):
        self.assertEqual(port.OLD,'5326e21a7eb232f9e21debdd5164e99bee3d1e2f')
        self.assertEqual(port.MID,'2837d10b68bacbd7f06758d301237e8f8b363adb')
        self.assertEqual(port.NEW,'14c45388ec8cb3ca72f2ac8bf83097b9285a8418')
        self.assertEqual(len(port.CORE_BLOBS),3)
        self.assertEqual(len(port.PATCH_BLOBS),2)

    def test_wrong_old_pin_is_blocked(self):
        with sample_workspace() as (_,src,donor,report,pin):
            wrong=replace(pin,old='0'*40)
            with self.assertRaises(port.PortError):port.verify_git_scope(donor,wrong)

    def test_wrong_mid_commit_is_blocked(self):
        with sample_workspace() as (_,src,donor,report,pin):
            wrong=replace(pin,mid='0'*40)
            with self.assertRaises(port.PortError):port.verify_git_scope(donor,wrong)

    def test_wrong_core_sha_is_blocked(self):
        with sample_workspace() as (_,src,donor,report,pin):
            wrong=dict(pin.core);wrong[next(iter(wrong))]='f'*40
            bad=replace(pin,core=wrong)
            with self.assertRaisesRegex(port.PortError,'CORE_BASE_DRIFT'):
                port.verify_git_scope(donor,bad)

    def test_wrong_host_patch_sha_is_blocked(self):
        with sample_workspace() as (_,src,donor,report,pin):
            wrong=dict(pin.patches);p=port.HOST_PATCH;wrong[p]=('f'*40,wrong[p][1])
            bad=replace(pin,patches=wrong)
            with self.assertRaisesRegex(port.PortError,'PATCH_BASE_DRIFT'):
                port.verify_git_scope(donor,bad)

    def test_extra_changed_file_blocks(self):
        with sample_workspace(extra=True) as (_,src,donor,report,pin):
            with self.assertRaisesRegex(port.PortError,'UNREVIEWED_PATH_CHANGE'):
                port.verify_git_scope(donor,pin)

    def test_changed_core_blocks(self):
        with sample_workspace(changed_core=True) as (_,src,donor,report,pin):
            with self.assertRaisesRegex(port.PortError,'UNREVIEWED_PATH_CHANGE'):
                port.verify_git_scope(donor,pin)

    def test_donor_dirty_blocks(self):
        with sample_workspace() as (_,src,donor,report,pin):
            (donor/'extra').write_text('dirty\n')
            with self.assertRaisesRegex(port.PortError,'DONOR_DIRTY'):
                port.verify_git_scope(donor,pin)

    def test_donor_checked_out_new_not_old_blocks(self):
        with sample_workspace() as (_,src,donor,report,pin):
            command(donor,'checkout','-q','--detach',pin.new)
            with self.assertRaisesRegex(port.PortError,'BUILD_PIN_CHANGED'):
                port.verify_git_scope(donor,pin)


class PortStageTests(unittest.TestCase):
    def test_patch_images_split_host_correctly(self):
        entries=port.images(sample_patch('host','old'))
        self.assertEqual(list(entries),['security/selinux/hooks.c'])
        self.assertEqual(entries['security/selinux/hooks.c'][0]['after'],['int check(void)\n',' old_hook();\n'])
        self.assertEqual(entries['security/selinux/hooks.c'][0]['before'],['int check(void)\n'])

    def test_duplicate_patch_path_rejected(self):
        p=sample_patch('host','old')*2
        with self.assertRaisesRegex(port.PortError,'DUPLICATES_FORBIDDEN'):
            port.images(p)

    def test_path_traversal_patch_rejected(self):
        p=sample_patch('host','old').replace('security/selinux/hooks.c','../escape.c')
        with self.assertRaisesRegex(port.PortError,'PATH_TRAVERSAL'):
            port.images(p)

    def test_exact_stage_in_memory_works(self):
        with sample_workspace() as (_,src,donor,report,pin):
            text=(src/'security/selinux/hooks.c').read_text()
            stage,n=port.stage_text(text,['int check(void)\n',' old_hook();\n'],
                                          ['int check(void)\n',' new_hook();\n'])
            self.assertIn('new_hook();',stage)
            self.assertEqual(n,1)
            self.assertEqual(text,(src/'security/selinux/hooks.c').read_text())

    def test_ambiguous_old_context_blocks(self):
        with self.assertRaisesRegex(port.PortError,'MISSING_OR_AMBIGUOUS'):
            port.stage_text('x_old\nx_old\n',['x_old\n'],['x_new\n'])

    def test_missing_old_context_blocks(self):
        with self.assertRaisesRegex(port.PortError,'MISSING_OR_AMBIGUOUS'):
            port.stage_text('unrelated', ['old\n'],['new\n'])

    def test_upstream_gki_preimage_change_blocks(self):
        with sample_workspace(patch_context_changed=True) as (_,src,donor,report,pin):
            old=port.git(donor,'show',pin.old+':'+port.HOST_PATCH)+'\n'
            new=port.git(donor,'show',pin.new+':'+port.HOST_PATCH)+'\n'
            row=port.classify_host(src,old,new)['findings'][0]
            self.assertEqual(row['result'],'UPSTREAM_GKI_BASE_CHANGED')

    def test_already_changed_host_source_requires_manual_rebase(self):
        with sample_workspace(hook_text='unknown') as (_,src,donor,report,pin):
            old=port.git(donor,'show',pin.old+':'+port.HOST_PATCH)+'\n'
            new=port.git(donor,'show',pin.new+':'+port.HOST_PATCH)+'\n'
            row=port.classify_host(src,old,new)['findings'][0]
            self.assertEqual(row['result'],'NEEDS_MANUAL_5_4_REBASE')

    def test_readonly_real_source_and_explicit_no_promotion(self):
        with sample_workspace() as (_,src,donor,report,pin):
            expected=(src/'security/selinux/hooks.c').read_bytes()
            result=port.probe(src,donor,report,pin)
            self.assertEqual(result['status'],'PROBE_COMPLETED_PORT_NOT_APPROVED')
            self.assertEqual(result['host_5_4']['host_paths_stageable_in_memory'],1)
            self.assertTrue(result['alternative_KernelSU_patch_additions_changed'])
            self.assertTrue(result['security']['automatic_promotion_blocked'])
            self.assertTrue(result['security']['SELinux_Enforcing_not_disabled'])
            self.assertTrue(result['security']['no_pin_update'])
            self.assertEqual(expected,(src/'security/selinux/hooks.c').read_bytes())
            self.assertTrue(report.exists())
            self.assertEqual(json.loads(report.read_text())['status'],result['status'])

    def test_second_probe_cannot_overwrite_report(self):
        with sample_workspace() as (_,src,donor,report,pin):
            port.probe(src,donor,report,pin)
            with self.assertRaisesRegex(port.PortError,'REPORT_CANNOT_MUTATE_SOURCE'):
                port.probe(src,donor,report,pin)

    def test_only_linux_5_4_can_probe(self):
        with sample_workspace(source='5.10') as (_,src,donor,report,pin):
            with self.assertRaisesRegex(port.PortError,'REQUIRES_KERNEL_5_4'):
                port.probe(src,donor,report,pin)
            self.assertFalse(report.exists())

    def test_runtime_fix_required(self):
        with sample_workspace() as (_,src,donor,report,pin):
            (src/'KernelSU/kernel/feature/selinux_hide.c').write_text('bad source\n')
            with self.assertRaisesRegex(port.PortError,'R4_RUNTIME_FIXED_SELINUX_HOOK_REQUIRED'):
                port.probe(src,donor,report,pin)
            self.assertFalse(report.exists())

    def test_omitted_kernelSU_patch_update_is_blocked_at_git_scope(self):
        with sample_workspace(alt_same=True) as (_,src,donor,report,pin):
            with self.assertRaisesRegex(port.PortError,'SUSFS_UNREVIEWED_PATH_CHANGE'):
                port.probe(src,donor,report,pin)

    def test_no_report_written_inside_source(self):
        with sample_workspace() as (_,src,donor,report,pin):
            with self.assertRaisesRegex(port.PortError,'REPORT_CANNOT_MUTATE_SOURCE'):
                port.probe(src,donor,src/'PORT.json',pin)

    def test_fleet_has_only_one_hook_after_existing_54_fixes(self):
        fleet=Path(__file__).resolve().parents[1]/'common/scripts/veux_fleet_35222_selinux_r3.py'
        text=fleet.read_text()
        self.assertEqual(text.count('susfs_54_port_probe('),1)
        self.assertGreater(text.index("proof=awinic_candidate.apply(src,kernel,work)"),
                           text.index('selinux_r3.apply_source_backport('))
        self.assertGreater(text.index('susfs_54_port_probe('),
                           text.index("status['awinic_r3_source_verified']=True"))
        self.assertLess(text.index('susfs_54_port_probe('),
                        text.index("status['source_preflight']=True"))
        self.assertIn("root/'report/SUSFS_54_PORT_PROBE_R1.json'",text)

class SemanticAuditR2Tests(unittest.TestCase):
    """R2: read-only host-layout proof, no unsafe semantics assumptions."""

    def test_exact_unused_declaration_absent_is_noop(self):
        old=['#ifdef CONFIG_KSU_SUSFS\n',port.UNUSED_EXEC_DECL,
             'extern int ksu_handle_execveat(void);\n','#endif\n']
        new=[old[0],old[2],old[3]]
        self.assertTrue(port.is_upstream_unused_decl_cleanup('fs/exec.c',old,new,
                     '#ifdef CONFIG_KSU_SUSFS\nextern int ksu_handle_execveat(void);\n#endif\n'))

    def test_unused_decl_cleanup_cannot_drop_live_symbol_use(self):
        old=['#ifdef CONFIG_KSU_SUSFS\n',port.UNUSED_EXEC_DECL]
        new=['#ifdef CONFIG_KSU_SUSFS\n']
        self.assertFalse(port.is_upstream_unused_decl_cleanup('fs/exec.c',old,new,
                         '__ksu_is_allow_uid_for_current(2000);'))
        self.assertFalse(port.is_upstream_unused_decl_cleanup('fs/exec.c',old,new,
                         port.UNUSED_EXEC_DECL))

    def test_unused_decl_cleanup_exact_gki_scope_only(self):
        old=[port.UNUSED_EXEC_DECL,'extern int good(void);\n']
        new=['extern int changed(void);\n']
        self.assertFalse(port.is_upstream_unused_decl_cleanup('fs/exec.c',old,new,''))
        self.assertFalse(port.is_upstream_unused_decl_cleanup('hooks.c',old,old[1:],''))
        self.assertFalse(port.is_upstream_unused_decl_cleanup('fs/exec.c',
                         ['extern int good(void);\n'],[],''))

    @staticmethod
    def make_hosts(root, wrappers:bool):
        h=root/'security/selinux/hooks.c';h.parent.mkdir(parents=True,exist_ok=True)
        f=root/'security/selinux/selinuxfs.c';f.parent.mkdir(parents=True,exist_ok=True)
        e=root/'fs/exec.c';e.parent.mkdir(parents=True,exist_ok=True)
        e.write_text('extern int ksu_handle_execveat(int *fd);\n')
        h.write_text('#ifdef CONFIG_KSU_SUSFS\n'
         'static int selinux_setprocattr(const char *name, void *value, size_t size) { return 0; }\n'
         + ('static int my_setprocattr(const char *name, void *value, size_t size) { return 0; }\n'
           if wrappers else '') + 'LSM_HOOK_INIT(setprocattr, selinux_setprocattr)\n'
         'ksu_selinux_hide_running\nsecurity_context_to_sid\n')
        f.write_text('static int sel_open_handle_status(void) { return 0; }\n'
         'static int sel_write_context(void) { return 0; }\n'
         'static int sel_write_access(void) { return 0; }\n'
         'ksu_selinux_hide_running\nfake_status_initialize_key\n'
         + ('static int my_sel_open_handle_status(void){return 0;}\n'
            'static int my_write_context(void){return 0;}\n'
            'static int my_write_access(void){return 0;}\n' if wrappers else ''))
        bakasu=root/'KernelSU/kernel/feature/selinux_hide.c'
        bakasu.parent.mkdir(parents=True,exist_ok=True)
        bakasu.write_text(('static int my_sel_open_handle_status(void) {return 0;}\n'
                           'static int my_write_access(void) {return 0;}\n'
                           'static int my_write_context(void) {return 0;}\n'
                           'ksu_handle_selinux_setprocattr\norig_context_write\n'
                           'orig_access_write\nkfree(canon);\nkfree(scon);\nkfree(tcon);\n')
                          if wrappers else 'ksu_handle_selinux_setprocattr\n')
        return h,f,e,bakasu

    def test_detects_wrapper_layout_but_never_approves(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);h,f,e,bakasu=self.make_hosts(root,True)
            snapshot={v:v.read_bytes() for v in (h,f,e,bakasu)}
            result=port.inspect_host_5_4_selinux(root)
            self.assertTrue(result['no_semantic_port_or_runtime_approval'])
            self.assertTrue(result['selinux_cleanup_requires_code_review'])
            self.assertEqual(result['source_paths']['security/selinux/hooks.c']['status'],
                             'LEGACY_WRAPPERS_PRESENT_REVIEW_ORIGINAL_CLEANUP')
            self.assertEqual(result['source_paths']['security/selinux/selinuxfs.c']['symbols']['my_write_context'],1)
            self.assertEqual(result['source_paths']['KernelSU/kernel/feature/selinux_hide.c']['status'],
                             'BAKASU_R4_LEGACY_WRAPPERS_REVIEW_RUNTIME_SEMANTICS')
            self.assertFalse(result['source_paths']['fs/exec.c']['review_required'])
            self.assertEqual({v:v.read_bytes() for v in (h,f,e,bakasu)},snapshot)

    def test_absence_of_named_wrappers_does_not_fake_equivalence(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);self.make_hosts(root,False)
            result=port.inspect_host_5_4_selinux(root)
            h=result['source_paths']['security/selinux/hooks.c']
            self.assertTrue(h['review_required'])
            self.assertEqual(h['status'],'NO_NAMED_GKI_WRAPPERS_FOUND_EQUIVALENCE_UNPROVEN')
            self.assertTrue(result['source_paths']['security/selinux/selinuxfs.c']['review_required'])
            self.assertEqual(result['source_paths']['KernelSU/kernel/feature/selinux_hide.c']['status'],
                             'BAKASU_R4_HOOK_LAYOUT_UNVERIFIED')

    def test_missing_hosts_are_blocked_not_silent_success(self):
        with tempfile.TemporaryDirectory() as td:
            result=port.inspect_host_5_4_selinux(Path(td))
            self.assertTrue(all(r['status']=='SOURCE_NOT_PRESENT_OR_UNSAFE' and r['review_required']
                                for r in result['source_paths'].values()))

    def test_symlink_outside_source_is_never_read(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/'kernel';root.mkdir()
            external=Path(td)/'external';external.write_text('a private outside file\n')
            file=root/'security/selinux/hooks.c';file.parent.mkdir(parents=True)
            file.symlink_to(external)
            proof=port.inspect_host_5_4_selinux(root)
            self.assertEqual(proof['source_paths']['security/selinux/hooks.c']['status'],
                             'SOURCE_NOT_PRESENT_OR_UNSAFE')

    def test_real_probe_embeds_layout_evidence_without_source_edit(self):
        with sample_workspace() as (_,src,donor,report,pin):
            h=src/'security/selinux/hooks.c';before=h.read_bytes()
            data=port.probe(src,donor,report,pin)
            self.assertEqual(h.read_bytes(),before)
            self.assertTrue(data['real_5_4_selinux_layout']['no_semantic_port_or_runtime_approval'])
            self.assertTrue(data['security']['source_only_no_kernel_compilation'])
            self.assertEqual(data['decision'],'MANUAL_REVIEW_5_4_HOOKS_REQUIRED')
            self.assertEqual(json.loads(report.read_text())['real_5_4_selinux_layout'],
                             data['real_5_4_selinux_layout'])

    def test_unused_decl_gki_patch_source_triggers_only_noop_state(self):
        old_lines=['int do_execve(void)\n',port.UNUSED_EXEC_DECL,'int unrelated(void)\n']
        new_lines=['int do_execve(void)\n','int unrelated(void)\n']
        self.assertTrue(port.is_upstream_unused_decl_cleanup('fs/exec.c',old_lines,new_lines,
                         'int do_execve(void)\nint unrelated(void)\n'))

    @staticmethod
    def exec_patch(declaration_present: bool):
        head='diff --git a/fs/exec.c b/fs/exec.c\n@@ -1,3 +1,4 @@\n'
        body=' #ifdef CONFIG_KSU_SUSFS\n'
        if declaration_present:
            body+='+'+port.UNUSED_EXEC_DECL
        body+=' extern int ksu_handle_execveat(void);\n #endif\n'
        return head+body

    def test_classify_exec_cleanup_not_present_in_real_54_is_noop(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);f=root/'fs/exec.c';f.parent.mkdir(parents=True)
            f.write_text('#ifdef CONFIG_KSU_SUSFS\nextern int ksu_handle_execveat(void);\n#endif\n')
            prior=f.read_bytes()
            proof=port.classify_host(root,self.exec_patch(True),self.exec_patch(False))
            row=proof['findings'][0]
            self.assertEqual(row['result'],'UPSTREAM_UNUSED_DECL_ALREADY_ABSENT_IN_5_4')
            self.assertEqual(proof['host_paths_requiring_manual_port'],0)
            self.assertEqual(row['candidate_sha256'],row['original_sha256'])
            self.assertEqual(f.read_bytes(),prior)

    def test_classify_exec_cleanup_present_only_stages_in_memory(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);f=root/'fs/exec.c';f.parent.mkdir(parents=True)
            f.write_text('#ifdef CONFIG_KSU_SUSFS\n'+port.UNUSED_EXEC_DECL+
                         'extern int ksu_handle_execveat(void);\n#endif\n')
            prior=f.read_bytes()
            row=port.classify_host(root,self.exec_patch(True),self.exec_patch(False))['findings'][0]
            self.assertEqual(row['result'],'IN_MEMORY_STAGE_ONLY_NOT_APPROVED')
            self.assertNotEqual(row['original_sha256'],row['candidate_sha256'])
            self.assertEqual(f.read_bytes(),prior)

    def test_classify_exec_cleanup_with_live_54_symbol_is_not_whitelisted(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);f=root/'fs/exec.c';f.parent.mkdir(parents=True)
            f.write_text('bool marker=__ksu_is_allow_uid_for_current(123);\n')
            row=port.classify_host(root,self.exec_patch(True),self.exec_patch(False))['findings'][0]
            self.assertEqual(row['result'],'NEEDS_MANUAL_5_4_REBASE')

class R4UnhookIdentityR3Tests(unittest.TestCase):
    """Regression for run 38385351673: old R4 blob vs pinned unhook postimage."""

    @staticmethod
    def sample():
        old=b'legacy R4 tested source\n'
        new=old+b'protected unhook error path\n'
        # Local test-only alternate pins are never used by the default
        # production workflow, which hard-pins official R4 and Unhook hashes.
        pin=replace(port.SourcePins(),r4_hook_blob=port.blob(old),
                    r4_hook_sha256=port.sha256(old),
                    r4_unhook_sha256=port.sha256(new))
        proof={'before_sha256':port.sha256(old),'after_sha256':port.sha256(new),
            'r4_effective_source_pinned':True,
            'setprocattr_r4_fallback_unchanged':True,
            'protects_original_pointers_after_restore_error':True,
            'reports_error_to_feature_set':True,
            'preserves_fake_status_when_exit_restore_fails':True,
            'selinux_enforcing_unchanged':True,
            'kernel_build':False,'device_pass':False,'promotion':False}
        return old,new,pin,proof

    def test_constants_match_actual_verified_artifact(self):
        self.assertEqual(port.R4_HOOK_SHA256,
                         '5e40cb29c74fbca6b2b15072e395fb971932894eebe9f846f970a7de139c0a8f')
        self.assertEqual(port.R4_UNHOOK_R1_SHA256,
                         'be787e0cab3c366c3a8f8dc4662a711370a9e50a137adbdb753ab65b11067f88')
        self.assertEqual(port.R4_HOOK_BLOB,'a2ef78981d1a1e39ab45649a3658367da770eba7')

    def test_baseline_without_proof_accepted(self):
        old,new,pin,proof=self.sample()
        result=port.verify_pinned_r4_hook(old,pin,None)
        self.assertEqual(result['status'],'PINNED_R4_BASELINE')
        self.assertFalse(result['unhook_proof_verified'])

    def test_new_postimage_with_full_proof_accepted(self):
        old,new,pin,proof=self.sample()
        self.assertNotEqual(port.blob(new),pin.r4_hook_blob)
        result=port.verify_pinned_r4_hook(new,pin,proof)
        self.assertEqual(result['status'],'PINNED_R4_PLUS_UNHOOK_R1')
        self.assertEqual(result['effective_sha256'],proof['after_sha256'])
        self.assertTrue(result['unhook_proof_verified'])

    def test_staged_source_without_proof_blocked(self):
        old,new,pin,proof=self.sample()
        with self.assertRaisesRegex(port.PortError,'R4_RUNTIME_FIXED_SELINUX_HOOK_REQUIRED'):
            port.verify_pinned_r4_hook(new,pin,None)

    def test_unexpected_source_edit_with_old_proof_blocked(self):
        old,new,pin,proof=self.sample()
        with self.assertRaisesRegex(port.PortError,'EFFECTIVE_SOURCE_HASH_MISMATCH'):
            port.verify_pinned_r4_hook(new+b'evil mutation',pin,proof)

    def test_before_hash_drift_blocked(self):
        old,new,pin,proof=self.sample()
        proof['before_sha256']='0'*64
        with self.assertRaisesRegex(port.PortError,'PREIMAGE_IDENTITY_MISSING'):
            port.verify_pinned_r4_hook(new,pin,proof)

    def test_after_hash_forgery_blocked(self):
        old,new,pin,proof=self.sample()
        proof['after_sha256']='0'*64
        with self.assertRaisesRegex(port.PortError,'POSTIMAGE_PROOF_MISMATCH'):
            port.verify_pinned_r4_hook(new,pin,proof)

    def test_missing_security_guarantees_blocked(self):
        old,new,pin,proof=self.sample()
        for key in ('r4_effective_source_pinned',
                    'setprocattr_r4_fallback_unchanged',
                    'protects_original_pointers_after_restore_error',
                    'reports_error_to_feature_set',
                    'preserves_fake_status_when_exit_restore_fails',
                    'selinux_enforcing_unchanged'):
            with self.subTest(key=key):
                mutated=dict(proof);mutated[key]=False
                with self.assertRaisesRegex(port.PortError,'PROOF_INCOMPLETE'):
                    port.verify_pinned_r4_hook(new,pin,mutated)

    def test_false_build_or_device_pass_blocked(self):
        old,new,pin,proof=self.sample()
        for key in ('kernel_build','device_pass','promotion'):
            with self.subTest(key=key):
                mutated=dict(proof);mutated[key]=True
                with self.assertRaisesRegex(port.PortError,'FALSE_RELEASE_CLAIM'):
                    port.verify_pinned_r4_hook(new,pin,mutated)

    def test_old_r4_source_cannot_pass_new_unhook_proof(self):
        old,new,pin,proof=self.sample()
        with self.assertRaisesRegex(port.PortError,'UNHOOK_PROOF_BUT_SOURCE_STILL_BASELINE'):
            port.verify_pinned_r4_hook(old,pin,proof)

    def test_full_source_only_probe_realizes_new_hook_without_writes(self):
        with sample_workspace() as (_,src,donor,report,pins):
            hook=src/'KernelSU/kernel/feature/selinux_hide.c'
            old=hook.read_bytes();new=old+b'protected unhook error path\n'
            hook.write_bytes(new)
            p=replace(pins,r4_hook_sha256=port.sha256(old),
                      r4_unhook_sha256=port.sha256(new))
            proof=dict(self.sample()[3],before_sha256=port.sha256(old),
                       after_sha256=port.sha256(new))
            result=port.probe(src,donor,report,p,unhook_proof=proof)
            self.assertEqual(result['r4_hook_identity']['status'],'PINNED_R4_PLUS_UNHOOK_R1')
            self.assertEqual(hook.read_bytes(),new)
            self.assertEqual(json.loads(report.read_text())['r4_hook_identity'],
                             result['r4_hook_identity'])
            self.assertFalse(result['security']['automatic_promotion_blocked'] is False)

    def test_actual_preflight_proof_is_forwarded_to_probe(self):
        repo=Path(__file__).resolve().parents[1]
        fleet=(repo/'common/scripts/veux_fleet_35222_selinux_r3.py').read_text()
        self.assertIn('unhook_proof=unhook_proof)',fleet)
        self.assertLess(fleet.index('unhook_proof = apply_source_guard('),
                        fleet.index('susfs_54_port_probe('))
        self.assertIn('PIN_PROMOTION=BLOCKED',SCRIPT.read_text())

if __name__=='__main__':
    unittest.main(verbosity=2)
