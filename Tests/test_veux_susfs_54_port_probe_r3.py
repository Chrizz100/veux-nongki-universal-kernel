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

if __name__=='__main__':
    unittest.main(verbosity=2)
