#!/usr/bin/env python3
"""Offline, deterministic BakaSU R3 backport unit/regression gates."""
from __future__ import annotations
import ast
import contextlib
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(REPO/'common/scripts'))
import veux_bakasu_selinux_backport_r3 as bp
import veux_fleet_35222_selinux_r3 as runner

@contextlib.contextmanager
def fake_candidate(*,extra_in_patch=False):
    with tempfile.TemporaryDirectory() as tmp:
        top=Path(tmp)
        donor=top/'donor';donor.mkdir()
        def git(*args):
            return subprocess.check_output(['git','-C',str(donor),*map(str,args)],text=True,stderr=subprocess.PIPE).strip()
        git('init','-q');git('config','user.name','VEUX unit')
        git('config','user.email','veux@example.invalid')
        paths=list(bp.FILE_BLOBS)
        for i,name in enumerate(paths):
            p=donor/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('PRE '+name+'\n')
        compat=donor/'kernel/tools/susfs_compat.mk'
        compat.write_text('compat checks valid\n')
        uapi=donor/'uapi/supercall.h'
        uapi.parent.mkdir(exist_ok=True,parents=True)
        uapi.write_text('static const __u32 KERNEL_SU_UAPI_VERSION = 5;\n')
        git('add','.');git('commit','-qm','pin')
        pin=git('rev-parse','HEAD')
        compat.write_text('compat checks valid\n$(error Please wait susfs update.)\n')
        git('commit','-qam','upstream guard')
        (donor/'rust.lock').write_text('new dependency\n')
        git('add','rust.lock');git('commit','-qm','userspace only')
        parent=git('rev-parse','HEAD')
        for i,name in enumerate(paths):
            (donor/name).write_text('POST '+name+'\n')
        if extra_in_patch:
            (donor/'extra').write_text('unexpected\n')
        git('add','.');git('commit','-qm','isolated selinux patch')
        commit=git('rev-parse','HEAD')
        git('checkout','-q','--detach',pin)
        blobs={name:(bp.git_blob(('PRE '+name+'\n').encode()),bp.git_blob(('POST '+name+'\n').encode())) for name in paths}
        src=top/'work/kernel'
        vendor=src/'KernelSU/kernel';vendor.mkdir(parents=True)
        for name in paths:
            p=src/'KernelSU'/name;p.parent.mkdir(parents=True,exist_ok=True)
            p.write_text('PRE '+name+'\n')
        (src/'drivers').mkdir()
        (src/'drivers/kernelsu').symlink_to('../KernelSU/kernel')
        # Faithfully model the 5.4 SELinux state and its global-function
        # declarations. Kernel 5.4 has one security_dump_masked_av and one
        # forward declaration plus definition of context_struct_compute_av.
        (src/'Makefile').write_text('VERSION = 5\nPATCHLEVEL = 4\nSUBLEVEL = 274\n')
        header=src/'security/selinux/include/security.h'
        header.parent.mkdir(parents=True)
        header.write_text('struct selinux_state { int active; };\n')
        services=src/'security/selinux/ss/services.c'
        services.parent.mkdir(parents=True)
        services.write_text(
            'static void context_struct_compute_av(struct policydb *policydb,\n'
            '  struct context *source, struct context *target,\n'
            '  u16 tclass, struct av_decision *avd, struct extended_perms *xperms);\n'
            'static void security_dump_masked_av(struct policydb *policydb,\n'
            '  struct context *source, struct context *target,\n'
            '  u16 tclass, u32 permissions, const char *reason) { }\n'
            'static void context_struct_compute_av(struct policydb *policydb,\n'
            '  struct context *source, struct context *target,\n'
            '  u16 tclass, struct av_decision *avd, struct extended_perms *xperms) { }\n'
        )
        override=dict(SOURCE_PIN=pin,BACKPORT_COMMIT=commit,BACKPORT_PARENT=parent,
                      FILE_BLOBS=blobs,
                      KNOWN_SUSFS_35222_BLOB=bp.git_blob(b'compat checks valid\n'),
                      KNOWN_UAPI5_BLOB=bp.git_blob(b'static const __u32 KERNEL_SU_UAPI_VERSION = 5;\n'))
        with patch.multiple(bp,**override):
            yield top,donor,src,blobs,paths,git

class BackportTests(unittest.TestCase):
    def test_production_frozen_sha_and_exact_five_paths(self):
        self.assertEqual(bp.SOURCE_PIN,'5b76b884c75f729a220bb317aa4a4fc78f0e0e9c')
        self.assertEqual(bp.BACKPORT_COMMIT,'fa12ffde8244008e9afdb7ac0c1bb1bc1b06b95a')
        self.assertEqual(bp.BACKPORT_PARENT,'9097b1a1c6c889756201bbc5713a84a9b23f7908')
        self.assertEqual(len(bp.FILE_BLOBS),5)
        self.assertTrue(all(name.startswith('kernel/') for name in bp.FILE_BLOBS))
        self.assertNotIn('kernel/tools/susfs_compat.mk',bp.FILE_BLOBS)
        self.assertTrue(all(len(d)==40 for p in bp.FILE_BLOBS.values() for d in p))

    def test_r3_retains_stable_components_and_proven_source_pins(self):
        self.assertEqual(runner.TARGETS['resukisu']['commit'],bp.SOURCE_PIN)
        self.assertEqual(runner.TARGETS['resukisu']['version'],'35222')
        self.assertEqual(runner.TARGETS['susfs']['version'],'2.3.0')
        self.assertEqual(runner.TARGETS['nomount']['version'],'21')
        self.assertEqual(runner.EXPECTED_KERNEL_R3,'5.4.274')

    def test_local_git_history_and_objects_are_verified(self):
        with fake_candidate() as (top,donor,src,blobs,paths,git):
            p=bp.verify_donor(donor)
            self.assertEqual(set(p['files']),set(paths))
            self.assertTrue(p['guard_not_integrated'])
            self.assertEqual(git('rev-parse','HEAD'),bp.SOURCE_PIN)

    def test_complete_backport_and_exact_postimage(self):
        with fake_candidate() as (top,donor,src,blobs,paths,git):
            report=top/'report/BACKPORT.json'
            p=bp.apply_source_backport(src,donor,report)
            self.assertFalse(p['device_pass'])
            self.assertFalse(p['kernel_build'])
            self.assertTrue(report.exists())
            self.assertEqual(p['changed_kernel_paths'],paths)
            self.assertEqual(p['host_kernel_symbol_exports']['symbols'],
                             {'security_dump_masked_av':1,'context_struct_compute_av':2})
            services=(src/'security/selinux/ss/services.c').read_text()
            self.assertNotIn('static void security_dump_masked_av',services)
            self.assertNotIn('static void context_struct_compute_av',services)
            self.assertEqual(services.count('void context_struct_compute_av'),2)
            self.assertEqual(services.count('void security_dump_masked_av'),1)
            for name,(_,after) in blobs.items():
                self.assertEqual(bp.git_blob((src/'KernelSU'/name).read_bytes()),after)
            self.assertTrue(b'$(error Please wait susfs update.)' not in (src/'KernelSU/kernel/tools/susfs_compat.mk').read_bytes() if (src/'KernelSU/kernel/tools/susfs_compat.mk').exists() else True)
            self.assertEqual(git('status','--porcelain'),'')

    def test_preimage_drift_fail_closed_no_partial_changes(self):
        with fake_candidate() as (top,donor,src,blobs,paths,git):
            (src/'KernelSU'/paths[3]).write_text('changed by another transformer\n')
            before=[(src/'KernelSU'/p).read_bytes() for p in paths]
            with self.assertRaisesRegex(bp.UnsafeBackport,'VEUX_SOURCE_PREIMAGE_DRIFT'):
                bp.apply_source_backport(src,donor,top/'report.json')
            self.assertEqual(before,[(src/'KernelSU'/p).read_bytes() for p in paths])

    def test_backport_scope_drift_rejected(self):
        with fake_candidate(extra_in_patch=True) as (top,donor,src,blobs,paths,git):
            with self.assertRaisesRegex(bp.UnsafeBackport,'BACKPORT_SCOPE_DRIFT'):
                bp.apply_source_backport(src,donor,top/'report.json')

    def test_donor_rewrite_fails(self):
        with fake_candidate() as (top,donor,src,blobs,paths,git):
            with patch.object(bp,'BACKPORT_PARENT','0'*40):
                with self.assertRaisesRegex(bp.UnsafeBackport,'UNEXPECTED_BACKPORT_PARENT'):
                    bp.verify_donor(donor)

    def test_missing_source_or_altered_pin_blocks(self):
        with fake_candidate() as (top,donor,src,blobs,paths,git):
            with patch.object(bp,'SOURCE_PIN','a'*40):
                with self.assertRaisesRegex(bp.UnsafeBackport,'SOURCE_PIN_MISMATCH'):
                    bp.verify_donor(donor)

    def test_dirty_donor_blocks(self):
        with fake_candidate() as (top,donor,src,blobs,paths,git):
            (donor/'unexpected').write_text('untracked')
            with self.assertRaisesRegex(bp.UnsafeBackport,'DIRTY_SOURCE_DONOR'):
                bp.apply_source_backport(src,donor,top/'report.json')

    def test_missing_file_blocks_before_mutation(self):
        with fake_candidate() as (top,donor,src,blobs,paths,git):
            (src/'KernelSU'/paths[-1]).unlink()
            before=(src/'KernelSU'/paths[0]).read_bytes()
            with self.assertRaisesRegex(bp.UnsafeBackport,'SOURCE_FILE_MISSING_OR_SYMLINK'):
                bp.apply_source_backport(src,donor,top/'report.json')
            self.assertEqual((src/'KernelSU'/paths[0]).read_bytes(),before)

    def test_symlink_in_source_blocks(self):
        with fake_candidate() as (top,donor,src,blobs,paths,git):
            name=paths[-1];target=src/'KernelSU'/name;target.unlink()
            target.symlink_to('/etc/passwd')
            with self.assertRaisesRegex(bp.UnsafeBackport,'SOURCE_FILE_MISSING_OR_SYMLINK'):
                bp.apply_source_backport(src,donor,top/'report.json')

    def test_host_export_preflight_does_not_modify_any_sources(self):
        with fake_candidate() as (top,donor,src,blobs,paths,git):
            host=src/'security/selinux/ss/services.c'
            old=host.read_bytes()
            path,before,after,proof=bp.stage_legacy_selinux_exports(src)
            self.assertEqual(path,host)
            self.assertEqual(host.read_bytes(),old)
            self.assertEqual(before,old)
            self.assertNotEqual(before,after)
            self.assertEqual(proof['host_kernel'],'5.4')
            self.assertEqual(proof['symbols']['context_struct_compute_av'],2)
            self.assertEqual(proof['symbols']['security_dump_masked_av'],1)
            self.assertFalse(proof['new_export_symbol_macros'])
            self.assertFalse(proof['changed_function_bodies'])

    def test_reject_wrong_kernel_version_without_writing(self):
        with fake_candidate() as (top,donor,src,blobs,paths,git):
            (src/'Makefile').write_text('VERSION = 5\nPATCHLEVEL = 10\n')
            original=(src/'KernelSU'/paths[0]).read_bytes()
            with self.assertRaisesRegex(bp.UnsafeBackport,'HOST_EXPORT_REQUIRES_LINUX_5_4'):
                bp.apply_source_backport(src,donor,top/'BAD.json')
            self.assertEqual(original,(src/'KernelSU'/paths[0]).read_bytes())
            self.assertFalse((top/'BAD.json').exists())

    def test_reject_missing_selinux_state(self):
        with fake_candidate() as (top,donor,src,blobs,paths,git):
            (src/'security/selinux/include/security.h').write_text('struct old_selinux_state {};\n')
            with self.assertRaisesRegex(bp.UnsafeBackport,'HOST_EXPORT_REQUIRES_SELINUX_STATE'):
                bp.stage_legacy_selinux_exports(src)

    def test_reject_unexpected_static_definition_count(self):
        with fake_candidate() as (top,donor,src,blobs,paths,git):
            f=src/'security/selinux/ss/services.c'
            f.write_text(f.read_text().replace('static void security_dump_masked_av','static int security_dump_masked_av'))
            with self.assertRaisesRegex(bp.UnsafeBackport,'HOST_EXPORT_UNEXPECTED_STATIC_COUNT'):
                bp.stage_legacy_selinux_exports(src)

    def test_reject_unapproved_export_prototype_signature(self):
        with fake_candidate() as (top,donor,src,blobs,paths,git):
            f=src/'security/selinux/ss/services.c'
            f.write_text(f.read_text().replace('security_dump_masked_av(struct policydb *policydb,',
                                               'security_dump_masked_av(struct olddb *policydb,'))
            with self.assertRaisesRegex(bp.UnsafeBackport,'HOST_EXPORT_SIGNATURE_CHANGED'):
                bp.stage_legacy_selinux_exports(src)

    def test_reject_host_symlink_before_upstream_changes(self):
        with fake_candidate() as (top,donor,src,blobs,paths,git):
            f=src/'security/selinux/ss/services.c'
            f.unlink()
            f.symlink_to('/etc/hosts')
            initial=(src/'KernelSU'/paths[0]).read_bytes()
            with self.assertRaisesRegex(bp.UnsafeBackport,'SELINUX_HOST_FILE_MISSING_OR_SYMLINK'):
                bp.apply_source_backport(src,donor,top/'BAD.json')
            self.assertEqual(initial,(src/'KernelSU'/paths[0]).read_bytes())

    def test_missing_host_source_does_not_mutate_upstream_backport(self):
        with fake_candidate() as (top,donor,src,blobs,paths,git):
            (src/'security/selinux/ss/services.c').unlink()
            before=[(src/'KernelSU'/rel).read_bytes() for rel in paths]
            with self.assertRaisesRegex(bp.UnsafeBackport,'SELINUX_HOST_FILE_MISSING_OR_SYMLINK'):
                bp.apply_source_backport(src,donor,top/'BAD.json')
            self.assertEqual(before,[(src/'KernelSU'/rel).read_bytes() for rel in paths])

    def test_host_export_rollback_on_failed_writer(self):
        with fake_candidate() as (top,donor,src,blobs,paths,git):
            host=src/'security/selinux/ss/services.c'
            before=[(src/'KernelSU'/rel).read_bytes() for rel in paths]
            host_before=host.read_bytes()
            original_method=Path.write_bytes
            attempts=[]
            def guarded_writer(path,data):
                # Only the write of the modified host source is denied once.
                if path==host and data!=host_before and not attempts:
                    attempts.append(1)
                    raise OSError('synthetic transient host write failure')
                return original_method(path,data)
            with patch.object(Path,'write_bytes',guarded_writer):
                with self.assertRaisesRegex(OSError,'synthetic transient'):
                    bp.apply_source_backport(src,donor,top/'FAILED.json')
            self.assertEqual(before,[(src/'KernelSU'/rel).read_bytes() for rel in paths])
            self.assertEqual(host_before,host.read_bytes())
            self.assertFalse((top/'FAILED.json').exists())

    def test_fix_matches_upstream_static_export_check_requirements(self):
        # BakaSU fa12 static_export_check.mk checks these same literal tokens.
        with fake_candidate() as (top,donor,src,blobs,paths,git):
            host=src/'security/selinux/ss/services.c'
            _,before,after,_=bp.stage_legacy_selinux_exports(src)
            self.assertIn(b'static void security_dump_masked_av',before)
            self.assertIn(b'static void context_struct_compute_av',before)
            for mark in (b'static void security_dump_masked_av',
                         b'static void context_struct_compute_av'):
                self.assertNotIn(mark,after)
            self.assertEqual(after.replace(b'void security_dump_masked_av',b'static void security_dump_masked_av').replace(
                b'void context_struct_compute_av',b'static void context_struct_compute_av'),before)

    def test_worker_injects_only_one_readonly_temp_source_site(self):
        s=bp.ANCHOR+"        overlay_hash = r.save_overlay(src, before, args.overlays / label, label, targets)\n"+bp.RESULT_ANCHOR
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'worker.py';q=Path(tmp)/'patched.py';p.write_text('def worker():\n    try:\n'+s+'    except Exception:\n        pass\n')
            info=bp.inject_worker(p,q)
            t=q.read_text()
            self.assertEqual(t.count('selinux_backport_r3 = apply_source_backport'),1)
            self.assertEqual(t.count("result['selinux_backport_r3'] = selinux_backport_r3"),1)
            self.assertNotEqual(info['original_sha256'],info['patched_sha256'])
            with self.assertRaisesRegex(bp.UnsafeBackport,'WORKER_DEST_ALREADY_EXISTS'):
                bp.inject_worker(p,q)

    def test_worker_drift_and_duplicate_anchors_block(self):
        with tempfile.TemporaryDirectory() as d:
            a=Path(d)/'in';b=Path(d)/'out'
            a.write_text(bp.ANCHOR*2+bp.RESULT_ANCHOR)
            with self.assertRaisesRegex(bp.UnsafeBackport,'WORKER_UPDATE_ANCHOR_DRIFT'):
                bp.inject_worker(a,b)
            self.assertFalse(b.exists())
            a.write_text(bp.ANCHOR+'different_compile_anchor\n')
            with self.assertRaisesRegex(bp.UnsafeBackport,'WORKER_COMPILE_ANCHOR_DRIFT'):
                bp.inject_worker(a,b)
            self.assertFalse(b.exists())

    def test_offline_workflow_never_promotes_frozen_candidate(self):
        p=REPO/'.github/workflows/VEUX_V4_BakaSU_35222_SELinux_Backport_R3.yml'
        if not p.exists(): self.skipTest('workflow not yet authored')
        from ruamel.yaml import YAML
        y=YAML(typ='safe');y.version=(1,2);y.allow_duplicate_keys=False
        o=y.load(p.read_text())
        self.assertEqual(o['permissions'],{'contents':'read'})
        self.assertEqual(list(o['on']),['workflow_dispatch'])
        self.assertEqual(o['jobs']['candidate']['name'],'BakaSU 35222 plus isolated SELinux backport: 5.4.274')
        self.assertNotIn('git push ',p.read_text())
        self.assertIn('NO_MAIN_PROMOTION=PASS',p.read_text())
        self.assertFalse(o['on']['workflow_dispatch']['inputs']['enable_build']['default'] is None)

if __name__=='__main__':unittest.main(verbosity=2)
