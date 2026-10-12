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
