#!/usr/bin/env python3
"""Offline fixtures. These tests do NOT represent a real 5.4.274 source build."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import importlib.util

loc=Path(__file__).with_name('prepare_stock274_p3.py')
spec=importlib.util.spec_from_file_location('p3',loc)
p3=importlib.util.module_from_spec(spec);spec.loader.exec_module(p3)

def run(*cmd):
    return subprocess.run(cmd,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True).stdout.strip()

def fixture(root,version='5.4.274',extra_cass_ref=False):
    paths={
       'Makefile':'VERSION = 5\nPATCHLEVEL = 4\nSUBLEVEL = '+version.split('.')[-1]+'\n',
       'arch/arm64/configs/veux_defconfig': 'CONFIG_LOCALVERSION="-lineageos"\nCONFIG_SCHED_CASS=y\nCONFIG_CPUSETS=y\n',
       'init/Kconfig':('menu "other"\nconfig FOO\n\tbool "foo"\n\n'
                       'config SCHED_CASS\n\tbool "Capacity Aware Superset Scheduler"\n'
                       '\thelp\n\t  hierarchy of criteria\n\nconfig SCHED_AUTOGROUP\n\tbool "group"\n'),
       'kernel/sched/fair.c': 'int select_task_rq_fair(void) {return 1;}\n'+p3.CASS_FAIR+'const int fair_sched_class = 1;\n',
       'kernel/sched/rt.c':'void select_task_rq_rt(void){}\n#include "cass_rt.h"\nconst int rt_sched_class = 2;\n',
       'kernel/sched/cass.c':'void cass_select_task_rq_fair(void) {}\n',
       'kernel/sched/cass_rt.h':'int cass_select_task_rq_rt(int a);\n',
       'kernel/sched/Makefile':'obj-y += core.o fair.o rt.o\n',
    }
    if extra_cass_ref: paths['kernel/sched/core.c']='int x = CONFIG_SCHED_CASS;\n'
    root.mkdir()
    run('git','init','-q',str(root))
    for name,content in paths.items():
      fn=root/name;fn.parent.mkdir(parents=True,exist_ok=True);fn.write_text(content)
    run('git','-C',str(root),'add','-A')
    run('git','-C',str(root),'-c','user.name=test','-c','user.email=test@example.org',
        'commit','-qm','fixture commit')
    return run('git','-C',str(root),'rev-parse','HEAD^{tree}')

class SourceStageTests(unittest.TestCase):
    def setUp(self):
       self.temp=tempfile.TemporaryDirectory()
       self.addCleanup(self.temp.cleanup)
       self.parent=Path(self.temp.name)
       self.src=self.parent/'p2'; self.dest=self.parent/'out'
       self.tree=fixture(self.src)
    def before(self):
       return {rel:p3.read_checked(self.src,rel) for rel in p3.SENSITIVE}
    def test_00_sha256_is_standard(self):
       self.assertEqual(p3.sha256(b'abc'),
              'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
    def test_01_genuine_p2_tree_pin_is_40_hex(self):
       self.assertEqual(len(p3.P2_SOURCE_TREE),40)
       self.assertEqual(p3.P2_CI_RUN,33832342297)
    def test_02_p2_gate_accepts_exact_synthetic_tree(self):
       self.assertEqual(p3.validate_source(self.src,self.tree)['source_tree'],self.tree)
    def test_03_p2_gate_rejects_real_pin_mismatch(self):
       with self.assertRaisesRegex(p3.Blocked,'P2_TREE_MISMATCH'):
         p3.validate_source(self.src)
    def test_04_edits_only_six_paths(self):
       after=p3.transform(self.before());self.assertEqual(set(after),p3.SENSITIVE)
    def test_05_config_cass_removed_not_renamed(self):
       after=p3.transform(self.before());s=after['arch/arm64/configs/veux_defconfig'].decode()
       self.assertNotIn('CONFIG_SCHED_CASS',s)
       self.assertNotIn('CONFIG_SCHED_WALT',s)
       self.assertIn('CONFIG_CPUSETS=y',s)
    def test_06_init_kconfig_cleanup_preserves_adjacent(self):
       after=p3.transform(self.before());s=after['init/Kconfig'].decode()
       self.assertNotIn('CASS',s);self.assertIn('config FOO',s)
       self.assertIn('config SCHED_AUTOGROUP',s)
    def test_07_fair_restores_original_dispatch(self):
       after=p3.transform(self.before());s=after['kernel/sched/fair.c'].decode()
       self.assertNotIn('cass',s.lower());self.assertIn('select_task_rq_fair',s)
    def test_08_rt_removes_header_not_class(self):
       after=p3.transform(self.before());s=after['kernel/sched/rt.c'].decode()
       self.assertNotIn('cass_rt.h',s);self.assertIn('rt_sched_class',s)
    def test_09_delete_cass_sources(self):
       after=p3.transform(self.before());self.assertIsNone(after['kernel/sched/cass.c'])
       self.assertIsNone(after['kernel/sched/cass_rt.h'])
    def test_10_real_git_apply_check_and_postimage(self):
       old=self.before();new=p3.transform(old)
       p3.audit_patch(old,new,p3.unified_patch(old,new))
    def test_11_create_patch_report_source_unchanged(self):
       old=self.before();head=run('git','-C',str(self.src),'rev-parse','HEAD')
       ret=p3.prepare(self.src,self.dest,expected_tree=self.tree)
       self.assertTrue((self.dest/'P2_TO_P3_REMOVE_CASS.patch').is_file())
       self.assertEqual(run('git','-C',str(self.src),'rev-parse','HEAD'),head)
       self.assertEqual(self.before(),old)
       self.assertEqual(ret['patch_git_apply_check'],'PASS')
       self.assertFalse(ret['walt_integrated'])
       self.assertFalse(ret['build_pass'])
    def test_12_modified_source_rejected(self):
       (self.src/'kernel/sched/fair.c').write_text('changes\n')
       with self.assertRaisesRegex(p3.Blocked,'SOURCE_DIRTY'):
         p3.validate_source(self.src,self.tree)
    def test_13_unpinned_kernel_version_rejected(self):
       (self.src/'Makefile').write_text('VERSION = 5\nPATCHLEVEL = 4\nSUBLEVEL = 268\n')
       run('git','-C',str(self.src),'add','Makefile')
       run('git','-C',str(self.src),'-c','user.name=test','-c','user.email=test@example.org',
        'commit','-qm','change version')
       tree=run('git','-C',str(self.src),'rev-parse','HEAD^{tree}')
       with self.assertRaisesRegex(p3.Blocked,'NOT_LINUX_5_4_274'):
         p3.validate_source(self.src,tree)
    def test_14_unreviewed_cass_reference_rejected(self):
       (self.src/'kernel/sched/extra.c').write_text('CONFIG_SCHED_CASS\n')
       run('git','-C',str(self.src),'add','kernel/sched/extra.c')
       run('git','-C',str(self.src),'-c','user.name=test','-c','user.email=test@example.org',
           'commit','-qm','extra dependency')
       tree=run('git','-C',str(self.src),'rev-parse','HEAD^{tree}')
       with self.assertRaisesRegex(p3.Blocked,'UNREVIEWED_CASS_DEPENDENCIES'):
         p3.validate_source(self.src,tree)
    def test_15_legacy_ksu_residue_rejected(self):
       (self.src/'drivers/kernelsu').mkdir(parents=True)
       with self.assertRaisesRegex(p3.Blocked,'ROOT_SUSFS_NOMOUNT_RESIDUE'):
         p3.validate_source(self.src,self.tree)
    def test_16_walt_present_must_stop_and_reaudit(self):
       (self.src/'kernel/sched/walt').mkdir()
       with self.assertRaisesRegex(p3.Blocked,'WALT_ALREADY_PRESENT'):
         p3.validate_source(self.src,self.tree)
    def test_17_duplicate_cass_config_rejected(self):
       old=self.before();old['arch/arm64/configs/veux_defconfig']+=b'CONFIG_SCHED_CASS=y\n'
       with self.assertRaisesRegex(p3.Blocked,'MISSING_OR_AMBIGUOUS'):
         p3.transform(old)
    def test_18_kconfig_unknown_change_blocks(self):
       old=self.before();old['init/Kconfig']=old['init/Kconfig'].replace(b'hierarchy of criteria',b'unknown')
       with self.assertRaisesRegex(p3.Blocked,'CASS_KCONFIG_BLOCK_DRIFT'):
         p3.transform(old)
    def test_19_wrong_fair_block_blocks(self):
       old=self.before();old['kernel/sched/fair.c']=old['kernel/sched/fair.c'].replace(b'wrapper',b'hook')
       with self.assertRaisesRegex(p3.Blocked,'MISSING_OR_AMBIGUOUS'):
         p3.transform(old)
    def test_20_no_output_into_source(self):
       with self.assertRaisesRegex(p3.Blocked,'OUTPUT_INSIDE_SOURCE'):
         p3.prepare(self.src,self.src/'out',expected_tree=self.tree)
    def test_21_refuse_existing_output(self):
       self.dest.mkdir()
       with self.assertRaisesRegex(p3.Blocked,'DESTINATION_EXISTS'):
         p3.prepare(self.src,self.dest,expected_tree=self.tree)
    def test_22_refuse_symlink(self):
       path=self.src/'kernel/sched/cass.c';path.unlink();path.symlink_to(self.src/'Makefile')
       with self.assertRaisesRegex(p3.Blocked,'MISSING_OR_SYMLINK_FILE'):
         p3.read_checked(self.src,'kernel/sched/cass.c')
    def test_23_git_patch_is_reproducible(self):
       before=self.before();after=p3.transform(before)
       self.assertEqual(p3.unified_patch(before,after),p3.unified_patch(before,after))
       self.assertIn(b'deleted file mode 100644',p3.unified_patch(before,after))
    def test_24_anomaly_no_susfs_or_walt_added(self):
       a=p3.transform(self.before())
       self.assertTrue(all(b'susfs' not in (x or b'') and b'CONFIG_SCHED_WALT=y' not in (x or b'')
                           for x in a.values()))

if __name__=='__main__':unittest.main(verbosity=2)
