#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile
import shutil
import json
import os

ROOT=Path(__file__).resolve().parents[2]
def module(name,source):
 spec=importlib.util.spec_from_file_location(name,ROOT/'tools/r54'/source)
 m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
bg=module('r54_b','r54_build_contract.py')
sg=module('r54_s','r54_susfs_54_references.py')
FILEBASE=Path(os.environ.get('R54_INPUT_DIR','/mnt/data/files'))
WORKFLOW=Path(os.environ.get('R54_R13_WORKFLOW',str(FILEBASE/'VEUX_R13_CASS_BUILD.yml')))
R13_ARTIFACT=Path(os.environ.get('R54_R13_ARTIFACT','/mnt/data/VEUX_R13_KERNEL_ORIGINAL_40921711051.zip'))

class ContractTests(unittest.TestCase):
 def test_01_sha_known(self):self.assertEqual(bg.sha(b'a'),__import__('hashlib').sha256(b'a').hexdigest())
 def test_02_r13_archive_exact(self):self.assertEqual(bg.file_sha(FILEBASE/'VEUX_R13_CASS_MAIN.zip'),bg.R13_SHA)
 def test_03_r41_archive_exact(self):self.assertEqual(bg.file_sha(FILEBASE/'VEUX_R41_NOMOUNT_SOURCE_MAIN.zip'),bg.R41_SHA)
 def test_04_archive_count(self):self.assertIn('r13/SOURCE_CONTRACT.json',bg.audit_zip(FILEBASE/'VEUX_R41_NOMOUNT_SOURCE_MAIN.zip',bg.R41_SHA,327))
 def test_05_tampered_archive_rejected(self):
  with self.assertRaises(bg.Rejected):bg.audit_zip(FILEBASE/'VEUX_R41_NOMOUNT_SOURCE_MAIN.zip','0'*64,327)
 def test_06_bad_member_count_rejected(self):
  with self.assertRaises(bg.Rejected):bg.audit_zip(FILEBASE/'VEUX_R41_NOMOUNT_SOURCE_MAIN.zip',bg.R41_SHA,319)
 def test_07_real_yaml_gate(self):
  r=bg.audit_workflow(WORKFLOW);self.assertGreaterEqual(len(r['protected_steps']),14)
 def test_08_duplicate_yaml_keys_rejected(self):
  with self.assertRaises(bg.Rejected):bg.yaml.load('x: 1\nx: 2',Loader=bg.StrictLoader)
 def test_09_safe_yaml_on_literal(self):self.assertIn('on',bg.yaml.load("'on':\n  workflow_dispatch: {}",Loader=bg.StrictLoader))
 def test_10_immutable_old_kernel_artifact(self):
  if not R13_ARTIFACT.is_file():self.skipTest("original R13 GitHub artifact not mirrored in this runner")
  r=bg.audit_kernel_artifact(R13_ARTIFACT)
  self.assertEqual(r['new_kernel_compiled'],False)
 def test_11_new_upstream_compilation_not_proven(self):
  r=bg.audit(FILEBASE/'VEUX_R13_CASS_MAIN.zip',FILEBASE/'VEUX_R41_NOMOUNT_SOURCE_MAIN.zip',WORKFLOW)
  self.assertEqual(r['new_upstreams_pending']['bakasu'],bg.NEW_BAKASU)
  self.assertFalse(r['flash_allowed'])

class ReferenceTests(unittest.TestCase):
 def test_12_blob_genuine_format(self):self.assertEqual(sg.blob(b'test'),__import__('hashlib').sha1(b'blob 4\0test').hexdigest())
 def test_13_single_section(self):self.assertEqual(sg.sections('diff --git a/a b/a\n@@ -1 +1 @@\n+x'),['a'])
 def test_14_duplicate_patch_target_blocked(self):
  with self.assertRaises(sg.Rejected):sg.sections('diff --git a/a b/a\ndiff --git a/a b/a\n')
 def test_15_no_5_4_partial_pass(self):
  with self.assertRaises(sg.Rejected):sg.source_audit('diff --git a/fs/susfs.c b/fs/susfs.c','', '', '')
 def test_16_tamper_reference_sha_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   f=Path(d)/'R41.zip';f.write_bytes(b'bad')
   with self.assertRaises(sg.Rejected):sg.audit(Path(d),Path(d),f)
 def test_17_prior_only_no_flash(self):self.assertFalse(bg.audit(FILEBASE/'VEUX_R13_CASS_MAIN.zip',FILEBASE/'VEUX_R41_NOMOUNT_SOURCE_MAIN.zip',WORKFLOW)['flash_allowed'])
 def test_18_ref_workflow_file_pins_present(self):
  self.assertEqual(len(sg.JACK_PINS),2);self.assertEqual(len(sg.MIDORI_PINS),5)
 def test_19_missing_workflow_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaises(OSError):bg.audit_workflow(Path(d)/'n.yml')
 def test_20_modified_build_source_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'w.yml';p.write_text('name: altered\n');
   with self.assertRaises(bg.Rejected):bg.audit_workflow(p)
if __name__=='__main__':unittest.main()
