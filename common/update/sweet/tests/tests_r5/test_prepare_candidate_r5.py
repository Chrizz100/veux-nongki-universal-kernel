from __future__ import annotations
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]
spec = importlib.util.spec_from_file_location('prepare_r5', ROOT / 'common/scripts/sweet/prepare_candidate_r5.py')
prep = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prep)

class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='sweet-r5-test-')
        self.root = Path(self.tmp.name)
        self.source = self.root / 'source'; self.source.mkdir()
        (self.source / 'file.txt').write_bytes(b'old\n')
        self.patch = self.root / 'one.patch'
        self.patch.write_bytes(b'diff --git a/file.txt b/file.txt\n--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-old\n+new\n')
        self.lock = {'base_commit':'fixture', 'base_tree':prep.tree_identity(self.source)[0],
          'patches':[{'path':'one.patch','sha256':prep.digest_file(self.patch)}],
          'changed_files':[{'path':'file.txt','after_sha256':hashlib.sha256(b'new\n').hexdigest()}]}
    def tearDown(self):
        self.tmp.cleanup()
    def test_identity_matches_real_git_including_symlink_and_mode(self):
        (self.source / 'sub').mkdir(); (self.source/'sub/exec').write_text('x\n'); (self.source/'sub/exec').chmod(0o755)
        (self.source/'link').symlink_to('sub/../file.txt')
        subprocess.run(['git','init','-q',str(self.source)],check=True)
        subprocess.run(['git','-C',str(self.source),'add','-A'],check=True)
        expected=subprocess.check_output(['git','-C',str(self.source),'write-tree'],text=True).strip()
        self.assertEqual(prep.tree_identity(self.source)[0],expected)
    def test_correct_patch_preserves_source(self):
        out=self.root/'new';r=prep.prepare(self.source,out,self.lock,self.root)
        self.assertTrue(r['source_preparation_passed']);self.assertFalse(r['flashable'])
        self.assertEqual((self.source/'file.txt').read_bytes(),b'old\n')
        self.assertEqual((out/'file.txt').read_bytes(),b'new\n')
    def test_existing_output_refused(self):
        out=self.root/'new';out.mkdir();(out/'sentinel').write_text('keep')
        with self.assertRaises(ValueError):prep.prepare(self.source,out,self.lock,self.root)
        self.assertEqual((out/'sentinel').read_text(),'keep')
    def test_nested_output_refused(self):
        with self.assertRaises(ValueError):prep.prepare(self.source,self.source/'nested',self.lock,self.root)
    def test_wrong_source_refused_before_copy(self):
        (self.source/'file.txt').write_bytes(b'altered\n');out=self.root/'new'
        with self.assertRaises(ValueError):prep.prepare(self.source,out,self.lock,self.root)
        self.assertFalse(out.exists())
    def test_changed_patch_refused_before_copy(self):
        self.patch.write_bytes(self.patch.read_bytes()+b'\n');out=self.root/'new'
        with self.assertRaises(ValueError):prep.prepare(self.source,out,self.lock,self.root)
        self.assertFalse(out.exists())
    def test_undeclared_changes_rejected(self):
        self.lock['changed_files']=[]
        with self.assertRaises(ValueError):prep.prepare(self.source,self.root/'new',self.lock,self.root)
        self.assertEqual((self.source/'file.txt').read_bytes(),b'old\n')
    def test_bad_result_hash_rejected(self):
        self.lock['changed_files'][0]['after_sha256']='0'*64
        with self.assertRaises(ValueError):prep.prepare(self.source,self.root/'new',self.lock,self.root)
    def test_expected_real_package_inputs(self):
        lock=json.loads(prep.LOCK.read_text())
        self.assertEqual(len(lock['patches']),4)
        self.assertEqual(len(lock['changed_files']),17)
        for item in lock['patches']:self.assertEqual(prep.digest_file(ROOT/item['path']),item['sha256'])

if __name__ == '__main__':unittest.main()
