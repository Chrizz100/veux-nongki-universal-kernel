import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import yaml

ROOT=Path(__file__).resolve().parents[2]
WORK=ROOT/'R54_WORKFLOW_ENTWURF_NICHT_FREIGEGEBEN.txt'
RUNNER=ROOT/'tools/r54/R54_GITHUB_REAL_SOURCE_PREBUILD_NOFLASH.sh'
class Strict(yaml.BaseLoader):
 def construct_mapping(self,node,deep=False):
  r={}
  for keynode,valnode in node.value:
   k=self.construct_object(keynode,deep=deep)
   if k in r:raise ValueError('duplicate key: '+str(k))
   r[k]=self.construct_object(valnode,deep=deep)
  return r

def doc():return yaml.load(WORK.read_text(),Loader=Strict)
class DraftChecks(unittest.TestCase):
 def test_01_manual_only(self):self.assertEqual(list(doc()['on']),['workflow_dispatch'])
 def test_02_no_extra_permissions(self):self.assertEqual(doc()['permissions'],{'contents':'read'})
 def test_03_one_no_flash_job(self):self.assertEqual(len(doc()['jobs']),1)
 def test_04_branch_main_repo_guard(self):
  s=doc()['jobs']['source_prebuild']['if'];self.assertIn('refs/heads/main',s);self.assertIn('Chrizz100/veux-nongki-universal-kernel',s)
 def test_05_checkout_pinned(self):
  acts=[x['uses'] for x in doc()['jobs']['source_prebuild']['steps'] if 'uses' in x]
  self.assertEqual(acts,['actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1','actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02'])
 def test_06_actionlint_official_sha(self):self.assertIn('8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8',WORK.read_text())
 def test_07_source_script_is_shell(self):self.assertEqual(RUNNER.read_text().splitlines()[0],'#!/usr/bin/env bash')
 def test_08_not_auto_publish_yml(self):self.assertIn('NICHT IN .github/workflows/ HOCHLADEN',WORK.read_text())
 def test_09_no_plaintext_secrets_or_write(self):
  d=doc();self.assertEqual(d['permissions']['contents'],'read')
  self.assertNotIn('secrets.',WORK.read_text())
 def test_10_kernel_compilation_not_claimed(self):
  s=RUNNER.read_text();self.assertIn('R54_BUILD_ALLOWED=NO',s);self.assertIn('R54_FLASH_ALLOWED=NO',s)
 def test_11_old_tests_r41_executed(self):self.assertIn('verify_r41_source.py',RUNNER.read_text())
 def test_12_old_tests_r51_r52_executed(self):
  s=RUNNER.read_text();self.assertIn('R51_SELFTEST.py',s);self.assertIn('test_r52_native54.py',s);self.assertIn('test_r52_workflow.py',s)
 def test_13_new_workflow_R54_executed(self):self.assertIn('test_r54_gates.py',RUNNER.read_text())
 def test_14_reference_jack_midori_pinned(self):
  s=RUNNER.read_text();self.assertIn('bd505f994e255156e8233c399d6835641423bbf6',s);self.assertIn('a6d0fe36e51fe0136fe5733ca42f737d564e6f33',s)
 def test_15_real_bakasu_git_replay(self):self.assertIn('--local-port "$STAGE/bakasu-local" --upstream "$STAGE/bakasu-upstream"',RUNNER.read_text())
 def test_16_old_unflashed_kernel_not_reused_as_new(self):self.assertNotIn('VEUX_R13_CASS_KERNEL.zip',RUNNER.read_text())
 def test_17_bash_syntax(self):
  p=subprocess.run(['bash','-n',str(RUNNER)],capture_output=True,text=True);self.assertEqual(p.returncode,0,p.stderr)
 def test_18_shellcheck_from_pinned_r41_archive(self):
  from zipfile import ZipFile
  import hashlib
  archive=Path(os.environ.get('R54_R41','/mnt/data/files/VEUX_R41_NOMOUNT_SOURCE_MAIN.zip'))
  b=ZipFile(archive).read('r12/host-tools/shellcheck')
  self.assertEqual(hashlib.sha256(b).hexdigest(),'4da528ddb3a4d1b7b24a59d4e16eb2f5fd960f4bd9a3708a15baddbdf1d5a55b')
  with tempfile.TemporaryDirectory() as tmp:
   exe=Path(tmp)/'shellcheck';exe.write_bytes(b);exe.chmod(0o700)
   p=subprocess.run([str(exe),'--severity=warning',str(RUNNER)],capture_output=True,text=True)
   self.assertEqual(p.returncode,0,p.stdout+p.stderr)
 def test_19_refuse_outside_github(self):
  env=os.environ.copy();env.update(GITHUB_WORKSPACE=str(ROOT),RUNNER_TEMP='/tmp');env.pop('GITHUB_ACTIONS',None)
  p=subprocess.run(['bash',str(RUNNER)],env=env,capture_output=True,text=True)
  self.assertEqual(p.returncode,3);self.assertIn('NOT_GITHUB_RUNNER',p.stderr)
 def test_20_wrong_repository(self):
  env=os.environ.copy();env.update(GITHUB_WORKSPACE=str(ROOT),RUNNER_TEMP='/tmp',GITHUB_ACTIONS='true',RUNNER_OS='Linux',GITHUB_REPOSITORY='other/repo')
  p=subprocess.run(['bash',str(RUNNER)],env=env,capture_output=True,text=True)
  self.assertEqual(p.returncode,3);self.assertIn('WRONG_REPOSITORY',p.stderr)
 def test_21_four_inline_shell_blocks_valid(self):
  b=[x['run'] for x in doc()['jobs']['source_prebuild']['steps'] if 'run' in x]
  self.assertEqual(len(b),4)
  for script in b:
   p=subprocess.run(['bash','-n'],input=script,capture_output=True,text=True)
   self.assertEqual(p.returncode,0,p.stderr)
 def test_22_no_bad_zip_uploads(self):
  s=WORK.read_text();self.assertNotIn('/VEUX_R13_CASS_KERNEL.zip',s)
  self.assertIn('R54_*.json',s)
 def test_23_all_artifact_step_on_failure(self):
  self.assertEqual(doc()['jobs']['source_prebuild']['steps'][-1]['if'],'always()')
 def test_24_r13_r41_originals_exact(self):
  s=RUNNER.read_text();self.assertIn('15770d93410c01ed9ad149ffc82b93d54a3ea73e6c53a274bd767b249cc975c1',s)
  self.assertIn('e9ea57fc1feb8d4d0e840a61b21174ad1d83d496216794bd9285b40f17026bff',s)
if __name__=='__main__':unittest.main()
