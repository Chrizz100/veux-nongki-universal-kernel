import hashlib
import os
from pathlib import Path
import subprocess
import unittest
import yaml

ROOT=Path(__file__).resolve().parents[2]
SHELL=ROOT/'tools/r52/R52_GITHUB_SOURCE_STAGE_NOFLASH.sh'
WORK=ROOT/'R52_WORKFLOW_ENTWURF_NICHT_FREIGEGEBEN.txt'

class Strict(yaml.BaseLoader):
 def construct_mapping(self,node,deep=False):
  result={}
  for keynode,valnode in node.value:
   key=self.construct_object(keynode,deep=deep)
   if key in result:raise ValueError('DUPLICATE_YAML_KEY:'+key)
   result[key]=self.construct_object(valnode,deep=deep)
  return result

def doc():return yaml.load(WORK.read_text(),Loader=Strict)

class Workflow(unittest.TestCase):
 def test_01_yaml_unique_keys(self):self.assertIn('jobs',doc())
 def test_02_workflow_manual_only(self):
  d=doc();self.assertEqual(list(d['on']),['workflow_dispatch'])
 def test_03_github_read_only(self):
  self.assertEqual(doc()['permissions'],{'contents':'read'})
 def test_04_only_approved_main_branch(self):
  self.assertIn('refs/heads/main',doc()['jobs']['source_staging']['if'])
  self.assertIn('Chrizz100/veux-nongki-universal-kernel',doc()['jobs']['source_staging']['if'])
 def test_05_pinned_actions(self):
  acts=[x['uses'] for x in doc()['jobs']['source_staging']['steps'] if 'uses' in x]
  self.assertEqual(acts,['actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1','actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02'])
 def test_06_exact_r41_sha(self):
  self.assertIn('e9ea57fc1feb8d4d0e840a61b21174ad1d83d496216794bd9285b40f17026bff',WORK.read_text())
 def test_07_official_actionlint_not_unproven(self):
  self.assertIn('8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8',WORK.read_text())
  self.assertIn('NICHT IN .github/workflows/ HOCHLADEN',WORK.read_text())
 def test_08_no_build_or_flash_commands(self):
  text=SHELL.read_text().lower()
  for pattern in ('mkbootimg ', 'fastboot flash', 'dd if=', 'insmod ', 'modprobe ', 'anykernel.sh ', 'mkfs.'):
   self.assertNotIn(pattern,text)
 def test_09_nonrunner_refusal(self):
  env=os.environ.copy();env['GITHUB_WORKSPACE']=str(ROOT)
  env['RUNNER_TEMP']='/tmp';env.pop('GITHUB_ACTIONS',None)
  p=subprocess.run(['bash',str(SHELL)],env=env,capture_output=True,text=True)
  self.assertEqual(p.returncode,3)
  self.assertIn('NON_GITHUB_RUNNER',p.stderr)
 def test_10_wrong_repo_refusal(self):
  env=os.environ.copy();env.update(GITHUB_WORKSPACE=str(ROOT),RUNNER_TEMP='/tmp',
     GITHUB_ACTIONS='true',RUNNER_OS='Linux',GITHUB_REPOSITORY='other/repo')
  p=subprocess.run(['bash',str(SHELL)],env=env,capture_output=True,text=True)
  self.assertEqual(p.returncode,3)
  self.assertIn('WRONG_REPOSITORY',p.stderr)
 def test_11_wrong_branch_refusal(self):
  env=os.environ.copy();env.update(GITHUB_WORKSPACE=str(ROOT),RUNNER_TEMP='/tmp',
     GITHUB_ACTIONS='true',RUNNER_OS='Linux',GITHUB_REPOSITORY='Chrizz100/veux-nongki-universal-kernel',GITHUB_REF='refs/heads/bad')
  p=subprocess.run(['bash',str(SHELL)],env=env,capture_output=True,text=True)
  self.assertEqual(p.returncode,3)
  self.assertIn('WRONG_REF',p.stderr)
 def test_12_no_autobuild(self):
  self.assertTrue(all(x['shell']=='bash' for x in doc()['jobs']['source_staging']['steps'] if 'run' in x))
  self.assertIn('source',doc()['jobs']['source_staging']['name'].lower())
 def test_13_early_sha_guard(self):
  src=SHELL.read_text()
  self.assertLess(src.index('sha256sum -c --strict'),src.index('git clone'))
 def test_14_fail_closed_remote_heads(self):
  src=SHELL.read_text()
  self.assertIn('SUSFS_HEAD_ADVANCED_REVIEW_REQUIRED',src)
  self.assertIn('BAKASU_HEAD_ADVANCED_REVIEW_REQUIRED',src)
 def test_15_invariant_build_gate(self):
  src=SHELL.read_text()
  self.assertIn('[[ "$rc" -eq 2 ]]',src)
  self.assertIn('R52_KERNEL_BUILD_ALLOWED=NO',src)
  self.assertIn('R52_FLASH_ALLOWED=NO',src)
 def test_16_no_automatic_credentials(self):
  d=doc()
  self.assertEqual(d['jobs']['source_staging']['steps'][0]['with']['persist-credentials'],'false')
 def test_17_branch_guard_below_stage(self):
  src=SHELL.read_text()
  self.assertLess(src.index('WRONG_REF'),src.index('mktemp -d'))
 def test_18_no_yaml_released(self):
  self.assertTrue(WORK.name.endswith('.txt'))

if __name__=='__main__':unittest.main(verbosity=2)
