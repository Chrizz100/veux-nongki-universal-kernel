"""R4.2: fail-closed OEM side-effect classification and real Git worktree tests."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO/'common/scripts/sweet'))
import audit


class SourceMutationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='sweet-r42-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base/'source'; self.source.mkdir()
        self.log = self.base/'commands.log'
        self.git('init', '-q')
        self.git('config', 'user.name', 'Local source audit')
        self.git('config', 'user.email', 'audit@example.invalid')
        self.git('config', 'core.filemode', 'true')
        (self.source/'include/dum').mkdir(parents=True)
        (self.source/'include/linux').mkdir(parents=True)
        for name in ('ktrace','rtmm'):
            (self.source/f'include/dum/{name}.h').write_text('/* fixture only */\n')
        (self.source/'kernel.c').write_text('int original;\n')
        (self.source/'.gitignore').write_text('*.ignored\n')
        self.git('add', '.'); self.git('commit', '-qm', 'local fixture')

    def git(self,*args):
        return subprocess.check_output(['git','-C',str(self.source),*args],stderr=subprocess.STDOUT).decode().strip()

    def generated(self):
        for name in audit.OEM_EMPTY_STUBS:
            path = self.source/name; path.parent.mkdir(parents=True,exist_ok=True); path.touch()
        for name,target in audit.OEM_HEADER_LINKS.items():
            (self.source/name).symlink_to(self.source/target)

    def state(self,pin=audit.K6A_STUB_COMMIT):
        return audit.workspace_state(self.source,pin)

    def test_clean_source_passes(self):
        self.assertTrue(audit.workspace_state(self.source)['passed'])

    def test_exact_six_oem_outputs_pass(self):
        self.generated(); state=self.state()
        self.assertTrue(state['passed']); self.assertEqual(len(state['accepted_oem_generated']),6)

    def test_r41_nonempty_status_reproduced(self):
        self.generated()
        self.assertTrue(self.git('status','--porcelain'))
        self.assertTrue(self.state()['passed'])

    def test_old_pin_rejects_oem_outputs(self):
        self.generated(); self.assertFalse(self.state('758bb7ef50af360e728662a1ed3b3a1b977a2f13')['passed'])

    def test_unknown_pin_rejects_oem_outputs(self):
        self.generated(); self.assertFalse(self.state('0'*40)['passed'])

    def test_pristine_policy_rejects_any_generated(self):
        self.generated(); self.assertFalse(audit.workspace_state(self.source)['passed'])

    def test_unknown_extra_rejected(self):
        self.generated(); (self.source/'rogue.c').write_text('new\n')
        self.assertFalse(self.state()['passed'])

    def test_git_ignored_extra_also_rejected(self):
        (self.source/'rogue.ignored').write_text('new\n')
        self.assertFalse(self.git('status','--porcelain'))
        self.assertFalse(self.state()['passed'])

    def test_tracked_change_rejected(self):
        self.generated(); (self.source/'kernel.c').write_text('altered\n')
        self.assertFalse(self.state()['passed'])

    def test_staged_change_rejected(self):
        (self.source/'kernel.c').write_text('altered\n');self.git('add','kernel.c')
        self.assertFalse(self.state()['passed'])

    def test_mode_change_rejected(self):
        (self.source/'kernel.c').chmod(0o755)
        self.assertFalse(self.state()['passed'])

    def test_wrong_symlink_target_rejected(self):
        self.generated(); p=self.source/'include/linux/rtmm.h'; p.unlink();p.symlink_to('/etc/passwd')
        self.assertFalse(self.state()['passed'])

    def test_relative_instead_of_exact_oem_link_rejected(self):
        self.generated(); p=self.source/'include/linux/rtmm.h'; p.unlink();p.symlink_to('../dum/rtmm.h')
        self.assertFalse(self.state()['passed'])

    def test_header_regular_file_rejected(self):
        self.generated();p=self.source/'include/linux/rtmm.h';p.unlink();p.write_text('')
        self.assertFalse(self.state()['passed'])

    def test_nonempty_stub_rejected(self):
        self.generated();(self.source/audit.OEM_EMPTY_STUBS[0]).write_text('config UNEXPECTED\n')
        self.assertFalse(self.state()['passed'])

    def test_symlink_instead_of_empty_stub_rejected(self):
        self.generated();p=self.source/audit.OEM_EMPTY_STUBS[0];p.unlink();p.symlink_to(self.source/'kernel.c')
        self.assertFalse(self.state()['passed'])

    def test_incomplete_generation_rejected(self):
        self.generated();(self.source/audit.OEM_EMPTY_STUBS[0]).unlink()
        self.assertFalse(self.state()['passed'])

    def test_changed_target_header_rejected(self):
        self.generated();(self.source/'include/dum/rtmm.h').write_text('changed\n')
        self.assertFalse(self.state()['passed'])

    def test_workspace_is_isolated(self):
        tree=self.git('rev-parse','HEAD^{tree}');ref=self.git('rev-parse','HEAD');work=self.base/'derived'
        audit.create_kconfig_workspace(self.source,work,ref,self.log)
        (work/'extra.c').write_text('only in derived\n')
        self.assertTrue(audit.workspace_state(self.source)['passed'])
        self.assertFalse(audit.workspace_state(work)['passed'])
        self.assertEqual(self.git('rev-parse','HEAD^{tree}'),tree)

    def test_existing_workspace_refused(self):
        work=self.base/'derived';work.mkdir()
        with self.assertRaises(FileExistsError):
            audit.create_kconfig_workspace(self.source,work,'HEAD',self.log)

    def test_workspace_inside_source_refused(self):
        with self.assertRaises(ValueError):
            audit.create_kconfig_workspace(self.source,self.source/'derived','HEAD',self.log)

    def test_dirty_source_refused_before_worktree(self):
        (self.source/'extra.c').write_text('dirty')
        with self.assertRaises(ValueError):
            audit.create_kconfig_workspace(self.source,self.base/'derived','HEAD',self.log)

    def test_classifier_does_not_modify_files(self):
        self.generated(); before=self.git('status','--porcelain','--untracked-files=all')
        first=self.state();second=self.state()
        self.assertEqual(first,second);self.assertEqual(before,self.git('status','--porcelain','--untracked-files=all'))


class WorkflowRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text=(REPO/'.github/workflows/sweet-oem-source-audit.yml').read_text()

    def test_runner_not_in_job_env(self):
        block=self.text.split('    env:\n',1)[1].split('    defaults:',1)[0]
        self.assertNotIn('runner.',block)

    def test_step_env_paths_retained(self):
        self.assertIn('          AUDIT_WORK: ${{ runner.temp }}/sweet-oem-audit',self.text)
        self.assertIn('          AUDIT_OUT: ${{ runner.temp }}/sweet-audit-artifacts',self.text)

    def test_node24_pins_and_archive_mode(self):
        self.assertIn('actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09',self.text)
        self.assertIn('actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a',self.text)
        self.assertIn('          archive: true',self.text)

    def test_no_error_suppression(self):
        self.assertNotIn('continue-on-error',self.text)
        self.assertNotIn('ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION',self.text)
        self.assertIn('  contents: read',self.text)

    def test_workflow_in_sparse_checkout_for_regression_tests(self):
        self.assertIn('            /.github/workflows/sweet-oem-source-audit.yml',self.text)


if __name__=='__main__':
    unittest.main()
