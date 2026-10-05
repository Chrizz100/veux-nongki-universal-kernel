#!/usr/bin/env python3
"""Regression checks for fixed repair inputs; no network or kernel compilation."""
import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

import veux_frozen_components as f


class FrozenComponentsTests(unittest.TestCase):
    def setUp(self):
        self.cfg = f.e.config()
        self.lock = f.load_contract(self.cfg)

    def test_reference_is_exact_flashed_run_and_only_274(self):
        self.assertEqual(self.lock['reference_run'], 37206832975)
        self.assertEqual(self.lock['kernel'], '5.4.274')
        self.assertEqual(self.lock['components']['resukisu']['version'], '35203')
        self.assertEqual(self.lock['components']['resukisu']['uapi'], 5)
        self.assertFalse(self.lock['device_pass_inferred'])

    def test_changed_lock_rejected_before_any_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / f.CONTRACT
            target.parent.mkdir(parents=True)
            changed = copy.deepcopy(self.lock)
            changed['components']['resukisu']['commit'] = 'a' * 40
            target.write_text(json.dumps(changed))
            with mock.patch.object(f.e, 'REPO', root), mock.patch.object(f.e, 'checkout') as checkout:
                with self.assertRaisesRegex(f.e.Blocked, 'lock changed'):
                    f.load_contract(self.cfg)
                checkout.assert_not_called()

    def test_new_kernel_recipe_rejected(self):
        cfg = copy.deepcopy(self.cfg)
        cfg['lineages']['5.4.274']['blob'] = 'b' * 40
        with self.assertRaisesRegex(f.e.Blocked, 'source recipe changed'):
            f.load_contract(cfg)

    def test_resolve_checks_out_exact_commits_without_head_resolution(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / 'bundle'
            with mock.patch.object(f.e, 'check_repo', return_value=(self.cfg, {})), \
                 mock.patch.object(f.e, 'git', return_value='c' * 40) as git, \
                 mock.patch.object(f.e, 'checkout') as checkout, \
                 mock.patch.object(f, 'verify_donor') as verify:
                result = f.resolve(work)
                self.assertEqual(result['components'], self.lock['components'])
                self.assertEqual(result['lineages'], ['5.4.274'])
                self.assertEqual(json.loads((work / 'targets.json').read_text()), result)
                self.assertEqual(checkout.call_args_list, [
                    mock.call(entry['url'], entry['commit'], work / name, full=True)
                    for name in f.e.COMPONENTS for entry in [self.lock['components'][name]]])
                self.assertEqual(verify.call_count, 3)
                git.assert_called_once_with(f.e.REPO, 'rev-parse', 'HEAD')

    def test_failed_checkout_never_publishes_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / 'bundle'
            with mock.patch.object(f.e, 'check_repo', return_value=(self.cfg, {})), \
                 mock.patch.object(f.e, 'git', return_value='c' * 40), \
                 mock.patch.object(f.e, 'checkout', side_effect=f.e.Blocked('fetch failed')):
                with self.assertRaises(f.e.Blocked):
                    f.resolve(work)
                self.assertFalse((work / 'targets.json').exists())

    def test_existing_work_directory_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(f.e, 'check_repo', return_value=(self.cfg, {})), \
                 mock.patch.object(f.e, 'checkout') as checkout:
                with self.assertRaises(FileExistsError):
                    f.resolve(Path(tmp))
                checkout.assert_not_called()

    def fake_git(self, entry, bad=None):
        def git(_root, *args):
            if args == ('rev-parse', 'HEAD'):
                return 'd' * 40 if bad == 'commit' else entry['commit']
            if args == ('status', '--porcelain'):
                return ' M changed' if bad == 'dirty' else ''
            if args[0] == 'merge-base':
                if bad == 'ancestry':
                    raise f.e.Blocked('unrelated ancestry')
                return ''
            if args[0] == 'rev-list':
                return str(entry['ahead'] if '..' in args[-1] else entry['local_version'])
            raise AssertionError(args)
        return git

    def test_wrong_checkout_dirty_source_or_ancestry_rejected(self):
        entry = self.lock['components']['susfs']
        for bad in ('commit', 'dirty', 'ancestry'):
            with self.subTest(bad=bad), mock.patch.object(f.e, 'git', side_effect=self.fake_git(entry, bad)):
                with self.assertRaises(f.e.Blocked):
                    f.verify_donor('susfs', Path('/unused'), entry)

    def test_susfs_and_nomount_versions_checked(self):
        for name, rel, macro, prefix in (
            ('susfs', 'kernel_patches/include/linux/susfs.h', 'SUSFS_VERSION', 'v'),
            ('nomount', 'kernel/src/nomount.h', 'NOMOUNT_VERSION', ''),
        ):
            entry = self.lock['components'][name]
            with self.subTest(component=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                header = root / rel
                header.parent.mkdir(parents=True)
                with mock.patch.object(f.e, 'git', side_effect=self.fake_git(entry)):
                    header.write_text('#define ' + macro + ' "' + prefix + entry['version'] + '"\n')
                    f.verify_donor(name, root, entry)
                    header.write_text('#define ' + macro + ' "999"\n')
                    with self.assertRaisesRegex(f.e.Blocked, 'version mismatch'):
                        f.verify_donor(name, root, entry)

    def test_resukisu_runs_existing_uapi5_actual_c_gate(self):
        entry = self.lock['components']['resukisu']
        ref = f.e.REPO / 'common/upstream/resukisu/uapi5'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'uapi').mkdir()
            (root / 'kernel/supercall').mkdir(parents=True)
            shutil.copy2(ref / 'supercall.h', root / 'uapi/supercall.h')
            (root / 'kernel/supercall/dispatch.c').write_text(
                (ref / 'report_event.c').read_text() + '\nstatic int do_set_sepolicy(void *arg) {}\n')
            (root / 'kernel/Kbuild').write_text('expr 30000 + $(KSU_LOCAL_VERSION) + 700\n')
            with mock.patch.object(f.e, 'git', side_effect=self.fake_git(entry)):
                f.verify_donor('resukisu', root, entry)
                wrong = dict(entry, version='35204')
                with self.assertRaisesRegex(f.e.Blocked, 'version mismatch'):
                    f.verify_donor('resukisu', root, wrong)

    def test_workflow_default_is_checks_only_and_no_promotion(self):
        path = f.e.REPO / '.github/workflows/VEUX_Basis_Stabilisierung_R1.yml'
        doc = f.e.yaml_read(path)
        self.assertFalse(doc['on']['workflow_dispatch']['inputs']['build_kernel']['default'])
        self.assertEqual(doc['permissions'], {'contents': 'read'})
        condition = doc['jobs']['kernel']['if']
        self.assertIn("github.event_name == 'workflow_dispatch'", condition)
        self.assertIn('inputs.build_kernel', condition)
        text = path.read_text()
        self.assertNotIn('veux_current_components.py --work', text)
        kernel_text = '\n'.join(step.get('run', '') for step in doc['jobs']['kernel']['steps'])
        self.assertNotIn('git push', kernel_text)
        self.assertNotIn(' promote ', kernel_text)
        self.assertEqual(set(doc['on']), {'workflow_dispatch'})
        self.assertEqual(doc['jobs']['kernel']['steps'][0]['with']['ref'],
                         '${{ needs.checks.outputs.commit }}')
        self.assertIn('veux_frozen_components.py resolve', text)
        self.assertIn('veux_release_device.py worker', text)
        self.assertIn('veux_frozen_components.py verify-result', text)
        uploads = [step for step in doc['jobs']['kernel']['steps']
                   if step.get('uses', '').startswith('actions/upload-artifact@')]
        self.assertEqual(len(uploads), 2)
        self.assertTrue(uploads[0]['with']['path'].endswith('/*_AnyKernel.zip'))
        self.assertEqual(uploads[1]['if'], 'failure()')

    def test_build_result_rejects_changed_components_and_inferred_device_pass(self):
        import veux_config_compat as compat
        import veux_device_fixes as fixes
        import veux_rpm_fixes as rpm
        import veux_wakeup_fixes as wakeup
        for case in ('good', 'component', 'kernel', 'device', 'build', 'manifest', 'repo'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                bundle = root / 'bundle'
                public = root / 'public'
                bundle.mkdir()
                public.mkdir()
                targets = {'components': self.lock['components'], 'lineages': ['5.4.274'],
                           'component_lock': {'sha256': f.CONTRACT_SHA256},
                           'repository_sha': 'c' * 40}
                f.e.write_json(bundle / 'targets.json', targets)
                row = {'targets': copy.deepcopy(targets['components']), 'kernel': '5.4.274',
                       'repository_sha': 'c' * 40, 'device': False, 'compile': True,
                       'package': True, 'static_boot': True, 'device_fixes': ['expected'],
                       'target_manifest_sha256': f.e.digest(bundle / 'targets.json')}
                if case == 'component': row['targets']['resukisu']['commit'] = 'd' * 40
                if case == 'kernel': row['kernel'] = '5.4.292'
                if case == 'device': row['device'] = True
                if case == 'build': row['static_boot'] = False
                if case == 'manifest': row['target_manifest_sha256'] = '0' * 64
                if case == 'repo': row['repository_sha'] = 'd' * 40
                f.e.write_json(public / 'RESULT.json', row)
                with mock.patch.object(f.e, 'check_repo', return_value=(self.cfg, {})), \
                     mock.patch.object(f.e, 'git', return_value='c' * 40), \
                     mock.patch.object(compat, 'verify_result') as config_gate, \
                     mock.patch.object(fixes, 'expected', return_value=['expected']), \
                     mock.patch.object(rpm, 'verify_result') as rpm_gate, \
                     mock.patch.object(wakeup, 'verify_result') as wakeup_gate:
                    if case == 'good':
                        f.verify_result(public, bundle)
                        config_gate.assert_called_once()
                        rpm_gate.assert_called_once()
                        wakeup_gate.assert_called_once()
                    else:
                        with self.assertRaises(f.e.Blocked):
                            f.verify_result(public, bundle)


if __name__ == '__main__':
    unittest.main()
