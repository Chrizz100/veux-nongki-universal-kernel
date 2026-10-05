#!/usr/bin/env python3
"""RPM error propagation, authenticated payload and release-gate regressions."""
import argparse
import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
import veux_rpm_fixes as rpm
import veux_wakeup_fixes as wakeup
import veux_device_fixes as fixes
import veux_config_compat as compat
import veux_release_device as device
import veux_release as release
import veux_update_engine as e


class RPMTests(unittest.TestCase):
    def fixture(self, root):
        folder, data, _ = rpm.load()
        repo, source, work = root / 'repo', root / 'source', root / 'work'
        payload = repo / rpm.PAYLOAD
        shutil.copytree(folder, payload)
        e.write_json(repo / 'common/update/source-recipes.json', e.config())
        target = source / data['source']
        target.parent.mkdir(parents=True)
        shutil.copy2(folder / 'sources/rpm-custom.c', target)
        work.mkdir()
        return repo, source, work, payload, target, data

    def test_real_patch_and_22_actual_c_cases_pass_on_first_and_repeat_apply(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, source, work, _, target, data = self.fixture(Path(tmp))
            with mock.patch.object(e, 'REPO', repo):
                proof = rpm.apply(source, '5.4.274', work)
                self.assertEqual(e.digest(target), data['after_sha256'])
                self.assertEqual(rpm.apply(source, '5.4.274', work), proof)
                rpm.verify_source(source, '5.4.274', proof)
                self.assertEqual(json.loads((work / 'RPM-FIXES.json').read_text()), proof)
                self.assertIn('CASES=22; REPRODUCED_FAILURE_CASES=11',
                              (work / 'rpm-host-tests.log').read_text())
                self.assertFalse(proof[0]['device_pass_inferred'])
                target.write_bytes(target.read_bytes() + b'\n/* changed by compile */\n')
                with self.assertRaisesRegex(e.Blocked, 'changed during build'):
                    rpm.verify_source(source, '5.4.274', proof)

    def test_payload_manifest_and_source_drift_block_before_source_mutation(self):
        modes = ('source', 'manifest', 'patch', 'test', 'reference', 'missing_asset',
                 'source_symlink', 'source_parent_symlink', 'asset_symlink', 'recipe')
        for mode in modes:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                repo, source, work, folder, target, data = self.fixture(Path(tmp))
                if mode == 'source':
                    target.write_text('unreviewed upstream source\n')
                elif mode == 'manifest':
                    p = folder / 'manifest.json'
                    p.write_bytes(p.read_bytes() + b'\n')
                elif mode in ('patch', 'test', 'reference'):
                    name = 'sources/system_pm_rpm.c' if mode == 'reference' else data[mode]
                    (folder / name).write_text('changed\n')
                elif mode == 'missing_asset':
                    (folder / data['patch']).unlink()
                elif mode in ('source_symlink', 'asset_symlink'):
                    p = target if mode == 'source_symlink' else folder / data['patch']
                    p.rename(p.with_suffix('.backup'))
                    p.symlink_to(p.with_suffix('.backup').name)
                elif mode == 'source_parent_symlink':
                    p = target.parent
                    p.rename(p.with_name('linked-backup'))
                    p.symlink_to('linked-backup', target_is_directory=True)
                elif mode == 'recipe':
                    config = e.config()
                    config['lineages']['5.4.274']['blob'] = '0' * 40
                    e.write_json(repo / 'common/update/source-recipes.json', config)
                before = target.read_bytes()
                with mock.patch.object(e, 'REPO', repo), self.assertRaises(e.Blocked):
                    rpm.apply(source, '5.4.274', work)
                self.assertEqual(target.read_bytes(), before)
                self.assertFalse((work / 'RPM-FIXES.json').exists())

    def test_host_failure_blocks_before_source_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, source, work, _, target, _ = self.fixture(Path(tmp))
            original_run, before = e.run, target.read_bytes()
            def run(command, **kwargs):
                if any(str(x).endswith('test_rpm_sleep.py') for x in command):
                    raise subprocess.CalledProcessError(1, command)
                return original_run(command, **kwargs)
            with mock.patch.object(e, 'REPO', repo), mock.patch.object(e, 'run', side_effect=run):
                with self.assertRaises(subprocess.CalledProcessError):
                    rpm.apply(source, '5.4.274', work)
            self.assertEqual(target.read_bytes(), before)
            self.assertFalse((work / 'RPM-FIXES.json').exists())

    def test_host_test_rejects_unfixed_input(self):
        folder, data, _ = rpm.load()
        result = subprocess.run(['python3', str(folder / data['test']),
                                 str(folder / 'sources/rpm-custom.c')], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('differs from reviewed correction', result.stderr)

    def test_other_five_lineages_are_unmodified(self):
        labels = set(e.config()['lineages']) - {'5.4.274'}
        self.assertEqual(labels, {'5.4.292', '5.4.293', '5.4.300', '5.4.301', '5.4.302'})
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for label in labels:
                self.assertEqual(rpm.apply(root, label, root), [])
                rpm.verify_source(root, label, [])
                rpm.verify_result(label, {})
                with self.assertRaises(e.Blocked):
                    rpm.verify_result(label, {'rpm_fixes': [{'id': 'wrong-lineage'}]})
            self.assertEqual(list(root.iterdir()), [])

    def test_missing_or_forged_proof_blocks_promotion_before_mutation(self):
        expected = rpm.expected('5.4.274')
        forged = copy.deepcopy(expected)
        forged[0]['source_sha256']['drivers/rpmsg/rpm-smd.c'] = '0' * 64
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            e.write_json(root / 'bundle/targets.json', {'lineages': ['5.4.274']})
            args = argparse.Namespace(bundle=root / 'bundle', artifacts=root / 'artifacts')
            for proof in (None, [], forged, expected):
                row = {'device_fixes': fixes.expected('5.4.274'),
                       'wakeup_fixes': wakeup.expected('5.4.274'),
                       'wakeup_linked_symbols': ['wakeup_reason_init', 'last_resume_reason_show', 'last_suspend_time_show'],
                       'config_compat': compat.expected_proof(),
                       'config_audit': compat.reference_report()}
                if proof is not None:
                    row['rpm_fixes'] = proof
                e.write_json(args.artifacts / '5.4.274/RESULT.json', row)
                with mock.patch.object(release, 'promote') as promote:
                    if proof == expected:
                        device.promote(args)
                        promote.assert_called_once_with(args)
                    else:
                        with self.assertRaisesRegex(e.Blocked, 'RPM fix proof'):
                            device.promote(args)
                        promote.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
