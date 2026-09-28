#!/usr/bin/env python3
"""Regression checks for source drift and diagnostic publication gates."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import veux_charger_diagnostic as d
import veux_update_engine as e


class ChargerTests(unittest.TestCase):
    def fixture(self, root):
        repo, src = root / 'repo', root / 'source'
        repo.mkdir()
        src.mkdir()
        e.git(src, 'init', '-q')
        target = src / 'drivers/power/supply/qcom/bq2589x_charger.c'
        target.parent.mkdir(parents=True)
        before, after = b'context\nremove\nend\n', b'context\nend\n'
        target.write_bytes(before)
        rel = target.relative_to(src).as_posix()
        patch = repo / 'change.patch'
        patch.write_text(f'--- a/{rel}\n+++ b/{rel}\n@@ -1,3 +1,2 @@\n context\n-remove\n end\n')
        spec = {'path': patch.name, 'sha256': e.digest(patch), 'source': rel,
                'before_sha256': hashlib.sha256(before).hexdigest(),
                'after_sha256': hashlib.sha256(after).hexdigest(),
                'added_lines': 0, 'removed_lines': 1}
        return repo, src, target, patch, {'patch': spec}

    def test_patch_applies_only_to_exact_preimage_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, src, target, _, contract = self.fixture(Path(tmp))
            with mock.patch.object(e, 'REPO', repo):
                proof = d.apply_diagnostic(src, contract)
                self.assertTrue(proof['applied'])
                self.assertEqual(target.read_bytes(), b'context\nend\n')
                with self.assertRaisesRegex(e.Blocked, 'preimage'):
                    d.apply_diagnostic(src, contract)

    def test_patch_or_source_drift_blocks_before_writing(self):
        for tamper in ('patch', 'source', 'scope'):
            with self.subTest(tamper=tamper), tempfile.TemporaryDirectory() as tmp:
                repo, src, target, patch, contract = self.fixture(Path(tmp))
                if tamper == 'patch':
                    patch.write_text(patch.read_text() + '\n')
                elif tamper == 'source':
                    target.write_bytes(b'changed\n')
                else:
                    contract['patch']['removed_lines'] = 2
                before = target.read_bytes()
                with mock.patch.object(e, 'REPO', repo), self.assertRaises(e.Blocked):
                    d.apply_diagnostic(src, contract)
                self.assertEqual(target.read_bytes(), before)

    def test_source_may_not_escape_build_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, src, target, _, contract = self.fixture(Path(tmp))
            external = repo / 'external.c'
            external.write_bytes(target.read_bytes())
            target.unlink()
            target.symlink_to(external)
            with mock.patch.object(e, 'REPO', repo), self.assertRaises(e.Blocked):
                d.apply_diagnostic(src, contract)
            self.assertEqual(external.read_bytes(), b'context\nremove\nend\n')

    def test_real_contract_authenticates_and_pins_components(self):
        contract, targets = d.authenticate()
        self.assertEqual(targets['lineages'], ['5.4.274'])
        self.assertEqual(targets['components']['resukisu']['version'], '35184')
        self.assertEqual(contract['patch']['removed_lines'], 5)
        altered = copy.deepcopy(contract)
        altered['components']['resukisu']['commit'] = '0' * 40
        original = Path.read_text

        def read(path, *args, **kwargs):
            if path == e.REPO / d.CONTRACT:
                return json.dumps(altered)
            return original(path, *args, **kwargs)

        with mock.patch.object(Path, 'read_text', read), self.assertRaisesRegex(e.Blocked, 'component drift'):
            d.authenticate()

    def test_no_package_published_after_compile_or_static_failure(self):
        contract, targets = d.authenticate()
        for failing_gate in ('compile_kernel', 'static_boot'):
            with self.subTest(gate=failing_gate), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                work, public, diag = (root / name for name in ('work', 'public', 'diagnostics'))
                row = {'kernel': '5.4.274'}
                def package(image, targets, result, stage, candidate):
                    (candidate / 'test_AnyKernel.zip').write_bytes(b'not validated')
                with mock.patch.object(d, 'authenticate', return_value=(contract, targets)), \
                     mock.patch.object(d, 'verify_checkout'), \
                     mock.patch.object(e, 'materialize', return_value={'source': str(work / 'source')}), \
                     mock.patch.object(e, 'prepare_dtb_reference', return_value={}), \
                     mock.patch.object(d.r, 'replay_current', return_value=True), \
                     mock.patch.object(d, 'apply_diagnostic', return_value={}), \
                     mock.patch.object(e, 'compile_kernel', return_value=(work / 'Image', row)), \
                     mock.patch.object(e, 'package_kernel', side_effect=package), \
                     mock.patch.object(e, failing_gate, side_effect=e.Blocked('gate rejected')):
                    with self.assertRaisesRegex(e.Blocked, 'gate rejected'):
                        d.build(work, public, diag, 2)
                self.assertFalse(public.exists())
                self.assertIn('gate rejected', (diag / 'BLOCKED.json').read_text())

    def test_existing_or_overlapping_output_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(e.Blocked, 'disjoint'):
                d.build(root / 'work', root / 'work/public', root / 'diag', 1)
            (root / 'public').mkdir()
            with self.assertRaisesRegex(e.Blocked, 'must be new'):
                d.build(root / 'work', root / 'public', root / 'diag', 1)


if __name__ == '__main__':
    unittest.main()
