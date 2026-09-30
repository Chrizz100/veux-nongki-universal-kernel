#!/usr/bin/env python3
"""Regression gates for mandatory driver fixes across update and replay paths."""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
import veux_device_fixes as f
import veux_release_device as d
import veux_release as r
import veux_update_engine as e
import test_veux_release as release_tests


class DeviceTests(unittest.TestCase):
    def fixture(self, root):
        repo = root / 'repo'
        folder = repo / f.PATCHSETS['5.4.274']
        folder.mkdir(parents=True)
        e.write_json(repo / 'common/update/source-recipes.json', e.config())
        src = root / 'source'
        work = root / 'work'
        work.mkdir()
        rows = []
        for i, name in enumerate(('bq2589x_charger.c', 'wt_chg.c')):
            rel = 'drivers/power/supply/qcom/' + name
            p = src / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text('original\n')
            patch = folder / (str(i) + '.patch')
            patch.write_text(f'--- a/{rel}\n+++ b/{rel}\n@@ -1 +1 @@\n-original\n+fixed\n')
            test = folder / (str(i) + '.py')
            test.write_text('import pathlib, sys\nassert pathlib.Path(sys.argv[1]).read_text() == "fixed\\n"\n')
            rows.append(dict(source=rel, patch=patch.name, test=test.name,
                before_sha256=e.digest(p), after_sha256=hashlib.sha256(b'fixed\n').hexdigest(),
                patch_sha256=e.digest(patch), test_sha256=e.digest(test)))
        (src / 'drivers/power/supply/qcom/bq2589x_reg.h').write_text('header\n')
        e.write_json(folder / 'manifest.json', dict(schema=1, id='fixture', kernel='5.4.274',
            recipe_blob=e.config()['lineages']['5.4.274']['blob'], reference_run='fixture', files=rows))
        return repo, src, work, folder, rows

    def test_real_manifest_preserves_exact_diag06_hashes_and_all_host_tests(self):
        proof = f.expected('5.4.274')[0]
        self.assertEqual(proof['id'], 'charger-diag06')
        self.assertEqual(proof['reference_run'], '36615353847')
        self.assertEqual(proof['source_sha256']['drivers/power/supply/qcom/bq2589x_charger.c'],
                         '0aa9b1516a8a5fa2efe30b4cc9be56c03d030f7282e1b7ef8066615c9172c241')
        self.assertEqual(proof['source_sha256']['drivers/power/supply/qcom/wt_chg.c'],
                         'e75f5c793d74311da59343eb46410563750b642e63fd70e1e1f2cabaad3d3e08')
        _, data, _ = f.load('5.4.274')
        diag05 = json.loads((e.REPO / 'common/device-fixes/5.4.274/charger-diag05/manifest.json').read_text())
        self.assertEqual(data['files'][0], diag05['files'][0])
        self.assertEqual(data['files'][1]['before_sha256'], diag05['files'][1]['before_sha256'])
        tests = {t['test']: t for row in data['files'] for t in f.host_tests(row)}
        self.assertEqual(set(tests), {'test_bq2589x.py', 'test_usb_voltage.py', 'test_i2c_callers.py', 'test_usb_type.py'})
        self.assertEqual(tests['test_usb_type.py']['test_sha256'],
                         '21de1bf28aaa03b79106a0f9517aded52b336b3d2b5f65ec2b4f6a48190e3459')
        self.assertEqual(tests['test_usb_type.py']['assets'], [{
            'file': 'usb_type_reference.h',
            'sha256': 'fe8b62b44b61bdeb0e618d3a53346a0c9bb77d36e30d08dc8c9dc22cf9f92146'}])
        self.assertEqual(tests['test_i2c_callers.py']['test_sha256'],
                         '400ac52e581c9f87ce33c474cccc2b38ad61b1c1a98e3e0dc7254c73140867d9')
        self.assertEqual(tests['test_i2c_callers.py']['assets'], [{
            'file': '0003-bq2589x-check-init-and-adapter-errors.patch',
            'sha256': '3575dc10c0d96ead626fdd1e555db16f402dadbff189f926569dd7e90cd705b2'}])

    def test_extra_tests_and_assets_are_required_before_driver_mutation(self):
        for mode in ('success', 'test_drift', 'asset_drift', 'host_failure',
                     'missing_asset', 'asset_path', 'asset_symlink'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                repo, src, work, folder, rows = self.fixture(Path(tmp))
                asset = folder / 'reference.patch'
                asset.write_text('reference\n')
                test = folder / 'extra.py'
                test.write_text('from pathlib import Path\nimport sys\n'
                    'assert Path(sys.argv[1]).read_text() == "fixed\\n"\n'
                    'assert Path(__file__).with_name("reference.patch").read_text() == "reference\\n"\n'
                    'print("EXTRA_TEST=PASS")\n')
                extra = dict(test=test.name, test_sha256=e.digest(test),
                    assets=[dict(file=asset.name, sha256=e.digest(asset))])
                if mode == 'test_drift':
                    test.write_text('print("tampered")\n')
                elif mode == 'asset_drift':
                    asset.write_text('tampered\n')
                elif mode == 'host_failure':
                    test.write_text('raise SystemExit(1)\n')
                    extra['test_sha256'] = e.digest(test)
                elif mode == 'missing_asset':
                    asset.unlink()
                elif mode == 'asset_path':
                    extra['assets'][0]['file'] = '../reference.patch'
                elif mode == 'asset_symlink':
                    asset.rename(asset.with_suffix('.backup'))
                    asset.symlink_to(asset.with_suffix('.backup').name)
                manifest = json.loads((folder / 'manifest.json').read_text())
                manifest['files'][1]['extra_tests'] = [extra]
                e.write_json(folder / 'manifest.json', manifest)
                before = [e.digest(src / row['source']) for row in rows]
                with mock.patch.object(e, 'REPO', repo):
                    if mode == 'success':
                        proof = f.apply(src, '5.4.274', work)
                        f.verify_source(src, '5.4.274', proof)
                        self.assertIn('EXTRA_TEST=PASS', (work / 'extra.py.log').read_text())
                    else:
                        with self.assertRaises((e.Blocked, subprocess.SubprocessError)):
                            f.apply(src, '5.4.274', work)
                        self.assertEqual([e.digest(src / row['source']) for row in rows], before)
                        self.assertFalse((work / 'DEVICE-FIXES.json').exists())

    def test_apply_and_repeat_accept_only_exact_postimages(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, src, work, _, rows = self.fixture(Path(tmp))
            with mock.patch.object(e, 'REPO', repo):
                proof = f.apply(src, '5.4.274', work)
                self.assertEqual(f.apply(src, '5.4.274', work), proof)
                f.verify_source(src, '5.4.274', proof)
                (src / rows[0]['source']).write_text('changed after compile\n')
                with self.assertRaisesRegex(e.Blocked, 'changed during build'):
                    f.verify_source(src, '5.4.274', proof)

    def test_source_payload_and_test_failures_leave_both_drivers_untouched(self):
        for mode in ('second_source', 'patch', 'test', 'postimage', 'host_failure', 'symlink'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                repo, src, work, folder, rows = self.fixture(Path(tmp))
                if mode == 'second_source':
                    (src / rows[1]['source']).write_text('unexpected\n')
                elif mode in ('patch', 'test'):
                    (folder / rows[1][mode]).write_text('tampered\n')
                elif mode == 'symlink':
                    p = src / rows[1]['source']
                    p.rename(p.with_suffix('.backup'))
                    p.symlink_to(p.with_suffix('.backup').name)
                else:
                    manifest = json.loads((folder / 'manifest.json').read_text())
                    if mode == 'postimage':
                        manifest['files'][1]['after_sha256'] = '0' * 64
                    else:
                        test = folder / rows[1]['test']
                        test.write_text('raise SystemExit(1)\n')
                        manifest['files'][1]['test_sha256'] = e.digest(test)
                    e.write_json(folder / 'manifest.json', manifest)
                before = [e.digest(src / row['source']) for row in rows]
                with mock.patch.object(e, 'REPO', repo), self.assertRaises((e.Blocked, subprocess.SubprocessError)):
                    f.apply(src, '5.4.274', work)
                self.assertEqual([e.digest(src / row['source']) for row in rows], before)

    def test_other_lineages_do_not_receive_274_driver_patches(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            for label in e.config()['lineages']:
                if label != '5.4.274':
                    self.assertEqual(f.apply(p, label, p), [])
            self.assertEqual(list(p.iterdir()), [])

    def test_both_integration_paths_require_fixes_before_compile(self):
        for replay in (True, False):
            for fail_fix in (True, False):
                with self.subTest(replay=replay, fail_fix=fail_fix), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    bundle = root / 'bundle'
                    bundle.mkdir()
                    targets = release_tests.ReleaseTests().targets()
                    targets.update(repository_sha=e.git(e.REPO, 'rev-parse', 'HEAD'),
                        golden_sha256=e.digest(e.REPO / e.config()['golden_contract']), lineages=['5.4.274'])
                    e.write_json(bundle / 'targets.json', targets)
                    args = argparse.Namespace(kernel='5.4.274', bundle=bundle, work=root/'builds/5.4.274',
                        public=root/'public/5.4.274', overlays=root/'overlays', jobs=1)
                    events = []
                    def materialize(label, work):
                        src = work / 'source'
                        release_tests.ReleaseTests().source(src)
                        return {'source': str(src)}
                    def apply(*unused):
                        events.append('fixes')
                        if fail_fix:
                            raise e.Blocked('injected driver drift')
                        return f.expected('5.4.274')
                    def compile(label, state, targets, work, jobs):
                        self.assertEqual(events, ['fixes', 'verified'])
                        events.append('compile')
                        image = work / 'Image'
                        image.write_bytes(b'kernel')
                        return image, dict(kernel=label, compile=True, image_sha256=e.digest(image))
                    def package(image, targets, result, work, public):
                        (public / 'kernel.zip').write_bytes(b'package')
                        result.update(package=True, package_file='kernel.zip')
                        e.write_json(public / 'PACKAGE-STATUS.json', result)
                    def boot(image, result, work):
                        p = work / 'static/boot.img'
                        p.parent.mkdir()
                        p.write_bytes(b'boot')
                        result.update(static_boot=True, static_boot_sha256=e.digest(p))
                    with ExitStack() as stack:
                        for obj, name, kwargs in [
                            (e, 'materialize', dict(side_effect=materialize)),
                            (e, 'prepare_dtb_reference', dict(return_value={})),
                            (r, 'replay_current', dict(return_value=replay)),
                            (e, 'apply_update', {}),
                            (f, 'apply', dict(side_effect=apply)),
                            (f, 'verify_source', dict(side_effect=lambda *a: events.append('verified'))),
                            (e, 'compile_kernel', dict(side_effect=compile)),
                            (e, 'package_kernel', dict(side_effect=package)),
                            (e, 'static_boot', dict(side_effect=boot))]:
                            stack.enter_context(mock.patch.object(obj, name, **kwargs))
                        if fail_fix:
                            with self.assertRaises(e.Blocked):
                                d.worker(args)
                            e.compile_kernel.assert_not_called()
                            self.assertFalse((args.public / 'RESULT.json').exists())
                        else:
                            d.worker(args)
                            self.assertEqual(events, ['fixes', 'verified', 'compile', 'verified'])
                            row = json.loads((args.public / 'RESULT.json').read_text())
                            self.assertEqual(row['device_fixes'], f.expected('5.4.274'))
                            self.assertFalse(row['device'])
                            self.assertEqual({p.name for p in args.public.iterdir()},
                                {'kernel.zip', row['boot_file'], 'RESULT.json', 'SHA256SUMS.txt'})
                        self.assertEqual(e.apply_update.call_count, 0 if replay else 1)
                    self.assertFalse(args.work.exists())

    def test_promotion_rejects_missing_or_old_fix_proof_before_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            e.write_json(root / 'bundle/targets.json', {'lineages': ['5.4.274']})
            args = argparse.Namespace(bundle=root/'bundle', artifacts=root/'artifacts')
            old_proofs = []
            for old_id in ('charger-diag04', 'charger-diag05'):
                old_manifest = e.REPO / f'common/device-fixes/5.4.274/{old_id}/manifest.json'
                old_data = json.loads(old_manifest.read_text())
                old_proofs.append([dict(id=old_data['id'], manifest_sha256=e.digest(old_manifest),
                    reference_run=old_data['reference_run'], host_tests=True,
                    source_sha256={row['source']: row['after_sha256'] for row in old_data['files']})])
            for proof in (None, [], *old_proofs, f.expected('5.4.274')):
                e.write_json(args.artifacts / '5.4.274/RESULT.json', {'device_fixes': proof})
                with mock.patch.object(r, 'promote') as promote:
                    if proof == f.expected('5.4.274'):
                        d.promote(args)
                        promote.assert_called_once_with(args)
                    else:
                        with self.assertRaises(e.Blocked):
                            d.promote(args)
                        promote.assert_not_called()

    def test_v4_uses_required_worker_and_promotion_and_preserves_legacy_scripts(self):
        workflow = e.yaml_read(e.REPO / '.github/workflows/veux-all-in-one-updater-v4.yml')
        steps = workflow['jobs']['update']['steps']
        run = '\n'.join(s.get('run', '') for s in steps)
        self.assertEqual(run.count('veux_release_device.py worker'), 6)
        self.assertEqual(run.count('veux_release_device.py promote'), 1)
        self.assertNotIn('veux_release.py worker', run)
        self.assertIn('test_veux_device_fixes.py', run)
        self.assertEqual(e.digest(e.REPO / 'common/scripts/veux_update_engine.py'),
                         '4f9ed7edfd19c802850039c654a5331f653d6fe07460c4680735534808b58b8d')
        self.assertEqual(e.digest(e.REPO / 'common/scripts/veux_release.py'),
                         'd8ab6d1724d25bc77b65e201eaac34d0f35bd0ac70b59b4eb822faa377c2a258')

    def test_real_promotion_retains_device_proof_in_current_build(self):
        expected = {label: f.expected(label) for label in e.config()['lineages']}
        with tempfile.TemporaryDirectory() as tmp:
            repo, targets, args = release_tests.ReleaseTests().fixture(Path(tmp))
            for label in targets['lineages']:
                path = args.artifacts / label / 'RESULT.json'
                row = json.loads(path.read_text())
                row['device_fixes'] = expected[label]
                e.write_json(path, row)
            with mock.patch.object(e, 'REPO', repo), \
                 mock.patch.object(e, 'check_repo', return_value=({'golden_contract': 'golden'}, {})), \
                 mock.patch.object(e, 'config', return_value={'golden_contract': 'golden'}), \
                 mock.patch.object(e, 'normalized_resukisu', side_effect=lambda donor, entry, dest: shutil.copytree(donor/'kernel', dest)), \
                 mock.patch.object(f, 'expected', side_effect=lambda label: expected[label]):
                d.promote(args)
            current = json.loads((repo / r.CURRENT).read_text())
            self.assertEqual(current['lineages']['5.4.274']['device_fixes'], expected['5.4.274'])
            self.assertFalse(current['device_pass_inferred'])


if __name__ == '__main__':
    unittest.main()
