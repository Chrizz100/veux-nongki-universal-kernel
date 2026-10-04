#!/usr/bin/env python3
"""Verify that raw evidence survives cleanup on successful and failed builds."""
from pathlib import Path
import shutil
import tempfile
import unittest
import veux_release_device as device


class RetentionTests(unittest.TestCase):
    def test_full_and_partial_evidence_survives_cleanup(self):
        for failed in (False, True):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); work = root / 'work'; public = root / 'public'; diag = root / 'diag'
                public.mkdir(); work.mkdir()
                evidence = {'config-reports/actual-build.config': b'CONFIG_KSU=y\n',
                            'config-reports/final-build.config': b'CONFIG_KSU=y\n',
                            'build/.config': b'CONFIG_KSU=y\n',
                            'compile.log': b'compiler evidence\n'}
                if failed:
                    evidence['BLOCKED.json'] = b'{"reason":"compile failure"}'
                else:
                    evidence.update({'config-reports/CONFIG-AUDIT.json': b'{"status":"PASS"}',
                                     'build/Module.symvers': b'0x1234 symbol kernel EXPORT_SYMBOL\n',
                                     'build/System.map': b'ffff T symbol\n',
                                     'static/AVB-VERIFY.txt': b'Successfully verified footer\n',
                                     'static/unpack-raw.log': b'boot header\n'})
                for name, content in evidence.items():
                    path = work / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(content)
                (work / 'source').mkdir(); (work / 'source/secret.env').write_text('do not archive source environment')
                device.preserve_device_diagnostics(work, public, diag)
                shutil.rmtree(work)
                for name, content in evidence.items():
                    self.assertEqual((diag / name).read_bytes(), content)
                self.assertFalse((diag / 'source').exists())

    def test_linked_report_is_not_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); work = root / 'work'; public = root / 'public'; diag = root / 'diag'
            (work / 'config-reports').mkdir(parents=True); public.mkdir()
            outside = root / 'outside'; outside.write_text('outside')
            (work / 'config-reports/linked').symlink_to(outside)
            with self.assertRaises(device.e.Blocked):
                device.preserve_device_diagnostics(work, public, diag)
            self.assertTrue(work.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
