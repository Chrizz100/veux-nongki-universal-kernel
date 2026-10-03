"""Regression tests for the isolated SWEET repository layout (no network)."""
from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO / 'common/scripts/sweet'))
import audit


class LayoutTests(unittest.TestCase):
    def test_repository_root_is_resolved_from_script(self):
        self.assertEqual(audit.REPO, REPO)

    def test_device_reference_is_sweet_only(self):
        self.assertEqual(audit.DEVICE_REFERENCE, REPO/'device/sweet/reference')
        self.assertTrue((audit.DEVICE_REFERENCE/'stock.config').is_file())

    def test_source_lock_is_in_sweet_lineage(self):
        self.assertEqual(audit.SOURCE_LOCK, REPO/'lineages/sweet/source_lock.json')
        self.assertEqual(set(json.loads(audit.SOURCE_LOCK.read_text())['sources']),
                         {'sweet-r-oss','sweet_k6a-r-oss'})

    def test_oem_references_have_fixed_paths(self):
        for branch in ('sweet-r-oss','sweet_k6a-r-oss'):
            self.assertTrue((audit.OEM_REFERENCE/f'{branch}.defconfig').is_file())

    def test_sweet_not_selected_by_existing_veux_glob(self):
        # The read VEUX discovery code uses exactly this one-level pattern.
        selected = list(REPO.glob('lineages/*/build.yml'))
        self.assertNotIn(REPO/'lineages/sweet/build.yml', selected)
        self.assertFalse((REPO/'lineages/sweet/build.yml').exists())

    def test_no_old_reference_paths_in_active_program(self):
        text=(REPO/'common/scripts/sweet/audit.py').read_text()
        self.assertNotIn('sweet-oem-audit/reference',text)
        self.assertNotIn('device/veux',text)
        self.assertNotIn('source-recipes.json',text)

    def test_import_and_reference_read_from_unrelated_cwd(self):
        with tempfile.TemporaryDirectory() as td:
            code=("import sys;from pathlib import Path;"
                  f"sys.path.insert(0,{str(REPO/'common/scripts/sweet')!r});"
                  "import audit;assert audit.SOURCE_LOCK.is_file();"
                  "assert (audit.DEVICE_REFERENCE/'stock.config').is_file()")
            p=subprocess.run([sys.executable,'-B','-c',code],cwd=td,
                             capture_output=True,text=True,timeout=20)
            self.assertEqual(p.returncode,0,p.stderr)

    def test_cli_help_needs_no_kernel_checkout(self):
        p=subprocess.run([sys.executable,'-B',str(REPO/'common/scripts/sweet/audit.py'),'--help'],
                         capture_output=True,text=True,timeout=20)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn('--branch',p.stdout)


if __name__=='__main__':
    unittest.main()
