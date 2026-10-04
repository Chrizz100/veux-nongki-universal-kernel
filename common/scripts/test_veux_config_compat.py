#!/usr/bin/env python3
"""Regression gates for permanent VEUX 5.4.274 ConfigDiag10 integration."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import veux_config_compat as c
import veux_update_engine as e


class CompatTests(unittest.TestCase):
    def test_assets_are_exact_successful_diag10_payloads(self):
        manifest = c.authenticate()
        self.assertEqual(manifest["id"], "ConfigDiag10")
        self.assertEqual(manifest["source_commit"],
                         "b2b7a3bbc36d120ee523ebc8d68e0f13a97df632")
        self.assertEqual(manifest["regular_patchset"], "charger-diag08")
        self.assertEqual(c.expected_proof()["reference_run"], "36738661110")
        self.assertEqual(c.expected_proof()["actual_config_sha256"],
                         "5904f8d2439e2cb05ef3db7edbe653d269e070b0e28d7e131a44600d61bab229")

    def test_exact_diag10_host_tests_pass(self):
        env = dict(os.environ)
        scripts = str(e.REPO / "common/scripts")
        env["PYTHONPATH"] = scripts + (os.pathsep + env["PYTHONPATH"]
                                      if env.get("PYTHONPATH") else "")
        for name in ("test_vintf_kernel.py", "test_sched_debug.py",
                     "test_config_audit.py"):
            result = subprocess.run(
                [sys.executable, str(c.ROOT / name)],
                cwd=c.ROOT, env=env, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.assertEqual(result.returncode, 0,
                             name + " failed:\n" + result.stdout)

    def test_other_lineages_use_unchanged_shared_compile(self):
        for label in ("5.4.292", "5.4.293", "5.4.300", "5.4.301", "5.4.302"):
            with self.subTest(kernel=label),                  mock.patch.object(e, "compile_kernel",
                                   return_value=("image", {"kernel": label})) as base:
                self.assertEqual(
                    c.compile_kernel(label, {}, {}, Path("/unused"), 1),
                    ("image", {"kernel": label}))
                base.assert_called_once()

    def test_promotion_proof_is_fail_closed(self):
        good = {
            "config_compat": c.expected_proof(),
            "config_audit": c.reference_report(),
        }
        c.verify_result("5.4.274", good)
        c.verify_result("5.4.292", {})
        for key in ("config_compat", "config_audit"):
            bad = dict(good)
            bad.pop(key)
            with self.subTest(missing=key), self.assertRaises(e.Blocked):
                c.verify_result("5.4.274", bad)
        wrong = dict(good)
        wrong["config_compat"] = dict(c.expected_proof(),
                                      actual_config_sha256="0" * 64)
        with self.assertRaises(e.Blocked):
            c.verify_result("5.4.274", wrong)


if __name__ == "__main__":
    unittest.main(verbosity=2)
