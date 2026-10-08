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
                         c.reference_report()['actual_config_sha256'])

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


class SemanticConfigProofTests(unittest.TestCase):
    """Exercise the live proof and release boundary without kernel compilation."""

    @staticmethod
    def report(text="# host fixture\n"):
        import hashlib
        report = c.reference_report()
        digest = hashlib.sha256(text.encode()).hexdigest()
        report.update(actual_config_sha256=digest, embedded_config_sha256=digest)
        return report

    @staticmethod
    def row(report):
        return {"config_audit": report, "config_compat": c.expected_proof(report)}

    def test_comments_and_new_build_digests_are_not_a_historical_lock(self):
        for text in ("# ReSukiSU\nCONFIG_IKCONFIG=y\n",
                     "# BakaSU\nCONFIG_IKCONFIG=y\n",
                     "# next build\nCONFIG_IKCONFIG=y\n"):
            with self.subTest(text=text):
                report = self.report(text)
                row = self.row(report)
                self.assertEqual(row["config_compat"]["actual_config_sha256"],
                                 report["actual_config_sha256"])
                c.verify_result("5.4.274", row)

    def test_semantic_gate_does_not_modify_or_share_input_objects(self):
        import copy
        report = self.report()
        before = copy.deepcopy(report)
        proof = c.expected_proof(report)
        self.assertEqual(report, before)
        proof["actual_config_sha256"] = "0" * 64
        self.assertEqual(report, before)
        self.assertEqual(c.expected_proof(), c.expected_proof(c.reference_report()))

    def test_invalid_or_mismatched_current_build_digests_are_rejected(self):
        for value in (None, "", "x" * 64, "0" * 63, "0" * 65, 0, [], {}):
            report = self.report()
            report.update(actual_config_sha256=value, embedded_config_sha256=value)
            with self.subTest(digest=value), self.assertRaises(e.Blocked):
                c.expected_proof(report)
        report = self.report()
        report["embedded_config_sha256"] = "0" * 64
        with self.assertRaises(e.Blocked):
            c.expected_proof(report)

    def test_required_configuration_settings_are_still_enforced(self):
        for name, wanted in c.reference_report()["options"].items():
            for wrong in (None, "n" if wanted == "y" else "y", "m"):
                report = self.report()
                if wrong is None:
                    del report["options"][name]
                else:
                    report["options"][name] = wrong
                with self.subTest(option=name, value=wrong), self.assertRaises(e.Blocked):
                    c.expected_proof(report)

    def test_rom_and_security_failures_are_not_converted_into_success(self):
        for key, values in {
            "status": ["FAIL", None], "id": ["other", None],
            "configuration_unchanged_during_compile": [False, None, 1],
            "cfi": ["disabled", None], "stack_protector": ["disabled", None],
            "device": [True, None, 0], "options": [None, []],
        }.items():
            for value in values:
                report = self.report()
                report[key] = value
                with self.subTest(field=key, value=value), self.assertRaises(e.Blocked):
                    c.expected_proof(report)
        for key, value in (("status", "FAIL"), ("requirements", 260),
                           ("passed", 260), ("passed", "261"),
                           ("failures", ["missing requirement"]), ("failures", None)):
            report = self.report()
            report["vintf_kernel"][key] = value
            with self.subTest(rom_field=key), self.assertRaises(e.Blocked):
                c.expected_proof(report)
        for report in (None, [], {}, {"status": "PASS"}):
            with self.subTest(report=report), self.assertRaises(e.Blocked):
                c.expected_proof(report) if report is not None else c._proof_from_report(report)

    def test_release_proof_cannot_be_reused_for_a_different_config(self):
        import copy
        row = self.row(self.report("one"))
        for key in ("config_audit", "config_compat"):
            bad = copy.deepcopy(row)
            del bad[key]
            with self.subTest(missing=key), self.assertRaises(e.Blocked):
                c.verify_result("5.4.274", bad)
        bad = copy.deepcopy(row)
        bad["config_audit"] = self.report("two")
        with self.assertRaises(e.Blocked):
            c.verify_result("5.4.274", bad)
        for key, value in (("actual_config_sha256", "0" * 64),
                           ("device_pass_inferred", True), ("rom_requirements", 260)):
            bad = copy.deepcopy(row)
            bad["config_compat"][key] = value
            with self.subTest(proof_field=key), self.assertRaises(e.Blocked):
                c.verify_result("5.4.274", bad)

    def test_compile_wrapper_and_final_verifier_share_the_same_dynamic_proof(self):
        from contextlib import nullcontext
        from types import SimpleNamespace
        report = self.report("# dynamically generated config\n")
        result = {"kernel": "5.4.274", "config_audit": report, "device": False}
        auditor = SimpleNamespace(compiler_audit=lambda path: nullcontext())
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder)
            with mock.patch.object(c, "_load_audit", return_value=auditor), \
                 mock.patch.object(e, "compile_kernel", return_value=("image", result)):
                image, actual = c.compile_kernel("5.4.274", {}, {}, work, 1)
            self.assertEqual(image, "image")
            self.assertEqual(actual["config_compat"], c.expected_proof(report))
            self.assertTrue((work / "build-result.json").is_file())
            c.verify_result("5.4.274", actual)

    def test_other_five_lineages_do_not_acquire_a_274_config_lock(self):
        for label in ("5.4.292", "5.4.293", "5.4.300", "5.4.301", "5.4.302"):
            with self.subTest(label=label), mock.patch.object(e, "compile_kernel",
                     return_value=("image", {"kernel": label})) as engine:
                self.assertEqual(c.compile_kernel(label, {}, {}, Path("/unused"), 1),
                                 ("image", {"kernel": label}))
                engine.assert_called_once_with(label, {}, {}, Path("/unused"), 1)
                c.verify_result(label, {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
