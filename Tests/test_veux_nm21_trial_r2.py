#!/usr/bin/env python3
"""Offline fail-closed checks for the isolated VEUX NoMount21 source trial."""
from __future__ import annotations

from pathlib import Path
import json
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "common/scripts"))

# The standalone ZIP can run without the full repository. When uploaded to the
# real repo, import the actual engine and resolver rather than dummy modules.
if not (ROOT / "common/scripts/veux_update_engine.py").is_file():
    m = types.ModuleType("veux_update_engine")
    m.Blocked = RuntimeError
    sys.modules["veux_update_engine"] = m
    sys.modules["veux_current_components"] = types.ModuleType("veux_current_components")

import veux_nm21_trial_r2 as trial

PROTOCOL = '''
enum {
  NM_CMD_UNSPEC = 0,
  NM_CMD_GET_VERSION,
  NM_CMD_ADD_RULE,
  NM_CMD_DEL_RULE,
  NM_CMD_ADD_UID,
  NM_CMD_DEL_UID,
  NM_CMD_CLEAR_ALL,
  NM_CMD_CLEAR_RULES,
  NM_CMD_CLEAR_UIDS,
  NM_CMD_GET_LIST,
  NM_CMD_GET_UIDS,
  NM_CMD_BLOCK_ISOLATED_UIDS,
  NM_CMD_GET_ISOLATED_STATE,
};
struct nm_payload {
    u64 magic;
    u32 cmd;
    u32 target_uid;
    int status;
    u32 arg1;
    u32 data_size;
    char buffer[4068];
} __attribute__((packed));
struct nm_rule_hdr {
    u32 flags;
    u32 uid;
    u16 v_len;
    u16 r_len;
} __attribute__((packed));
struct nm_del_hdr {
    u32 uid;
    u16 v_len;
} __attribute__((packed));
'''


class IsolatedTrialTests(unittest.TestCase):
    def fixtures(self):
        old = '#define NOMOUNT_VERSION "20"\n' + PROTOCOL
        new = ('#define NOMOUNT_BASE_VERSION "21"\n'
               '#ifdef NOMOUNT_COMMIT_COUNT\n'
               '#define NOMOUNT_VERSION NOMOUNT_BASE_VERSION "-" NOMOUNT_COMMIT_COUNT\n'
               '#endif\n' + PROTOCOL)
        return old, new

    def test_wire_abi_unmodified_when_only_version_scheme_changes(self):
        old, new = self.fixtures()
        result = trial.abi_guard(old, new)
        self.assertEqual(set(result), {"enum", "nm_payload", "nm_rule_hdr", "nm_del_hdr"})
        self.assertEqual(set(result.values()), {"IDENTICAL"})

    def test_rejects_wire_payload_change(self):
        old, new = self.fixtures()
        with self.assertRaisesRegex(trial.TrialBlocked, "wire-protocol changed: nm_payload"):
            trial.abi_guard(old, new.replace("buffer[4068]", "buffer[4000]"))

    def test_rejects_wire_opcode_change(self):
        old, new = self.fixtures()
        with self.assertRaisesRegex(trial.TrialBlocked, "wire-protocol changed: enum"):
            trial.abi_guard(old, new.replace("NM_CMD_CLEAR_UIDS,", "NM_CMD_CLEAR_UIDS = 99,"))

    def test_rejects_wrong_versions(self):
        old, new = self.fixtures()
        with self.assertRaises(trial.TrialBlocked):
            trial.abi_guard(old.replace('"20"', '"21"'), new)
        with self.assertRaises(trial.TrialBlocked):
            trial.abi_guard(old, new.replace('"21"', '"22"'))

    def test_accepts_internal_symlink_chain(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "uapi").mkdir()
            (root / "uapi/supercall.h").write_text("header")
            (root / "kernel/include").mkdir(parents=True)
            (root / "kernel/include/uapi").symlink_to("../../uapi")
            (root / "next").symlink_to("kernel/include/uapi")
            links = trial.check_symlinks(root)
            self.assertEqual({x["path"] for x in links}, {"kernel/include/uapi", "next"})

    def test_rejects_escaping_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "src"
            root.mkdir()
            (Path(d) / "outside").write_text("untrusted")
            (root / "escape").symlink_to("../outside")
            with self.assertRaisesRegex(trial.TrialBlocked, "escapes source"):
                trial.check_symlinks(root)

    def test_rejects_absolute_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "absolute").symlink_to("/etc/passwd")
            with self.assertRaisesRegex(trial.TrialBlocked, "absolute upstream"):
                trial.check_symlinks(root)

    def test_rejects_broken_and_cyclic_symlinks(self):
        for target in ("missing", "link"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                (root / "link").symlink_to(target)
                with self.assertRaisesRegex(trial.TrialBlocked, "broken or cyclic"):
                    trial.check_symlinks(root)

    def test_workflow_precreated_empty_report_directory_is_allowed(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            checkout = base / "checkout"
            checkout.mkdir()
            work = base / "runner-temp" / "veux-nm21-r2"
            report = work / "report"
            report.mkdir(parents=True)
            self.assertEqual(trial.initialize_workspace(checkout, work), work.resolve())
            self.assertTrue(report.is_dir())
            self.assertEqual(list(report.iterdir()), [])

    def test_empty_new_workspace_is_allowed(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            checkout = base / "checkout"
            checkout.mkdir()
            work = base / "runner-temp" / "new"
            self.assertEqual(trial.initialize_workspace(checkout, work), work.resolve())
            self.assertTrue(work.is_dir())

    def test_existing_report_directory_receives_failure_diagnostics(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            checkout = base / "checkout"
            checkout.mkdir()
            work = base / "work"
            (work / "report").mkdir(parents=True)
            with mock.patch.object(trial, "check_project_identity",
                                   side_effect=trial.TrialBlocked("expected test failure")):
                with self.assertRaisesRegex(trial.TrialBlocked, "expected test failure"):
                    trial.prepare(checkout, work)
            report = json.loads((work / "report" / "NOMOUNT21_R2.json").read_text())
            self.assertEqual(report["status"], "BLOCKED")
            self.assertEqual(report["reason"], "expected test failure")
            self.assertFalse(report["repository_written"])
            self.assertFalse(report["can_flash"])

    def test_unexpected_workspace_content_remains_blocked(self):
        for kind in ("file", "directory", "report_file", "report_subdir"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                base = Path(temp)
                checkout = base / "checkout"
                checkout.mkdir()
                work = base / "work"
                work.mkdir()
                if kind == "file":
                    (work / "targets.json").write_text("stale")
                elif kind == "directory":
                    (work / "bundle").mkdir()
                elif kind == "report_file":
                    (work / "report").mkdir()
                    (work / "report" / "old.json").write_text("stale")
                else:
                    (work / "report" / "nested").mkdir(parents=True)
                with self.assertRaises(trial.TrialBlocked):
                    trial.initialize_workspace(checkout, work)

    def test_workspace_symlinks_and_nested_checkout_remain_blocked(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            checkout = base / "checkout"
            checkout.mkdir()
            existing = base / "outside"
            existing.mkdir()
            linked_root = base / "linked-root"
            linked_root.symlink_to(existing, target_is_directory=True)
            with self.assertRaisesRegex(trial.TrialBlocked, "workspace symlink"):
                trial.initialize_workspace(checkout, linked_root)
            work = base / "work"
            work.mkdir()
            (work / "report").symlink_to(existing, target_is_directory=True)
            with self.assertRaisesRegex(trial.TrialBlocked, "unsafe pre-created report"):
                trial.initialize_workspace(checkout, work)
            with self.assertRaisesRegex(trial.TrialBlocked, "OUTSIDE repository"):
                trial.initialize_workspace(checkout, checkout / "temp")

    def test_frozen_component_contract_is_required(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / ".git").mkdir()
            (root / "common/scripts").mkdir(parents=True)
            (root / "common/contracts").mkdir(parents=True)
            (root / "common/scripts/veux_update_engine.py").write_text("fake test source")
            targets = {}
            for name, sha in trial.EXPECTED_INTEGRATED.items():
                targets[name] = {"commit": sha, "url": f"https://example.org/{name}.git",
                                 "ref": "refs/heads/main", "version": "20" if name == "nomount" else "1"}
            targets["resukisu"]["uapi"] = 5
            contract = {"status": "compile-package-static-validated", "device_pass_inferred": False,
                        "targets": targets,
                        "lineages": {k: {"targets": targets} for k in trial.LINEAGES}}
            contract_path = root / "common/contracts/CURRENT_BUILD.json"
            with mock.patch.object(trial, "file_git_blob", return_value=trial.EXPECTED_ENGINE_GIT_BLOB):
                contract_path.write_text(json.dumps(contract))
                trial.validate_contract(root)
                contract["targets"]["nomount"]["commit"] = "0" * 40
                contract_path.write_text(json.dumps(contract))
                with self.assertRaisesRegex(trial.TrialBlocked, "integrated nomount changed"):
                    trial.validate_contract(root)
                contract["targets"]["nomount"]["commit"] = trial.EXPECTED_INTEGRATED["nomount"]
                contract["device_pass_inferred"] = True
                contract_path.write_text(json.dumps(contract))
                with self.assertRaisesRegex(trial.TrialBlocked, "device-pass"):
                    trial.validate_contract(root)

    def test_remote_ref_identity_cannot_be_ambiguous_or_malformed(self):
        valid = trial.PINNED_NOMOUNT21 + "\trefs/heads/master"
        with mock.patch.object(trial, "command", return_value=valid):
            self.assertEqual(trial.tracked_head("https://example.org/nomount", "refs/heads/master"),
                             trial.PINNED_NOMOUNT21)
        for value in ("", valid + "\n" + valid, "notasha\trefs/heads/master", valid.replace("master", "dev")):
            with self.subTest(value=value), mock.patch.object(trial, "command", return_value=value):
                with self.assertRaises(trial.TrialBlocked):
                    trial.tracked_head("https://example.org/nomount", "refs/heads/master")

    def test_complete_manifest_declares_only_one_kernel_for_trial(self):
        self.assertEqual(trial.KERNEL, "5.4.274")
        self.assertEqual(trial.EXPECTED_INTEGRATED["resukisu"],
                         "8770c7e324a22895703c4916b8a16520e0b81c79")
        self.assertEqual(trial.PINNED_NOMOUNT21,
                         "1ded61dc908c511072162fa0bee44e6ccdb7b4c7")


if __name__ == "__main__":
    unittest.main(verbosity=2)
