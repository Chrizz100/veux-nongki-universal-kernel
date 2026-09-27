#!/usr/bin/env python3
"""Fail-closed checks for the shared engine; no network or kernel build claimed."""
import copy
import gzip
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import zipfile

sys.dont_write_bytecode = True
import veux_update_engine as e


class EngineTests(unittest.TestCase):
    def test_authenticated_avb_identical_duplicate_properties_are_preserved(self):
        info = ("Algorithm: NONE\nPartition Name: boot\nHash Algorithm: sha256\nSalt: abcdef\n"
                "Prop: com.android.build.boot.security_patch -> '2024-12-01'\n"
                "Prop: com.android.build.boot.security_patch -> '2024-12-01'\n")
        self.assertEqual(len(e.avb_metadata(info)["props"]), 2)
        with self.assertRaises(e.Blocked):
            e.avb_metadata(info + "Prop: com.android.build.boot.security_patch -> '2025-01-01'\n")

    def test_invisible_disabled_kconfig_children_are_valid(self):
        conf = ["CONFIG_KSU_SUSFS=y", "# CONFIG_KSU_MANUAL_HOOK is not set"]
        disabled = ["KSU_MANUAL_HOOK", "KSU_MANUAL_HOOK_AUTO_SETUID_HOOK"]
        e.validate_build_config(conf, ["KSU_SUSFS"], disabled)
        for value in ("y", "m"):
            with self.assertRaises(e.Blocked):
                e.validate_build_config(conf + ["CONFIG_KSU_MANUAL_HOOK_AUTO_SETUID_HOOK=" + value],
                                        ["KSU_SUSFS"], disabled)
        with self.assertRaises(e.Blocked):
            e.validate_build_config([], ["KSU_SUSFS"], disabled)

    def test_real_historical_vendor_checkout_uses_pinned_commit_and_history(self):
        recipe = e.config()["lineages"]["5.4.274"]
        doc = e.yaml_read(e.REPO / recipe["workflow"])
        steps = next(iter(doc["jobs"].values()))["steps"]
        opts = next(s["with"] for s in steps if s.get("name") == "Checkout exact VEUX vendor source")
        dest = Path("/unused-test-checkout")
        with mock.patch.object(e, "checkout") as checkout:
            e.source_checkout(opts, recipe, {}, {}, {}, dest)
            checkout.assert_called_once_with("https://github.com/dereference23/kernel_xiaomi_sm6375.git",
                                             "b2b7a3bbc36d120ee523ebc8d68e0f13a97df632", dest, full=True)
        with mock.patch.object(e, "checkout") as checkout:
            with self.assertRaises(e.Blocked):
                e.source_checkout(dict(opts, ref="unreviewed-tag"), recipe, {}, {}, {}, dest)
            checkout.assert_not_called()

    def test_real_legacy_susfs_migration_preserves_compatibility(self):
        fixture = e.REPO / "common/update/tests/susfs-legacy-source.json.gz"
        data = json.loads(gzip.decompress(fixture.read_bytes()))
        migration = e.config()["susfs_migration"]
        patch = e.REPO / migration["patch"]
        self.assertEqual(e.digest(patch), migration["patch_sha256"])
        with tempfile.TemporaryDirectory() as d:
            src = Path(d)
            for rel, text in data.items():
                p = src / rel; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(text)
            for rel, value in migration["legacy_sha256"].items():
                self.assertEqual(e.digest(src / rel), value)
            # A changed preimage must fail without any partial edits.
            bad = src / "fs/statfs.c"
            good = bad.read_text(); bad.write_text(good.replace("int vfs_get_fsid(", "int changed_vfs_get_fsid("))
            before = e.tree_hashes(src)
            with self.assertRaises(e.Blocked):
                e.run(["git", "apply", "--check", patch], cwd=src)
            self.assertEqual(e.tree_hashes(src), before)
            bad.write_text(good)
            e.run(["git", "apply", "--check", patch], cwd=src)
            e.run(["git", "apply", patch], cwd=src)
            c = (src / "fs/susfs.c").read_text()
            for name in ("susfs_open_redirect_spoof_vfs_readlink", "susfs_open_redirect_spoof_do_proc_readlink",
                         "susfs_open_redirect_spoof_vfs_statfs", "susfs_open_redirect_spoof_seq_show",
                         "susfs_get_enabled_features"):
                import re
                pattern = r"^(?:int|void) " + name + r"\([^;]+?\{.*?^}"
                self.assertEqual(re.search(pattern, c, re.M | re.S).group(),
                                 re.search(pattern, data["fs/susfs.c"], re.M | re.S).group())
            self.assertIn(".handle_event = susfs_handle_sdcard_inode_event", c)
            self.assertIn("DEFINE_SRCU(susfs_srcu_sus_path_loop)", c)
            stat = (src / "fs/stat.c").read_text()
            self.assertIn("is_fuse ? STATX_SUS_KSTAT_FUSE : STATX_SUS_KSTAT", stat)
            self.assertNotIn("stat->mnt_id", stat)
            self.assertNotIn("stat->result_mask |= STATX_SUS_KSTAT", stat)
            self.assertIn("susfs_sus_kstat_spoof_vfs_statfs", (src / "fs/statfs.c").read_text())

    def test_failure_still_checks_repository_integrity(self):
        doc = e.yaml_read(e.REPO / ".github/workflows/veux-all-in-one-updater-v3.yml")
        steps = doc["jobs"]["update"]["steps"]
        gate = next(s for s in steps if s["name"] == "Prove checkout and Golden remain unchanged")
        self.assertEqual(gate["if"], "always()")

    def test_real_relocated_statfs_delta_and_ambiguous_preimage(self):
        fixture = e.REPO / "common/update/tests/susfs-relocated-statfs.json.gz"
        data = json.loads(gzip.decompress(fixture.read_bytes()))
        old = e.patch_images(data["before"])["fs/statfs.c"]
        new = e.patch_images(data["after"])["fs/statfs.c"]
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "statfs.c"; p.write_text(data["source"])
            for a, b in zip(old, new):
                e.apply_host_delta(p, a["after"], b["after"])
            updated = p.read_text()
            self.assertIn("int calculate_f_flags_wrapper(struct vfsmount *mnt)", updated)
            self.assertIn("susfs_statfs_by_dentry(path->dentry, path->mnt, buf, &is_fuse)", updated)
            self.assertIn("EXPORT_SYMBOL(vfs_get_fsid);", updated)
            self.assertIn("buf->f_flags = calculate_f_flags(mnt);", updated)
            p.write_text("same\nsame\n")
            with self.assertRaises(e.Blocked):
                e.apply_host_delta(p, ["same\n"], ["changed\n"])
            self.assertEqual(p.read_text(), "same\nsame\n")

    def test_clang_archive_accepts_runner_temp_and_rejects_escape(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            env = {"VEUX_SOURCE_WORK": str(root / "source-work"),
                   "VEUX_TRANSPORT_WORK": str(root / "source-temp")}
            url = e.config()["toolchain_transport"]["url"]
            with mock.patch.dict(os.environ, env), mock.patch.object(e.subprocess, "run") as run:
                run.return_value.returncode = 0
                e.transport_curl([url, "-o", str(root / "source-temp/clang.tar.gz")])
                run.assert_called_once()
                run.reset_mock()
                with self.assertRaises(e.Blocked):
                    e.transport_curl([url, "-o", str(root / "outside.tar.gz")])
                run.assert_not_called()

    def test_repository_contracts(self):
        cfg, fleet = e.check_repo()
        self.assertEqual(len(fleet["lineages"]), 6)
        for row in cfg["lineages"].values():
            if "golden_transform" in row:
                t = row["golden_transform"]
                self.assertEqual(e.digest(e.REPO / t["path"]), t["sha256"])

    def test_yaml12_and_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.yml"
            p.write_text("on: yes\nflag: true\n")
            self.assertEqual(e.yaml_read(p), {"on": "yes", "flag": True})
            p.write_text("x: 1\nx: 2\n")
            with self.assertRaises(Exception):
                e.yaml_read(p)

    def test_shared_topology_rejects_divergent_mirror_and_escape(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "src"
            root = src / "KernelSU"
            (root / "kernel").mkdir(parents=True)
            (root / "uapi").mkdir()
            (root / "kernel/Kbuild").write_text("content\n")
            (root / "uapi/supercall.h").write_text("uapi\n")
            (src / "drivers").mkdir()
            link = src / "drivers/kernelsu"
            link.symlink_to("../KernelSU/kernel")
            self.assertEqual(e.topology(src)[0], root.resolve())
            link.unlink()
            link.mkdir()
            (link / "Kbuild").write_text("drift\n")
            with self.assertRaises(e.Blocked):
                e.topology(src)
            (link / "Kbuild").write_text("content\n")
            self.assertEqual(e.topology(src)[1], [link])
            (link / "Kbuild").unlink(); link.rmdir()
            link.symlink_to(Path(d))
            with self.assertRaises(e.Blocked):
                e.topology(src)

    def test_three_way_merge_preserves_local_compat_and_blocks_conflicts(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            p = root / "host.c"
            base = b"first\nsecond\nthird\nfourth\nfifth\n"
            local = base.replace(b"first", b"local compat")
            target = base.replace(b"fifth", b"upstream")
            p.write_bytes(local)
            e.merge_file(p, base, target, root)
            self.assertIn(b"local compat", p.read_bytes())
            self.assertIn(b"upstream", p.read_bytes())
            p.write_bytes(local)
            with self.assertRaises(e.Blocked):
                e.merge_file(p, base, base.replace(b"first", b"conflict"), root)
            self.assertEqual(p.read_bytes(), local)

    def test_make_boundary_stops_before_compile(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            capture = root / "capture.json"
            env = dict(os.environ, VEUX_CAPTURE=str(capture), VEUX_SOURCE_WORK=str(root),
                       SECRET_TOKEN="must-not-be-captured")
            p = subprocess.Popen([sys.executable, str(e.HERE), "capture-make", "--", "-C", str(root),
                                  "O=out", "ARCH=arm64", "-j2", "Image", "dtbs"], env=env, start_new_session=True)
            try:
                end = time.monotonic() + 10
                while not capture.exists() and p.poll() is None and time.monotonic() < end:
                    time.sleep(0.02)
                self.assertTrue(capture.exists())
                data = json.loads(capture.read_text())
                self.assertEqual(data["source"], str(root))
                self.assertEqual(data["targets"], ["Image", "dtbs"])
                self.assertNotIn("SECRET_TOKEN", data["env"])
                self.assertNotIn("must-not-be-captured", capture.read_text())
            finally:
                if p.poll() is None:
                    os.killpg(p.pid, signal.SIGKILL)
                p.wait()

    def test_make_argument_unknown_option_blocks(self):
        with self.assertRaises(e.Blocked):
            e.make_parts(["--eval=unexpected", "Image"], Path.cwd())

    def test_normalization_real_stable_snapshot(self):
        with tempfile.TemporaryDirectory() as d:
            entry = {"local_version": 4470, "version": "35170", "tag": "v4.1.0",
                     "commit": "9be0f347f38e790c846915bd5f9c24b337f85c4e", "ref": "refs/heads/main"}
            stage = e.normalized_resukisu(e.REPO / "third_party/resukisu", entry, Path(d) / "stage")
            self.assertIn("KSU_VERSION := 35170", (stage / "kernel/Kbuild").read_text())
            self.assertFalse((stage / "kernel/feature/module_load_filter.c").exists())

    def test_all_source_workflow_shells_parse(self):
        # Legacy workflow blobs are pinned; validate their literal Bash before replay.
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "step.sh"
            for row in e.config()["lineages"].values():
                doc = e.yaml_read(e.REPO / row["workflow"])
                for job in doc["jobs"].values():
                    for step in job["steps"]:
                        if "run" in step:
                            path.write_text(step["run"])
                            e.run(["bash", "-n", path])

    def test_promotion_refuses_missing_duplicate_tampered_and_device_claim(self):
        cfg, _ = e.check_repo()
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); bundle = root / "bundle"; bundle.mkdir()
            targets = {"repository_sha": e.git(e.REPO, "rev-parse", "HEAD"),
                       "golden_sha256": e.digest(e.REPO / cfg["golden_contract"]),
                       "lineages": sorted(cfg["lineages"]), "components": {}}
            e.write_json(bundle / "targets.json", targets)
            arts = root / "artifacts"; arts.mkdir()
            with self.assertRaises(e.Blocked):
                e.prepare_promotion(bundle, arts, root / "out")
            for label in targets["lineages"]:
                dest = arts / label; dest.mkdir()
                package = dest / "kernel.zip"
                with zipfile.ZipFile(package, "w") as z:
                    z.writestr("Image", b"test-only-evidence")
                image = dest / "image-for-hash"; image.write_bytes(b"test-only-evidence")
                row = {"kernel": label, "repository_sha": targets["repository_sha"], "targets": {},
                       "target_manifest_sha256": e.digest(bundle / "targets.json"),
                       "compile": True, "package": True, "static_boot": True, "device": False,
                       "package_file": "kernel.zip", "package_sha256": e.digest(package), "image_sha256": e.digest(image)}
                e.write_json(dest / "RESULT.json", row)
            first = arts / targets["lineages"][0] / "RESULT.json"
            good = json.loads(first.read_text())
            for key, value in (("device", True), ("static_boot", False), ("repository_sha", "bad"), ("package_sha256", "bad")):
                bad = copy.deepcopy(good); bad[key] = value; e.write_json(first, bad)
                with self.assertRaises(e.Blocked, msg=key):
                    e.prepare_promotion(bundle, arts, root / "out")
            e.write_json(first, good)
            dup = arts / "duplicate"; dup.mkdir(); e.write_json(dup / "RESULT.json", good)
            with self.assertRaises(e.Blocked):
                e.prepare_promotion(bundle, arts, root / "out")


if __name__ == "__main__":
    unittest.main(verbosity=2)
