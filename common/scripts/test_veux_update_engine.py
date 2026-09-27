#!/usr/bin/env python3
"""Fail-closed checks for the shared engine; no network or kernel build claimed."""
import copy
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile

sys.dont_write_bytecode = True
import veux_update_engine as e


class EngineTests(unittest.TestCase):
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
