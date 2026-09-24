#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, sys
from pathlib import Path
import yaml

COMPONENTS = {
    "resukisu": {
        "version": "35170",
        "commit": "9be0f347f38e790c846915bd5f9c24b337f85c4e",
        "required": [
            "kernel/Kbuild",
            "kernel/Kconfig",
            "kernel/Makefile",
            "uapi/ksu.h",
        ],
    },
    "susfs": {
        "version": "2.3.0",
        "commit": "04a9d713106191ba98be680bd7ad9547ab1de964",
        "required": [
            "kernel_patches/fs/susfs.c",
            "kernel_patches/include/linux/susfs.h",
            "kernel_patches/include/linux/susfs_def.h",
            "kernel_patches/KernelSU/10_enable_susfs_for_ksu.patch",
        ],
    },
    "nomount": {
        "version": "2.0.0",
        "commit": "b8d268353b4e7ecc53c67d1816a626b7d6579201",
        "required": [
            "kernel/src/Kconfig",
            "kernel/src/Makefile",
            "kernel/src/nomount.c",
            "kernel/src/nomount.h",
        ],
    },
}

def die(msg: str) -> None:
    print(f"LOCAL_SNAPSHOT_ERROR: {msg}", file=sys.stderr)
    raise SystemExit(1)

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def parse_sums(path: Path) -> dict[str, str]:
    out = {}
    for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        parts = raw.split(None, 1)
        if len(parts) != 2 or len(parts[0]) != 64:
            die(f"{path}:{n}: malformed checksum line")
        rel = parts[1].lstrip("*").strip()
        if rel in out:
            die(f"{path}:{n}: duplicate checksum path {rel}")
        out[rel] = parts[0].lower()
    if not out:
        die(f"{path}: empty checksum list")
    return out

def check_component(root: Path, name: str, spec: dict) -> None:
    base = root / "third_party" / name
    if not base.is_dir():
        die(f"missing snapshot directory: {base}")

    prov = base / "_VEUX_SOURCE.yml"
    sums = base / "SHA256SUMS.txt"
    if not prov.is_file() or not sums.is_file():
        die(f"{name}: provenance/checksum files missing")

    p = yaml.safe_load(prov.read_text(encoding="utf-8"))
    if not isinstance(p, dict):
        die(f"{name}: invalid provenance yaml")
    if str(p.get("component")) != name:
        die(f"{name}: provenance component mismatch")
    if str(p.get("version")) != spec["version"]:
        die(f"{name}: version mismatch")
    if str(p.get("commit")).lower() != spec["commit"]:
        die(f"{name}: commit mismatch")

    listed = parse_sums(sums)
    for rel, expected in sorted(listed.items()):
        f = base / rel
        if not f.is_file():
            die(f"{name}: checksum file missing: {rel}")
        got = sha256(f)
        if got != expected:
            die(f"{name}: checksum mismatch: {rel}")

    for rel in spec["required"]:
        if not (base / rel).is_file():
            die(f"{name}: required file missing: {rel}")

    if name == "resukisu":
        forbidden = [
            base / "kernel/feature/module_load_filter.c",
            base / "kernel/feature/module_load_filter.h",
        ]
        # Full source evidence MUST retain them. They are excluded only from
        # the VEUX integration stage, never from the snapshot itself.
        if not all(x.is_file() for x in forbidden):
            die("resukisu: full evidence snapshot unexpectedly incomplete")

    print(f"LOCAL_SNAPSHOT_{name.upper()}=PASS")

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", default=".")
    args = ap.parse_args()
    root = Path(args.repo_root).resolve()

    for name, spec in COMPONENTS.items():
        check_component(root, name, spec)

    print("LOCAL_UPSTREAM_SNAPSHOTS=PASS")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
