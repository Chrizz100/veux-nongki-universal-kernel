#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import shutil
import sys
import tempfile

RESUKISU_COMMIT = "9be0f347f38e790c846915bd5f9c24b337f85c4e"
RESUKISU_VERSION = 35170
RESUKISU_UAPI = 4
RESUKISU_SHORT = "9be0f347"

MODULE_FILTER_FILES = (
    "kernel/feature/module_load_filter.c",
    "kernel/feature/module_load_filter.h",
)

ALLOWED_RESUKISU_STAGE_DELTA = {
    "kernel/Kbuild",
    "kernel/core/init.c",
    *MODULE_FILTER_FILES,
}

HOST_FREEZE = (
    "fs/open.c",
    "fs/stat.c",
    "fs/exec.c",
    "fs/susfs.c",
    "include/linux/susfs.h",
)

NOMOUNT_FILES = ("Kconfig", "Makefile", "nomount.c", "nomount.h")


def die(msg: str) -> None:
    print(f"LOCAL_292_STAGE_ERROR: {msg}", file=sys.stderr)
    raise SystemExit(1)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def replace_exact(path: Path, old: str, new: str = "") -> None:
    data = path.read_text(encoding="utf-8")
    count = data.count(old)
    if count != 1:
        die(f"{path}: expected exactly one preimage, got {count}: {old!r}")
    path.write_text(data.replace(old, new, 1), encoding="utf-8")


def copy_tree_contents(src: Path, dst: Path) -> None:
    if not src.is_dir():
        die(f"copy source directory missing: {src}")
    if dst.exists() or dst.is_symlink():
        die(f"copy destination must not pre-exist: {dst}")
    dst.mkdir(parents=True, exist_ok=False)

    for child in src.iterdir():
        target = dst / child.name
        if child.is_symlink():
            target.symlink_to(child.readlink(), target_is_directory=child.is_dir())
        elif child.is_dir():
            shutil.copytree(child, target, symlinks=True)
        else:
            shutil.copy2(child, target)


def clean_vendor_preserve_git(vendor: Path) -> None:
    if not (vendor / ".git").exists():
        die(f"baseline ReSukiSU git plumbing missing: {vendor / '.git'}")
    for child in list(vendor.iterdir()):
        if child.name == ".git":
            continue
        if child.is_symlink() or child.is_file():
            child.unlink()
        else:
            shutil.rmtree(child)


def patch_pinned_kbuild(path: Path) -> None:
    data = path.read_text(encoding="utf-8")
    start_marker = '$(shell cd $(KSU_SRC); [ -f ../.git/shallow ] && $(GIT_BIN) fetch --unshallow)\n'
    end_marker = 'KSU_BRANCH_NAME := $(shell cd $(KSU_SRC); $(GIT_BIN) branch --show-current 2>/dev/null || echo "unknown")\n'
    if data.count(start_marker) != 1 or data.count(end_marker) != 1:
        die("ReSukiSU Kbuild git-identity preimage drift")
    a = data.index(start_marker)
    b = data.index(end_marker, a) + len(end_marker)
    replacement = (
        "# VEUX: source bytes are authenticated by third_party/resukisu/SHA256SUMS.txt.\n"
        "# Keep the known upstream 35170 identity without network/git-history access.\n"
        "KSU_LOCAL_VERSION := 4470\n"
        f"KSU_VERSION := {RESUKISU_VERSION}\n"
        'KSU_TAG_NAME := v4.1.0\n'
        f"KSU_COMMIT_SHA := {RESUKISU_SHORT}\n"
        "KSU_BRANCH_NAME := main\n"
    )
    path.write_text(data[:a] + replacement + data[b:], encoding="utf-8")

    final = path.read_text(encoding="utf-8")
    required = (
        "KSU_LOCAL_VERSION := 4470",
        "KSU_VERSION := 35170",
        "KSU_COMMIT_SHA := 9be0f347",
        "KSU_BRANCH_NAME := main",
    )
    for marker in required:
        if final.count(marker) != 1:
            die(f"Kbuild pinned identity marker mismatch: {marker}")
    for forbidden in (
        "git rev-list --count HEAD",
        "git describe --abbrev=0 --tags",
        "git rev-parse --short=8 HEAD",
        "git diff-index --quiet HEAD",
        "fetch --unshallow",
    ):
        if forbidden in final:
            die(f"Kbuild still contains network/history identity dependency: {forbidden}")


def remove_module_filter(vendor: Path) -> None:
    for rel in MODULE_FILTER_FILES:
        p = vendor / rel
        if not p.is_file():
            die(f"module_load_filter source missing before exclusion: {rel}")
        p.unlink()

    replace_exact(vendor / "kernel/Kbuild", "kernelsu-objs += feature/module_load_filter.o\n")
    replace_exact(vendor / "kernel/core/init.c", '#include "feature/module_load_filter.h"\n')
    replace_exact(
        vendor / "kernel/core/init.c",
        'char ksu_block_modules[256];\n'
        'module_param_string(block_modules, ksu_block_modules, sizeof(ksu_block_modules), 0);\n'
        'MODULE_PARM_DESC(block_modules, "Comma-separated preset module names to acknowledge without loading");\n\n',
    )
    replace_exact(vendor / "kernel/core/init.c", "        ksu_module_load_filter_hook_init();\n\n")
    replace_exact(vendor / "kernel/core/init.c", "    ksu_module_load_filter_hook_exit();\n")

    hits = []
    for p in (vendor / "kernel").rglob("*"):
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if any(x in text for x in ("module_load_filter", "ksu_block_modules", "block_modules")):
            hits.append(str(p.relative_to(vendor)))
    if hits:
        die("module_load_filter references remain: " + ", ".join(hits[:20]))


def snapshot_files(snapshot: Path) -> dict[str, str]:
    out = {}
    for base_name in ("kernel", "uapi"):
        base = snapshot / base_name
        if not base.is_dir():
            die(f"ReSukiSU snapshot missing {base_name}/")
        for p in sorted(base.rglob("*")):
            if p.is_file():
                out[p.relative_to(snapshot).as_posix()] = sha256(p)
    lic = snapshot / "LICENSE"
    if not lic.is_file():
        die("ReSukiSU snapshot missing LICENSE")
    out["LICENSE"] = sha256(lic)
    return out


def verify_resukisu_stage(vendor: Path, snapshot: Path, expected: dict[str, str]) -> None:
    # Everything except the explicit VEUX integration delta must remain
    # byte-for-byte identical to the authenticated local snapshot.
    for rel, want in expected.items():
        p = vendor / rel
        if rel in MODULE_FILTER_FILES:
            if p.exists():
                die(f"excluded module filter file still exists: {rel}")
            continue
        if not p.is_file():
            die(f"staged ReSukiSU file missing: {rel}")
        if rel not in {"kernel/Kbuild", "kernel/core/init.c"} and sha256(p) != want:
            die(f"unexpected ReSukiSU snapshot byte drift: {rel}")

    uapi = (vendor / "uapi/supercall.h").read_text(encoding="utf-8")
    marker = f"static const __u32 KERNEL_SU_UAPI_VERSION = {RESUKISU_UAPI};"
    if marker not in uapi:
        die("ReSukiSU UAPI 4 marker missing")

    markers = {
        "kernel/compat/kernel_compat.h": ("ksu_filp_open_nonotify",),
        "kernel/manager/manager.c": ("void ksu_unregister_all_manager(void)",),
        "kernel/selinux/sepolicy.c": ("#define avtab_for_each",),
    }
    for rel, needles in markers.items():
        text = (vendor / rel).read_text(encoding="utf-8")
        for needle in needles:
            if needle not in text:
                die(f"ReSukiSU 35170 semantic marker missing in {rel}: {needle}")

    print("LOCAL_RESUKISU_35170_SNAPSHOT_STAGE=PASS")
    print("LOCAL_RESUKISU_35170_IDENTITY_PIN=PASS")
    print("MODULE_LOAD_FILTER_EXCLUDED=PASS")


def integrate_nomount(src: Path, snapshot: Path) -> None:
    nm = snapshot / "kernel/src"
    for name in NOMOUNT_FILES:
        if not (nm / name).is_file():
            die(f"NoMount local snapshot missing kernel/src/{name}")

    dest = src / "fs/nomount"
    if dest.exists() or dest.is_symlink():
        die("fs/nomount already exists")
    before = {rel: sha256(src / rel) for rel in HOST_FREEZE}

    dest.mkdir(parents=True)
    for name in NOMOUNT_FILES:
        shutil.copy2(nm / name, dest / name)

    kconfig = src / "fs/Kconfig"
    makefile = src / "fs/Makefile"
    kline = 'source "fs/nomount/Kconfig"'
    mline = "obj-$(CONFIG_NOMOUNT) += nomount/"

    kt = kconfig.read_text(encoding="utf-8")
    mt = makefile.read_text(encoding="utf-8")
    if kt.count(kline) != 0 or mt.count(mline) != 0:
        die("NoMount host preimage already contains integration line")
    if not kt.endswith("\n"):
        kt += "\n"
    if not mt.endswith("\n"):
        mt += "\n"
    kconfig.write_text(kt + "\n" + kline + "\n", encoding="utf-8")
    makefile.write_text(mt + "\n" + mline + "\n", encoding="utf-8")

    if kconfig.read_text(encoding="utf-8").count(kline) != 1:
        die("NoMount Kconfig postcondition failed")
    if makefile.read_text(encoding="utf-8").count(mline) != 1:
        die("NoMount Makefile postcondition failed")
    for name in NOMOUNT_FILES:
        if sha256(dest / name) != sha256(nm / name):
            die(f"NoMount copy byte mismatch: {name}")

    after = {rel: sha256(src / rel) for rel in HOST_FREEZE}
    if before != after:
        changed = sorted(k for k in before if before[k] != after[k])
        die(f"NoMount changed frozen host surface: {changed}")

    print("LOCAL_NOMOUNT_2_0_0_STAGE=PASS")
    print("NOMOUNT_HOST_SURFACE_FREEZE=PASS")


def stage(src: Path, resukisu: Path, nomount: Path) -> None:
    vendor = src / ".resukisu"
    symlink = src / "drivers/kernelsu"
    if not vendor.is_dir() or not (vendor / ".git").exists():
        die("expected O51 baseline .resukisu worktree missing")
    if not symlink.is_symlink() or symlink.resolve() != (vendor / "kernel").resolve():
        die("drivers/kernelsu baseline symlink contract failed")

    before_host = {rel: sha256(src / rel) for rel in HOST_FREEZE}
    expected = snapshot_files(resukisu)

    clean_vendor_preserve_git(vendor)
    copy_tree_contents(resukisu / "kernel", vendor / "kernel")
    copy_tree_contents(resukisu / "uapi", vendor / "uapi")
    shutil.copy2(resukisu / "LICENSE", vendor / "LICENSE")

    patch_pinned_kbuild(vendor / "kernel/Kbuild")
    remove_module_filter(vendor)
    verify_resukisu_stage(vendor, resukisu, expected)

    after_rs = {rel: sha256(src / rel) for rel in HOST_FREEZE}
    if before_host != after_rs:
        changed = sorted(k for k in before_host if before_host[k] != after_rs[k])
        die(f"ReSukiSU stage changed frozen host surface: {changed}")

    integrate_nomount(src, nomount)

    print(f"RESUKISU_COMMIT={RESUKISU_COMMIT}")
    print(f"RESUKISU_VERSION={RESUKISU_VERSION}")
    print(f"RESUKISU_UAPI={RESUKISU_UAPI}")
    print("RESUKISU_SOURCE=LOCAL_SNAPSHOT")
    print("NOMOUNT_SOURCE=LOCAL_SNAPSHOT")
    print("LOCAL_292_TARGET_STAGE=PASS")


def selftest() -> None:
    with tempfile.TemporaryDirectory(prefix="veux-local-292-stage-") as td:
        root = Path(td)
        kbuild = root / "Kbuild"
        kbuild.write_text(
            'x\n'
            '$(shell cd $(KSU_SRC); [ -f ../.git/shallow ] && $(GIT_BIN) fetch --unshallow)\n'
            'KSU_LOCAL_VERSION := $(shell cd $(KSU_SRC); $(GIT_BIN) rev-list --count HEAD)\n'
            'KSU_VERSION := $(shell expr 30000 + $(KSU_LOCAL_VERSION) + 700)\n\n'
            'KSU_TAG_NAME    := $(shell cd $(KSU_SRC); $(GIT_BIN) describe --abbrev=0 --tags 2>/dev/null || echo "v4.1.0")\n'
            'KSU_COMMIT_SHA  := $(shell cd $(KSU_SRC); $(GIT_BIN) rev-parse --short=8 HEAD 2>/dev/null || echo "unknown")\n'
            'ifneq ($(shell cd $(KSU_SRC); $(GIT_BIN) diff-index --quiet HEAD; echo $$?),0)\n'
            'KSU_COMMIT_SHA  := $(KSU_COMMIT_SHA)-dirty\n'
            'endif\n'
            'KSU_BRANCH_NAME := $(shell cd $(KSU_SRC); $(GIT_BIN) branch --show-current 2>/dev/null || echo "unknown")\n'
            '# call subst to process placeholders\n',
            encoding="utf-8",
        )
        patch_pinned_kbuild(kbuild)
        text = kbuild.read_text(encoding="utf-8")
        if "KSU_VERSION := 35170" not in text or "rev-list --count" in text:
            die("selftest pinned Kbuild transform failed")

        # Regression for run 36056318740: after preserving only .git,
        # kernel/ and uapi/ no longer exist. The copy helper must create the
        # destination directory itself and must preserve dotfiles.
        copy_src = root / "copy-src"
        (copy_src / "nested").mkdir(parents=True)
        (copy_src / ".clangd.example").write_text("dotfile\n", encoding="utf-8")
        (copy_src / "nested/data.txt").write_text("nested\n", encoding="utf-8")
        copy_dst = root / "copy-dst"
        copy_tree_contents(copy_src, copy_dst)
        if (copy_dst / ".clangd.example").read_text(encoding="utf-8") != "dotfile\n":
            die("selftest hidden-file copy regression failed")
        if (copy_dst / "nested/data.txt").read_text(encoding="utf-8") != "nested\n":
            die("selftest nested-directory copy regression failed")

        vendor = root / "vendor"
        (vendor / "kernel/feature").mkdir(parents=True)
        (vendor / "kernel/core").mkdir(parents=True)
        (vendor / "kernel/Kbuild").write_text(
            "kernelsu-objs += feature/module_load_filter.o\n", encoding="utf-8"
        )
        (vendor / "kernel/core/init.c").write_text(
            '#include "feature/module_load_filter.h"\n'
            'char ksu_block_modules[256];\n'
            'module_param_string(block_modules, ksu_block_modules, sizeof(ksu_block_modules), 0);\n'
            'MODULE_PARM_DESC(block_modules, "Comma-separated preset module names to acknowledge without loading");\n\n'
            '        ksu_module_load_filter_hook_init();\n\n'
            '    ksu_module_load_filter_hook_exit();\n',
            encoding="utf-8",
        )
        for rel in MODULE_FILTER_FILES:
            p = vendor / rel
            p.write_text("x\n", encoding="utf-8")
        remove_module_filter(vendor)
        if any((vendor / rel).exists() for rel in MODULE_FILTER_FILES):
            die("selftest module filter exclusion failed")

    print("LOCAL_292_STAGE_SELFTEST=PASS")


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest")
    p = sub.add_parser("stage")
    p.add_argument("--src", required=True)
    p.add_argument("--resukisu", required=True)
    p.add_argument("--nomount", required=True)
    args = ap.parse_args()

    if args.cmd == "selftest":
        selftest()
    else:
        stage(
            Path(args.src).resolve(),
            Path(args.resukisu).resolve(),
            Path(args.nomount).resolve(),
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
