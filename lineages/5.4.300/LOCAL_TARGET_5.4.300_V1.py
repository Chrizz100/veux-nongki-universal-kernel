#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import shutil
import sys
import tempfile

RESUKISU_VERSION = 35170
RESUKISU_UAPI = 4
RESUKISU_SHORT = "9be0f347"

MODULE_FILTER_FILES = (
    "kernel/feature/module_load_filter.c",
    "kernel/feature/module_load_filter.h",
)

# Files belonging to the already-proven 5.4.300 outer integration which
# this ReSukiSU/NoMount stage must never mutate.
HOST_FREEZE = (
    "fs/open.c",
    "fs/stat.c",
    "fs/exec.c",
    "fs/susfs.c",
    "include/linux/susfs.h",
    "include/linux/susfs_def.h",
    "include/linux/key.h",
    "include/linux/cred.h",
    "security/keys/process_keys.c",
)

NOMOUNT_FILES = ("Kconfig", "Makefile", "nomount.c", "nomount.h")


def die(msg: str) -> None:
    print(f"LOCAL_300_STAGE_ERROR: {msg}", file=sys.stderr)
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
        die(f"KernelSU git plumbing missing: {vendor / '.git'}")
    for child in list(vendor.iterdir()):
        if child.name == ".git":
            continue
        if child.is_symlink() or child.is_file():
            child.unlink()
        else:
            shutil.rmtree(child)


def patch_pinned_kbuild(path: Path) -> None:
    data = path.read_text(encoding="utf-8")
    start = '$(shell cd $(KSU_SRC); [ -f ../.git/shallow ] && $(GIT_BIN) fetch --unshallow)\n'
    end = 'KSU_BRANCH_NAME := $(shell cd $(KSU_SRC); $(GIT_BIN) branch --show-current 2>/dev/null || echo "unknown")\n'
    if data.count(start) != 1 or data.count(end) != 1:
        die("ReSukiSU 35170 Kbuild identity preimage drift")
    a = data.index(start)
    b = data.index(end, a) + len(end)
    replacement = (
        "# VEUX 5.4.300: authenticated local ReSukiSU 35170 snapshot.\n"
        "KSU_LOCAL_VERSION := 4470\n"
        "KSU_VERSION := 35170\n"
        "KSU_TAG_NAME := v4.1.0\n"
        f"KSU_COMMIT_SHA := {RESUKISU_SHORT}\n"
        "KSU_BRANCH_NAME := main\n"
    )
    path.write_text(data[:a] + replacement + data[b:], encoding="utf-8")

    final = path.read_text(encoding="utf-8")
    for marker in (
        "KSU_LOCAL_VERSION := 4470",
        "KSU_VERSION := 35170",
        "KSU_COMMIT_SHA := 9be0f347",
        "KSU_BRANCH_NAME := main",
    ):
        if final.count(marker) != 1:
            die(f"Kbuild identity marker mismatch: {marker}")
    for forbidden in (
        "git rev-list --count HEAD",
        "git describe --abbrev=0 --tags",
        "git rev-parse --short=8 HEAD",
        "git diff-index --quiet HEAD",
        "fetch --unshallow",
    ):
        if forbidden in final:
            die(f"Kbuild still depends on git/network identity: {forbidden}")


def ensure_no_module_filter(vendor: Path) -> None:
    hits = []
    for base_name in ("kernel", "uapi"):
        base = vendor / base_name
        if not base.is_dir():
            continue
        for p in base.rglob("*"):
            if not p.is_file():
                continue
            try:
                text = p.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            if any(x in text for x in ("module_load_filter", "ksu_block_modules", "block_modules")):
                hits.append(str(p.relative_to(vendor)))
    if hits:
        die("module_load_filter contract present: " + ", ".join(hits[:20]))


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
    ensure_no_module_filter(vendor)


def uapi_gate(vendor: Path) -> None:
    marker = "static const __u32 KERNEL_SU_UAPI_VERSION = 4;"
    text = (vendor / "uapi/supercall.h").read_text(encoding="utf-8")
    if text.count(marker) != 1:
        die("ReSukiSU UAPI4 marker mismatch")
    print("RESUKISU_UAPI4=PASS")


def compat_300_gate(vendor: Path) -> None:
    # These are the same old-kernel compatibility contracts authenticated by
    # the O43 lineage and they are present in the pinned 35170 snapshot.
    checks = {
        "kernel/compat/kernel_compat.c": (
            "struct key *init_session_keyring = NULL;",
            "install_session_keyring_to_cred(ksu_cred, init_session_keyring);",
        ),
        "kernel/hook/lsm_hooks.c": (
            "LSM_HOOK_INIT(key_permission, ksu_handle_key_permission)",
        ),
        "kernel/core/init.c": (
            "init_session_keyring = ksu_get_session_keyring(current_cred());",
        ),
        "kernel/compat/kernel_compat.h": (
            "ksu_filp_open_nonotify",
        ),
        "kernel/manager/manager.c": (
            "void ksu_unregister_all_manager(void)",
        ),
    }
    for rel, needles in checks.items():
        if isinstance(needles, str):
            needles = (needles,)
        text = (vendor / rel).read_text(encoding="utf-8")
        for needle in needles:
            if needle not in text:
                die(f"5.4.300 compatibility marker missing in {rel}: {needle}")
    print("KERNELSU_300_COMPATIBILITY=PASS")


def snapshot_files(snapshot: Path) -> dict[str, str]:
    result = {}
    for base_name in ("kernel", "uapi"):
        base = snapshot / base_name
        if not base.is_dir():
            die(f"ReSukiSU snapshot missing {base_name}/")
        for p in sorted(base.rglob("*")):
            if p.is_file():
                result[p.relative_to(snapshot).as_posix()] = sha256(p)
    lic = snapshot / "LICENSE"
    if not lic.is_file():
        die("ReSukiSU snapshot missing LICENSE")
    result["LICENSE"] = sha256(lic)
    return result


def verify_snapshot_stage(vendor: Path, expected: dict[str, str]) -> None:
    for rel, want in expected.items():
        p = vendor / rel
        if rel in MODULE_FILTER_FILES:
            if p.exists():
                die(f"excluded module filter file still exists: {rel}")
            continue
        if not p.is_file():
            die(f"staged ReSukiSU file missing: {rel}")
        # These are the only intentional byte deltas from the authenticated
        # snapshot: pinned build identity and module-filter removal.
        if rel not in {"kernel/Kbuild", "kernel/core/init.c"} and sha256(p) != want:
            die(f"unexpected ReSukiSU snapshot drift: {rel}")
    print("RESUKISU_35170_SNAPSHOT_PARITY=PASS")


def verify_baseline(src: Path) -> None:
    vendor = src / "KernelSU"
    if not vendor.is_dir() or not (vendor / ".git").exists():
        die("O43/O51 KernelSU baseline tree missing")
    for rel in ("kernel/Kbuild", "kernel/core/init.c", "uapi/supercall.h"):
        if not (vendor / rel).is_file():
            die(f"baseline KernelSU file missing: {rel}")
    uapi_gate(vendor)
    ensure_no_module_filter(vendor)
    compat_300_gate(vendor)
    print("NATIVE_300_BASELINE_LAYOUT=PASS")


def integrate_nomount(src: Path, snapshot: Path) -> None:
    nm = snapshot / "kernel/src"
    for name in NOMOUNT_FILES:
        if not (nm / name).is_file():
            die(f"NoMount snapshot missing kernel/src/{name}")

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
    if kline in kt or mline in mt:
        die("NoMount integration already present")
    kconfig.write_text(kt.rstrip("\n") + "\n\n" + kline + "\n", encoding="utf-8")
    makefile.write_text(mt.rstrip("\n") + "\n\n" + mline + "\n", encoding="utf-8")

    if kconfig.read_text(encoding="utf-8").count(kline) != 1:
        die("NoMount Kconfig integration count mismatch")
    if makefile.read_text(encoding="utf-8").count(mline) != 1:
        die("NoMount Makefile integration count mismatch")
    for name in NOMOUNT_FILES:
        if sha256(dest / name) != sha256(nm / name):
            die(f"NoMount copy mismatch: {name}")

    after = {rel: sha256(src / rel) for rel in HOST_FREEZE}
    if before != after:
        changed = sorted(k for k in before if before[k] != after[k])
        die(f"NoMount changed frozen 5.4.300 host surface: {changed}")
    print("NOMOUNT_2_0_0_NATIVE_300_STAGE=PASS")


def stage(src: Path, resukisu: Path, nomount: Path) -> None:
    vendor = src / "KernelSU"
    verify_baseline(src)

    before = {rel: sha256(src / rel) for rel in HOST_FREEZE}
    expected = snapshot_files(resukisu)

    clean_vendor_preserve_git(vendor)
    copy_tree_contents(resukisu / "kernel", vendor / "kernel")
    copy_tree_contents(resukisu / "uapi", vendor / "uapi")
    shutil.copy2(resukisu / "LICENSE", vendor / "LICENSE")

    patch_pinned_kbuild(vendor / "kernel/Kbuild")
    remove_module_filter(vendor)
    verify_snapshot_stage(vendor, expected)
    uapi_gate(vendor)
    compat_300_gate(vendor)

    after = {rel: sha256(src / rel) for rel in HOST_FREEZE}
    if before != after:
        changed = sorted(k for k in before if before[k] != after[k])
        die(f"ReSukiSU changed frozen 5.4.300 host surface: {changed}")

    integrate_nomount(src, nomount)

    print("RESUKISU_COMMIT=9be0f347f38e790c846915bd5f9c24b337f85c4e")
    print("RESUKISU_VERSION=35170")
    print("RESUKISU_UAPI=4")
    print("MODULE_LOAD_FILTER=EXCLUDED")
    print("LOCAL_300_TARGET_STAGE=PASS")


def verify_target(src: Path) -> None:
    vendor = src / "KernelSU"
    if not vendor.is_dir() or not (vendor / ".git").exists():
        die("target KernelSU tree missing")
    kbuild = (vendor / "kernel/Kbuild").read_text(encoding="utf-8")
    for marker in (
        "KSU_LOCAL_VERSION := 4470",
        "KSU_VERSION := 35170",
        "KSU_COMMIT_SHA := 9be0f347",
        "KSU_BRANCH_NAME := main",
    ):
        if kbuild.count(marker) != 1:
            die(f"target identity marker mismatch: {marker}")
    uapi_gate(vendor)
    ensure_no_module_filter(vendor)
    compat_300_gate(vendor)

    if not (src / "fs/nomount/nomount.c").is_file():
        die("NoMount source missing")
    if (src / "fs/Kconfig").read_text(encoding="utf-8").count('source "fs/nomount/Kconfig"') != 1:
        die("NoMount Kconfig count mismatch")
    if (src / "fs/Makefile").read_text(encoding="utf-8").count("obj-$(CONFIG_NOMOUNT) += nomount/") != 1:
        die("NoMount Makefile count mismatch")
    print("NATIVE_300_TARGET_VERIFY=PASS")


def selftest() -> None:
    with tempfile.TemporaryDirectory(prefix="veux-300-native-") as td:
        root = Path(td)
        kbuild = root / "Kbuild"
        kbuild.write_text(
            '$(shell cd $(KSU_SRC); [ -f ../.git/shallow ] && $(GIT_BIN) fetch --unshallow)\n'
            'KSU_LOCAL_VERSION := $(shell cd $(KSU_SRC); $(GIT_BIN) rev-list --count HEAD)\n'
            'KSU_VERSION := $(shell expr 30000 + $(KSU_LOCAL_VERSION) + 700)\n\n'
            'KSU_TAG_NAME    := $(shell cd $(KSU_SRC); $(GIT_BIN) describe --abbrev=0 --tags 2>/dev/null || echo "v4.1.0")\n'
            'KSU_COMMIT_SHA  := $(shell cd $(KSU_SRC); $(GIT_BIN) rev-parse --short=8 HEAD 2>/dev/null || echo "unknown")\n'
            'ifneq ($(shell cd $(KSU_SRC); $(GIT_BIN) diff-index --quiet HEAD; echo $$?),0)\n'
            'KSU_COMMIT_SHA  := $(KSU_COMMIT_SHA)-dirty\n'
            'endif\n'
            'KSU_BRANCH_NAME := $(shell cd $(KSU_SRC); $(GIT_BIN) branch --show-current 2>/dev/null || echo "unknown")\n',
            encoding="utf-8",
        )
        patch_pinned_kbuild(kbuild)
        if "KSU_VERSION := 35170" not in kbuild.read_text(encoding="utf-8"):
            die("selftest Kbuild identity transform failed")

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
            (vendor / rel).write_text("x\n", encoding="utf-8")
        remove_module_filter(vendor)
        if any((vendor / rel).exists() for rel in MODULE_FILTER_FILES):
            die("selftest module filter removal failed")

    print("LOCAL_300_STAGE_SELFTEST=PASS")


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest")
    p = sub.add_parser("verify-baseline")
    p.add_argument("--src", required=True)
    p = sub.add_parser("stage")
    p.add_argument("--src", required=True)
    p.add_argument("--resukisu", required=True)
    p.add_argument("--nomount", required=True)
    p = sub.add_parser("verify-target")
    p.add_argument("--src", required=True)
    args = ap.parse_args()

    src = Path(getattr(args, "src", ".")).resolve()
    if args.cmd == "selftest":
        selftest()
    elif args.cmd == "verify-baseline":
        verify_baseline(src)
    elif args.cmd == "stage":
        stage(src, Path(args.resukisu).resolve(), Path(args.nomount).resolve())
    else:
        verify_target(src)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
