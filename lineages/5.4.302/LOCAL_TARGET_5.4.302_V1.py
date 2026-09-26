#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import os
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

# Host files that the ReSukiSU/NoMount stage must not modify.  The final three
# entries are the O45-v2 5.4.300->5.4.302 conflict resolutions frozen by O46-v3.
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
    "net/ipv4/inet_connection_sock.c",
    "include/linux/pm.h",
    "drivers/soc/qcom/smcinvoke.c",
)


O44_SUSFS_SHA256 = {
    "fs/susfs.c": "e430d573ba5875a55d1ca70ba1b304e4b6727bbc42b8c3ac16f2c175b29a59c1",
    "include/linux/susfs.h": "3c5fb1bcc28a70c82ee5cfe0a7375bb8e7babd26618ce9b451e598fa31aa3b6e",
    "include/linux/susfs_def.h": "b16108a5fcd4cdd7203d9f084c2154da708ab3ae6bed17109e4ec63f04ff0f68",
}

NOMOUNT_FILES = ("Kconfig", "Makefile", "nomount.c", "nomount.h")


def die(msg: str) -> None:
    print(f"LOCAL_302_STAGE_ERROR: {msg}", file=sys.stderr)
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
        "# VEUX 5.4.302: authenticated local ReSukiSU 35170 snapshot.\n"
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
    hits: list[str] = []
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


def _check_compat_markers(vendor: Path, checks: dict[str, tuple[str, ...]], label: str) -> None:
    for rel, needles in checks.items():
        path = vendor / rel
        if not path.is_file():
            die(f"{label}: compatibility file missing: {rel}")
        data = path.read_text(encoding="utf-8")
        for needle in needles:
            if needle not in data:
                die(f"{label}: compatibility marker missing in {rel}: {needle}")


def baseline_35158_compat_gate(vendor: Path) -> None:
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
    }
    _check_compat_markers(vendor, checks, "35158 baseline")
    print("BASELINE_35158_COMPATIBILITY=PASS")


def target_35170_compat_gate(vendor: Path) -> None:
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
        "kernel/compat/kernel_compat.h": ("ksu_filp_open_nonotify",),
        "kernel/manager/manager.c": ("void ksu_unregister_all_manager(void)",),
    }
    _check_compat_markers(vendor, checks, "35170 target")
    print("TARGET_35170_COMPATIBILITY=PASS")


def verify_302_host(src: Path) -> None:
    # O44/O41 5.4.302 authority contracts. These are checked directly against
    # the reconstructed 5.4.302 source before and after the local target stage.
    for rel, expected in O44_SUSFS_SHA256.items():
        p = src / rel
        if not p.is_file():
            die(f"O44 frozen 5.4.302 host file missing: {rel}")
        got = sha256(p)
        if got != expected:
            die(f"O44 frozen 5.4.302 SUSFS drift: {rel}: {got} != {expected}")

    inet = (src / "net/ipv4/inet_connection_sock.c").read_text(encoding="utf-8")
    if "del_timer_sync(&req->rsk_timer)" not in inet:
        die("O44 5.4.302 del_timer_sync contract missing")
    if "timer_delete_sync(&req->rsk_timer)" in inet:
        die("O44 5.4.302 timer_delete_sync regression present")

    if "needs_force_resume:1;" not in (src / "include/linux/pm.h").read_text(encoding="utf-8"):
        die("O41/O44 5.4.302 PM dependency closure missing")
    smci = (src / "drivers/soc/qcom/smcinvoke.c").read_text(encoding="utf-8")
    if "smci_size_add" not in smci:
        die("O41/O44 5.4.302 timer/sizeadd dependency closure missing")
    if "ksu_handle_post_execve" not in (src / "fs/exec.c").read_text(encoding="utf-8"):
        die("P13 post-exec hook missing from 5.4.302 host")
    print("O44_302_FROZEN_HOST=PASS")


def snapshot_files(snapshot: Path) -> dict[str, str]:
    result: dict[str, str] = {}
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
        if rel not in {"kernel/Kbuild", "kernel/core/init.c"} and sha256(p) != want:
            die(f"unexpected ReSukiSU snapshot drift: {rel}")
    print("RESUKISU_35170_SNAPSHOT_PARITY=PASS")


def verify_baseline(src: Path) -> None:
    verify_302_host(src)
    vendor = src / "KernelSU"
    if not vendor.is_dir() or not (vendor / ".git").exists():
        die("O44/O51 5.4.302 KernelSU baseline tree missing")
    for rel in ("kernel/Kbuild", "kernel/core/init.c", "uapi/supercall.h"):
        if not (vendor / rel).is_file():
            die(f"baseline KernelSU file missing: {rel}")
    uapi_gate(vendor)
    ensure_no_module_filter(vendor)
    baseline_35158_compat_gate(vendor)
    print("NATIVE_302_BASELINE_LAYOUT=PASS")


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
        die(f"NoMount changed frozen 5.4.302 host surface: {changed}")
    print("NOMOUNT_2_0_0_NATIVE_302_STAGE=PASS")


def stage(src: Path, resukisu: Path, nomount: Path) -> None:
    verify_baseline(src)
    vendor = src / "KernelSU"
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
    target_35170_compat_gate(vendor)
    after = {rel: sha256(src / rel) for rel in HOST_FREEZE}
    if before != after:
        changed = sorted(k for k in before if before[k] != after[k])
        die(f"ReSukiSU changed frozen 5.4.302 host surface: {changed}")
    integrate_nomount(src, nomount)
    print(f"RESUKISU_COMMIT={RESUKISU_COMMIT}")
    print(f"RESUKISU_VERSION={RESUKISU_VERSION}")
    print(f"RESUKISU_UAPI={RESUKISU_UAPI}")
    print("MODULE_LOAD_FILTER=EXCLUDED")
    print("LOCAL_302_TARGET_STAGE=PASS")


def verify_target(src: Path) -> None:
    verify_302_host(src)
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
    target_35170_compat_gate(vendor)
    if not (src / "fs/nomount/nomount.c").is_file():
        die("NoMount source missing")
    if (src / "fs/Kconfig").read_text(encoding="utf-8").count('source "fs/nomount/Kconfig"') != 1:
        die("NoMount Kconfig count mismatch")
    if (src / "fs/Makefile").read_text(encoding="utf-8").count("obj-$(CONFIG_NOMOUNT) += nomount/") != 1:
        die("NoMount Makefile count mismatch")
    print("NATIVE_302_TARGET_VERIFY=PASS")


def manifest(base: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted(base.rglob("*")):
        if path.is_file():
            result[path.relative_to(base).as_posix()] = sha256(path)
    return result


def verify_topology(src: Path, report: Path) -> None:
    logical = src / "KernelSU"
    canonical = logical / "kernel"
    built = src / "drivers/kernelsu"
    forbidden = src / "kernel/kernelsu"
    candidates = []
    for name, path in (("KernelSU", logical), ("drivers/kernelsu", built), ("kernel/kernelsu", forbidden)):
        if path.exists() or path.is_symlink():
            candidates.append(name)
    if candidates != ["KernelSU", "drivers/kernelsu"]:
        die(f"unexpected KernelSU candidates: {candidates!r}")
    if not logical.is_dir() or not canonical.is_dir() or not built.is_dir():
        die("expected KernelSU/kernel and drivers/kernelsu directories are not both valid")
    if forbidden.exists() or forbidden.is_symlink():
        die("unexpected kernel/kernelsu integration exists")
    if built.is_symlink():
        if built.resolve() != canonical.resolve():
            die(f"drivers/kernelsu symlink target mismatch: {built.resolve()} != {canonical.resolve()}")
        topology = "SYMLINK_TO_KERNELSU_KERNEL"
    else:
        cm = manifest(canonical)
        bm = manifest(built)
        if cm != bm:
            only_canon = sorted(set(cm) - set(bm))[:20]
            only_built = sorted(set(bm) - set(cm))[:20]
            changed = sorted(k for k in set(cm) & set(bm) if cm[k] != bm[k])[:20]
            die(f"drivers/kernelsu is not a byte-identical mirror; only_canonical={only_canon} only_built={only_built} changed={changed}")
        topology = "BYTE_IDENTICAL_MIRROR"
    required = ("Kbuild", "core/init.c", "compat/kernel_compat.c", "hook/lsm_hooks.c", "manager/manager.c")
    rows: list[tuple[str, str, bool]] = []
    for rel in required:
        a = canonical / rel
        b = built / rel
        if not a.is_file() or not b.is_file():
            die(f"required KernelSU binding file missing: {rel}")
        digest = sha256(a)
        if digest != sha256(b):
            die(f"KernelSU binding hash mismatch: {rel}")
        try:
            same_inode = os.path.samefile(a, b)
        except OSError:
            same_inode = False
        rows.append((rel, digest, same_inode))
    kbuild = (canonical / "Kbuild").read_text(encoding="utf-8")
    for marker in ("KSU_VERSION := 35170", "KSU_COMMIT_SHA := 9be0f347", "KSU_BRANCH_NAME := main"):
        if kbuild.count(marker) != 1:
            die(f"35170 Kbuild marker mismatch: {marker}")
    uapi_gate(logical)
    ensure_no_module_filter(logical)
    report.parent.mkdir(parents=True, exist_ok=True)
    with report.open("w", encoding="utf-8") as f:
        f.write("KSU_DIR_COUNT=2\n")
        f.write("KSU_CANONICAL=KernelSU/kernel\n")
        f.write("KSU_BUILD_PATH=drivers/kernelsu\n")
        f.write(f"KSU_TOPOLOGY={topology}\n")
        for rel, digest, same_inode in rows:
            f.write(f"BINDING_FILE={rel} SHA256={digest} SAME_INODE={str(same_inode).lower()}\n")
        f.write("RESUKISU_VERSION=35170\n")
        f.write("RESUKISU_COMMIT_SHORT=9be0f347\n")
        f.write("UAPI=4\n")
        f.write("MODULE_LOAD_FILTER=EXCLUDED\n")
        f.write("PORT302_KSU_DUAL_PATH_BINDING=PASS\n")
    print("PORT302_KSU_DUAL_PATH_BINDING=PASS")


def selftest() -> None:
    with tempfile.TemporaryDirectory(prefix="veux-302-native-") as td:
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
        text = kbuild.read_text(encoding="utf-8")
        if "KSU_VERSION := 35170" not in text or "rev-list --count" in text:
            die("selftest Kbuild identity transform failed")

        vendor = root / "vendor"
        (vendor / "kernel/feature").mkdir(parents=True)
        (vendor / "kernel/core").mkdir(parents=True)
        (vendor / "kernel/Kbuild").write_text("kernelsu-objs += feature/module_load_filter.o\n", encoding="utf-8")
        (vendor / "kernel/core/init.c").write_text(
            '#include "feature/module_load_filter.h"\n'
            'char ksu_block_modules[256];\n'
            'module_param_string(block_modules, ksu_block_modules, sizeof(ksu_block_modules), 0);\n'
            'MODULE_PARM_DESC(block_modules, "Comma-separated preset module names to acknowledge without loading");\n\n'
            '        ksu_module_load_filter_hook_init();\n\n'
            '    ksu_module_load_filter_hook_exit();\n', encoding="utf-8")
        for rel in MODULE_FILTER_FILES:
            (vendor / rel).write_text("x\n", encoding="utf-8")
        remove_module_filter(vendor)
        if any((vendor / rel).exists() for rel in MODULE_FILTER_FILES):
            die("selftest module filter removal failed")

        # ReSukiSU setup topology: drivers/kernelsu -> ../KernelSU/kernel.
        topo = root / "topology"
        logical = topo / "KernelSU"
        canonical = logical / "kernel"
        (canonical / "core").mkdir(parents=True)
        (canonical / "compat").mkdir(parents=True)
        (canonical / "hook").mkdir(parents=True)
        (canonical / "manager").mkdir(parents=True)
        (logical / "uapi").mkdir(parents=True)
        (topo / "drivers").mkdir(parents=True)
        (canonical / "Kbuild").write_text(
            "KSU_LOCAL_VERSION := 4470\n"
            "KSU_VERSION := 35170\n"
            "KSU_TAG_NAME := v4.1.0\n"
            "KSU_COMMIT_SHA := 9be0f347\n"
            "KSU_BRANCH_NAME := main\n", encoding="utf-8")
        (canonical / "core/init.c").write_text("init\n", encoding="utf-8")
        (canonical / "compat/kernel_compat.c").write_text("compat\n", encoding="utf-8")
        (canonical / "hook/lsm_hooks.c").write_text("hook\n", encoding="utf-8")
        (canonical / "manager/manager.c").write_text("manager\n", encoding="utf-8")
        (logical / "uapi/supercall.h").write_text(
            "static const __u32 KERNEL_SU_UAPI_VERSION = 4;\n", encoding="utf-8")
        (topo / "drivers/kernelsu").symlink_to("../KernelSU/kernel", target_is_directory=True)
        verify_topology(topo, root / "topology-report.txt")
        if "PORT302_KSU_DUAL_PATH_BINDING=PASS" not in (root / "topology-report.txt").read_text(encoding="utf-8"):
            die("selftest topology report missing PASS marker")
    print("LOCAL_302_STAGE_SELFTEST=PASS")


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
    p = sub.add_parser("verify-topology")
    p.add_argument("--src", required=True)
    p.add_argument("--report", required=True)
    args = ap.parse_args()
    src = Path(getattr(args, "src", ".")).resolve()
    if args.cmd == "selftest":
        selftest()
    elif args.cmd == "verify-baseline":
        verify_baseline(src)
    elif args.cmd == "stage":
        stage(src, Path(args.resukisu).resolve(), Path(args.nomount).resolve())
    elif args.cmd == "verify-target":
        verify_target(src)
    else:
        verify_topology(src, Path(args.report).resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
