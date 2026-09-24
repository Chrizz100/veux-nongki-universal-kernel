#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import sys
import tempfile

BASE_COMMIT = "6d18926ae6eeb571a04c1ce7552c324d606fa9d8"
TARGET_COMMIT = "9be0f347f38e790c846915bd5f9c24b337f85c4e"
TARGET_VERSION = 35170
EXPECTED_DELTA_COMMITS = 12
TARGET_MANAGER_BLOB = "793469e587bfdb92a6b60c1126b14da560317340"
EXPECTED_UAPI = 4

NOMOUNT_COMMIT = "b8d268353b4e7ecc53c67d1816a626b7d6579201"
NOMOUNT_BLOBS = {
    "kernel/src/Kconfig": "638b9427ef638f786d288d0a93f731676cf32c62",
    "kernel/src/Makefile": "90099e5ec7ad9d9323ccbfb20d4e0d7c38015610",
    "kernel/src/nomount.c": "18fd5468fde03b7a7e48fe7f2b775d696077df20",
    "kernel/src/nomount.h": "38f7e7411d3a859e84db7b339aed7a85e15f597f",
}

EXPECTED_TARGET_DELTA = {
    "kernel/Kbuild",
    "kernel/compat/kernel_compat.c",
    "kernel/compat/kernel_compat.h",
    "kernel/core/init.c",
    "kernel/feature/dynamic_manager.c",
    "kernel/feature/kernel_umount.c",
    "kernel/hook/arm64/patch_memory.c",
    "kernel/hook/lsm_hooks.c",
    "kernel/hook/syscall_hook_manager.c",
    "kernel/include/ksu.h",
    "kernel/infra/su_mount_ns.c",
    "kernel/manager/apk_sign.c",
    "kernel/manager/manager.c",
    "kernel/manager/manager_identity.h",
    "kernel/manager/throne_tracker.c",
    "kernel/manager/throne_tracker.h",
    "kernel/selinux/rules.c",
    "kernel/selinux/sepolicy.c",
    "kernel/tools/inline_hook_check.mk",
    "kernel/tools/kernel_compat.mk",
}

MODULE_FILTER_DELTA = {
    "kernel/Kbuild",
    "kernel/core/init.c",
    "kernel/feature/module_load_filter.c",
    "kernel/feature/module_load_filter.h",
}


def die(msg: str) -> "None":
    print(f"GOLDEN_PORT_ERROR: {msg}", file=sys.stderr)
    raise SystemExit(1)


def run(args: list[str], cwd: Path | None = None) -> str:
    p = subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if p.returncode:
        if p.stdout:
            print(p.stdout, file=sys.stderr, end="")
        if p.stderr:
            print(p.stderr, file=sys.stderr, end="")
        die(f"command failed rc={p.returncode}: {' '.join(args)}")
    return p.stdout.strip()


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def git_head(root: Path) -> str:
    return run(["git", "-C", str(root), "rev-parse", "HEAD"])


def git_diff_names(root: Path) -> set[str]:
    text = run(["git", "-C", str(root), "diff", "--name-only"])
    return {x for x in text.splitlines() if x.strip()}


def git_untracked(root: Path) -> set[str]:
    text = run(["git", "-C", str(root), "ls-files", "--others", "--exclude-standard"])
    return {x for x in text.splitlines() if x.strip()}


def version_code(root: Path, commit: str = "HEAD") -> int:
    count = int(run(["git", "-C", str(root), "rev-list", "--count", commit]))
    return 30700 + count


def uapi_version(root: Path) -> int:
    p = root / "uapi/supercall.h"
    text = p.read_text(encoding="utf-8")
    hits = [line for line in text.splitlines() if "KERNEL_SU_UAPI_VERSION" in line and "=" in line]
    parsed = []
    for line in hits:
        m = re.search(r"KERNEL_SU_UAPI_VERSION\s*=\s*(\d+)\s*;", line)
        if m:
            parsed.append(int(m.group(1)))
    if parsed != [EXPECTED_UAPI]:
        die(f"unexpected UAPI version markers: {parsed}")
    return parsed[0]


def ensure_no_module_filter(root: Path) -> None:
    hits: list[str] = []
    for p in (root / "kernel").rglob("*"):
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if any(x in text for x in ("module_load_filter", "ksu_block_modules", "block_modules")):
            hits.append(str(p.relative_to(root)))
    if hits:
        die("module_load_filter contract leaked into target: " + ", ".join(hits[:20]))


def replace_exact(path: Path, old: str, new: str = "") -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        die(f"{path}: expected exactly one preimage, found {count}: {old!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def remove_module_filter(root: Path) -> None:
    for rel in (
        "kernel/feature/module_load_filter.c",
        "kernel/feature/module_load_filter.h",
    ):
        p = root / rel
        if not p.is_file():
            die(f"expected module filter file missing: {rel}")
        p.unlink()

    replace_exact(root / "kernel/Kbuild", "kernelsu-objs += feature/module_load_filter.o\n")
    replace_exact(root / "kernel/core/init.c", '#include "feature/module_load_filter.h"\n')
    replace_exact(
        root / "kernel/core/init.c",
        'char ksu_block_modules[256];\n'
        'module_param_string(block_modules, ksu_block_modules, sizeof(ksu_block_modules), 0);\n'
        'MODULE_PARM_DESC(block_modules, "Comma-separated preset module names to acknowledge without loading");\n\n',
    )
    replace_exact(
        root / "kernel/core/init.c",
        "        ksu_module_load_filter_hook_init();\n\n",
    )
    replace_exact(
        root / "kernel/core/init.c",
        "    ksu_module_load_filter_hook_exit();\n",
    )
    ensure_no_module_filter(root)


def function_region(text: str, signature: str) -> str:
    start = text.find(signature)
    if start < 0:
        die(f"function signature not found: {signature}")
    brace = text.find("{", start)
    if brace < 0:
        die(f"function opening brace not found: {signature}")
    depth = 0
    in_string: str | None = None
    escaped = False
    i = brace
    while i < len(text):
        ch = text[i]
        if in_string is not None:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == in_string:
                in_string = None
        else:
            if ch in ("'", '"'):
                in_string = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[start:i + 1]
        i += 1
    die(f"function closing brace not found: {signature}")


def ordering(region: str, invalid_marker: str, work_markers: tuple[str, ...], label: str) -> None:
    invalid = region.find(invalid_marker)
    if invalid < 0:
        die(f"{label}: invalid-argument validation marker missing")
    work_positions = []
    for marker in work_markers:
        pos = region.find(marker)
        if pos < 0:
            die(f"{label}: runtime-work marker missing: {marker}")
        work_positions.append(pos)
    if invalid >= min(work_positions):
        die(f"{label}: invalid-argument validation is not before KSU/SUSFS runtime work")


def verify_fastfail(src: Path) -> None:
    open_text = (src / "fs/open.c").read_text(encoding="utf-8")
    stat_text = (src / "fs/stat.c").read_text(encoding="utf-8")
    open_fn = function_region(open_text, "long do_faccessat(")
    stat_fn = function_region(stat_text, "int vfs_statx(")

    open_count = open_fn.count("ksu_handle_faccessat(")
    stat_count = stat_fn.count("ksu_handle_stat(")
    if open_count != 1:
        die(f"open.c: expected one faccessat KSU hook in function, got {open_count}")
    if stat_count != 1:
        die(f"stat.c: expected one stat KSU hook in function, got {stat_count}")

    ordering(
        open_fn,
        "if (mode & ~S_IRWXO)",
        ("getname_flags(", "ksu_handle_faccessat("),
        "do_faccessat",
    )
    ordering(
        stat_fn,
        "if ((flags & ~(",
        ("getname_flags(", "ksu_handle_stat("),
        "vfs_statx",
    )
    print("OPEN_INVALID_ARGUMENT_FASTFAIL=PASS")
    print("STAT_INVALID_ARGUMENT_FASTFAIL=PASS")
    print("U7_N4_FASTFAIL_BEHAVIORAL_CONTRACT=PASS")


def verify_pre(src: Path) -> None:
    vendor = src / ".resukisu"
    if not vendor.is_dir() or not (vendor / ".git").exists():
        die("vendored ReSukiSU worktree missing")
    if git_head(vendor) != BASE_COMMIT:
        die(f"baseline ReSukiSU HEAD mismatch: {git_head(vendor)}")
    if version_code(vendor) != 35158:
        die(f"baseline ReSukiSU version mismatch: {version_code(vendor)}")
    if uapi_version(vendor) != EXPECTED_UAPI:
        die(f"baseline UAPI mismatch: {uapi_version(vendor)}")
    actual = git_diff_names(vendor)
    if actual != MODULE_FILTER_DELTA:
        die(f"baseline ReSukiSU local delta mismatch: {sorted(actual)}")
    if git_untracked(vendor):
        die(f"baseline ReSukiSU contains unexpected untracked files: {sorted(git_untracked(vendor))}")
    ensure_no_module_filter(vendor)
    verify_fastfail(src)
    print("BASELINE_35158_VENDOR_CONTRACT=PASS")
    print("BASELINE_FASTFAIL_ORDERING=PASS")


def authenticate_target(vendor: Path) -> None:
    run(["git", "-C", str(vendor), "cat-file", "-e", f"{BASE_COMMIT}^{{commit}}"])
    run(["git", "-C", str(vendor), "cat-file", "-e", f"{TARGET_COMMIT}^{{commit}}"])
    run(["git", "-C", str(vendor), "merge-base", "--is-ancestor", BASE_COMMIT, TARGET_COMMIT])
    delta = int(run(["git", "-C", str(vendor), "rev-list", "--count", f"{BASE_COMMIT}..{TARGET_COMMIT}"]))
    if delta != EXPECTED_DELTA_COMMITS:
        die(f"35158->35170 commit delta mismatch: {delta}")

    changed = set(filter(None, run([
        "git", "-C", str(vendor), "diff", "--name-only", BASE_COMMIT, TARGET_COMMIT, "--", "kernel", "uapi"
    ]).splitlines()))
    if changed != EXPECTED_TARGET_DELTA:
        die(
            "35158->35170 kernel/uapi file delta mismatch: "
            f"missing={sorted(EXPECTED_TARGET_DELTA - changed)} "
            f"extra={sorted(changed - EXPECTED_TARGET_DELTA)}"
        )

    uapi_changed = run([
        "git", "-C", str(vendor), "diff", "--name-only", BASE_COMMIT, TARGET_COMMIT, "--", "uapi"
    ])
    if uapi_changed.strip():
        die(f"unexpected UAPI delta: {uapi_changed}")

    manager_blob = run([
        "git", "-C", str(vendor), "rev-parse", f"{TARGET_COMMIT}:kernel/manager/manager.c"
    ])
    if manager_blob != TARGET_MANAGER_BLOB:
        die(f"manager target blob mismatch: {manager_blob}")

    if version_code(vendor, TARGET_COMMIT) != TARGET_VERSION:
        die(f"target ReSukiSU version mismatch: {version_code(vendor, TARGET_COMMIT)}")

    print(f"RESUKISU_35158_TO_35170_COMMITS={delta}")
    print(f"RESUKISU_35170_KERNEL_UAPI_DELTA_FILES={len(changed)}")
    print("RESUKISU_35170_UAPI_DELTA=NONE")
    print("RESUKISU_35170_TARGET_AUTH=PASS")


def verify_target(src: Path) -> None:
    vendor = src / ".resukisu"
    if git_head(vendor) != TARGET_COMMIT:
        die(f"target ReSukiSU HEAD mismatch: {git_head(vendor)}")
    if version_code(vendor) != TARGET_VERSION:
        die(f"target ReSukiSU version mismatch: {version_code(vendor)}")
    if uapi_version(vendor) != EXPECTED_UAPI:
        die(f"target UAPI mismatch: {uapi_version(vendor)}")
    actual = git_diff_names(vendor)
    if actual != MODULE_FILTER_DELTA:
        die(f"target ReSukiSU local delta mismatch: {sorted(actual)}")
    if git_untracked(vendor):
        die(f"target ReSukiSU contains unexpected untracked files: {sorted(git_untracked(vendor))}")
    ensure_no_module_filter(vendor)

    if not (src / "drivers/kernelsu").is_symlink():
        die("drivers/kernelsu symlink missing after target update")
    if (src / "drivers/kernelsu").resolve() != (vendor / "kernel").resolve():
        die("drivers/kernelsu symlink no longer targets vendored ReSukiSU kernel")

    markers = {
        "kernel/compat/kernel_compat.h": [
            "ksu_filp_open_nonotify",
            "#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)",
        ],
        "kernel/compat/kernel_compat.c": [
            "#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)",
            "__weak int path_umount(struct path *path, int flags)",
        ],
        "kernel/manager/apk_sign.c": [
            "ksu_filp_open_nonotify(path, O_RDONLY | O_NOATIME)",
        ],
        "kernel/manager/manager.c": [
            "void ksu_unregister_all_manager(void)",
        ],
        "kernel/selinux/rules.c": [
            "old_pol = rcu_dereference_protected(selinux_state.policy",
        ],
        "kernel/selinux/sepolicy.c": [
            "#define avtab_for_each(avtab, cur) ksu_hash_for_each(avtab.htable, avtab.nslot, cur)",
        ],
    }
    for rel, needles in markers.items():
        text = (vendor / rel).read_text(encoding="utf-8")
        for needle in needles:
            if needle not in text:
                die(f"target ReSukiSU semantic marker missing in {rel}: {needle}")

    verify_fastfail(src)
    print("RESUKISU_35170_TARGET_CONTRACT=PASS")
    print("MODULE_LOAD_FILTER_EXCLUDED=PASS")
    print("FASTFAIL_ORDERING_AFTER_35170=PASS")


def upgrade_resukisu(src: Path) -> None:
    vendor = src / ".resukisu"
    verify_pre(src)
    run(["git", "-C", str(vendor), "fetch", "-q", "origin", TARGET_COMMIT])
    authenticate_target(vendor)
    run(["git", "-C", str(vendor), "reset", "--hard", "-q", TARGET_COMMIT])
    run(["git", "-C", str(vendor), "clean", "-fdx", "-q"])
    remove_module_filter(vendor)
    verify_target(src)
    print("RESUKISU_35158_TO_35170_PORT=PASS")


def integrate_nomount(src: Path, nm: Path) -> None:
    if git_head(nm) != NOMOUNT_COMMIT:
        die(f"NoMount HEAD mismatch: {git_head(nm)}")
    for rel, expected in NOMOUNT_BLOBS.items():
        actual = run(["git", "-C", str(nm), "rev-parse", f"HEAD:{rel}"])
        if actual != expected:
            die(f"NoMount blob mismatch {rel}: expected={expected} actual={actual}")

    dest = src / "fs/nomount"
    if dest.exists() or dest.is_symlink():
        die("fs/nomount already exists")

    sensitive = [
        "fs/open.c",
        "fs/stat.c",
        "fs/exec.c",
        "fs/susfs.c",
        "include/linux/susfs.h",
    ]
    before = {rel: sha256(src / rel) for rel in sensitive}

    src_nm = nm / "kernel/src"
    dest.mkdir(parents=True)
    for name in ("Kconfig", "Makefile", "nomount.c", "nomount.h"):
        data = (src_nm / name).read_bytes()
        (dest / name).write_bytes(data)

    kconfig = src / "fs/Kconfig"
    makefile = src / "fs/Makefile"
    kline = 'source "fs/nomount/Kconfig"'
    mline = "obj-$(CONFIG_NOMOUNT) += nomount/"

    kt = kconfig.read_text(encoding="utf-8")
    mt = makefile.read_text(encoding="utf-8")
    if kt.count(kline) != 0:
        die(f"NoMount Kconfig preimage count must be 0, got {kt.count(kline)}")
    if mt.count(mline) != 0:
        die(f"NoMount Makefile preimage count must be 0, got {mt.count(mline)}")

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

    for rel in NOMOUNT_BLOBS:
        leaf = Path(rel).name
        if sha256(dest / leaf) != sha256(nm / rel):
            die(f"NoMount copied file byte mismatch: {leaf}")

    after = {rel: sha256(src / rel) for rel in sensitive}
    if before != after:
        changed = sorted(k for k in before if before[k] != after[k])
        die(f"NoMount unexpectedly changed frozen host surfaces: {changed}")

    verify_fastfail(src)
    print("NOMOUNT_2_0_0_SOURCE_BLOBS=PASS")
    print("NOMOUNT_BUILTIN_INTEGRATION=PASS")
    print("NOMOUNT_HOST_SURFACE_FREEZE=PASS")
    print("FASTFAIL_ORDERING_AFTER_NOMOUNT=PASS")


def selftest() -> None:
    early_open = """
long do_faccessat(int dfd, const char __user *filename, int mode)
{
    int x;
    if (mode & ~S_IRWXO)
        return -EINVAL;
    x = getname_flags(filename, 0, 0);
    ksu_handle_faccessat(&dfd, &x, &mode, 0);
    return 0;
}
"""
    late_open = """
long do_faccessat(int dfd, const char __user *filename, int mode)
{
    int x;
    x = getname_flags(filename, 0, 0);
    ksu_handle_faccessat(&dfd, &x, &mode, 0);
    if (mode & ~S_IRWXO)
        return -EINVAL;
    return 0;
}
"""
    fn = function_region(early_open, "long do_faccessat(")
    ordering(fn, "if (mode & ~S_IRWXO)", ("getname_flags(", "ksu_handle_faccessat("), "open-selftest")
    bad = function_region(late_open, "long do_faccessat(")
    if bad.find("if (mode & ~S_IRWXO)") < min(
        bad.find("getname_flags("), bad.find("ksu_handle_faccessat(")
    ):
        die("ordering selftest failed to model late validation")

    with tempfile.TemporaryDirectory(prefix="golden-port-module-filter-") as td:
        root = Path(td)
        (root / "kernel/feature").mkdir(parents=True)
        (root / "kernel/core").mkdir(parents=True)
        (root / "kernel/Kbuild").write_text(
            "x\nkernelsu-objs += feature/module_load_filter.o\n", encoding="utf-8"
        )
        (root / "kernel/core/init.c").write_text(
            '#include "feature/module_load_filter.h"\n'
            'char ksu_block_modules[256];\n'
            'module_param_string(block_modules, ksu_block_modules, sizeof(ksu_block_modules), 0);\n'
            'MODULE_PARM_DESC(block_modules, "Comma-separated preset module names to acknowledge without loading");\n\n'
            '        ksu_module_load_filter_hook_init();\n\n'
            '    ksu_module_load_filter_hook_exit();\n',
            encoding="utf-8",
        )
        (root / "kernel/feature/module_load_filter.c").write_text("x\n", encoding="utf-8")
        (root / "kernel/feature/module_load_filter.h").write_text("x\n", encoding="utf-8")
        remove_module_filter(root)
        if (root / "kernel/feature/module_load_filter.c").exists():
            die("module filter selftest deletion failed")
    print("GOLDEN_PORT_HELPER_SELFTEST=PASS")


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest")

    for name in ("verify-pre", "upgrade-resukisu", "verify-target", "fastfail"):
        p = sub.add_parser(name)
        p.add_argument("--src", required=True)

    p = sub.add_parser("integrate-nomount")
    p.add_argument("--src", required=True)
    p.add_argument("--nomount", required=True)

    args = ap.parse_args()
    if args.cmd == "selftest":
        selftest()
    elif args.cmd == "verify-pre":
        verify_pre(Path(args.src).resolve())
    elif args.cmd == "upgrade-resukisu":
        upgrade_resukisu(Path(args.src).resolve())
    elif args.cmd == "verify-target":
        verify_target(Path(args.src).resolve())
    elif args.cmd == "fastfail":
        verify_fastfail(Path(args.src).resolve())
    elif args.cmd == "integrate-nomount":
        integrate_nomount(Path(args.src).resolve(), Path(args.nomount).resolve())
    else:
        die(f"unknown command {args.cmd}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
