#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys

SOURCE_COMMIT = "fb3bbb10bc0480282c01b88ccaf39c0145cd9f51"
RESUKISU_COMMIT = "6ec8d9a8a8be30878c388504cacf8ae7849c757b"
EXPECTED_KERNEL_VERSION = "5.4.292"

SURFACES = {
    "fs/Makefile": [
        "obj-y :=",
    ],
    "fs/dcache.c": [
        "__d_lookup_rcu",
        "__d_lookup(",
    ],
    "fs/exec.c": [
        "do_execveat_common",
        "__do_execve_file",
    ],
    "fs/namei.c": [
        "may_follow_link",
        "__lookup_hash",
        "__lookup_slow",
        "filename_lookup",
        "may_delete",
        "may_open",
        "lookup_open",
        "do_filp_open",
    ],
    "fs/namespace.c": [
        "mnt_alloc_id",
        "mnt_free_id",
        "mnt_alloc_group_id",
        "mnt_release_group_id",
        "alloc_vfsmnt",
        "clone_mnt",
        "copy_mnt_ns",
    ],
    "fs/notify/fdinfo.c": [
        "show_fdinfo",
    ],
    "fs/proc_namespace.c": [
        "show_vfsmnt",
        "show_mountinfo",
    ],
    "fs/statfs.c": [
        "user_statfs",
        "fd_statfs",
    ],
    "include/linux/mount.h": [
        "struct vfsmount",
    ],
    "include/linux/sched.h": [
        "struct task_struct",
    ],
    "kernel/kallsyms.c": [
        "s_show",
    ],
    "kernel/sys.c": [
        "setresuid",
    ],
    "fs/open.c": [
        "faccessat",
    ],
    "fs/read_write.c": [
        "SYSCALL_DEFINE3(read",
    ],
    "fs/stat.c": [
        "newfstatat",
    ],
    "kernel/reboot.c": [
        "SYSCALL_DEFINE4(reboot",
    ],
    "drivers/input/input.c": [
        "input_event",
    ],
}

INLINE_KSU_HOOKS = {
    "kernel/sys.c": "ksu_handle_setresuid",
    "fs/exec.c": "ksu_handle_execveat",
    "fs/open.c": "ksu_handle_faccessat",
    "fs/read_write.c": "ksu_handle_sys_read",
    "fs/stat.c": "ksu_handle_stat",
    "kernel/reboot.c": "ksu_handle_sys_reboot",
    "drivers/input/input.c": "ksu_handle_input_handle_event",
}

INCOMPATIBLE_HOOKS = {
    "fs/read_write.c": ["ksu_vfs_read_hook", "ksu_init_rc_hook"],
    "drivers/input/input.c": ["ksu_input_hook"],
    "fs/exec.c": ["ksu_execveat_hook"],
    "fs/stat.c": ["ksu_init_rc_hook"],
}

MANUAL_GUARD_FILES = [
    "kernel/sys.c",
    "fs/exec.c",
    "fs/open.c",
    "fs/read_write.c",
    "fs/stat.c",
    "kernel/reboot.c",
    "drivers/input/input.c",
]

def die(msg: str, code: int = 1) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    raise SystemExit(code)

def git(root: Path, *args: str) -> str:
    p = subprocess.run(
        ["git", "-C", str(root), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if p.returncode != 0:
        die(f"git {' '.join(args)} failed: {p.stderr.strip()}")
    return p.stdout.strip()

def read(root: Path, rel: str) -> str:
    p = root / rel
    if not p.is_file():
        die(f"required file missing: {rel}")
    return p.read_text(encoding="utf-8", errors="replace")

def audit(root: Path, strict_git: bool = True) -> int:
    root = root.resolve()

    if strict_git:
        if not (root / ".git").exists():
            die("kernel root is not a git checkout")
        head = git(root, "rev-parse", "HEAD")
        if head != SOURCE_COMMIT:
            die(f"source commit mismatch: {head}")

        rs = root / ".resukisu"
        if not (rs / ".git").exists():
            die("vendored ReSukiSU git metadata missing")
        rs_head = git(rs, "rev-parse", "HEAD")
        if rs_head != RESUKISU_COMMIT:
            die(f"ReSukiSU commit mismatch: {rs_head}")

    # Read-only structural audit.
    missing = []
    for rel, anchors in SURFACES.items():
        data = read(root, rel)
        for anchor in anchors:
            if anchor not in data:
                missing.append(f"{rel}:{anchor}")

    if missing:
        print("SURFACE_ANCHOR_AUDIT=FAIL")
        for item in missing:
            print(f"MISSING={item}")
        return 20

    # ReSukiSU inline-hook contract.
    hook_missing = []
    manual_guard = []
    incompatible = []
    for rel, hook in INLINE_KSU_HOOKS.items():
        data = read(root, rel)
        if hook not in data:
            hook_missing.append(f"{rel}:{hook}")
    for rel in MANUAL_GUARD_FILES:
        data = read(root, rel)
        if "CONFIG_KSU_MANUAL_HOOK" in data:
            manual_guard.append(rel)
    for rel, needles in INCOMPATIBLE_HOOKS.items():
        data = read(root, rel)
        for needle in needles:
            if needle in data:
                incompatible.append(f"{rel}:{needle}")

    # 5.4 Android KABI slots used by official old SUSFS branch.
    mount_h = read(root, "include/linux/mount.h")
    sched_h = read(root, "include/linux/sched.h")

    kabi_mount4 = "ANDROID_KABI_RESERVE(4)" in mount_h or "ANDROID_KABI_USE(4" in mount_h
    kabi_sched7 = "ANDROID_KABI_RESERVE(7)" in sched_h or "ANDROID_KABI_USE(7" in sched_h
    kabi_sched8 = "ANDROID_KABI_RESERVE(8)" in sched_h or "ANDROID_KABI_USE(8" in sched_h

    print("SURFACE_ANCHOR_AUDIT=PASS")
    print(f"INLINE_KSU_HOOKS_PRESENT={'YES' if not hook_missing else 'NO'}")
    for item in hook_missing:
        print(f"INLINE_HOOK_PORT_REQUIRED={item}")

    print(f"MANUAL_GUARD_FILE_COUNT={len(manual_guard)}")
    for rel in manual_guard:
        print(f"MANUAL_GUARD_PRESENT={rel}")

    print(f"INCOMPATIBLE_HOOK_COUNT={len(incompatible)}")
    for item in incompatible:
        print(f"INCOMPATIBLE_HOOK={item}")

    print(f"KABI_MOUNT_SLOT_4={'PRESENT' if kabi_mount4 else 'MISSING'}")
    print(f"KABI_TASK_SLOT_7={'PRESENT' if kabi_sched7 else 'MISSING'}")
    print(f"KABI_TASK_SLOT_8={'PRESENT' if kabi_sched8 else 'MISSING'}")

    # Classification: this audit intentionally does not mutate.
    if incompatible:
        status = "BLOCKED"
    elif not (kabi_mount4 and kabi_sched7 and kabi_sched8):
        status = "PORT_REQUIRED"
    elif hook_missing or manual_guard:
        status = "PORT_REQUIRED"
    else:
        status = "COMPATIBLE"

    print(f"SUSFS_SURFACE_CLASS={status}")
    print("SUSFS_TARGET_VERSION=2.3.0")
    print("DIRECT_PATCH_APPLICATION=NO")
    print("SOURCE_MUTATED=NO")
    return 0

def fixture(root: Path) -> None:
    # Minimal positive structure with expected 5.4 anchors and current V2 manual hooks.
    for rel in SURFACES:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        anchors = "\n".join(SURFACES[rel])
        p.write_text(anchors + "\n", encoding="utf-8")

    # KABI slots expected from VEUX Android 5.4 vendor kernels.
    (root / "include/linux/mount.h").write_text(
        "struct vfsmount {\nANDROID_KABI_RESERVE(4);\n};\n",
        encoding="utf-8",
    )
    (root / "include/linux/sched.h").write_text(
        "struct task_struct {\nANDROID_KABI_RESERVE(7);\nANDROID_KABI_RESERVE(8);\n};\n",
        encoding="utf-8",
    )

    # Simulate current ReSukiSU V2 host delta: some manual hooks present, others auto-hooked.
    for rel, hook in INLINE_KSU_HOOKS.items():
        p = root / rel
        data = p.read_text(encoding="utf-8")
        if rel in {"fs/exec.c", "fs/open.c", "fs/stat.c", "kernel/reboot.c"}:
            data += f"#ifdef CONFIG_KSU_MANUAL_HOOK\n{hook}();\n#endif\n"
        p.write_text(data, encoding="utf-8")

def selftest() -> None:
    import tempfile
    with tempfile.TemporaryDirectory(prefix="susfs-surface-audit-") as td:
        root = Path(td)
        fixture(root)
        rc = audit(root, strict_git=False)
        if rc != 0:
            die(f"fixture audit failed: {rc}")
    print("FIXTURE_SELFTEST=PASS")

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("kernel_root", nargs="?")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        selftest()
        return

    if not args.kernel_root:
        ap.error("kernel_root is required unless --selftest is used")

    raise SystemExit(audit(Path(args.kernel_root), strict_git=True))

if __name__ == "__main__":
    main()
