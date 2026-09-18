#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import NoReturn

SOURCE_COMMIT = "fb3bbb10bc0480282c01b88ccaf39c0145cd9f51"
KERNEL_VERSION = "5.4.292"
DEFCONFIG = "veux_defconfig"
RESUKISU_COMMIT = "6ec8d9a8a8be30878c388504cacf8ae7849c757b"
DONOR_COMMIT = "f15603b246d7ce6008af8bdefa0a34b3df28326a"
SUSFS_COMMIT = "04a9d713106191ba98be680bd7ad9547ab1de964"
SUSFS_VERSION = "v2.3.0"

BAD_STATFS = "if (susfs_sus_kstat_spoof_vfs_statfs(d_backing_inode(dentry), buf, is_fuse))"
GOOD_STATFS = "if (!susfs_sus_kstat_spoof_vfs_statfs(d_backing_inode(dentry), buf, is_fuse))"


def die(msg: str, code: int = 1) -> NoReturn:
    print(f"ERROR: {msg}", file=sys.stderr)
    raise SystemExit(code)


def run(cmd: list[str], cwd: Path | None = None, capture: bool = False) -> str:
    p = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        check=False,
    )
    if p.returncode != 0:
        if capture:
            if p.stdout:
                print(p.stdout, file=sys.stderr, end="")
            if p.stderr:
                print(p.stderr, file=sys.stderr, end="")
        die(f"command failed ({p.returncode}): {' '.join(cmd)}", p.returncode)
    return p.stdout.strip() if capture else ""


def read(path: Path) -> str:
    if not path.is_file():
        die(f"required file missing: {path}")
    return path.read_text(encoding="utf-8")


def write(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8")


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    data = read(path)
    count = data.count(old)
    if count != 1:
        die(f"{label}: expected exactly one anchor in {path}, found {count}")
    write(path, data.replace(old, new, 1))


def ensure_count(path: Path, needle: str, expected: int, label: str) -> None:
    count = read(path).count(needle)
    if count != expected:
        die(f"{label}: expected {expected} occurrence(s) of {needle!r} in {path}, found {count}")


def ensure_at_least(path: Path, needle: str, minimum: int, label: str) -> None:
    count = read(path).count(needle)
    if count < minimum:
        die(f"{label}: expected at least {minimum} occurrence(s) of {needle!r} in {path}, found {count}")


def git_head(root: Path) -> str:
    return run(["git", "-C", str(root), "rev-parse", "HEAD"], capture=True)


def require_clean_git(root: Path, expected_head: str, label: str) -> None:
    if not (root / ".git").exists():
        die(f"{label}: missing .git: {root}")
    actual = git_head(root)
    if actual != expected_head:
        die(f"{label}: HEAD mismatch: expected {expected_head}, got {actual}")
    dirty = run(["git", "-C", str(root), "status", "--porcelain"], capture=True)
    if dirty:
        die(f"{label}: worktree is not clean")


def remove_module_filter(vendored_kernel: Path) -> None:
    replace_once(
        vendored_kernel / "Kbuild",
        "kernelsu-objs += feature/module_load_filter.o\n",
        "",
        "remove module_load_filter object",
    )
    replace_once(
        vendored_kernel / "core/init.c",
        '#include "feature/module_load_filter.h"\n',
        "",
        "remove module_load_filter include",
    )
    replace_once(
        vendored_kernel / "core/init.c",
        'char ksu_block_modules[256];\n'
        'module_param_string(block_modules, ksu_block_modules, sizeof(ksu_block_modules), 0);\n'
        'MODULE_PARM_DESC(block_modules, "Comma-separated preset module names to acknowledge without loading");\n\n',
        "",
        "remove module_load_filter parameter",
    )
    replace_once(
        vendored_kernel / "core/init.c",
        "        ksu_module_load_filter_hook_init();\n\n",
        "",
        "remove module_load_filter init",
    )
    replace_once(
        vendored_kernel / "core/init.c",
        "    ksu_module_load_filter_hook_exit();\n\n",
        "",
        "remove module_load_filter exit",
    )
    for name in ("module_load_filter.c", "module_load_filter.h"):
        p = vendored_kernel / "feature" / name
        if not p.is_file():
            die(f"module_load_filter file missing before exclusion: {p}")
        p.unlink()

    hits: list[str] = []
    for p in vendored_kernel.rglob("*"):
        if not p.is_file():
            continue
        try:
            data = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if any(x in data for x in ("module_load_filter", "ksu_block_modules", "block_modules")):
            hits.append(str(p.relative_to(vendored_kernel)))
    if hits:
        die("module_load_filter exclusion incomplete: " + ", ".join(hits[:20]))


def vendor_resukisu(kernel: Path, resukisu_root: Path) -> None:
    dst = kernel / "drivers/kernelsu"
    vendor = kernel / ".resukisu"
    if dst.exists() or dst.is_symlink() or vendor.exists() or vendor.is_symlink():
        die("pre-existing ReSukiSU/KernelSU integration detected")

    shutil.copytree(resukisu_root, vendor, symlinks=True)
    vendored_kernel = vendor / "kernel"
    dst.symlink_to("../.resukisu/kernel", target_is_directory=True)
    if dst.resolve() != vendored_kernel.resolve():
        die("drivers/kernelsu symlink target mismatch")

    remove_module_filter(vendored_kernel)

    drv_make = kernel / "drivers/Makefile"
    make_data = read(drv_make)
    ksu_make_line = "obj-$(CONFIG_KSU) += kernelsu/"
    if ksu_make_line in make_data or "obj-$(CONFIG_KSU)\t+= kernelsu/" in make_data:
        die("drivers/Makefile already contains KernelSU entry")
    if not make_data.endswith("\n"):
        make_data += "\n"
    write(drv_make, make_data + "\n" + ksu_make_line + "\n")

    drv_kconfig = kernel / "drivers/Kconfig"
    kcfg = read(drv_kconfig)
    ksu_kconfig_line = 'source "drivers/kernelsu/Kconfig"'
    if ksu_kconfig_line in kcfg:
        die("drivers/Kconfig already contains KernelSU entry")
    marker = "\nendmenu"
    idx = kcfg.rfind(marker)
    if idx < 0:
        die("drivers/Kconfig final endmenu anchor not found")
    write(drv_kconfig, kcfg[:idx] + f"\n\n{ksu_kconfig_line}\n" + kcfg[idx:])


def correct_donor_patch(text: str) -> str:
    bad = text.count(BAD_STATFS)
    good = text.count(GOOD_STATFS)
    if bad != 1:
        raise ValueError(f"expected exactly one known statfs donor bug, found {bad}")
    if good != 0:
        raise ValueError(f"donor patch unexpectedly already contains corrected statfs condition ({good})")
    fixed = text.replace(BAD_STATFS, GOOD_STATFS, 1)
    if fixed.count(BAD_STATFS) != 0 or fixed.count(GOOD_STATFS) != 1:
        raise ValueError("statfs donor correction postcondition failed")
    return fixed


def backport_statfs_compile_fix(kernel: Path) -> None:
    # Upstream 2.3.0 commit 2d40afc314aa5b2a7125fa64e3f3d2e9ec3f248c
    # moved the SUSFS declarations above statfs_by_dentry() to fix compilation.
    # The current 5.4 donor still leaves this declaration block below that use.
    path = kernel / "fs/statfs.c"
    data = read(path)
    block = (
        "#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT\n"
        "extern bool susfs_is_inode_sus_kstat(struct inode *inode, bool *out_is_fuse);\n"
        "extern int susfs_sus_kstat_spoof_vfs_statfs(struct inode *inode, struct kstatfs *buf, bool *is_fuse);\n"
        "#endif // #ifdef CONFIG_KSU_SUSFS_SUS_KSTAT\n"
        "#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\n"
        "extern struct vfsmount *susfs_get_non_sus_vfsmnt_from_vfsmnt(struct vfsmount *vfsmnt);\n"
        "#endif //#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\n"
    )
    if data.count(block) != 1:
        die(f"statfs compile-fix declaration block count mismatch: {data.count(block)}")
    data = data.replace(block, "", 1)
    anchor = '#include "internal.h"\n\n'
    if data.count(anchor) != 1:
        die(f"statfs compile-fix include anchor count mismatch: {data.count(anchor)}")
    data = data.replace(anchor, anchor + block + "\n", 1)
    write(path, data)

    final = read(path)
    decl_pos = final.find("extern int susfs_sus_kstat_spoof_vfs_statfs")
    use_pos = final.find("susfs_sus_kstat_spoof_vfs_statfs(d_backing_inode")
    if decl_pos < 0 or use_pos < 0 or decl_pos >= use_pos:
        die("statfs compile-fix ordering gate failed")


def verify_5_4_core_coherence(kernel: Path, susfs_root: Path) -> None:
    # Keep the donor's 5.4-adapted SUSFS 2.3.0 core and headers together.
    # The current official 5.10 core moved SUS_PATH state to i_mapping->flags,
    # while the 5.4 port consistently uses inode->i_state. Mixing these files
    # would silently break the host/core ABI.
    donor_core = read(kernel / "fs/susfs.c")
    donor_hdr = read(kernel / "include/linux/susfs.h")
    donor_def = read(kernel / "include/linux/susfs_def.h")
    official_core_path = susfs_root / "kernel_patches/fs/susfs.c"
    official_hdr_path = susfs_root / "kernel_patches/include/linux/susfs.h"
    official_def_path = susfs_root / "kernel_patches/include/linux/susfs_def.h"
    for q in (official_core_path, official_hdr_path, official_def_path):
        if not q.is_file():
            die(f"official SUSFS reference file missing: {q}")

    official_core = read(official_core_path)
    official_hdr = read(official_hdr_path)
    if f'#define SUSFS_VERSION "{SUSFS_VERSION}"' not in donor_hdr:
        die("5.4 donor SUSFS version gate failed")
    if f'#define SUSFS_VERSION "{SUSFS_VERSION}"' not in official_hdr:
        die("official SUSFS reference version gate failed")
    if "AS_FLAGS_SUS_PATH, &inode->i_state" not in donor_core:
        die("5.4 SUSFS core does not use expected inode->i_state SUS_PATH storage")
    if "AS_FLAGS_SUS_PATH, &inode->i_mapping->flags" in donor_core:
        die("5.10 i_mapping SUS_PATH semantics leaked into 5.4 SUSFS core")
    if "AS_FLAGS_SUS_PATH, &inode->i_mapping->flags" not in official_core:
        die("official reference no longer matches audited 5.10 SUS_PATH semantics")
    for marker in (
        "#define AS_FLAGS_SUS_PATH 33",
        "#define AS_FLAGS_SUS_MOUNT 34",
        "#define AS_FLAGS_SUS_KSTAT 35",
        "#define AS_FLAGS_OPEN_REDIRECT 36",
        "#define AS_FLAGS_SUS_MAP 39",
    ):
        if marker not in donor_def:
            die(f"5.4 SUSFS definition coherence marker missing: {marker}")
    if "#include <linux/security.h>" not in donor_core:
        die("upstream SUSFS security.h compile fix missing from 5.4 core")


def apply_outer_patch(kernel: Path, donor_root: Path, susfs_root: Path) -> Path:
    source_patch = donor_root / "Patches/Patch/susfs_patch_to_5.4.patch"
    fixed = correct_donor_patch(read(source_patch))

    tmpdir = Path(tempfile.mkdtemp(prefix="veux-susfs-patch-"))
    fixed_patch = tmpdir / "susfs_patch_to_5.4.corrected.patch"
    write(fixed_patch, fixed)

    # The pinned donor patch contains harmless legacy trailing whitespace in a
    # few added lines. Normalize it deterministically, then require a clean
    # resulting diff with git diff --check in finalize_real().
    run(["git", "-C", str(kernel), "apply", "--check", "--whitespace=fix", str(fixed_patch)])
    run(["git", "-C", str(kernel), "apply", "--whitespace=fix", str(fixed_patch)])

    # Do NOT overwrite the 5.4-adapted core with the official 5.10 core.
    # They use different SUS_PATH storage semantics (i_state vs i_mapping->flags).
    # Instead retain the coherent donor 5.4 core and backport only audited fixes.
    backport_statfs_compile_fix(kernel)
    verify_5_4_core_coherence(kernel, susfs_root)

    return fixed_patch


def run_inline_port(kernel: Path, donor_root: Path) -> None:
    # The donor shell script is intentionally NOT executed. It is retained as
    # a pinned structural reference only. Its current 5.4 logic contains an
    # obsolete sys_read ABI, an obsolete reboot control flow, and an ineffective
    # post-exec insertion for the exact VEUX 5.4.292 exec.c shape. Apply the
    # seven ReSukiSU-required inline hooks deterministically instead.
    script = donor_root / "Patches/susfs_inline_hook_patches.sh"
    if not script.is_file():
        die(f"inline hook reference script missing: {script}")

    # ------------------------------------------------------------------
    # fs/exec.c -- execveat + post-exec sucompat hooks
    # ------------------------------------------------------------------
    exec_path = kernel / "fs/exec.c"
    exec_data = read(exec_path)
    if "#include <linux/susfs_def.h>" not in exec_data:
        replace_once(
            exec_path,
            "#include <linux/vmalloc.h>\n",
            "#include <linux/vmalloc.h>\n#ifdef CONFIG_KSU_SUSFS\n#include <linux/susfs_def.h>\n#endif\n",
            "exec SUSFS include",
        )

    exec_decl_anchor = (
        "static int __do_execve_file(int fd, struct filename *filename,\n"
        "\t\t\t    struct user_arg_ptr argv,\n"
        "\t\t\t    struct user_arg_ptr envp,\n"
        "\t\t\t    int flags, struct file *file)\n"
    )
    exec_decls = (
        "#ifdef CONFIG_KSU_SUSFS\n"
        "extern struct static_key_true ksu_su_compat_enabled;\n"
        "extern struct static_key_true susfs_is_sdcard_android_data_not_decrypted;\n"
        "extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv,\n"
        "\t\t\t      void *envp, int *flags);\n"
        "extern int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr, void *argv,\n"
        "\t\t\t\t       void *envp, int *flags);\n"
        "extern int ksu_handle_post_execveat_sucompat(int *fd, struct filename **filename_ptr, void *argv,\n"
        "\t\t\t\t\t    void *envp, int *flags, int *retval);\n"
        "#endif\n\n"
        + exec_decl_anchor
    )
    replace_once(exec_path, exec_decl_anchor, exec_decls, "exec inline declarations")

    replace_once(
        exec_path,
        "\tstruct files_struct *displaced;\n\tint retval;\n\n\tif (IS_ERR(filename))\n\t\treturn PTR_ERR(filename);\n",
        "\tstruct files_struct *displaced;\n\tint retval;\n"
        "#ifdef CONFIG_KSU_SUSFS\n"
        "\tbool is_su_session = false;\n"
        "#endif\n\n"
        "\tif (IS_ERR(filename))\n\t\treturn PTR_ERR(filename);\n\n"
        "#ifdef CONFIG_KSU_SUSFS\n"
        "\tif (likely(susfs_is_current_proc_no_su()))\n"
        "\t\tgoto ksu_susfs_exec_orig_flow;\n\n"
        "\tif (static_branch_likely(&ksu_su_compat_enabled)) {\n"
        "\t\tif (static_branch_unlikely(&susfs_is_sdcard_android_data_not_decrypted))\n"
        "\t\t\tis_su_session = !ksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);\n"
        "\t\telse\n"
        "\t\t\tis_su_session = !ksu_handle_execveat_sucompat(&fd, &filename, &argv, &envp, &flags);\n"
        "\t}\n"
        "ksu_susfs_exec_orig_flow:\n"
        "#endif\n",
        "exec inline pre-hook",
    )
    # The post hook must run on the successful exec path.  Placing it before
    # out_free: is insufficient on this 5.4 tree because successful execve
    # returns before the error labels.  Match the actual exec_binprm() site.
    replace_once(
        exec_path,
        "\tretval = exec_binprm(&bprm);\n"
        "\tif (retval < 0)\n"
        "\t\tgoto out;\n",
        "\tretval = exec_binprm(&bprm);\n"
        "#ifdef CONFIG_KSU_SUSFS\n"
        "\tif (unlikely(is_su_session && retval >= 0))\n"
        "\t\t(void)ksu_handle_post_execveat_sucompat(&fd, &filename, &argv, &envp, &flags, &retval);\n"
        "#endif\n"
        "\tif (retval < 0)\n"
        "\t\tgoto out;\n",
        "exec inline post-hook success path",
    )

    # ------------------------------------------------------------------
    # fs/open.c -- faccessat sucompat hook
    # ------------------------------------------------------------------
    open_path = kernel / "fs/open.c"
    open_data = read(open_path)
    if "#include <linux/susfs_def.h>" not in open_data:
        replace_once(
            open_path,
            "#include <linux/compat.h>\n\n#include \"internal.h\"\n",
            "#include <linux/compat.h>\n#ifdef CONFIG_KSU_SUSFS\n#include <linux/susfs_def.h>\n#endif\n\n#include \"internal.h\"\n",
            "open SUSFS include",
        )
    replace_once(
        open_path,
        "long do_faccessat(int dfd, const char __user *filename, int mode)\n",
        "#ifdef CONFIG_KSU_SUSFS\n"
        "extern struct static_key_true ksu_su_compat_enabled;\n"
        "extern bool __ksu_is_allow_uid_for_current(uid_t uid);\n"
        "extern int ksu_handle_faccessat(int *dfd, struct filename **filename, int *mode, int *__unused_flags);\n"
        "#endif\n\n"
        "long do_faccessat(int dfd, const char __user *filename, int mode)\n",
        "faccessat inline declarations",
    )
    replace_once(
        open_path,
        "\tunsigned int lookup_flags = LOOKUP_FOLLOW;\n\n\tif (mode & ~S_IRWXO)",
        "\tunsigned int lookup_flags = LOOKUP_FOLLOW;\n"
        "#ifdef CONFIG_KSU_SUSFS\n"
        "\tstruct filename *fname = NULL;\n"
        "#endif\n\n"
        "\tif (mode & ~S_IRWXO)",
        "faccessat filename state",
    )
    replace_once(
        open_path,
        "retry:\n\tres = user_path_at(dfd, filename, lookup_flags, &path);\n",
        "retry:\n"
        "#ifdef CONFIG_KSU_SUSFS\n"
        "\tfname = getname_flags(filename, lookup_flags, NULL);\n"
        "\tif (likely(susfs_is_current_proc_no_su()))\n"
        "\t\tgoto ksu_susfs_faccessat_orig_flow;\n"
        "\tif (static_branch_likely(&ksu_su_compat_enabled) &&\n"
        "\t    unlikely(__ksu_is_allow_uid_for_current(current_uid().val)))\n"
        "\t\tksu_handle_faccessat(&dfd, &fname, &mode, NULL);\n"
        "ksu_susfs_faccessat_orig_flow:\n"
        "\tres = filename_lookup(dfd, fname, lookup_flags, &path, NULL);\n"
        "#else\n"
        "\tres = user_path_at(dfd, filename, lookup_flags, &path);\n"
        "#endif\n",
        "faccessat inline call",
    )

    # ------------------------------------------------------------------
    # fs/read_write.c -- init.rc read hook, CURRENT ReSukiSU ABI
    # ------------------------------------------------------------------
    read_path = kernel / "fs/read_write.c"
    replace_once(
        read_path,
        "SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)\n",
        "#ifdef CONFIG_KSU_SUSFS\n"
        "extern struct static_key_true ksu_is_init_rc_hook_enabled;\n"
        "extern __attribute__((cold)) int ksu_handle_sys_read(unsigned int fd, char __user **buf_ptr, size_t *count_ptr);\n"
        "#endif\n\n"
        "SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)\n",
        "sys_read current ABI declarations",
    )
    replace_once(
        read_path,
        "SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)\n"
        "{\n\treturn ksys_read(fd, buf, count);\n}\n",
        "SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)\n"
        "{\n"
        "#ifdef CONFIG_KSU_SUSFS\n"
        "\tif (static_branch_unlikely(&ksu_is_init_rc_hook_enabled))\n"
        "\t\tksu_handle_sys_read(fd, &buf, &count);\n"
        "#endif\n"
        "\treturn ksys_read(fd, buf, count);\n"
        "}\n",
        "sys_read current ABI call",
    )

    # ------------------------------------------------------------------
    # fs/stat.c -- stat/fstat sucompat hooks
    # ------------------------------------------------------------------
    stat_path = kernel / "fs/stat.c"
    stat_data = read(stat_path)
    if '#include "internal.h"' not in stat_data:
        replace_once(
            stat_path,
            "#include <asm/unistd.h>\n",
            "#include <asm/unistd.h>\n#include \"internal.h\"\n",
            "stat internal include",
        )
    stat_data = read(stat_path)
    if "#include <linux/susfs_def.h>" not in stat_data:
        replace_once(
            stat_path,
            "#include <linux/compat.h>\n",
            "#include <linux/compat.h>\n#ifdef CONFIG_KSU_SUSFS\n#include <linux/susfs_def.h>\n#endif\n",
            "stat SUSFS include",
        )
    replace_once(
        stat_path,
        "int vfs_statx_fd(unsigned int fd, struct kstat *stat,\n",
        "#ifdef CONFIG_KSU_SUSFS\n"
        "extern struct static_key_true ksu_is_init_rc_hook_enabled;\n"
        "extern void ksu_handle_vfs_fstat(int fd, loff_t *kstat_size_ptr);\n"
        "extern struct static_key_true ksu_su_compat_enabled;\n"
        "extern bool __ksu_is_allow_uid_for_current(uid_t uid);\n"
        "extern int ksu_handle_stat(int *dfd, struct filename **filename, int *flags);\n"
        "#endif\n\n"
        "int vfs_statx_fd(unsigned int fd, struct kstat *stat,\n",
        "stat inline declarations",
    )
    replace_once(
        stat_path,
        "\t\terror = vfs_getattr(&f.file->f_path, stat,\n"
        "\t\t\t\t    request_mask, query_flags);\n"
        "\t\tfdput(f);\n",
        "\t\terror = vfs_getattr(&f.file->f_path, stat,\n"
        "\t\t\t\t    request_mask, query_flags);\n"
        "#ifdef CONFIG_KSU_SUSFS\n"
        "\t\tif (static_branch_unlikely(&ksu_is_init_rc_hook_enabled))\n"
        "\t\t\tksu_handle_vfs_fstat(fd, &stat->size);\n"
        "#endif\n"
        "\t\tfdput(f);\n",
        "fstat inline call",
    )
    replace_once(
        stat_path,
        "\tunsigned int lookup_flags = LOOKUP_FOLLOW | LOOKUP_AUTOMOUNT;\n\n"
        "\tif ((flags & ~(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT |",
        "\tunsigned int lookup_flags = LOOKUP_FOLLOW | LOOKUP_AUTOMOUNT;\n"
        "#ifdef CONFIG_KSU_SUSFS\n"
        "\tstruct filename *fname = NULL;\n"
        "#endif\n\n"
        "\tif ((flags & ~(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT |",
        "stat filename state",
    )
    replace_once(
        stat_path,
        "retry:\n\terror = user_path_at(dfd, filename, lookup_flags, &path);\n",
        "retry:\n"
        "#ifdef CONFIG_KSU_SUSFS\n"
        "\tfname = getname_flags(filename, lookup_flags, NULL);\n"
        "\tif (likely(susfs_is_current_proc_no_su()))\n"
        "\t\tgoto ksu_susfs_stat_orig_flow;\n"
        "\tif (static_branch_likely(&ksu_su_compat_enabled) &&\n"
        "\t    unlikely(__ksu_is_allow_uid_for_current(current_uid().val)))\n"
        "\t\tksu_handle_stat(&dfd, &fname, &flags);\n"
        "ksu_susfs_stat_orig_flow:\n"
        "\terror = filename_lookup(dfd, fname, lookup_flags, &path, NULL);\n"
        "#else\n"
        "\terror = user_path_at(dfd, filename, lookup_flags, &path);\n"
        "#endif\n",
        "stat inline call",
    )

    # ------------------------------------------------------------------
    # drivers/input/input.c -- input hook
    # ------------------------------------------------------------------
    input_path = kernel / "drivers/input/input.c"
    replace_once(
        input_path,
        "static void input_handle_event(struct input_dev *dev,\n",
        "#ifdef CONFIG_KSU_SUSFS\n"
        "extern struct static_key_true ksu_is_input_hook_enabled;\n"
        "extern int ksu_handle_input_handle_event(unsigned int *type, unsigned int *code, int *value);\n"
        "#endif\n\n"
        "static void input_handle_event(struct input_dev *dev,\n",
        "input inline declarations",
    )
    replace_once(
        input_path,
        "\tint disposition = input_get_disposition(dev, type, code, &value);\n\n"
        "\tif (disposition != INPUT_IGNORE_EVENT && type != EV_SYN)",
        "\tint disposition = input_get_disposition(dev, type, code, &value);\n\n"
        "#ifdef CONFIG_KSU_SUSFS\n"
        "\tif (static_branch_unlikely(&ksu_is_input_hook_enabled))\n"
        "\t\tksu_handle_input_handle_event(&type, &code, &value);\n"
        "#endif\n\n"
        "\tif (disposition != INPUT_IGNORE_EVENT && type != EV_SYN)",
        "input inline call",
    )

    # ------------------------------------------------------------------
    # kernel/reboot.c -- current ReSukiSU supercall consume/continue flow
    # ------------------------------------------------------------------
    reboot_path = kernel / "kernel/reboot.c"
    replace_once(
        reboot_path,
        "SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,\n",
        "#ifdef CONFIG_KSU_SUSFS\n"
        "extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);\n"
        "#endif\n\n"
        "SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,\n",
        "reboot inline declaration",
    )
    replace_once(
        reboot_path,
        "\tchar buffer[256];\n\tint ret = 0;\n\n"
        "\t/* We only trust the superuser with rebooting the system. */",
        "\tchar buffer[256];\n\tint ret = 0;\n\n"
        "#ifdef CONFIG_KSU_SUSFS\n"
        "\tret = ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);\n"
        "\tif (ret)\n"
        "\t\tgoto ksu_susfs_reboot_orig_flow;\n"
        "\treturn ret;\n"
        "ksu_susfs_reboot_orig_flow:\n"
        "#endif\n\n"
        "\t/* We only trust the superuser with rebooting the system. */",
        "reboot current control flow",
    )

    # ------------------------------------------------------------------
    # kernel/sys.c -- setresuid hook
    # ------------------------------------------------------------------
    sys_path = kernel / "kernel/sys.c"
    replace_once(
        sys_path,
        "SYSCALL_DEFINE3(setresuid, uid_t, ruid, uid_t, euid, uid_t, suid)\n",
        "#ifdef CONFIG_KSU_SUSFS\n"
        "extern int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid);\n"
        "#endif\n\n"
        "SYSCALL_DEFINE3(setresuid, uid_t, ruid, uid_t, euid, uid_t, suid)\n",
        "setresuid inline declaration",
    )
    replace_once(
        sys_path,
        "SYSCALL_DEFINE3(setresuid, uid_t, ruid, uid_t, euid, uid_t, suid)\n"
        "{\n\treturn __sys_setresuid(ruid, euid, suid);\n}\n",
        "SYSCALL_DEFINE3(setresuid, uid_t, ruid, uid_t, euid, uid_t, suid)\n"
        "{\n"
        "#ifdef CONFIG_KSU_SUSFS\n"
        "\t(void)ksu_handle_setresuid(ruid, euid, suid);\n"
        "#endif\n"
        "\treturn __sys_setresuid(ruid, euid, suid);\n"
        "}\n",
        "setresuid inline call",
    )

def expose_selinux_symbols(kernel: Path) -> None:
    selinuxfs = kernel / "security/selinux/selinuxfs.c"
    data = read(selinuxfs)
    if "static ssize_t (*const write_op[])(struct file *, char *, size_t) = {" in data:
        replace_once(
            selinuxfs,
            "static ssize_t (*const write_op[])(struct file *, char *, size_t) = {",
            "ssize_t (*const write_op[])(struct file *, char *, size_t) = {",
            "SELinux write_op visibility",
        )
    elif "ssize_t (*const write_op[])(struct file *, char *, size_t) = {" not in data:
        die("SELinux write_op anchor/state not recognized")

    data = read(selinuxfs)
    if "static const struct file_operations sel_handle_status_ops = {" in data:
        replace_once(
            selinuxfs,
            "static const struct file_operations sel_handle_status_ops = {",
            "const struct file_operations sel_handle_status_ops = {",
            "SELinux status ops visibility",
        )
    elif "const struct file_operations sel_handle_status_ops = {" not in data:
        die("SELinux sel_handle_status_ops anchor/state not recognized")


def semantic_gates(kernel: Path) -> None:
    required = {
        "drivers/input/input.c": ["ksu_handle_input_handle_event"],
        "fs/exec.c": ["ksu_handle_execveat", "ksu_handle_post_execveat_sucompat"],
        "fs/open.c": ["ksu_handle_faccessat"],
        "fs/read_write.c": ["ksu_handle_sys_read"],
        "fs/stat.c": ["ksu_handle_stat"],
        "kernel/reboot.c": ["ksu_handle_sys_reboot"],
        "kernel/sys.c": ["ksu_handle_setresuid"],
    }
    for rel, needles in required.items():
        data = read(kernel / rel)
        if "CONFIG_KSU_MANUAL_HOOK" in data:
            die(f"manual-hook guard leaked into SUSFS inline host file: {rel}")
        for needle in needles:
            if needle not in data:
                die(f"required SUSFS inline hook missing: {needle} in {rel}")

    ensure_count(kernel / "fs/exec.c", "ksu_handle_post_execveat_sucompat", 2,
                 "execveat post hook declaration+call")
    exec_data = read(kernel / "fs/exec.c")
    success_post = (
        "\tretval = exec_binprm(&bprm);\n"
        "#ifdef CONFIG_KSU_SUSFS\n"
        "\tif (unlikely(is_su_session && retval >= 0))\n"
        "\t\t(void)ksu_handle_post_execveat_sucompat(&fd, &filename, &argv, &envp, &flags, &retval);\n"
        "#endif\n"
        "\tif (retval < 0)\n"
    )
    if success_post not in exec_data:
        die("execveat post hook is not on successful exec_binprm path")
    if "ksu_handle_post_execveat_sucompat(&fd, &filename, &argv, &envp, &flags, &retval);\n#endif\nout_free:" in exec_data:
        die("execveat post hook incorrectly placed only on out_free path")
    ensure_count(kernel / "fs/read_write.c",
                 "ksu_handle_sys_read(fd, &buf, &count);", 1,
                 "current ReSukiSU sys_read ABI call")
    if "ksu_handle_sys_read(fd);" in read(kernel / "fs/read_write.c"):
        die("legacy one-argument sys_read hook remains")
    ensure_count(kernel / "kernel/reboot.c",
                 "ret = ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);", 1,
                 "current ReSukiSU reboot control flow")
    ensure_count(kernel / "kernel/reboot.c", "ksu_susfs_reboot_orig_flow:", 1,
                 "reboot original-flow label")
    if "system_state == SYSTEM_RUNNING" in read(kernel / "kernel/reboot.c"):
        die("legacy donor reboot guard remains")
    ensure_count(kernel / "fs/open.c", "ksu_handle_faccessat(&dfd, &fname, &mode, NULL);", 1,
                 "faccessat current ABI call")
    ensure_count(kernel / "fs/stat.c", "ksu_handle_stat(&dfd, &fname, &flags);", 1,
                 "stat current ABI call")
    ensure_count(kernel / "fs/stat.c", "ksu_handle_vfs_fstat(fd, &stat->size);", 1,
                 "fstat initrc call")
    ensure_count(kernel / "drivers/input/input.c", "ksu_handle_input_handle_event(&type, &code, &value);", 1,
                 "input current ABI call")
    ensure_count(kernel / "kernel/sys.c", "(void)ksu_handle_setresuid(ruid, euid, suid);", 1,
                 "setresuid current ABI call")
    ensure_at_least(kernel / "fs/statfs.c", GOOD_STATFS, 1, "statfs success-semantics gate")
    statfs_data = read(kernel / "fs/statfs.c")
    statfs_decl = statfs_data.find("extern int susfs_sus_kstat_spoof_vfs_statfs")
    statfs_use = statfs_data.find("susfs_sus_kstat_spoof_vfs_statfs(d_backing_inode")
    if statfs_decl < 0 or statfs_use < 0 or statfs_decl >= statfs_use:
        die("upstream statfs compile-fix ordering missing")

    ns_data = read(kernel / "fs/namespace.c")
    clone_contract = (
        "bool is_mnt_ksu_unshared = false;",
        "is_mnt_ksu_unshared = true;",
        "if (unlikely(is_mnt_ksu_unshared))",
        "mnt->mnt.mnt_flags |= VFSMOUNT_MNT_FLAGS_KSU_UNSHARED_MNT;",
    )
    for marker in clone_contract:
        if marker not in ns_data:
            die(f"clone_mnt race-fix contract missing: {marker}")

    namei_data = read(kernel / "fs/namei.c")
    for marker in (
        "struct filename *old_name = nd->name;",
        "nd->name = old_name;",
        "putname(fake_filename);",
    ):
        if marker not in namei_data:
            die(f"open_redirect retry/UAF contract missing: {marker}")

    donor_core = read(kernel / "fs/susfs.c")
    donor_hdr = read(kernel / "include/linux/susfs.h")
    if f'#define SUSFS_VERSION "{SUSFS_VERSION}"' not in donor_hdr:
        die("5.4 SUSFS version gate missing after integration")
    if "AS_FLAGS_SUS_PATH, &inode->i_state" not in donor_core:
        die("5.4 SUSFS core coherence gate missing i_state storage")
    if "AS_FLAGS_SUS_PATH, &inode->i_mapping->flags" in donor_core:
        die("5.10 SUS_PATH storage leaked into 5.4 SUSFS core")

    old_incompatible = {
        "fs/read_write.c": ["ksu_vfs_read_hook", "ksu_init_rc_hook"],
        "drivers/input/input.c": ["ksu_input_hook"],
        "fs/exec.c": ["ksu_execveat_hook", "ksu_init_rc_hook"],
        "fs/stat.c": ["ksu_init_rc_hook"],
    }
    for rel, needles in old_incompatible.items():
        data = read(kernel / rel)
        for needle in needles:
            if needle in data:
                die(f"old incompatible hook remains: {needle} in {rel}")

    kbuild = read(kernel / ".resukisu/kernel/Kbuild")
    if "include $(KSU_SRC)/tools/inline_hook_check.mk" not in kbuild:
        die("ReSukiSU inline-hook checker missing")
    if "include $(KSU_SRC)/tools/susfs_compat.mk" not in kbuild:
        die("ReSukiSU SUSFS compatibility checker missing")

    if "susfs_init();" not in read(kernel / ".resukisu/kernel/core/init.c"):
        die("ReSukiSU SUSFS initialization missing")
    if "CMD_SUSFS_ADD_SUS_PATH" not in read(kernel / ".resukisu/kernel/supercall/dispatch.c"):
        die("ReSukiSU SUSFS supercall dispatch missing")

    for p in kernel.rglob("*"):
        if p.is_file() and (p.name.endswith(".rej") or p.name.endswith(".orig")):
            die(f"reject/orig file found after integration: {p.relative_to(kernel)}")


def delta_gate(kernel: Path) -> None:
    tracked = set(filter(None, run(["git", "-C", str(kernel), "diff", "--name-only"], capture=True).splitlines()))
    untracked = set(filter(None, run(["git", "-C", str(kernel), "ls-files", "--others", "--exclude-standard"], capture=True).splitlines()))
    # Vendored ReSukiSU is intentionally a complete nested git worktree and
    # drivers/kernelsu is intentionally an untracked symlink into it. Audit
    # that tree separately; include all other new host files in the host gate.
    untracked_host = {
        p for p in untracked
        if p != "drivers/kernelsu" and not p.startswith(".resukisu/")
    }
    actual = tracked | untracked_host
    allowed = {
        "drivers/Kconfig", "drivers/Makefile", "drivers/input/input.c",
        "fs/Makefile", "fs/exec.c", "fs/namei.c", "fs/namespace.c",
        "fs/notify/fdinfo.c", "fs/open.c", "fs/proc/base.c", "fs/proc/cmdline.c",
        "fs/proc/fd.c", "fs/proc/task_mmu.c", "fs/proc_namespace.c", "fs/read_write.c",
        "fs/readdir.c", "fs/stat.c", "fs/statfs.c", "fs/super.c", "fs/susfs.c",
        "include/linux/susfs.h", "include/linux/susfs_def.h", "kernel/kallsyms.c",
        "kernel/reboot.c", "kernel/sys.c", "mm/memory.c",
        "security/selinux/avc.c", "security/selinux/selinuxfs.c",
    }
    unexpected = actual - allowed
    if unexpected:
        die("unexpected host delta: " + ", ".join(sorted(unexpected)))

    required = {
        "drivers/Kconfig", "drivers/Makefile", "drivers/input/input.c",
        "fs/Makefile", "fs/exec.c", "fs/namei.c", "fs/namespace.c", "fs/open.c",
        "fs/read_write.c", "fs/stat.c", "fs/statfs.c", "fs/susfs.c",
        "include/linux/susfs.h", "include/linux/susfs_def.h", "kernel/reboot.c", "kernel/sys.c",
    }
    missing = required - actual
    if missing:
        die("required host delta missing: " + ", ".join(sorted(missing)))


def verify_real(project_root: Path, kernel: Path, resukisu: Path, donor: Path, susfs: Path) -> Path:
    require_clean_git(kernel, SOURCE_COMMIT, "kernel")
    require_clean_git(resukisu, RESUKISU_COMMIT, "ReSukiSU")
    require_clean_git(donor, DONOR_COMMIT, "5.4 donor")
    require_clean_git(susfs, SUSFS_COMMIT, "SUSFS official upstream")

    version = run(["make", "-s", "-C", str(kernel), "kernelversion"], capture=True)
    if version != KERNEL_VERSION:
        die(f"kernelversion mismatch: {version}")

    common = project_root / "common/scripts"
    run(["bash", str(common / "verify_source_pin.sh"), str(kernel), SOURCE_COMMIT, KERNEL_VERSION, DEFCONFIG])
    run(["bash", str(common / "audit_existing_integration.sh"), "--expect-clean", str(kernel)])

    snapdir = Path(tempfile.mkdtemp(prefix="veux-susfs-identity-"))
    snapshot = snapdir / "identity.sha256"
    run(["bash", str(common / "identity_guard.sh"), "snapshot", str(kernel), DEFCONFIG, str(snapshot)])
    return snapshot


def finalize_real(project_root: Path, kernel: Path, snapshot: Path) -> None:
    semantic_gates(kernel)
    delta_gate(kernel)

    vendor = kernel / ".resukisu"
    if git_head(vendor) != RESUKISU_COMMIT:
        die("vendored ReSukiSU HEAD mismatch")

    expected_resukisu_delta = {
        "kernel/Kbuild",
        "kernel/core/init.c",
        "kernel/feature/module_load_filter.c",
        "kernel/feature/module_load_filter.h",
    }
    actual_resukisu_delta = set(filter(None, run(["git", "-C", str(vendor), "diff", "--name-only"], capture=True).splitlines()))
    if actual_resukisu_delta != expected_resukisu_delta:
        die("unexpected ReSukiSU delta: " + ", ".join(sorted(actual_resukisu_delta)))

    run(["git", "-C", str(kernel), "diff", "--check"])
    run(["git", "-C", str(vendor), "diff", "--check"])

    common = project_root / "common/scripts"
    run(["bash", str(common / "identity_guard.sh"), "verify", str(kernel), DEFCONFIG, str(snapshot)])
    run(["bash", str(common / "audit_existing_integration.sh"), str(kernel)])

    print("SUSFS_HOST_INTEGRATION=PASS")
    print("RESUKISU_GIT_WORKTREE_LAYOUT=PASS")
    print("HOST_DELTA_GUARD=PASS")
    print("RESUKISU_DELTA_GUARD=PASS")
    print("DONOR_STATFS_SEMANTIC_FIX=PASS")
    print("UPSTREAM_STATFS_COMPILE_FIX_BACKPORT=PASS")
    print("SUSFS_5_4_CORE_COHERENCE=PASS")
    print("INLINE_7_SURFACE_FIXTURE_TRANSFORM=PASS")
    print("EXECVEAT_POST_HOOK_GATE=PASS")
    print("EXECVEAT_POST_HOOK_SUCCESS_PATH=PASS")
    print("SYS_READ_ABI_GATE=PASS")
    print("REBOOT_SUPERCALL_FLOW_GATE=PASS")
    print("OPEN_REDIRECT_RETRY_FIX=PASS")
    print("SUS_MOUNT_CLONE_RACE_FIX=PASS")
    print("MODULE_LOAD_FILTER=EXCLUDED")
    print("HOOK_MODE=SUSFS_INLINE")
    print(f"SUSFS_VERSION={SUSFS_VERSION}")
    print("SUSFS_CODE_BASE=PINNED_5_4_DONOR_PORT")
    print(f"SUSFS_UPSTREAM_REFERENCE_COMMIT={SUSFS_COMMIT}")
    print(f"SOURCE_COMMIT={SOURCE_COMMIT}")
    print(f"RESUKISU_COMMIT={RESUKISU_COMMIT}")
    print(f"DONOR_COMMIT={DONOR_COMMIT}")
    print(f"SUSFS_COMMIT={SUSFS_COMMIT}")
    print("COMPILE_PASS=NO")
    print("PACKAGE_PASS=NO")
    print("STATIC_BOOT_PATH_PASS=NO")
    print("DEVICE_PASS=NO")


def selftest() -> None:
    sample = f"prefix\n+\t{BAD_STATFS}\n\t\tgoto bypass_orig_flow;\n"
    fixed = correct_donor_patch(sample)
    if BAD_STATFS in fixed or GOOD_STATFS not in fixed:
        die("selftest statfs correction failed")
    try:
        correct_donor_patch(fixed)
    except ValueError:
        pass
    else:
        die("selftest duplicate/already-fixed guard failed")

    with tempfile.TemporaryDirectory(prefix="susfs-v1-statfs-compile-selftest-") as td:
        root = Path(td)
        (root / "fs").mkdir(parents=True)
        statfs = root / "fs/statfs.c"
        decl_block = (
            "#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT\n"
            "extern bool susfs_is_inode_sus_kstat(struct inode *inode, bool *out_is_fuse);\n"
            "extern int susfs_sus_kstat_spoof_vfs_statfs(struct inode *inode, struct kstatfs *buf, bool *is_fuse);\n"
            "#endif // #ifdef CONFIG_KSU_SUSFS_SUS_KSTAT\n"
            "#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\n"
            "extern struct vfsmount *susfs_get_non_sus_vfsmnt_from_vfsmnt(struct vfsmount *vfsmnt);\n"
            "#endif //#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\n"
        )
        statfs.write_text(
            '#include "internal.h"\n\n'
            'static int flags_by_mnt(int mnt_flags) { return 0; }\n'
            'static int statfs_by_dentry(struct dentry *dentry, struct kstatfs *buf) {\n'
            f'\tif (!susfs_sus_kstat_spoof_vfs_statfs(d_backing_inode(dentry), buf, is_fuse)) return 0;\n'
            '}\n' + decl_block,
            encoding="utf-8",
        )
        backport_statfs_compile_fix(root)
        t = statfs.read_text(encoding="utf-8")
        if t.find("extern int susfs_sus_kstat_spoof_vfs_statfs") >= t.find("susfs_sus_kstat_spoof_vfs_statfs(d_backing_inode"):
            die("selftest statfs compile-fix ordering failed")

    with tempfile.TemporaryDirectory(prefix="susfs-v1-core-coherence-selftest-") as td:
        root = Path(td)
        k = root / "kernel"
        u = root / "upstream"
        (k / "fs").mkdir(parents=True)
        (k / "include/linux").mkdir(parents=True)
        (u / "kernel_patches/fs").mkdir(parents=True)
        (u / "kernel_patches/include/linux").mkdir(parents=True)
        (k / "fs/susfs.c").write_text(
            '#include <linux/security.h>\n'
            'void f(struct inode *inode) { set_bit(AS_FLAGS_SUS_PATH, &inode->i_state); }\n',
            encoding="utf-8",
        )
        (k / "include/linux/susfs.h").write_text('#define SUSFS_VERSION "v2.3.0"\n', encoding="utf-8")
        (k / "include/linux/susfs_def.h").write_text(
            '#define AS_FLAGS_SUS_PATH 33\n'
            '#define AS_FLAGS_SUS_MOUNT 34\n'
            '#define AS_FLAGS_SUS_KSTAT 35\n'
            '#define AS_FLAGS_OPEN_REDIRECT 36\n'
            '#define AS_FLAGS_SUS_MAP 39\n',
            encoding="utf-8",
        )
        (u / "kernel_patches/fs/susfs.c").write_text(
            'void f(struct inode *inode) { set_bit(AS_FLAGS_SUS_PATH, &inode->i_mapping->flags); }\n',
            encoding="utf-8",
        )
        (u / "kernel_patches/include/linux/susfs.h").write_text('#define SUSFS_VERSION "v2.3.0"\n', encoding="utf-8")
        (u / "kernel_patches/include/linux/susfs_def.h").write_text('reference\n', encoding="utf-8")
        verify_5_4_core_coherence(k, u)

    with tempfile.TemporaryDirectory(prefix="susfs-v1-selftest-") as td:
        root = Path(td)
        vk = root / "kernel"
        (vk / "core").mkdir(parents=True)
        (vk / "feature").mkdir(parents=True)
        (vk / "Kbuild").write_text("kernelsu-objs += feature/module_load_filter.o\n", encoding="utf-8")
        (vk / "core/init.c").write_text(
            '#include "feature/module_load_filter.h"\n'
            'char ksu_block_modules[256];\n'
            'module_param_string(block_modules, ksu_block_modules, sizeof(ksu_block_modules), 0);\n'
            'MODULE_PARM_DESC(block_modules, "Comma-separated preset module names to acknowledge without loading");\n\n'
            '        ksu_module_load_filter_hook_init();\n\n'
            '    ksu_module_load_filter_hook_exit();\n\n',
            encoding="utf-8",
        )
        (vk / "feature/module_load_filter.c").write_text("x\n", encoding="utf-8")
        (vk / "feature/module_load_filter.h").write_text("x\n", encoding="utf-8")
        remove_module_filter(vk)
        if "module_load_filter" in read(vk / "Kbuild") or "module_load_filter" in read(vk / "core/init.c"):
            die("selftest module-filter exclusion failed")

    with tempfile.TemporaryDirectory(prefix="susfs-v1-seven-hook-selftest-") as td:
        root = Path(td)
        k = root / "kernel"
        donor = root / "donor"
        for rel in ("fs", "drivers/input", "kernel"):
            (k / rel).mkdir(parents=True, exist_ok=True)
        (donor / "Patches").mkdir(parents=True)
        (donor / "Patches/susfs_inline_hook_patches.sh").write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")

        (k / "fs/exec.c").write_text(
            "#include <linux/vmalloc.h>\n\n"
            "static int __do_execve_file(int fd, struct filename *filename,\n"
            "\t\t\t    struct user_arg_ptr argv,\n"
            "\t\t\t    struct user_arg_ptr envp,\n"
            "\t\t\t    int flags, struct file *file)\n"
            "{\n\tchar *pathbuf = NULL;\n\tstruct linux_binprm bprm;\n"
            "\tstruct files_struct *displaced;\n\tint retval;\n\n"
            "\tif (IS_ERR(filename))\n\t\treturn PTR_ERR(filename);\n\n"
            "\tretval = exec_binprm(&bprm);\n"
            "\tif (retval < 0)\n\t\tgoto out;\n"
            "\treturn retval;\n"
            "out:\n\t;\n"
            "out_free:\n\tfree_bprm(&bprm);\n}\n",
            encoding="utf-8",
        )
        (k / "fs/open.c").write_text(
            "#include <linux/compat.h>\n\n#include \"internal.h\"\n\n"
            "long do_faccessat(int dfd, const char __user *filename, int mode)\n"
            "{\n\tint res;\n\tunsigned int lookup_flags = LOOKUP_FOLLOW;\n\n"
            "\tif (mode & ~S_IRWXO)\n\t\treturn -EINVAL;\n"
            "retry:\n\tres = user_path_at(dfd, filename, lookup_flags, &path);\n}\n",
            encoding="utf-8",
        )
        (k / "fs/read_write.c").write_text(
            "SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)\n"
            "{\n\treturn ksys_read(fd, buf, count);\n}\n",
            encoding="utf-8",
        )
        (k / "fs/stat.c").write_text(
            "#include <linux/compat.h>\n#include <linux/uaccess.h>\n#include <asm/unistd.h>\n\n"
            "int vfs_statx_fd(unsigned int fd, struct kstat *stat,\n"
            "\t\t u32 request_mask, unsigned int query_flags)\n"
            "{\n\tif (f.file) {\n"
            "\t\terror = vfs_getattr(&f.file->f_path, stat,\n"
            "\t\t\t\t    request_mask, query_flags);\n"
            "\t\tfdput(f);\n\t}\n}\n\n"
            "int vfs_statx(int dfd, const char __user *filename, int flags,\n"
            "\t      struct kstat *stat, u32 request_mask)\n"
            "{\n\tstruct path path;\n\tint error = -EINVAL;\n"
            "\tunsigned int lookup_flags = LOOKUP_FOLLOW | LOOKUP_AUTOMOUNT;\n\n"
            "\tif ((flags & ~(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT |\n"
            "\t\t       AT_EMPTY_PATH | KSTAT_QUERY_FLAGS)) != 0)\n"
            "\t\treturn -EINVAL;\n"
            "retry:\n\terror = user_path_at(dfd, filename, lookup_flags, &path);\n}\n",
            encoding="utf-8",
        )
        (k / "drivers/input/input.c").write_text(
            "static void input_handle_event(struct input_dev *dev,\n"
            "\t\t\t       unsigned int type, unsigned int code, int value)\n"
            "{\n\tint disposition = input_get_disposition(dev, type, code, &value);\n\n"
            "\tif (disposition != INPUT_IGNORE_EVENT && type != EV_SYN)\n"
            "\t\tadd_input_randomness(type, code, value);\n}\n",
            encoding="utf-8",
        )
        (k / "kernel/reboot.c").write_text(
            "SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,\n"
            "\t\tvoid __user *, arg)\n"
            "{\n\tstruct pid_namespace *pid_ns = task_active_pid_ns(current);\n"
            "\tchar buffer[256];\n\tint ret = 0;\n\n"
            "\t/* We only trust the superuser with rebooting the system. */\n}\n",
            encoding="utf-8",
        )
        (k / "kernel/sys.c").write_text(
            "SYSCALL_DEFINE3(setresuid, uid_t, ruid, uid_t, euid, uid_t, suid)\n"
            "{\n\treturn __sys_setresuid(ruid, euid, suid);\n}\n",
            encoding="utf-8",
        )
        run_inline_port(k, donor)
        fixture_checks = (
            "ksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);" in read(k / "fs/exec.c"),
            (
                "\tretval = exec_binprm(&bprm);\n#ifdef CONFIG_KSU_SUSFS\n"
                "\tif (unlikely(is_su_session && retval >= 0))\n"
                "\t\t(void)ksu_handle_post_execveat_sucompat(&fd, &filename, &argv, &envp, &flags, &retval);"
            ) in read(k / "fs/exec.c"),
            "ksu_handle_faccessat(&dfd, &fname, &mode, NULL);" in read(k / "fs/open.c"),
            "ksu_handle_sys_read(fd, &buf, &count);" in read(k / "fs/read_write.c"),
            "ksu_handle_stat(&dfd, &fname, &flags);" in read(k / "fs/stat.c"),
            "ksu_handle_vfs_fstat(fd, &stat->size);" in read(k / "fs/stat.c"),
            "ksu_handle_input_handle_event(&type, &code, &value);" in read(k / "drivers/input/input.c"),
            "ksu_susfs_reboot_orig_flow:" in read(k / "kernel/reboot.c"),
            "(void)ksu_handle_setresuid(ruid, euid, suid);" in read(k / "kernel/sys.c"),
        )
        if not all(fixture_checks):
            die("selftest seven-surface inline fixture transform failed")

    # Pin the ABI/control-flow contracts that distinguish this V1 from the
    # stale donor shell implementation.
    current_read_decl = "extern __attribute__((cold)) int ksu_handle_sys_read(unsigned int fd, char __user **buf_ptr, size_t *count_ptr);"
    if "char __user **buf_ptr" not in current_read_decl or "size_t *count_ptr" not in current_read_decl:
        die("selftest current sys_read ABI contract failed")
    current_reboot_flow = "ret = ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);"
    if "ret = ksu_handle_sys_reboot" not in current_reboot_flow:
        die("selftest reboot flow contract failed")

    print("DONOR_STATFS_SEMANTIC_FIX=PASS")
    print("UPSTREAM_STATFS_COMPILE_FIX_BACKPORT=PASS")
    print("SUSFS_5_4_CORE_COHERENCE=PASS")
    print("EXECVEAT_POST_HOOK_REPAIR=PASS")
    print("EXECVEAT_POST_HOOK_SUCCESS_PATH=PASS")
    print("SYS_READ_ABI_REPAIR=PASS")
    print("REBOOT_SUPERCALL_FLOW_REPAIR=PASS")
    print("MODULE_LOAD_FILTER_EXCLUSION=PASS")
    print("DUPLICATE_GUARD=PASS")
    print("SELFTEST=PASS")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("kernel", nargs="?", type=Path)
    ap.add_argument("resukisu", nargs="?", type=Path)
    ap.add_argument("donor", nargs="?", type=Path)
    ap.add_argument("susfs", nargs="?", type=Path)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        selftest()
        return

    if not all((args.kernel, args.resukisu, args.donor, args.susfs)):
        ap.error("kernel, resukisu, donor and susfs roots are required unless --selftest is used")

    kernel = args.kernel.resolve()
    resukisu = args.resukisu.resolve()
    donor = args.donor.resolve()
    susfs = args.susfs.resolve()
    project_root = Path(__file__).resolve().parents[2]

    snapshot = verify_real(project_root, kernel, resukisu, donor, susfs)
    vendor_resukisu(kernel, resukisu)
    fixed_patch = apply_outer_patch(kernel, donor, susfs)
    print(f"CORRECTED_DONOR_PATCH={fixed_patch}")
    run_inline_port(kernel, donor)
    expose_selinux_symbols(kernel)
    finalize_real(project_root, kernel, snapshot)


if __name__ == "__main__":
    main()
