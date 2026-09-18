#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

SOURCE_COMMIT = "fb3bbb10bc0480282c01b88ccaf39c0145cd9f51"
KERNEL_VERSION = "5.4.292"
DEFCONFIG = "veux_defconfig"
RESUKISU_COMMIT = "6ec8d9a8a8be30878c388504cacf8ae7849c757b"

def die(msg: str, code: int = 1) -> "NoReturn":
    print(f"ERROR: {msg}", file=sys.stderr)
    raise SystemExit(code)

def run(cmd, cwd=None, capture=False):
    p = subprocess.run(
        cmd, cwd=cwd, text=True,
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
        die(f"command failed ({p.returncode}): {' '.join(map(str, cmd))}", p.returncode)
    return p.stdout.strip() if capture else ""

def read(path: Path) -> str:
    if not path.is_file():
        die(f"required file missing: {path}")
    return path.read_text(encoding="utf-8")

def write(path: Path, data: str) -> None:
    path.write_text(data, encoding="utf-8")

def replace_once(path: Path, old: str, new: str, label: str) -> None:
    data = read(path)
    count = data.count(old)
    if count != 1:
        die(f"{label}: expected exactly one anchor in {path}, found {count}")
    write(path, data.replace(old, new, 1))

def ensure_absent(root: Path, needles: list[str], label: str) -> None:
    hits = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        try:
            data = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for needle in needles:
            if needle in data:
                hits.append(f"{p.relative_to(root)}:{needle}")
    if hits:
        die(f"{label}: forbidden references remain: " + ", ".join(hits[:20]))

def ensure_count(path: Path, needle: str, expected: int, label: str) -> None:
    count = read(path).count(needle)
    if count != expected:
        die(f"{label}: expected {expected} occurrence(s) of {needle!r} in {path}, found {count}")

def patch_tree(kernel: Path, resukisu_kernel: Path) -> None:
    # Hard fail on pre-existing integration/hook traces in host files.
    preexisting = {
        kernel / "fs/exec.c": ["ksu_handle_execveat", "ksu_handle_post_execveat"],
        kernel / "fs/open.c": ["ksu_handle_faccessat"],
        kernel / "fs/stat.c": ["ksu_handle_stat", "ksu_handle_newfstat_ret", "ksu_handle_fstat64_ret"],
        kernel / "kernel/reboot.c": ["ksu_handle_sys_reboot"],
    }
    for path, needles in preexisting.items():
        data = read(path)
        for needle in needles:
            if needle in data:
                die(f"pre-existing hook detected: {needle} in {path}")

    dst = kernel / "drivers/kernelsu"
    if dst.exists() or dst.is_symlink():
        die(f"KernelSU target already exists: {dst}")
    shutil.copytree(resukisu_kernel, dst, symlinks=True)

    # Remove module_load_filter from the copied ReSukiSU kernel tree.
    replace_once(
        dst / "Kbuild",
        "kernelsu-objs += feature/module_load_filter.o\n",
        "",
        "remove module_load_filter object",
    )
    replace_once(
        dst / "core/init.c",
        '#include "feature/module_load_filter.h"\n',
        "",
        "remove module_load_filter include",
    )
    replace_once(
        dst / "core/init.c",
        'char ksu_block_modules[256];\n'
        'module_param_string(block_modules, ksu_block_modules, sizeof(ksu_block_modules), 0);\n'
        'MODULE_PARM_DESC(block_modules, "Comma-separated preset module names to acknowledge without loading");\n\n',
        "",
        "remove module_load_filter parameter",
    )
    replace_once(
        dst / "core/init.c",
        "        ksu_module_load_filter_hook_init();\n\n",
        "",
        "remove module_load_filter init",
    )
    replace_once(
        dst / "core/init.c",
        "    ksu_module_load_filter_hook_exit();\n\n",
        "",
        "remove module_load_filter exit",
    )
    for name in ("module_load_filter.c", "module_load_filter.h"):
        p = dst / "feature" / name
        if not p.is_file():
            die(f"expected module_load_filter file missing before removal: {p}")
        p.unlink()

    ensure_absent(
        dst,
        ["module_load_filter", "ksu_block_modules", "block_modules"],
        "module_load_filter exclusion",
    )

    # Official ReSukiSU 3.14+ execveat hook pattern.
    exec_path = kernel / "fs/exec.c"
    exec_old = (
        "static int do_execveat_common(int fd, struct filename *filename,\n"
        "\t\t\t      struct user_arg_ptr argv,\n"
        "\t\t\t      struct user_arg_ptr envp,\n"
        "\t\t\t      int flags)\n"
        "{\n"
        "\treturn __do_execve_file(fd, filename, argv, envp, flags, NULL);\n"
        "}\n"
    )
    exec_new = (
        "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
        "__attribute__((hot))\n"
        "extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr,\n"
        "\t\t\t      void *argv, void *envp, int *flags);\n"
        "__attribute__((hot))\n"
        "extern int ksu_handle_post_execveat(int *fd, struct filename **filename_ptr,\n"
        "\t\t\t\t   void *argv, void *envp, int *flags, int *retval);\n"
        "#endif\n\n"
        "static int do_execveat_common(int fd, struct filename *filename,\n"
        "\t\t\t      struct user_arg_ptr argv,\n"
        "\t\t\t      struct user_arg_ptr envp,\n"
        "\t\t\t      int flags)\n"
        "{\n"
        "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
        "\tint retval;\n"
        "\tksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);\n"
        "\tretval = __do_execve_file(fd, filename, argv, envp, flags, NULL);\n"
        "\tksu_handle_post_execveat(&fd, &filename, &argv, &envp, &flags, &retval);\n"
        "\treturn retval;\n"
        "#else\n"
        "\treturn __do_execve_file(fd, filename, argv, envp, flags, NULL);\n"
        "#endif\n"
        "}\n"
    )
    replace_once(exec_path, exec_old, exec_new, "execveat hook")

    # faccessat hook.
    open_path = kernel / "fs/open.c"
    open_old = (
        "SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)\n"
        "{\n"
        "\treturn do_faccessat(dfd, filename, mode);\n"
        "}\n"
    )
    open_new = (
        "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
        "__attribute__((hot))\n"
        "extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,\n"
        "\t\t\t\tint *mode, int *flags);\n"
        "#endif\n\n"
        "SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)\n"
        "{\n"
        "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
        "\tksu_handle_faccessat(&dfd, &filename, &mode, NULL);\n"
        "#endif\n"
        "\treturn do_faccessat(dfd, filename, mode);\n"
        "}\n"
    )
    replace_once(open_path, open_old, open_new, "faccessat hook")

    # stat hooks including 32-bit/compat paths.
    stat_path = kernel / "fs/stat.c"
    stat_decl_anchor = "#if !defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_SYS_NEWFSTATAT)\n"
    stat_decls = (
        "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
        "__attribute__((hot))\n"
        "extern int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags);\n"
        "extern void ksu_handle_newfstat_ret(unsigned int *fd, struct stat __user **statbuf_ptr);\n"
        "#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)\n"
        "extern void ksu_handle_fstat64_ret(unsigned long *fd, struct stat64 __user **statbuf_ptr);\n"
        "#endif\n"
        "#endif\n\n"
        + stat_decl_anchor
    )
    replace_once(stat_path, stat_decl_anchor, stat_decls, "stat hook declarations")

    newfstatat_sig = (
        "SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,\n"
        "\t\tstruct stat __user *, statbuf, int, flag)\n"
        "{\n"
        "\tstruct kstat stat;\n"
        "\tint error;\n\n"
        "\terror = vfs_fstatat(dfd, filename, &stat, flag);\n"
    )
    newfstatat_repl = (
        "SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,\n"
        "\t\tstruct stat __user *, statbuf, int, flag)\n"
        "{\n"
        "\tstruct kstat stat;\n"
        "\tint error;\n\n"
        "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
        "\tksu_handle_stat(&dfd, &filename, &flag);\n"
        "#endif\n"
        "\terror = vfs_fstatat(dfd, filename, &stat, flag);\n"
    )
    replace_once(stat_path, newfstatat_sig, newfstatat_repl, "newfstatat hook")

    replace_once(
        stat_path,
        "\tif (!error)\n\t\terror = cp_new_stat(&stat, statbuf);\n\n\treturn error;\n",
        "\tif (!error)\n\t\terror = cp_new_stat(&stat, statbuf);\n\n"
        "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
        "\tksu_handle_newfstat_ret(&fd, &statbuf);\n"
        "#endif\n"
        "\treturn error;\n",
        "newfstat return hook",
    )

    replace_once(
        stat_path,
        "\tif (!error)\n\t\terror = cp_new_stat64(&stat, statbuf);\n\n\treturn error;\n}\n\n"
        "SYSCALL_DEFINE4(fstatat64, int, dfd, const char __user *, filename,\n",
        "\tif (!error)\n\t\terror = cp_new_stat64(&stat, statbuf);\n\n"
        "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
        "\tksu_handle_fstat64_ret(&fd, &statbuf);\n"
        "#endif\n"
        "\treturn error;\n}\n\n"
        "SYSCALL_DEFINE4(fstatat64, int, dfd, const char __user *, filename,\n",
        "fstat64 return hook",
    )

    # Match the fstatat64 body specifically after its signature.
    data = read(stat_path)
    sig = (
        "SYSCALL_DEFINE4(fstatat64, int, dfd, const char __user *, filename,\n"
        "\t\tstruct stat64 __user *, statbuf, int, flag)\n"
        "{\n"
        "\tstruct kstat stat;\n"
        "\tint error;\n\n"
        "\terror = vfs_fstatat(dfd, filename, &stat, flag);\n"
    )
    repl = (
        "SYSCALL_DEFINE4(fstatat64, int, dfd, const char __user *, filename,\n"
        "\t\tstruct stat64 __user *, statbuf, int, flag)\n"
        "{\n"
        "\tstruct kstat stat;\n"
        "\tint error;\n\n"
        "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
        "\tksu_handle_stat(&dfd, &filename, &flag);\n"
        "#endif\n"
        "\terror = vfs_fstatat(dfd, filename, &stat, flag);\n"
    )
    if data.count(sig) != 1:
        die(f"fstatat64 hook: expected exactly one anchor in {stat_path}, found {data.count(sig)}")
    write(stat_path, data.replace(sig, repl, 1))

    # reboot hook.
    reboot_path = kernel / "kernel/reboot.c"
    reboot_sig = (
        "SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,\n"
        "\t\tvoid __user *, arg)\n"
    )
    reboot_with_decl = (
        "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
        "extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd,\n"
        "\t\t\t\t void __user **arg);\n"
        "#endif\n\n"
        + reboot_sig
    )
    replace_once(reboot_path, reboot_sig, reboot_with_decl, "reboot declaration")
    replace_once(
        reboot_path,
        "\tchar buffer[256];\n\tint ret = 0;\n\n\t/* We only trust the superuser with rebooting the system. */\n",
        "\tchar buffer[256];\n\tint ret = 0;\n\n"
        "#ifdef CONFIG_KSU_MANUAL_HOOK\n"
        "\tksu_handle_sys_reboot(magic1, magic2, cmd, &arg);\n"
        "#endif\n\n"
        "\t/* We only trust the superuser with rebooting the system. */\n",
        "reboot call",
    )

    # Static symbol visibility for non-KALLSYMS_ALL path.
    selinuxfs = kernel / "security/selinux/selinuxfs.c"
    replace_once(
        selinuxfs,
        "static ssize_t (*const write_op[])(struct file *, char *, size_t) = {",
        "ssize_t (*const write_op[])(struct file *, char *, size_t) = {",
        "SELinux write_op visibility",
    )
    replace_once(
        selinuxfs,
        "static const struct file_operations sel_handle_status_ops = {",
        "const struct file_operations sel_handle_status_ops = {",
        "SELinux status ops visibility",
    )

    # Wire ReSukiSU into drivers exactly once.
    drv_make = kernel / "drivers/Makefile"
    make_data = read(drv_make)
    if "obj-$(CONFIG_KSU) += kernelsu/" in make_data or "obj-$(CONFIG_KSU)\t+= kernelsu/" in make_data:
        die("drivers/Makefile already contains KernelSU entry")
    if not make_data.endswith("\n"):
        make_data += "\n"
    write(drv_make, make_data + "\nobj-$(CONFIG_KSU) += kernelsu/\n")

    drv_kconfig = kernel / "drivers/Kconfig"
    kcfg = read(drv_kconfig)
    line = 'source "drivers/kernelsu/Kconfig"'
    if line in kcfg:
        die("drivers/Kconfig already contains KernelSU entry")
    marker = "\nendmenu"
    idx = kcfg.rfind(marker)
    if idx < 0:
        die("drivers/Kconfig final endmenu anchor not found")
    kcfg = kcfg[:idx] + f"\n\n{line}\n" + kcfg[idx:]
    write(drv_kconfig, kcfg)

    # Post-transform semantic gates.
    gates = {
        kernel / "fs/exec.c": ["ksu_handle_execveat", "ksu_handle_post_execveat"],
        kernel / "fs/open.c": ["ksu_handle_faccessat"],
        kernel / "fs/stat.c": ["ksu_handle_stat", "ksu_handle_newfstat_ret", "ksu_handle_fstat64_ret"],
        kernel / "kernel/reboot.c": ["ksu_handle_sys_reboot"],
    }
    for path, needles in gates.items():
        data = read(path)
        for needle in needles:
            if needle not in data:
                die(f"post-transform gate missing {needle} in {path}")

    ensure_count(drv_make, "obj-$(CONFIG_KSU) += kernelsu/", 1, "Makefile integration")
    ensure_count(drv_kconfig, line, 1, "Kconfig integration")
    ensure_absent(dst, ["module_load_filter", "ksu_block_modules", "block_modules"],
                  "module_load_filter final gate")

def verify_real(project_root: Path, kernel: Path, resukisu: Path) -> Path:
    if not (kernel / ".git").exists():
        die(f"kernel root is not a git checkout: {kernel}")
    if not (resukisu / ".git").exists():
        die(f"ReSukiSU root is not a git checkout: {resukisu}")

    actual_source = run(["git", "-C", str(kernel), "rev-parse", "HEAD"], capture=True)
    if actual_source != SOURCE_COMMIT:
        die(f"kernel source commit mismatch: {actual_source}")

    if run(["make", "-s", "-C", str(kernel), "kernelversion"], capture=True) != KERNEL_VERSION:
        die("kernelversion mismatch")

    if run(["git", "-C", str(kernel), "status", "--porcelain"], capture=True):
        die("kernel source worktree is not clean")

    actual_resukisu = run(["git", "-C", str(resukisu), "rev-parse", "HEAD"], capture=True)
    if actual_resukisu != RESUKISU_COMMIT:
        die(f"ReSukiSU commit mismatch: {actual_resukisu}")

    if run(["git", "-C", str(resukisu), "status", "--porcelain"], capture=True):
        die("ReSukiSU worktree is not clean")

    common = project_root / "common/scripts"
    run([
        "bash", str(common / "verify_source_pin.sh"),
        str(kernel), SOURCE_COMMIT, KERNEL_VERSION, DEFCONFIG
    ])
    run([
        "bash", str(common / "audit_existing_integration.sh"),
        "--expect-clean", str(kernel)
    ])

    snap_dir = Path(tempfile.mkdtemp(prefix="veux-identity-"))
    snap = snap_dir / "identity.sha256"
    run([
        "bash", str(common / "identity_guard.sh"),
        "snapshot", str(kernel), DEFCONFIG, str(snap)
    ])
    return snap

def finalize_real(project_root: Path, kernel: Path, snapshot: Path) -> None:
    common = project_root / "common/scripts"
    run(["git", "-C", str(kernel), "diff", "--check"])

    bad = []
    for p in kernel.rglob("*"):
        if p.is_file() and (p.name.endswith(".rej") or p.name.endswith(".orig")):
            bad.append(str(p.relative_to(kernel)))
    if bad:
        die("reject/orig files present: " + ", ".join(bad))

    run([
        "bash", str(common / "identity_guard.sh"),
        "verify", str(kernel), DEFCONFIG, str(snapshot)
    ])
    run([
        "bash", str(common / "audit_existing_integration.sh"),
        str(kernel)
    ])

    print("RESUKISU_HOST_INTEGRATION=PASS")
    print(f"SOURCE_COMMIT={SOURCE_COMMIT}")
    print(f"RESUKISU_COMMIT={RESUKISU_COMMIT}")
    print("HOOK_MODE=MANUAL")
    print("MODULE_LOAD_FILTER=EXCLUDED")
    print("SUSFS=NOT_PRESENT")
    print("COMPILE_PASS=NO")
    print("PACKAGE_PASS=NO")
    print("STATIC_BOOT_PATH_PASS=NO")
    print("DEVICE_PASS=NO")

def make_fixture(root: Path):
    k = root / "kernel"
    r = root / "resukisu"
    for d in [
        k/"fs", k/"kernel", k/"security/selinux", k/"drivers",
        r/"kernel/core", r/"kernel/feature"
    ]:
        d.mkdir(parents=True, exist_ok=True)

    (k/"fs/exec.c").write_text(
        "static int do_execveat_common(int fd, struct filename *filename,\n"
        "\t\t\t      struct user_arg_ptr argv,\n"
        "\t\t\t      struct user_arg_ptr envp,\n"
        "\t\t\t      int flags)\n"
        "{\n"
        "\treturn __do_execve_file(fd, filename, argv, envp, flags, NULL);\n"
        "}\n", encoding="utf-8"
    )
    (k/"fs/open.c").write_text(
        "SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)\n"
        "{\n\treturn do_faccessat(dfd, filename, mode);\n}\n", encoding="utf-8"
    )
    (k/"fs/stat.c").write_text(
        "SYSCALL_DEFINE2(newlstat, const char __user *, filename,\n"
        "\t\tstruct stat __user *, statbuf)\n{\n\treturn 0;\n}\n\n"
        "#if !defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_SYS_NEWFSTATAT)\n"
        "SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,\n"
        "\t\tstruct stat __user *, statbuf, int, flag)\n"
        "{\n\tstruct kstat stat;\n\tint error;\n\n"
        "\terror = vfs_fstatat(dfd, filename, &stat, flag);\n"
        "\tif (error)\n\t\treturn error;\n\treturn cp_new_stat(&stat, statbuf);\n}\n#endif\n\n"
        "SYSCALL_DEFINE2(newfstat, unsigned int, fd, struct stat __user *, statbuf)\n"
        "{\n\tstruct kstat stat;\n\tint error = vfs_fstat(fd, &stat);\n\n"
        "\tif (!error)\n\t\terror = cp_new_stat(&stat, statbuf);\n\n\treturn error;\n}\n"
        "SYSCALL_DEFINE2(fstat64, unsigned long, fd, struct stat64 __user *, statbuf)\n"
        "{\n\tstruct kstat stat;\n\tint error = vfs_fstat(fd, &stat);\n\n"
        "\tif (!error)\n\t\terror = cp_new_stat64(&stat, statbuf);\n\n\treturn error;\n}\n\n"
        "SYSCALL_DEFINE4(fstatat64, int, dfd, const char __user *, filename,\n"
        "\t\tstruct stat64 __user *, statbuf, int, flag)\n"
        "{\n\tstruct kstat stat;\n\tint error;\n\n"
        "\terror = vfs_fstatat(dfd, filename, &stat, flag);\n"
        "\tif (error)\n\t\treturn error;\n\treturn cp_new_stat64(&stat, statbuf);\n}\n",
        encoding="utf-8"
    )
    (k/"kernel/reboot.c").write_text(
        "SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,\n"
        "\t\tvoid __user *, arg)\n{\n"
        "\tstruct pid_namespace *pid_ns = task_active_pid_ns(current);\n"
        "\tchar buffer[256];\n\tint ret = 0;\n\n"
        "\t/* We only trust the superuser with rebooting the system. */\n"
        "\treturn ret;\n}\n", encoding="utf-8"
    )
    (k/"security/selinux/selinuxfs.c").write_text(
        "static ssize_t (*const write_op[])(struct file *, char *, size_t) = {\n};\n"
        "static const struct file_operations sel_handle_status_ops = {\n};\n",
        encoding="utf-8"
    )
    (k/"drivers/Makefile").write_text("obj-y += base/\n", encoding="utf-8")
    (k/"drivers/Kconfig").write_text('menu "Device Drivers"\n\nendmenu\n', encoding="utf-8")

    (r/"kernel/Kbuild").write_text(
        "kernelsu-objs := core/init.o\n"
        "kernelsu-objs += feature/module_load_filter.o\n",
        encoding="utf-8"
    )
    (r/"kernel/core/init.c").write_text(
        '#include "feature/module_load_filter.h"\n'
        'char ksu_block_modules[256];\n'
        'module_param_string(block_modules, ksu_block_modules, sizeof(ksu_block_modules), 0);\n'
        'MODULE_PARM_DESC(block_modules, "Comma-separated preset module names to acknowledge without loading");\n\n'
        'void f(void)\n{\n'
        '        ksu_module_load_filter_hook_init();\n\n'
        '}\n'
        'void g(void)\n{\n'
        '    ksu_module_load_filter_hook_exit();\n\n'
        '}\n',
        encoding="utf-8"
    )
    (r/"kernel/feature/module_load_filter.c").write_text("module_load_filter\n", encoding="utf-8")
    (r/"kernel/feature/module_load_filter.h").write_text("module_load_filter\n", encoding="utf-8")
    return k, r

def selftest() -> None:
    with tempfile.TemporaryDirectory(prefix="veux-resukisu-selftest-") as td:
        root = Path(td)
        k, r = make_fixture(root)
        patch_tree(k, r/"kernel")

        # Success gates
        assert "ksu_handle_execveat" in read(k/"fs/exec.c")
        assert "ksu_handle_faccessat" in read(k/"fs/open.c")
        assert "ksu_handle_newfstat_ret" in read(k/"fs/stat.c")
        assert "ksu_handle_fstat64_ret" in read(k/"fs/stat.c")
        assert "ksu_handle_sys_reboot" in read(k/"kernel/reboot.c")
        assert "static ssize_t (*const write_op[])" not in read(k/"security/selinux/selinuxfs.c")
        assert "static const struct file_operations sel_handle_status_ops" not in read(k/"security/selinux/selinuxfs.c")
        ensure_absent(k/"drivers/kernelsu",
                      ["module_load_filter", "ksu_block_modules", "block_modules"],
                      "selftest module filter gate")

        # Second application must fail closed.
        try:
            patch_tree(k, r/"kernel")
        except SystemExit:
            pass
        else:
            die("selftest duplicate-application guard failed")

    print("FIXTURE_TRANSFORM=PASS")
    print("MODULE_LOAD_FILTER_EXCLUSION=PASS")
    print("DUPLICATE_GUARD=PASS")
    print("SELFTEST=PASS")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kernel_root", nargs="?")
    ap.add_argument("resukisu_root", nargs="?")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        selftest()
        return

    if not args.kernel_root or not args.resukisu_root:
        ap.error("kernel_root and resukisu_root are required unless --selftest is used")

    kernel = Path(args.kernel_root).resolve()
    resukisu = Path(args.resukisu_root).resolve()
    project_root = Path(__file__).resolve().parents[2]

    snapshot = verify_real(project_root, kernel, resukisu)
    try:
        patch_tree(kernel, resukisu/"kernel")
        finalize_real(project_root, kernel, snapshot)
    finally:
        shutil.rmtree(snapshot.parent, ignore_errors=True)

if __name__ == "__main__":
    main()
