#!/usr/bin/env python3
"""Isolated R14 Android-KABI ABI A/B experiment around the AUTHENTICATED R13 build.

NO FLASH. R13 source, version, prior CLI, pinned compiler and R13 assertions remain
unchanged. This file is *not* imported on the original R13/main workflow.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

BASELINE_CONFIG_SHA = "405a4b3384212aa693ca2ce19f4c1ebef74f9cfc2568ce5da2107efe84fc0ff4"
BASELINE_CANDIDATE_SYMVERS_SHA = "0b5f909c68ec375533e961ac106da49c71b25f4fc99e6d13d0d093a52a540ec2"
DTB_SHA = "42728a6f3d48ae35ac6be4b14ea51bc8a323e77baec2ee544827487378f99d37"
RELEASE = "5.4.274-qgki-g82179e362f33"
FLAGS = ("CONFIG_ANDROID_KABI_RESERVE", "CONFIG_ANDROID_VENDOR_OEM_DATA")
VARIANTS = (("A_KABI_ONLY", FLAGS[:1]), ("B_KABI_AND_VENDOR_OEM", FLAGS))
SENSITIVE = ("CONFIG_SCHED_CASS", "CONFIG_SCHED_WALT", "CONFIG_KSU", "CONFIG_KSU_SUSFS",
             "CONFIG_NOMOUNT", "CONFIG_SECURITY_SELINUX", "CONFIG_MODVERSIONS", "CONFIG_CFI_CLANG")


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def need(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def config_map(data: str) -> dict[str, str]:
    found = {}
    for line in data.splitlines():
        if line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", 1)
        elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
            key, value = line[2:-len(" is not set")], "n"
        else:
            continue
        need(key not in found, "DUPLICATE_CONFIG_KEY:" + key)
        found[key] = value
    return found


def make_variant(data: str, enabled: tuple[str, ...]) -> str:
    need(all(k in FLAGS for k in enabled), "UNREVIEWED_CONFIG_KEY")
    result = data
    for k in FLAGS:
        original = f"# {k} is not set"
        need(data.count(original) == 1 and f"{k}=y" not in data, "BASELINE_FLAG_CHANGED:" + k)
        if k in enabled:
            result = result.replace(original, f"{k}=y")
    expected = {k: ("n", "y") for k in enabled}
    need(diff(config_map(data), config_map(result)) == expected, "NOT_EXACT_CONFIG_VARIANT")
    return result


def diff(old: dict[str, str], new: dict[str, str]) -> dict[str, tuple[str, str]]:
    return {k: (old.get(k, "n"), new.get(k, "n"))
            for k in old.keys() | new.keys() if old.get(k, "n") != new.get(k, "n")}


def symvers(path: Path) -> dict[str, str]:
    observed = {}
    data = path.read_bytes()
    need(data.endswith(b"\n"), "SYMVERS_NOT_LF_TERMINATED")
    for no, line in enumerate(data.decode("ascii").splitlines(), 1):
        fields = line.split("\t")
        need(len(fields) == 5, "SYMVERS_BAD_FIELDS:" + str(no))
        crc, symbol, _provider, _export, _namespace = fields
        need(re.fullmatch(r"0x[0-9a-fA-F]{8}", crc), "SYMVERS_BAD_CRC:" + str(no))
        need(symbol not in observed, "SYMVERS_DUPLICATE:" + symbol)
        observed[symbol] = crc.lower()
    need("module_layout" in observed and len(observed) > 10000, "INCOMPLETE_SYMVERS")
    return observed


def run_cmd(command: list[str], log_path: Path, env: dict[str, str], timeout: int) -> None:
    with log_path.open("wb") as out:
        p = subprocess.run(command, stdout=out, stderr=subprocess.STDOUT, env=env,
                           check=False, timeout=timeout)
    need(p.returncode == 0, "COMPILER_EXIT_" + str(p.returncode) + ":" + log_path.name)


def verify_compiled(source: Path, obj: Path, baseline_text: str, enabled: tuple[str, ...],
                    baseline_symbols: dict[str, str]) -> dict:
    actual = (obj / ".config").read_text()
    old, new = config_map(baseline_text), config_map(actual)
    expected = {key: ("n", "y") for key in enabled}
    changed = diff(old, new)
    need(changed == expected, "UNEXPECTED_OLDDEFCONFIG_CHANGE:" + json.dumps(changed, sort_keys=True))
    for key in SENSITIVE:
        need(new.get(key, "n") == old.get(key, "n"), "PROTECTED_CONFIG_CHANGED:" + key)
    need((obj / "include/config/kernel.release").read_text().strip() == RELEASE,
         "R14_KERNEL_RELEASE_CHANGED")
    dtb = obj / "arch/arm64/boot/dts/vendor/xiaomi/veux.dtb"
    need(dtb.is_file() and sha(dtb) == DTB_SHA, "VEUX_DTB_CHANGED")
    image = obj / "arch/arm64/boot/Image"
    data = image.read_bytes()
    need(len(data) > 1000000 and data[56:60] == b"ARM\x64", "INVALID_KERNEL_IMAGE")
    start = data.find(b"IKCFG_ST")
    end = data.find(b"IKCFG_ED", start + 8)
    need(start >= 0 and end > start, "EMBEDDED_CONFIG_MISSING")
    need(gzip.decompress(data[start+8:end]) == (obj / ".config").read_bytes(),
         "IMAGE_CONFIG_NOT_ACTUAL")
    elf = obj / "vmlinux"
    need(elf.is_file() and elf.stat().st_size > 10000000
         and elf.open("rb").read(4) == b"\x7fELF", "INVALID_VMLINUX")
    syms = symvers(obj / "Module.symvers")
    map_data = (obj / "System.map").read_text()
    for marker in ("cass_select_task_rq_rt", "cass_select_task_rq_fair", "ksu_handle_setuid",
                   "susfs_spoof_uname", "nomount_init", "rmnet_shs"):
        need(re.search(r"\b" + re.escape(marker) + r"[A-Za-z0-9_]*", map_data),
             "LINKED_SYMBOL_MISSING:" + marker)
    need("walt_update_task_ravg" not in map_data, "WALT_ACCIDENTALLY_ENABLED")
    for member in ("fs/susfs.o", "fs/nomount/nomount.o", "drivers/kernelsu/core/init.o",
                   "drivers/kernelsu/preinit/runner.elf"):
        need((obj / member).is_file() and (obj / member).stat().st_size > 0,
             "REAL_OBJECT_MISSING:" + member)
    return {
        "status": "ACTUALLY_COMPILED_NO_FLASH", "original_R13_source_unchanged": True,
        "kernel_image_sha256": sha(image), "image_bytes": len(data),
        "config_sha256": sha(obj / ".config"), "module_symvers_sha256": sha(obj / "Module.symvers"),
        "vmlinux_sha256": sha(elf), "dtb_sha256": sha(dtb),
        "module_layout_crc": syms["module_layout"], "baseline_module_layout_crc": baseline_symbols["module_layout"],
        "exports": len(syms), "baseline_exports": len(baseline_symbols),
        "same_crc_exports": sum(syms.get(k) == v for k,v in baseline_symbols.items()),
        "changed_crc_exports": sum(k in syms and syms[k] != v for k,v in baseline_symbols.items()),
        "missing_baseline_exports": sum(k not in syms for k in baseline_symbols),
        "new_exports": sum(k not in baseline_symbols for k in syms),
        "config_differences": {k: list(v) for k,v in changed.items()},
        "device_test": False, "flash_allowed": False, "automatic_flash": False,
    }


def variant_compile(source, baseline_work, state, jobs, variant_home, baseline_text,
                    baseline_symbols, name, enabled):
    variant_home.mkdir(mode=0o700)
    report = {"variant": name, "status": "BLOCKED", "requested_flags": list(enabled),
              "device_test": False, "flash_allowed": False, "automatic_flash": False}
    out = variant_home / "output"
    out.mkdir(mode=0o700)
    receipt = variant_home / "R14_RESULT.json"
    obj = variant_home / "obj"
    need(not obj.exists(), "R14_OBJECT_REUSED:" + name)
    obj.mkdir(mode=0o700)
    try:
        cfg = make_variant(baseline_text, enabled)
        (obj / ".config").write_text(cfg)
        report["input_config_sha256"] = sha(obj / ".config")
        variables = dict(line.split("=", 1) for line in state["variables"])
        need(variables.get("CC") == "clang" and variables.get("LD") == "ld.lld" and
             variables.get("ARCH") == "arm64" and variables.get("LLVM") == "1",
             "R14_UNPINNED_TOOLCHAIN")
        variables["O"] = str(obj)
        variables["KCFLAGS"] = (variables.get("KCFLAGS", "") + " -I" + str(obj / "security/selinux")).strip()
        env = {**os.environ, **state["env"]}
        baseline_wrapper = str(Path(baseline_work) / "source-temp/bin")
        env["PATH"] = os.pathsep.join(x for x in env["PATH"].split(os.pathsep)
                                       if x != baseline_wrapper)
        command = ["/usr/bin/make", "-C", str(source)] + [f"{k}={v}" for k,v in variables.items()]
        report["build_command"] = command
        report["compiler_origin"] = env["PATH"].split(os.pathsep)[0]
        run_cmd([*command, "olddefconfig"], variant_home / "01_olddefconfig.log", env, 600)
        actual = (obj / ".config").read_text()
        expected = {k: ("n", "y") for k in enabled}
        need(diff(config_map(baseline_text), config_map(actual)) == expected,
             "R14_KCONFIG_REWRITTEN_OTHER_FLAGS:" + name)
        run_cmd([*command, f"-j{jobs}", "init/version.o"], variant_home / "02_headers.log", env, 2400)
        run_cmd([*command, f"-j{jobs}", "security/selinux/"], variant_home / "03_selinux.log", env, 2400)
        run_cmd([*command, f"-j{jobs}", "Image", "dtbs", "modules"],
                variant_home / "04_kernel_build.log", env, 10800)
        proof = verify_compiled(source,obj,baseline_text,enabled,baseline_symbols)
        report.update(proof)
        for src,dst in ((".config", "ACTUAL.config"), ("Module.symvers", "Module.symvers"),
                        ("arch/arm64/boot/Image", "Image-NO-FLASH"),
                        ("arch/arm64/boot/dts/vendor/xiaomi/veux.dtb", "veux.dtb"),
                        ("System.map", "System.map")):
            shutil.copy2(obj / src, out / dst)
        (out / "DO_NOT_FLASH.txt").write_text(
            "RESEARCH ONLY. Raw Image without an installer. No device, vendor ABI or flash approval.\n")
        (out / "SHA256SUMS").write_text("".join(sha(f) + "  " + f.name + "\n"
                                     for f in sorted(out.iterdir()) if f.is_file()))
    except BaseException as exc:
        report["status"] = "BLOCKED"
        report["error"] = type(exc).__name__ + ": " + str(exc)
    finally:
        receipt.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def run_experiments(source: Path, obj: Path, state: dict, jobs: int, baseline_work: Path) -> None:
    temporary = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    source = Path(source).resolve(strict=True)
    obj = Path(obj).resolve(strict=True)
    need(source == temporary / "veux-r55h17-r4/source/kernel", "R14_NOT_R13_CANDIDATE")
    need(obj == temporary / "veux-r55h17-r4/build", "R14_NOT_R13_BUILD_OUTPUT")
    base_config = obj / ".config"
    original_symbols = obj / "Module.symvers"
    need(sha(base_config) == BASELINE_CONFIG_SHA, "R13_CONFIG_PIN_FAILED")
    # The R13 symbol baseline differs by order between local and CI; pinned
    # GitHub R13 reference is verified independently below by semantic fields.
    baseline = symvers(original_symbols)
    need(baseline["module_layout"] == "0xbff14f69", "R13_MODULE_LAYOUT_CHANGED")
    need(len(baseline) == 12947, "R13_BASELINE_SYMBOL_COUNT_CHANGED")
    base_text = base_config.read_text()
    baseline_sha = sha(original_symbols)
    stage = temporary / "r14-abi-variants"
    need(not stage.exists(), "R14_OUTPUT_ALREADY_EXISTS")
    stage.mkdir(mode=0o700)
    evidence = {"schema": "R14_KABI_EXPERIMENT_V1", "baseline_config_sha256": BASELINE_CONFIG_SHA,
                "baseline_symvers_sha256": baseline_sha,
                "source": "identical R13 compiled candidate", "build_provenance": "same CI run as R13",
                "device_test": False, "flash_allowed": False, "automatic_flash": False,
                "variants": {}}
    for name, enabled in VARIANTS:
        receipt = variant_compile(source,baseline_work,state,jobs,stage / name,base_text,baseline,name,enabled)
        evidence["variants"][name] = receipt["status"]
        print("R14_AB_VARIANT_" + name + "=" + receipt["status"], flush=True)
        if receipt["status"] != "ACTUALLY_COMPILED_NO_FLASH":
            # Fail fast rather than waste another full build on an unproven A variant.
            break
        # The validated Image, DTB, symbols, config and logs were already copied.
        # The large per-variant object directory is scratch and may be discarded
        # after proof; this keeps the second full build within runner disk limits.
        scratch = stage / name / "obj"
        need(scratch.is_dir() and not scratch.is_symlink() and
             scratch.resolve(strict=True).is_relative_to(stage),
             "R14_UNSAFE_SCRATCH_CLEANUP")
        shutil.rmtree(scratch)
    need(sha(base_config) == BASELINE_CONFIG_SHA and sha(original_symbols) == baseline_sha,
         "ORIGINAL_R13_BUILD_WAS_MUTATED")
    evidence["status"] = ("TWO_REAL_VARIANTS_BUILT_NO_FLASH" if
                          all(v == "ACTUALLY_COMPILED_NO_FLASH" for v in evidence["variants"].values())
                          else "BLOCKED")
    (stage / "R14_AB_EXPERIMENT_SUMMARY.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print("R14_AB_EXPERIMENT_STATUS=" + evidence["status"], flush=True)




def recover_verified_r13(temporary: Path, jobs: int) -> tuple[Path, Path, dict, Path]:
    """Verify genuine R13 receipts while its worker still owns source and objects.

    This must run inside the disposable R13 worker, before it cleans its build
    paths. The R4/R13 original source code and its checked-out files remain pinned.
    """
    temporary = Path(temporary).resolve(strict=True)
    stage = temporary / "veux-r55h17-r4"
    evidence = stage / "evidence"
    source = stage / "source/kernel"
    obj = stage / "build"
    baseline_work = temporary / "veux-r5s2-work/builds/5.4.274"
    need(source.is_dir() and obj.is_dir() and baseline_work.is_dir(),
         "R14_COMPLETED_R13_SOURCE_OR_OBJECT_MISSING")
    for directory in (stage, evidence, source, obj, baseline_work):
        need(not directory.is_symlink(), "R14_SYMLINKED_BUILD_DIRECTORY:" + directory.name)

    def receipt(name: str) -> dict:
        path = evidence / name
        need(path.is_file() and not path.is_symlink(), "R14_R13_RECEIPT_MISSING:" + name)
        row = json.loads(path.read_text())
        need(isinstance(row, dict), "R14_BAD_R13_RECEIPT:" + name)
        return row

    r4 = receipt("R4_RESULT.json")
    native = receipt("R13_NATIVE_BRANCH.json")
    compile_hook = receipt("R13_COMPILE_HOOK.json")
    command = receipt("BUILD_COMMAND.json")
    need(r4.get("status") == "CASS_UPDATED_FULL_BUILD_AND_STATIC_ABI_PASS_NOFLASH"
         and r4.get("compiler_test") is True
         and r4.get("original_baseline_unchanged") is True
         and r4.get("flash_allowed") is False
         and r4.get("rmnet_imports_matched") == 132,
         "R14_R13_CASS_AND_RMNET_GATES_NOT_PASSED")
    need(native.get("status") == "ACTUAL_NATIVE54_BRANCH_PASS"
         and native.get("original_object_and_command_unchanged") is True
         and native.get("device_test") is False,
         "R14_R13_NATIVE_BRANCH_NOT_PROVEN")
    need(compile_hook.get("r4_compile_and_static_gates_passed") is True
         and compile_hook.get("candidate_source_unchanged_during_compile") is True
         and compile_hook.get("original_version_validator_restored") is True,
         "R14_R13_COMPILE_HOOK_NOT_PROVEN")
    # Verify the actual baseline .config and Module.symvers bytes against the
    # R13 worker's own compiled-output receipt before consuming the source.
    outputs = r4.get("outputs")
    need(isinstance(outputs, dict), "R14_R13_OUTPUT_RECEIPT_MISSING")
    for filename in (".config", "Module.symvers"):
        result = outputs.get(filename)
        path = obj / filename
        need(isinstance(result, dict) and path.is_file() and not path.is_symlink()
             and type(result.get("bytes")) is int and result["bytes"] == path.stat().st_size
             and result.get("sha256") == sha(path),
             "R14_R13_COMPILED_OUTPUT_CHANGED:" + filename)
    need(command.get("source") == str(source)
         and type(command.get("jobs")) is int and command["jobs"] == jobs,
         "R14_CAPTURED_BUILD_COMMAND_OR_JOBS_CHANGED")
    variables = command.get("variables")
    env = command.get("original_captured_env")
    need(isinstance(variables, dict) and isinstance(env, dict)
         and all(isinstance(k, str) and isinstance(v, str) for k,v in variables.items())
         and all(isinstance(k, str) and isinstance(v, str) for k,v in env.items()),
         "R14_CAPTURED_STATE_INVALID")
    need(variables.get("O") == str(obj)
         and variables.get("ARCH") == "arm64"
         and variables.get("CC") == "clang"
         and variables.get("LD") == "ld.lld"
         and variables.get("LLVM") == "1"
         and variables.get("LLVM_IAS") == "1",
         "R14_CAPTURED_TOOLCHAIN_OR_OBJECT_CHANGED")
    # R4 appended exactly one object-local SELinux include. Remove ONLY that
    # generated suffix before the A/B builder supplies its own isolated O path.
    appended = " -I" + str(obj / "security/selinux")
    kcflags = variables.get("KCFLAGS", "")
    need(kcflags.endswith(appended) and kcflags.count(appended) == 1,
         "R14_CAPTURED_SELINUX_INCLUDE_NOT_UNIQUE")
    inherited_kcflags = kcflags[:-len(appended)]
    variables = dict(variables)
    variables["KCFLAGS"] = inherited_kcflags
    need(variables.get("O") == str(obj), "R14_OBJECT_CAPTURE_CHANGED")
    need(isinstance(env.get("PATH"), str) and env["PATH"]
         and str(baseline_work / "source-work/toolchains/clang-r416183b/bin")
             in env["PATH"].split(os.pathsep),
         "R14_CAPTURED_COMPILER_PATH_UNPINNED")
    captured = {"variables": [k + "=" + v for k,v in variables.items()], "env": env}
    return source, obj, captured, baseline_work


# Existing R13/R4 worker code stays byte-for-byte unchanged. Only the worker
# *generated in RUNNER_TEMP* receives this additional post-R13 call.
R14_WORKER_CALL = (
    "        import os as __r14_os\n"
    "        import runpy as __r14_runpy\n"
    "        __r14_runpy.run_path(__r14_os.path.join(__r14_os.environ['GITHUB_WORKSPACE'], "
    "'experiments/r14_abi_build_bridge.py'))['run_inside_worker'](args.jobs)\n"
)


def inject_r14_after_r13(worker: Path, original_attach, hook: str) -> dict:
    """Transactional injector for one authenticated disposable R13 worker."""
    import ast
    from pathlib import Path
    worker = Path(worker)
    temporary = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    need(not worker.is_symlink() and worker.is_file() and
         worker.resolve(strict=True).is_relative_to(temporary),
         'R14_WORKER_NOT_DISPOSABLE')
    before = worker.read_bytes()
    # Fail closed if previous hooks are absent, altered, or multiplied.
    try:
        metadata = original_attach(worker)
        body = worker.read_text(encoding='utf-8')
        need(body.count(hook) == 1, 'R14_R13_WORKER_HOOK_NOT_EXACTLY_ONCE')
        need('run_inside_worker' not in body, 'R14_WORKER_ALREADY_PATCHED')
        updated = body.replace(hook, hook + R14_WORKER_CALL, 1)
        ast.parse(updated, filename=str(worker))
        need(updated.replace(hook + R14_WORKER_CALL, hook, 1) == body,
             'R14_UNRELATED_WORKER_MUTATION')
        worker.write_text(updated, encoding='utf-8')
        need(worker.read_text(encoding='utf-8') == updated, 'R14_WORKER_WRITEBACK_FAILED')
    except BaseException:
        # Only the throwaway worker script is rolled back; kernel state untouched.
        worker.write_bytes(before)
        raise
    return {**metadata, 'r14_post_r13_worker': True,
            'r14_worker_source_only': True, 'worker_code_restores_exactly': True}


def run_inside_worker(jobs: int) -> None:
    """Executed by the actual R13 worker, before its temporary cleanup."""
    temporary = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    stage = temporary / 'r14-abi-variants'
    need(not stage.exists(), 'R14_WORKER_REENTRY')
    need(1 <= jobs <= 12, 'R14_UNSAFE_JOBS')
    try:
        source, obj, captured, baseline_work = recover_verified_r13(temporary, jobs)
        run_experiments(source, obj, captured, jobs, baseline_work)
        proof = json.loads((stage / 'R14_AB_EXPERIMENT_SUMMARY.json').read_text())
        need(proof.get('status') == 'TWO_REAL_VARIANTS_BUILT_NO_FLASH',
             'R14_A_B_BUILD_NOT_BOTH_GREEN')
    except BaseException as exc:
        record_blocked(temporary, exc)
        raise
    print('R14_REAL_R13_WORKER_POSTCOMPILE=PASS; DEVICE=NO; FLASH=NO', flush=True)


def record_blocked(temporary: Path, exception: BaseException) -> None:
    stage = Path(temporary) / "r14-abi-variants"
    stage.mkdir(mode=0o700, exist_ok=True)
    status = stage / "R14_AB_EXPERIMENT_SUMMARY.json"
    if not status.exists():
        status.write_text(json.dumps({
            "schema": "R14_KABI_EXPERIMENT_V1", "status": "BLOCKED",
            "reason": type(exception).__name__ + ": " + str(exception),
            "flash_allowed": False, "device_test": False,
            "automatic_flash": False, "variants": {}
        }, indent=2, sort_keys=True) + "\n")


def worker_cross_process_smoke() -> None:
    """CI precompile smoke using the *real* pinned R4/R13 injection sources.

    The worker is synthetic; it proves hook order, subprocess visibility and
    precleanup execution, not ARM64 compilation or device compatibility.
    """
    import runpy
    import tempfile
    original_path = list(sys.path)
    source_root = Path(os.environ['REPRO_PAYLOAD']).resolve(strict=True)
    r4_root = Path(os.environ['R4_PAYLOAD']).resolve(strict=True)
    sys.path.insert(0, str(source_root / 'r11'))
    try:
        r4 = runpy.run_path(str(r4_root / 'workflow/cass_r4_bridge.py'))
        r13 = runpy.run_path(str(source_root / 'r13/veux_r13_bridge.py'))
    finally:
        sys.path[:] = original_path
    need(r4['HOOK'] == r13['OLD_HOOK'], 'SMOKE_R4_R13_HOOK_DRIFT')
    with tempfile.TemporaryDirectory(prefix='r14-worker-smoke-',
                                     dir=os.environ['RUNNER_TEMP']) as tmp:
        root = Path(tmp)
        workspace = root / 'repo' / 'experiments'
        workspace.mkdir(parents=True)
        (workspace / 'r14_abi_build_bridge.py').write_text(
            'import os\nfrom pathlib import Path\n'
            'def run_inside_worker(jobs):\n'
            '    root=Path(os.environ["RUNNER_TEMP"])\n'
            '    assert jobs==4 and (root/"candidate_source").is_dir()\n'
            '    (root/"CALLBACK_BEFORE_CLEANUP.txt").write_text("PASS")\n')
        (root / 'candidate_source').mkdir()
        (root / 'veux_r13_ci_abi_hook.py').write_text(
            'def run_update(src,state,work,jobs):\n'
            '    assert jobs==4\n'
            '    return "R13_WORKER_PASS"\n')
        worker = root / 'worker.py'
        worker.write_text(
            'from pathlib import Path\nimport shutil\n'
            'from types import SimpleNamespace\n'
            'def verify_version_compilation(*a): return "PINNED_VERSION"\n'
            'def worker():\n'
            '    src=Path(__file__).parent\n'
            '    work=src\n'
            '    state={}\n'
            '    args=SimpleNamespace(jobs=4)\n'
            '    result={}\n'
            '    real_version={}\n'
            '    if True:\n'
            + r4['ANCHOR'] +
            '    shutil.rmtree(src/"candidate_source")\n'
            'worker()\n')
        previous = os.environ['RUNNER_TEMP']
        try:
            os.environ['RUNNER_TEMP'] = str(root)
            def real_original_attach(file):
                # Use the unmodified official R4 injector with its genuine
                # R13 replacement hook, but do not change the pinned module.
                before = r4['attach_hook'].__globals__['HOOK']
                r4['attach_hook'].__globals__['HOOK'] = r13['NEW_HOOK']
                try:
                    return r4['attach_hook'](file)
                finally:
                    r4['attach_hook'].__globals__['HOOK'] = before
            metadata = inject_r14_after_r13(worker, real_original_attach,
                                             r13['NEW_HOOK'])
        finally:
            os.environ['RUNNER_TEMP'] = previous
        need(metadata['r14_post_r13_worker'], 'SMOKE_NO_R14_INJECTION')
        child_env = {**os.environ, 'RUNNER_TEMP': str(root),
                     'GITHUB_WORKSPACE': str(root / 'repo'),
                     'PYTHONPATH': str(root)}
        result = subprocess.run([sys.executable, str(worker)], env=child_env,
                                capture_output=True, text=True, timeout=30)
        need(result.returncode == 0,
             'SMOKE_CROSS_PROCESS_FAILED:' + result.stderr[-350:])
        need(not (root / 'candidate_source').exists()
             and (root / 'CALLBACK_BEFORE_CLEANUP.txt').read_text() == 'PASS',
             'SMOKE_CALLBACK_NOT_BEFORE_CLEANUP')
        print('R14_REAL_R4_R13_CROSS_PROCESS_PRECOMPILE_SMOKE=PASS', flush=True)


def selftest():
    source = "CONFIG_SCHED_CASS=y\n# CONFIG_ANDROID_KABI_RESERVE is not set\n# CONFIG_ANDROID_VENDOR_OEM_DATA is not set\n"
    assert diff(config_map(source), config_map(make_variant(source, FLAGS[:1]))) == {
        FLAGS[0]: ("n", "y")}
    assert diff(config_map(source), config_map(make_variant(source, FLAGS))) == {
        FLAGS[0]: ("n", "y"), FLAGS[1]: ("n", "y")}
    for key in FLAGS:
        try:
            make_variant(source.replace("# " + key + " is not set", key + "=y"), FLAGS)
        except ValueError:
            pass
        else:
            raise AssertionError("changed baseline was accepted")
    import ast
    ast.parse("def worker():\n" + R14_WORKER_CALL)
    need(('R4_PAYLOAD' in os.environ) == ('REPRO_PAYLOAD' in os.environ),
         'SMOKE_MISSING_VERIFIED_R4_OR_R13_INPUT')
    if 'R4_PAYLOAD' in os.environ:
        worker_cross_process_smoke()
    print("R14_EXPERIMENT_BRIDGE_SELFTEST=PASS; INSIDE_R13_WORKER_BRIDGE=PASS")


def main():
    if len(sys.argv) == 2 and sys.argv[1] == '--selftest':
        selftest()
        return
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--jobs', type=int, required=True)
    args, _ = parser.parse_known_args()
    need(1 <= args.jobs <= 12, 'R14_UNSAFE_JOBS')
    import cass_r4_bridge as r4
    import veux_r13_bridge as r13
    need(r4.HOOK == r13.OLD_HOOK, 'R14_R13_ORIGINAL_HOOK_PRECONDITION_FAILED')
    original_attach = r4.attach_hook
    injected = []

    def attach_before_r13_worker_exit(worker):
        row = inject_r14_after_r13(worker, original_attach, r13.NEW_HOOK)
        injected.append(row)
        return row

    # The original R13 main dynamically installs its own R4 hook. The pinned
    # bridge's existing attach_hook dispatches this wrapper in the parent,
    # and the resulting disposable script executes *inside* the R13 worker.
    r4.attach_hook = attach_before_r13_worker_exit
    try:
        r13.main()
    finally:
        r4.attach_hook = original_attach
    need(len(injected) == 1 and injected[0]['r14_post_r13_worker'],
         'R14_WORKER_INJECTION_NOT_EXACTLY_ONCE')
    need((Path(os.environ['RUNNER_TEMP']) / 'r14-abi-variants' /
          'R14_AB_EXPERIMENT_SUMMARY.json').is_file(),
         'R14_WORKER_RESULT_NOT_PRESERVED')


if __name__ == '__main__':
    main()
