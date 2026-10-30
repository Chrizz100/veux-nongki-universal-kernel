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
    need(sha(base_config) == BASELINE_CONFIG_SHA and sha(original_symbols) == baseline_sha,
         "ORIGINAL_R13_BUILD_WAS_MUTATED")
    evidence["status"] = ("TWO_REAL_VARIANTS_BUILT_NO_FLASH" if
                          all(v == "ACTUALLY_COMPILED_NO_FLASH" for v in evidence["variants"].values())
                          else "BLOCKED")
    (stage / "R14_AB_EXPERIMENT_SUMMARY.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print("R14_AB_EXPERIMENT_STATUS=" + evidence["status"], flush=True)


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
    print("R14_EXPERIMENT_BRIDGE_SELFTEST=PASS")


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--selftest":
        selftest()
        return
    # The pinned R13 bridge and build code are deliberately unchanged. Scope the
    # compile callback to an in-memory wrapper, restore it unconditionally.
    import cass_r4_build as original
    import veux_r13_bridge as r13
    base_compile = original.compile_candidate

    def original_then_ab(candidate, obj, baseline_config, state, version, evidence,
                         jobs, baseline_work=None):
        result = base_compile(candidate, obj, baseline_config, state, version, evidence,
                              jobs, baseline_work)
        need(baseline_work is not None, "MISSING_ORIGINAL_BASELINE")
        run_experiments(Path(candidate),Path(obj),state,jobs,Path(baseline_work))
        return result

    original.compile_candidate = original_then_ab
    try:
        r13.main()
    finally:
        original.compile_candidate = base_compile


if __name__ == "__main__":
    main()
