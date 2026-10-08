#!/usr/bin/env python3
"""Permanent VEUX 5.4.274 ConfigDiag10 gate for the regular release path.

This module reuses the exact source/config audit payloads that passed
GitHub Actions run 36738661110 and were subsequently device-checked.
It intentionally affects only kernel 5.4.274. Other VEUX lineages call the
unchanged shared engine directly.
"""
import importlib.util
import json
import os
from pathlib import Path
import sys

import veux_update_engine as e

KERNEL = "5.4.274"
ROOT = e.REPO / "common/diagnostics/config-5.4.274-diag10"
REFERENCE_RUN = "36738661110"

ASSETS = {
    'manifest.json': 'c60052d22d85688edd649c7d6871eb785a49506f73b12a4634cdf2fe973e3601',
    'embed-real-config.patch': 'e59ea6e82044671f52b9a3df310cbb8b0919d337aafa4cbe080881e7022e3598',
    'baseline-evidence.json': 'cde1f9c73d28425b26d95e53140413dac148f9440ce7c81278eb36add0a63602',
    'config_audit.py': '8a78893987e1a993a1ef346fc555c4826f5201357474abafb8df4c80872d88dc',
    'vintf_kernel.py': '94a9bf0994c0726df729f51796e99c7b818ac2c396061f90896e7daeea3ed415',
    'test_config_audit.py': '41161bb0b0e4c52facfa16f364e9d68b973d09d2e6e88739c944f251c70be6c8',
    'test_vintf_kernel.py': '84a2f7aa7edb83fadf882a69de9a0829e5bb4559731bdcc9d43442f5ccdcf237',
    'rom-kernel-requirements.xml': '69cb367264e7377cc04e545c96067bffcc77106aa13aed9a197cb8564e149712',
    'rom-evidence.json': '1c68ba83b56985b67a01bf4dee3cbb5cd64bafb9c7fee6396e2a3ae01365b619',
    'diag09-actual.config': 'a71fd6c33449b4d3e55b1713aeaf636b40523cba68e0be2d42de7ed487a3d20a',
    'sched-debug-manifest.json': '7e355746dee280be91c938d0190dc1cff7d6f42fbf13a32b090e12624846acec',
    'sched-debug-pm.patch': 'a12bd25d37d5b7bcbc03713f9c11a3f145789758daf3ddd8272f0a65cf296e09',
    'test_sched_debug.py': '511be033fac79d778572866f1ac4d03c4a7ebbc82271616c94c628c10e5c409f',
    'source/arch/arm64/configs/stock_defconfig': '722bcc5a40b5998f147b7e40712fb230be3f8549a593b9c538763324987469de',
    'source/arch/arm64/configs/veux_defconfig': '77906c4876f1fff5fd65411757be85a99c6ec77e0202ef9b81fe9dc1d37533a7',
    'source/kernel/Makefile': 'f27b67d514325559eade0530c2bb3265ecd25ece0c3e3fedd89e56b3507d2744',
    'source/kernel/configs.c': '221375bdb85f3ac14a84988589ce0789f499e5806a3a5c8eca579facf29187ae',
    'source/kernel/sched/debug.c': '1b156c025085839c15a6114ea3eb3dcf0c0b79f9bdc817d9ab43344b1e67de03',
    'source/lib/Kconfig.debug': 'b979a9e4a0eabb4f8f3e928c29bc1aff22f3dfea15a6c1049698c872775baeec',
    'source/scripts/Kbuild.include': 'c640d23c2a096d39f41ec6737511619d2113e06d8a2e1b940cb9ceeac985d9f9',
    'source/scripts/Makefile.lib': '76e2b9ee96091ea7b0bec368bf0271702aa92dbf70a4d27e2481f5a8cf25af01',
}


def authenticate():
    """Fail closed unless every reviewed Diag10 input is byte-exact."""
    e.require(ROOT.is_dir() and not ROOT.is_symlink(),
              "ConfigDiag10 asset directory missing or linked")
    for rel, expected in ASSETS.items():
        path = e.inside(ROOT / rel, ROOT)
        e.require(path.is_file() and not path.is_symlink(),
                  "ConfigDiag10 input missing or linked: " + rel)
        e.require(e.digest(path) == expected,
                  "ConfigDiag10 input drift: " + rel)
    manifest = json.loads((ROOT / "manifest.json").read_text())
    e.require(manifest.get("id") == "ConfigDiag10",
              "ConfigDiag10 manifest identity changed")
    e.require(manifest.get("source_commit") ==
              "b2b7a3bbc36d120ee523ebc8d68e0f13a97df632",
              "ConfigDiag10 source baseline changed")
    e.require(manifest.get("regular_patchset") == "charger-diag08",
              "ConfigDiag10 requires cumulative charger-diag08")
    return manifest


def _load_audit():
    """Load the reviewed audit implementation without changing global PYTHONPATH."""
    authenticate()
    root = str(ROOT)
    added = root not in sys.path
    if added:
        sys.path.insert(0, root)
    try:
        spec = importlib.util.spec_from_file_location(
            "veux_configdiag10_audit", ROOT / "config_audit.py")
        e.require(spec is not None and spec.loader is not None,
                  "cannot load ConfigDiag10 audit")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        if added:
            try:
                sys.path.remove(root)
            except ValueError:
                pass


def expected_proof(report=None):
    """Derive a proof from this build; the default is a synthetic test fixture.

    REFERENCE_RUN describes the origin of the audited source fixes, not a
    required byte representation of every future build's configuration.
    """
    return _proof_from_report(reference_report() if report is None else report)



def reference_report():
    """Synthetic host-test fixture. Never an authority for a real build's hash."""
    import hashlib
    options = {
        "IKCONFIG": "y", "IKCONFIG_PROC": "y", "LTO": "y",
        "LTO_CLANG": "y", "THINLTO": "y", "CFI_CLANG": "y",
        "CFI_CLANG_SHADOW": "y", "CFI_PERMISSIVE": "n",
    }
    fixture = "".join("CONFIG_" + name + "=" + value + "\n"
                      for name, value in sorted(options.items())).encode("ascii")
    actual = hashlib.sha256(fixture).hexdigest()
    return {
        "id": "ConfigDiag10", "status": "PASS",
        "actual_config_sha256": actual,
        "embedded_config_sha256": actual,
        "configuration_unchanged_during_compile": True,
        "options": options,
        "vintf_kernel": {
            "status": "PASS", "requirements": 261,
            "passed": 261, "failures": [],
        },
        "cfi": "configured-and-core-instrumented",
        "stack_protector": "strong-configured-and-core-instrumented",
        "device": False,
    }

def _proof_from_report(report):
    """Validate audited settings and same-build consistency, not an old file hash.

    The unchanged config audit checks all captured ROM requirements, generated
    compiler options, compiler evidence and exact actual/embedded configuration
    bytes. A raw digest is recorded for provenance, never compared with a
    historical configuration. A project-name comment therefore cannot fail CI.
    """
    import re
    e.require(isinstance(report, dict) and report.get("status") == "PASS",
              "ConfigDiag10 audit did not pass")
    e.require(report.get("id") == "ConfigDiag10", "ConfigDiag10 audit identity missing")
    actual = report.get("actual_config_sha256")
    embedded = report.get("embedded_config_sha256")
    e.require(isinstance(actual, str) and
              re.fullmatch(r"[0-9a-f]{64}", actual) is not None,
              "invalid actual configuration digest")
    e.require(isinstance(embedded, str) and embedded == actual,
              "embedded IKCONFIG differs from this build's actual configuration")
    e.require(report.get("configuration_unchanged_during_compile") is True,
              "configuration was not proven unchanged during compilation")
    required = {
        "IKCONFIG": "y", "IKCONFIG_PROC": "y", "LTO": "y",
        "LTO_CLANG": "y", "THINLTO": "y", "CFI_CLANG": "y",
        "CFI_CLANG_SHADOW": "y", "CFI_PERMISSIVE": "n",
    }
    options = report.get("options")
    e.require(isinstance(options, dict), "audited configuration options missing")
    for name, value in required.items():
        e.require(options.get(name) == value,
                  "required audited setting differs: CONFIG_" + name)
    vintf = report.get("vintf_kernel")
    e.require(isinstance(vintf, dict) and vintf.get("status") == "PASS"
              and type(vintf.get("requirements")) is int
              and vintf["requirements"] == 261
              and type(vintf.get("passed")) is int and vintf["passed"] == 261
              and vintf.get("failures") == [],
              "captured ROM kernel requirements are not 261/261 PASS")
    e.require(report.get("cfi") == "configured-and-core-instrumented",
              "CFI compile evidence missing")
    e.require(report.get("stack_protector") ==
              "strong-configured-and-core-instrumented",
              "strong stack-protector compile evidence missing")
    e.require(report.get("device") is False,
              "CI must not infer a device PASS")
    return {
        "id": "ConfigDiag10", "reference_run": REFERENCE_RUN,
        "actual_config_sha256": actual,
        "rom_requirements": vintf["requirements"], "rom_status": "PASS",
        "cfi": report["cfi"], "stack_protector": report["stack_protector"],
        "device_pass_inferred": False,
    }


def compile_kernel(label, state, targets, work, jobs):
    """Use the unchanged shared engine; add ConfigDiag10 only to 5.4.274."""
    if label != KERNEL:
        return e.compile_kernel(label, state, targets, work, jobs)

    audit = _load_audit()
    with audit.compiler_audit(work / "config-reports"):
        image, result = e.compile_kernel(label, state, targets, work, jobs)

    proof = _proof_from_report(result.get("config_audit"))
    result["config_compat"] = proof
    e.write_json(work / "build-result.json", result)
    print("CONFIG_DIAG10_REGULAR_RELEASE=PASS; ROM=261/261; DEVICE_PASS=NO",
          flush=True)
    return image, result


def verify_result(label, row):
    """Validate the proof against its own audit, including after packaging."""
    if label != KERNEL:
        return
    e.require(isinstance(row, dict), "invalid ConfigDiag10 build result")
    proof = _proof_from_report(row.get("config_audit"))
    e.require(row.get("config_compat") == proof,
              "ConfigDiag10 promotion proof differs from this build's audit")
