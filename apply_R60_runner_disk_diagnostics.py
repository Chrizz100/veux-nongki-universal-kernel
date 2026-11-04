#!/usr/bin/env python3
"""R60 NOFLASH: instrument *only* disk usage. No deletion, cleanup or new gates.

Run on the exact reviewed R12 workflow. This never writes to GitHub and never
changes the kernel sources, toolchain, input archive, or build requirements.
"""
from __future__ import annotations
import argparse
import hashlib
from pathlib import Path

BASE_SHA1 = "7bde2cc7b7cc278f59f2644bc9f1679ebf99ed91"
BASE_SHA256 = "27de0e4074b668917ec12d7b0df56d3aa8316f4b0996294249953ff8450d38c0"
WORKFLOW_NAME = "VEUX_R60_NATIVE54_CASS_BUILD_NOFLASH.yml"


def blob_sha(content: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()


INITIAL_ANCHOR = "        echo 'R12_IMMUTABLE_REPOSITORY=PASS'\n"
BASELINE_ANCHOR = '        export PYTHONPATH="$REPRO_PAYLOAD/r13:$REPRO_PAYLOAD/r11:$R4_PAYLOAD/workflow:$REPRO_PAYLOAD/r12:$VERSION_OVERLAY/common/scripts:$R5S2_OVERLAY/common/scripts:$R5S1_OVERLAY/common/scripts:$R5_OVERLAY/common/scripts:$R4_OVERLAY/common/scripts:$NM211_R2_OVERLAY/common/scripts${PYTHONPATH:+:$PYTHONPATH}"\n'
NATIVE_ANCHOR = '        bash "$R58_PAYLOAD/tools/r59_build_no_flash.sh"\n'


def report(stage: str, include_sizes: bool) -> str:
    # This is a non-blocking read-only measurement, not a disk-space gate.
    output = (
        f"        echo 'R60_DISK_DIAG_{stage}'\n"
        '        df -hP "$RUNNER_TEMP" "$GITHUB_WORKSPACE" || true\n'
        '        df -iP "$RUNNER_TEMP" || true\n'
    )
    if include_sizes:
        output += (
            '        for diagnostic_path in "$RUNNER_TEMP/veux-r5s2-work" "$RUNNER_TEMP/veux-r60-clang-cache" "$RUNNER_TEMP/veux-real-bakasu-history" "$RUNNER_TEMP/veux-r58" "$GITHUB_WORKSPACE"; do\n'
            '          if [[ -d "$diagnostic_path" && ! -L "$diagnostic_path" ]]; then\n'
            '            du -sh -- "$diagnostic_path" || true\n'
            '          fi\n'
            '        done\n'
        )
    return output


def replace_once(data: str, anchor: str, replacement: str) -> str:
    hits = data.count(anchor)
    if hits != 1:
        raise ValueError(f"Expected exactly one insertion anchor; got {hits}: {anchor[:80]!r}")
    return data.replace(anchor, replacement, 1)


def patch(data: str) -> str:
    if "R60_DISK_DIAG_INITIAL" in data:
        raise ValueError("Disk diagnostics already present, refuse double insertion")
    result = replace_once(data, INITIAL_ANCHOR, INITIAL_ANCHOR + report("INITIAL", False))
    result = replace_once(result, BASELINE_ANCHOR, report("BEFORE_BASELINE", True) + BASELINE_ANCHOR)
    result = replace_once(result, NATIVE_ANCHOR, report("BEFORE_NATIVE54", True) + NATIVE_ANCHOR)
    # All baseline RUN, jobs, uses, security pins, arguments, and labels must stay.
    def structure(src: str) -> tuple[list[str], list[str]]:
        lines = src.splitlines()
        return ([line for line in lines if line.lstrip().startswith("- name:")],
                [line for line in lines if line.lstrip().startswith("uses:")])
    if structure(result) != structure(data):
        raise ValueError("Workflow steps or pinned GitHub actions were modified")
    if result.count("sudo rm") != data.count("sudo rm"):
        raise ValueError("Unexpected deletion instruction")
    for expected in (
        "FLASH_ALLOWED=NO",
        "R60_MAIN_SHA256: d6b0e06d60374c131a5f3730790db1f2f35e538adddeb407f50d5c8874b58d67",
        "R5S2_MAIN_SHA256: 37a85d967df5cd9fa4dd3302e2073bc3b9ce461a6e03cd0ef51914fa5f5358b8",
    ):
        if expected not in result:
            raise ValueError("R60 original source integrity/NOFLASH contract missing: " + expected)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a diagnostics-only R60 YAML from exact R12 original")
    parser.add_argument("original", type=Path, help="Unmodified workflow file from GitHub main at the pinned R12 blob")
    parser.add_argument("--output", type=Path, help="Destination for generated YAML; defaults to sibling _DIAG.yml")
    args = parser.parse_args()
    original = args.original.read_bytes()
    if blob_sha(original) != BASE_SHA1 or hashlib.sha256(original).hexdigest() != BASE_SHA256:
        parser.error("Input is not the exact reviewed GitHub R60-R12 workflow; no changes written")
    try:
        result = patch(original.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        parser.error(str(exc))
    target = args.output or args.original.with_name(WORKFLOW_NAME.removesuffix(".yml") + "_DIAG.yml")
    if target.exists():
        parser.error("Output path already exists: " + str(target))
    target.write_bytes(result.encode("utf-8"))
    print("DISK_DIAGNOSTICS=3/3; NO_DELETION=YES; NO_NEW_CAPACITY_GATES=YES")
    print("WORKFLOW_STEPS_AND_ACTION_PINS=UNCHANGED; FLASH_ALLOWED=NO")
    print("OUTPUT=" + str(target))
    print("OUTPUT_SHA256=" + hashlib.sha256(target.read_bytes()).hexdigest())


if __name__ == "__main__":
    main()
