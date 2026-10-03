#!/usr/bin/env python3
"""Collect pinned Xiaomi sources and real olddefconfig evidence; NEVER build/flash.

The workflow result describes evidence collection. Compatibility is a separate
field in report.json. Even a compatible config is not a kernel release approval.
Requires Python 3.10+, Git, make, host build tools and aarch64-linux-gnu-gcc.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import traceback
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
DEVICE_REFERENCE = REPO / "device" / "sweet" / "reference"
LINEAGE_ROOT = REPO / "lineages" / "sweet"
SOURCE_LOCK = LINEAGE_ROOT / "source_lock.json"
OEM_REFERENCE = LINEAGE_ROOT / "reference"
NAME = re.compile(r"CONFIG_[A-Za-z0-9_]+")
ASSIGN = re.compile(r'^(CONFIG_[A-Za-z0-9_]+)=(y|m|n|-?[0-9]+|0[xX][0-9A-Fa-f]+|"(?:[^"\\]|\\.)*")$')
DISABLED = re.compile(r"^# (CONFIG_[A-Za-z0-9_]+) is not set$")
SYMBOL = re.compile(r"^\s*(?:config|menuconfig)\s+([A-Za-z0-9_]+)(?:\s*(?:#.*)?)$")
COMMIT = re.compile(r"[0-9a-f]{40}")
CRITICAL = (
    "64BIT ARM64 ARCH_QCOM ARCH_SM6150 ARCH_SDMMAGPIE "
    "TOUCHSCREEN_GOODIX_GTX9896_K6 TOUCHSCREEN_FTS_K6 "
    "TOUCHSCREEN_XIAOMI_TOUCHFEATURE FINGERPRINT_FS_TEE "
    "INPUT_AW8624_HAPTIC BATT_VERIFY_BY_DS28E16 ONEWIRE_GPIO "
    "K6_CHARGE BQ2597X_CHARGE_PUMP CHARGER_LN8000 QPNP_SMB5 "
    "SCSI_UFSHCD SCSI_UFS_QCOM SCSI_UFS_CRYPTO SCSI_UFS_CRYPTO_QTI "
    "UFSFEATURE UFSHPB UFSTW UFSTW_IGNORE_GUARANTEE_BIT SCSI_SKHPB "
    "BLK_INLINE_ENCRYPTION BLK_INLINE_ENCRYPTION_FALLBACK "
    "DM_CRYPT DM_DEFAULT_KEY F2FS_FS F2FS_FS_ENCRYPTION "
    "FS_ENCRYPTION_INLINE_CRYPT OVERLAY_FS SECURITY_SELINUX "
    "MODULES MODVERSIONS IKCONFIG IKCONFIG_PROC "
    "SERIAL_MSM_GENI_CONSOLE LEDS_QPNP_VIBRATOR_LDO "
    "ANDROID_LOW_MEMORY_KILLER KPROBES CMDLINE"
).split()


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def git_blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def parse_config(text: str) -> dict[str, Any]:
    """Parse assignments only; not a Kconfig dependency solver.

    In particular '#CONFIG_FOO is not set' is a comment, NOT the canonical
    disabled assignment accepted by this kernel's confdata.c. Preserve this
    distinction instead of silently repairing an upstream defconfig.
    """
    values: dict[str, str] = {}
    duplicates: list[dict[str, Any]] = []
    commented_directives: list[dict[str, Any]] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if not line:
            continue
        match = ASSIGN.fullmatch(line)
        disabled = DISABLED.fullmatch(line)
        if match:
            key, value = match.groups()
        elif disabled:
            key, value = disabled.group(1), "n"
        elif line.startswith("#"):
            if line.startswith("#CONFIG_"):
                commented_directives.append({"line": lineno, "text": line})
            continue
        else:
            raise ValueError(f"Unsupported config syntax at line {lineno}: {line!r}")
        if key in values:
            if values[key] != value:
                raise ValueError(f"Conflicting duplicate assignment: {key}")
            duplicates.append({"line": lineno, "symbol": key, "value": value})
        values[key] = value
    if not values:
        raise ValueError("Configuration has no assignments")
    return {"values": values, "identical_duplicates": duplicates,
            "commented_directives": commented_directives}


def compare_configs(reference: dict[str, str], candidate: dict[str, str]) -> dict[str, Any]:
    shared = reference.keys() & candidate.keys()
    changed = [{"symbol": k, "stock": reference[k], "candidate": candidate[k]}
               for k in sorted(shared) if reference[k] != candidate[k]]
    missing = [{"symbol": k, "stock": reference[k]}
               for k in sorted(reference.keys() - candidate.keys())]
    added = [{"symbol": k, "candidate": candidate[k]}
             for k in sorted(candidate.keys() - reference.keys())]
    return {"same": sum(reference[k] == candidate[k] for k in shared),
            "changed": changed, "missing": missing, "added": added,
            "note": "Absence is recorded separately from an explicit n; no dependency inference."}


def critical_gate(reference: dict[str, str], candidate: dict[str, str]) -> dict[str, Any]:
    failures: list[dict[str, Any]] = []
    for short in CRITICAL:
        key = "CONFIG_" + short
        if key not in reference:
            raise ValueError(f"Critical setting not in supplied stock reference: {key}")
        actual = candidate.get(key)
        if actual != reference[key]:
            failures.append({"symbol": key, "stock": reference[key], "candidate": actual})
    return {"scope": "selected stock config values only; NOT ABI/build/device validation",
            "checked": len(CRITICAL), "passed": not failures, "failures": failures}


def write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def run(argv: list[str], log: Path, timeout: int = 600) -> str:
    """Execute without a shell. Failures retain their original command output."""
    print("$ " + " ".join(argv), flush=True)
    with log.open("ab") as stream:
        stream.write(("$ " + " ".join(argv) + "\n").encode("utf-8"))
        stream.flush()
        done = subprocess.run(argv, stdout=stream, stderr=subprocess.STDOUT,
                              timeout=timeout, check=False)
    if done.returncode:
        raise RuntimeError(f"Command exited {done.returncode}; see {log.name}: {argv[0]}")
    return ""


def git_output(source: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(source), *args],
                                   text=True, encoding="utf-8", timeout=120).strip()


def acquire_source(repository: str, commit: str, source: Path, log: Path) -> None:
    if not COMMIT.fullmatch(commit):
        raise ValueError("A complete 40-hex commit is required")
    if source.exists():
        raise FileExistsError(f"Refusing to overwrite source directory: {source}")
    source.parent.mkdir(parents=True, exist_ok=True)
    run(["git", "init", "--quiet", str(source)], log)
    run(["git", "-C", str(source), "remote", "add", "origin", repository], log)
    for attempt in range(2):
        try:
            run(["git", "-C", str(source), "fetch", "--no-tags", "--depth=1",
                 "origin", commit], log, timeout=600)
            break
        except (RuntimeError, subprocess.TimeoutExpired):
            if attempt == 1:
                raise
            time.sleep(5)
    run(["git", "-C", str(source), "checkout", "--quiet", "--detach", "FETCH_HEAD"], log)
    if git_output(source, "rev-parse", "HEAD") != commit:
        raise ValueError("Checked-out commit differs from source lock")
    run(["git", "-C", str(source), "fsck", "--full", "--no-dangling"], log)
    if git_output(source, "status", "--porcelain"):
        raise ValueError("Checkout is unexpectedly modified")


def archive_source(source: Path, branch: str, commit: str, output: Path, log: Path) -> Path:
    if not re.fullmatch(r"[a-zA-Z0-9_-]+", branch) or not COMMIT.fullmatch(commit):
        raise ValueError("Unsafe archive label or commit")
    archive = output / f"{branch}_{commit[:12]}_source.tar.gz"
    run(["git", "-C", str(source), "archive", "--format=tar.gz",
         f"--prefix={branch}/", f"--output={archive}", commit], log)
    if not archive.is_file() or not archive.stat().st_size:
        raise ValueError("Source archive is missing or empty")
    return archive


def verify_source_archive(source: Path, archive: Path, branch: str, commit: str) -> dict[str, Any]:
    """Hash every archived file against the pinned Git tree, including symlink data.

    This detects export-ignore/export-subst omissions or transformations rather
    than silently calling an incomplete git archive a complete source snapshot.
    No archive entries are extracted or executed.
    """
    raw = subprocess.check_output(
        ["git", "-C", str(source), "ls-tree", "-rz", commit], timeout=120)
    expected: dict[str, tuple[str, str]] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        meta, name = record.split(b"\t", 1)
        mode, kind, blob = meta.decode("ascii").split()
        if kind != "blob" or mode not in {"100644", "100755", "120000"}:
            raise ValueError(f"Unarchived dependency or unsupported Git entry: {name!r}")
        expected[name.decode("utf-8")] = (mode, blob)
    seen: set[str] = set()
    total_bytes = 0
    links = 0
    prefix = branch + "/"
    with tarfile.open(archive, mode="r|gz") as stream:
        for item in stream:
            if item.isdir():
                continue
            if not item.name.startswith(prefix):
                raise ValueError(f"Archive entry outside expected root: {item.name}")
            name = item.name[len(prefix):]
            if name in seen or name not in expected:
                raise ValueError(f"Duplicate or unexpected archived entry: {name}")
            mode, blob = expected[name]
            if mode == "120000":
                if not item.issym():
                    raise ValueError(f"Symlink was not preserved: {name}")
                data = item.linkname.encode("utf-8")
                digest = git_blob(data)
                total_bytes += len(data)
                links += 1
            else:
                if not item.isfile():
                    raise ValueError(f"Expected regular archived file: {name}")
                if bool(item.mode & 0o111) != (mode == "100755"):
                    raise ValueError(f"Executable bit differs: {name}")
                payload = stream.extractfile(item)
                if payload is None:
                    raise ValueError(f"Missing archive payload: {name}")
                h = hashlib.sha1(b"blob " + str(item.size).encode("ascii") + b"\0")
                size = 0
                for block in iter(lambda: payload.read(1024 * 1024), b""):
                    h.update(block)
                    size += len(block)
                if size != item.size:
                    raise ValueError(f"Truncated archive entry: {name}")
                digest = h.hexdigest()
                total_bytes += size
            if digest != blob:
                raise ValueError(f"Archived contents differ from Git blob: {name}")
            seen.add(name)
    missing = sorted(expected.keys() - seen)
    if missing:
        raise ValueError(f"Archive omits {len(missing)} Git entries, first: {missing[0]}")
    return {"all_git_blobs_matched": True, "entries": len(seen),
            "symlinks": links, "uncompressed_bytes": total_bytes}


def inventory_kconfig(source: Path) -> dict[str, Any]:
    raw = subprocess.check_output(["git", "-C", str(source), "ls-files", "-z"], timeout=120)
    symbols: dict[str, list[dict[str, Any]]] = {}
    files = 0
    for name in raw.decode("utf-8").split("\0"):
        if not name or not Path(name).name.startswith("Kconfig"):
            continue
        path = source / name
        # Stay inside this checkout, including when a tracked file is a symlink.
        if not path.resolve().is_relative_to(source.resolve()):
            raise ValueError(f"External Kconfig link: {name}")
        if not path.is_file():
            raise FileNotFoundError(f"Missing tracked Kconfig file: {name}")
        files += 1
        for lineno, text in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            match = SYMBOL.fullmatch(text)
            if match:
                symbols.setdefault("CONFIG_" + match.group(1), []).append({"path": name, "line": lineno})
    return {"scope": "lexical definitions only; does not establish Kconfig reachability",
            "files_scanned": files, "symbols": symbols}


def version_from_makefile(text: str) -> str:
    parts = []
    for key in ("VERSION", "PATCHLEVEL", "SUBLEVEL"):
        matches = re.findall(r"^" + key + r"\s*=\s*([0-9]+)\s*$", text, flags=re.M)
        if len(matches) != 1:
            raise ValueError(f"Invalid kernel version field: {key}")
        parts.append(matches[0])
    return ".".join(parts)


def save_checksums(output: Path) -> None:
    entries = []
    for path in sorted(output.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS.txt":
            entries.append(f"{sha256(path)}  {path.relative_to(output).as_posix()}")
    (output / "SHA256SUMS.txt").write_text("\n".join(entries) + "\n", encoding="utf-8")



# This narrow policy comes from the pinned OEM Makefile, lines 293-302.
# It is NOT permission to alter source, disable checks or install RTMM/KTRACE.
K6A_STUB_COMMIT = "10c33d40a11ecdc75cc1dadb5bd07894bab05815"
OEM_EMPTY_STUBS = (
    "drivers/staging/ktrace/Kconfig", "drivers/staging/ktrace/Makefile",
    "drivers/staging/rtmm/Kconfig", "drivers/staging/rtmm/Makefile",
)
OEM_HEADER_LINKS = {
    "include/linux/ktrace.h": "include/dum/ktrace.h",
    "include/linux/rtmm.h": "include/dum/rtmm.h",
}


def workspace_state(source: Path, upstream_commit: str | None = None) -> dict[str, Any]:
    """Classify tracked changes and ALL extra files, including Git-ignored files.

    Only the six exact, verified OEM side effects in an isolated K6A workspace
    are accepted. All tracked changes, nonempty stubs and unexpected links fail.
    No files are removed, rewritten, staged, or hidden from Git by this check.
    """
    def names(*args: str) -> list[str]:
        raw = subprocess.check_output(["git", "-C", str(source), *args], timeout=120)
        return [v.decode("utf-8") for v in raw.split(b"\0") if v]
    tracked = names("diff", "--no-ext-diff", "--no-textconv", "--name-only", "-z", "HEAD", "--")
    extra = names("ls-files", "--others", "-z", "--")  # deliberately no exclude-standard
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    expected = set(OEM_EMPTY_STUBS) | set(OEM_HEADER_LINKS)
    for name in sorted(extra):
        path = source / name
        info: dict[str, Any] = {"path": name}
        mode = path.lstat().st_mode
        allowed = False
        if stat.S_ISLNK(mode):
            target = os.readlink(path)
            info.update(type="symlink", target=target)
            if upstream_commit == K6A_STUB_COMMIT and name in OEM_HEADER_LINKS:
                expected_target = source.resolve() / OEM_HEADER_LINKS[name]
                allowed = (target == str(expected_target)
                           and expected_target.is_file() and not expected_target.is_symlink())
        elif stat.S_ISREG(mode):
            info.update(type="file", size=path.stat().st_size, sha256=sha256(path))
            allowed = (upstream_commit == K6A_STUB_COMMIT
                       and name in OEM_EMPTY_STUBS and path.stat().st_size == 0)
        else:
            info.update(type="unsupported")
        (accepted if allowed else rejected).append(info)
    incomplete = bool(accepted) and {v["path"] for v in accepted} != expected
    status = subprocess.check_output(
        ["git", "-C", str(source), "status", "--porcelain=v1", "--untracked-files=all"],
        text=True, encoding="utf-8", timeout=120)
    return {"upstream_policy_commit": upstream_commit,
            "tracked_changes": tracked, "accepted_oem_generated": accepted,
            "unexpected_generated": rejected, "incomplete_oem_generation": incomplete,
            "all_extra_files_checked_including_ignored": True,
            "git_status": status,
            "passed": not tracked and not rejected and not incomplete}


def create_kconfig_workspace(source: Path, workspace: Path, ref: str, log: Path) -> None:
    if workspace.exists():
        raise FileExistsError(f"Refusing existing Kconfig workspace: {workspace}")
    if workspace.resolve().is_relative_to(source.resolve()):
        raise ValueError("Kconfig workspace must be outside the pristine checkout")
    if not workspace_state(source)["passed"]:
        raise ValueError("Pristine checkout is already dirty before Kconfig")
    run(["git", "-C", str(source), "worktree", "add", "--detach", str(workspace), ref], log)
    if git_output(workspace, "rev-parse", "HEAD") != git_output(source, "rev-parse", ref):
        raise ValueError("Kconfig worktree uses a different commit")
    if not workspace_state(workspace)["passed"]:
        raise ValueError("Kconfig worktree is not initially clean")


def audit_kconfig(source: Path, ref: str, upstream_commit: str, stock: Path,
                  work_dir: Path, output: Path, reference: dict[str, str],
                  report: dict[str, Any], *, cc: str = "aarch64-linux-gnu-gcc",
                  cross_compile: str = "aarch64-linux-gnu-") -> None:
    """Run real Kconfig in a disposable worktree; the archived source stays clean.

    cc/cross_compile are explicit parameters for host-only local reproduction,
    not extra workflow inputs and not a release-kernel toolchain selection.
    """
    workspace = work_dir.resolve() / "kconfig-source"
    build_out = work_dir.resolve() / "kconfig-out"
    if output.resolve().is_relative_to(workspace) or output.resolve().is_relative_to(build_out):
        raise ValueError("Evidence output must be outside Kconfig work directories")
    create_kconfig_workspace(source, workspace, ref, output / "kconfig-worktree.log")
    write_json(output / "source_state_before.json", {
        "pristine": workspace_state(source), "kconfig_workspace": workspace_state(workspace)})
    build_out.mkdir(parents=True, exist_ok=False)
    (build_out / ".config").write_bytes(stock.read_bytes())
    command = ["make", "-C", str(workspace), f"O={build_out}", "ARCH=arm64",
               f"CROSS_COMPILE={cross_compile}", f"CC={cc}", "HOSTCC=gcc", "olddefconfig"]
    report["olddefconfig_command"] = command
    report["olddefconfig_ok"] = False
    report["kconfig_uses_isolated_worktree"] = True
    try:
        run(command, output / "olddefconfig_1.log", timeout=600)
        first = (build_out / ".config").read_bytes()
        (output / "resolved.config").write_bytes(first)
        resolved = parse_config(first.decode("utf-8"))["values"]
        differences = compare_configs(reference, resolved)
        write_json(output / "resolved_vs_stock.json", differences)
        report["critical_config_gate"] = critical_gate(reference, resolved)
        report["all_active_stock_options"] = {
            "scope": "all stock y/m symbols, NOT ABI or device compatibility",
            "missing_or_changed": [
                {"symbol": key, "stock": value, "candidate": resolved.get(key)}
                for key, value in sorted(reference.items())
                if value in {"y", "m"} and resolved.get(key) != value],
        }
        run(command, output / "olddefconfig_2.log", timeout=600)
        if (build_out / ".config").read_bytes() != first:
            raise ValueError("Repeated olddefconfig is not byte-idempotent")
        report["olddefconfig_ok"] = True
        report["olddefconfig_idempotent"] = True
    finally:
        # Keep exact diagnostics even when make or config comparison failed.
        pristine = workspace_state(source)
        derived = workspace_state(workspace, upstream_commit)
        write_json(output / "source_state_after.json", {
            "pristine": pristine, "kconfig_workspace": derived})
        diff = subprocess.check_output(
            ["git", "-C", str(workspace), "diff", "--no-ext-diff", "--no-textconv", "HEAD", "--"],
            timeout=120)
        (output / "kconfig_workspace_tracked.diff").write_bytes(diff)
        report["source_unchanged"] = pristine["passed"]
        report["kconfig_workspace_integrity_ok"] = derived["passed"]
        report["oem_generated_paths"] = [v["path"] for v in derived["accepted_oem_generated"]]
    if not pristine["passed"] or not derived["passed"]:
        raise ValueError("Unexpected source changes; see source_state_after.json and kconfig_workspace_tracked.diff")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--branch", required=True, choices=["sweet-r-oss", "sweet_k6a-r-oss"])
    ap.add_argument("--work-dir", required=True, type=Path)
    ap.add_argument("--output-dir", required=True, type=Path)
    args = ap.parse_args()
    output = args.output_dir.resolve()
    if output.exists() and any(output.iterdir()):
        print("Refusing to mix old and new audit results", file=sys.stderr)
        return 2
    output.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {
        "branch": args.branch, "audit_completed": False,
        "kernel_built": False, "device_tested": False, "release_eligible": False,
        "artifacts_flashable": False,
        "important": "A successful collection job is NOT a kernel Green Pass. Read the critical_config_gate.",
        "configuration_compiler": "GCC cross compiler for Kconfig audit only; not the release Clang toolchain"
    }
    exit_code = 1
    try:
        lock = json.loads(SOURCE_LOCK.read_text(encoding="utf-8"))
        if lock.get("schema") != 1 or lock.get("mode") != "source_and_kconfig_audit_only":
            raise ValueError("Unsupported source-lock schema")
        stock = DEVICE_REFERENCE / "stock.config"
        expected_stock_hash = lock["stock_config_sha256"]
        if sha256(stock) != expected_stock_hash:
            raise ValueError("Stock config hash does not match the recorded boot.img reference")
        reference = parse_config(stock.read_text(encoding="utf-8"))["values"]
        critical_gate(reference, reference)  # verify that every gate key is real
        source_spec = lock["sources"][args.branch]
        commit = source_spec["commit"]
        report["source_commit"] = commit
        source = args.work_dir.resolve() / "source"
        if output == source or output.is_relative_to(source):
            raise ValueError("Output directory must be outside the kernel checkout")
        acquire_source(lock["repository"], commit, source, output / "git.log")
        archive = archive_source(source, args.branch, commit, output, output / "archive.log")
        report["source_archive"] = {"file": archive.name, "sha256": sha256(archive)}
        report["source_archive"]["git_tree_verification"] = verify_source_archive(
            source, archive, args.branch, commit)
        raw_defconfig = (source / source_spec["defconfig_path"]).read_bytes()
        if git_blob(raw_defconfig) != source_spec["defconfig_blob"]:
            raise ValueError("OEM defconfig differs from pinned Git blob")
        (output / "oem.defconfig").write_bytes(raw_defconfig)
        (output / "stock.input.config").write_bytes(stock.read_bytes())
        version = version_from_makefile((source / "Makefile").read_text(encoding="utf-8"))
        report["source_kernel_version"] = version
        if version != source_spec["declared_kernel_version"]:
            raise ValueError("Unexpected source Makefile version")
        parsed_defconfig = parse_config(raw_defconfig.decode("utf-8"))
        write_json(output / "literal_defconfig_vs_stock.json",
                   {"diff": compare_configs(reference, parsed_defconfig["values"]),
                    "scope": "written defaults only; NOT the resolved .config",
                    "commented_directives": parsed_defconfig["commented_directives"],
                    "identical_duplicates": parsed_defconfig["identical_duplicates"]})
        inventory = inventory_kconfig(source)
        write_json(output / "kconfig_inventory.json", inventory)
        write_json(output / "stock_symbols_not_declared.json", [
            {"symbol": key, "stock": value}
            for key, value in sorted(reference.items()) if key not in inventory["symbols"]
        ])
        report["kconfig_files_scanned"] = inventory["files_scanned"]
        for cmd in (["git", "--version"], ["make", "--version"], ["gcc", "--version"],
                    ["aarch64-linux-gnu-gcc", "--version"], ["uname", "-a"]):
            run(cmd, output / "environment.log", timeout=60)
        audit_kconfig(source, commit, commit, stock, args.work_dir, output, reference, report)
        if sha256(stock) != expected_stock_hash:
            raise ValueError("Stock reference changed during audit")
        report["audit_completed"] = True
        report["source_unchanged"] = True
        if not report["critical_config_gate"]["passed"]:
            count = len(report["critical_config_gate"]["failures"])
            print(f"::warning::SWEET source collection complete, but {count} critical stock options are missing or changed. NOT a kernel release.", flush=True)
        # Known compatibility findings do not falsify completed data collection.
        # No flag anywhere in this program can grant release/flash approval.
        exit_code = 0
    except Exception as exc:
        report["error"] = str(exc)
        (output / "failure.log").write_text(traceback.format_exc(), encoding="utf-8")
        print(f"AUDIT ERROR: {exc}", file=sys.stderr)
    finally:
        write_json(output / "report.json", report)
        gate = report.get("critical_config_gate", {})
        state = "PASS" if gate.get("passed") else "BLOCKED / NOT COMPLETE"
        text = (f"# SWEET OEM audit: {args.branch}\n\n"
                f"Evidence collection completed: {report['audit_completed']}\n\n"
                f"Critical stock-config preservation: **{state}**\n\n"
                "**No kernel build. No AK3. No new boot.img. Not flashable.**\n\n"
                "A green collection job is not a kernel Green Pass. The source archives\n"
                "are unmodified OEM snapshots. Kconfig differences remain findings even\n"
                "when collection succeeds. Read report.json and resolved_vs_stock.json.\n")
        if gate.get("failures"):
            text += "\n| Stock option | Stock | Resolved |\n|---|---|---|\n"
            for item in gate["failures"]:
                text += f"| {item['symbol']} | {item['stock']} | {item['candidate'] or 'absent'} |\n"
        text += ("\nKconfig uses a separate worktree. The archived original is checked independently. "
                 "Only the six byte/type/target-checked OEM placeholder outputs of the pinned K6A "
                 "Makefile are accepted in that worktree. This does not restore missing stock features.\n")
        (output / "SUMMARY.md").write_text(text, encoding="utf-8")
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as stream:
                stream.write(text + "\n")
        save_checksums(output)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
