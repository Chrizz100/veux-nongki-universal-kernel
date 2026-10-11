#!/usr/bin/env python3
"""VEUX R2: isolated, read-only NoMount 21 integration trial for kernel 5.4.274.

Neither this tool nor the accompanying workflow modifies the checked-out repo,
changes CURRENT_BUILD, updates third_party/current, or automatically flashes.
Do not treat a source preflight or CI compile as a successful device validation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import traceback

import veux_update_engine as engine
import veux_current_components as components

REPOSITORY = "Chrizz100/veux-nongki-universal-kernel"
EXPECTED_ENGINE_GIT_BLOB = "1b59c48392fa63af9640dce47b111057ab237b31"
EXPECTED_INTEGRATED = {
    "resukisu": "8770c7e324a22895703c4916b8a16520e0b81c79",
    "susfs": "5326e21a7eb232f9e21debdd5164e99bee3d1e2f",
    "nomount": "c5fad9d8f97c5a207f7342fd91789449915ea047",
}
PINNED_NOMOUNT21 = "1ded61dc908c511072162fa0bee44e6ccdb7b4c7"
KERNEL = "5.4.274"
LINEAGES = ("5.4.274", "5.4.292", "5.4.293", "5.4.300", "5.4.301", "5.4.302")


class TrialBlocked(RuntimeError):
    """Mandatory validation gate refused source integration."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise TrialBlocked(reason)


def file_git_blob(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\x00" + data).hexdigest()


def command(*args: str, cwd: Path | None = None) -> str:
    p = subprocess.run([str(x) for x in args], cwd=cwd, capture_output=True,
                       text=True, timeout=240, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
    if p.returncode:
        raise TrialBlocked(f"command failed rc={p.returncode}: {args[0]}: {p.stderr[-800:]}")
    return p.stdout.strip()


def tracked_head(url: str, ref: str) -> str:
    lines = command("git", "ls-remote", "--exit-code", "--refs", url, ref).splitlines()
    require(len(lines) == 1, f"upstream ref missing or ambiguous: {ref}")
    parts = lines[0].split()
    require(len(parts) == 2 and parts[1] == ref and re.fullmatch(r"[0-9a-f]{40}", parts[0]),
            f"invalid upstream ref response: {ref}")
    return parts[0]


def check_symlinks(root: Path) -> list[dict]:
    real_root = root.resolve(strict=True)
    found = []
    for p in sorted(root.rglob("*")):
        if not p.is_symlink():
            continue
        target = Path(os.readlink(p))
        require(not target.is_absolute(), f"absolute upstream symlink: {p}")
        try:
            resolved = p.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise TrialBlocked(f"broken or cyclic upstream symlink: {p}") from exc
        require(resolved.is_relative_to(real_root), f"upstream symlink escapes source: {p}")
        found.append({"path": str(p.relative_to(root)), "target": str(target)})
    return found


def _canonical(text: str) -> str:
    text = re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)
    return " ".join(re.findall(r"[A-Za-z_][A-Za-z_0-9]*|\d+|[^\s]", text))


def _declaration(source: str, name: str) -> str:
    if name == "enum":
        pattern = r"enum\s*\{\s*NM_CMD_UNSPEC\s*=\s*0,[\s\S]*?\};"
    else:
        pattern = (r"\bstruct\s+" + re.escape(name)
                   + r"\s*\{[\s\S]*?\}\s*__attribute__\s*\(\(packed\)\)\s*;")
    matches = re.findall(pattern, source, flags=re.S)
    require(len(matches) == 1, f"NoMount protocol declaration missing/ambiguous: {name}")
    return _canonical(matches[0])


def abi_guard(baseline: str, candidate: str) -> dict:
    """Compare *wire protocol declarations*, not private VFS structures."""
    details = {}
    for name in ("enum", "nm_payload", "nm_rule_hdr", "nm_del_hdr"):
        old, new = _declaration(baseline, name), _declaration(candidate, name)
        require(old == new, f"NoMount 21 wire-protocol changed: {name}; review necessary")
        details[name] = "IDENTICAL"
    require(re.search(r'^\s*#define\s+NOMOUNT_VERSION\s+"20"', baseline, re.M) is not None,
            "baseline is not validated NoMount 20")
    require(re.search(r'^\s*#define\s+NOMOUNT_BASE_VERSION\s+"21"', candidate, re.M) is not None,
            "candidate is not NoMount base-version 21")
    require("NOMOUNT_COMMIT_COUNT" in candidate, "expected optional version suffix missing")
    return details


def validate_contract(repo: Path) -> dict:
    require(repo.is_dir() and (repo / ".git").exists(), "repository checkout missing")
    require(not (repo / "common/scripts/veux_update_engine.py").is_symlink(), "linked engine rejected")
    actual_blob = file_git_blob(repo / "common/scripts/veux_update_engine.py")
    require(actual_blob == EXPECTED_ENGINE_GIT_BLOB,
            f"engine drift: {actual_blob}; expected {EXPECTED_ENGINE_GIT_BLOB}")
    current = json.loads((repo / "common/contracts/CURRENT_BUILD.json").read_text())
    require(current.get("status") == "compile-package-static-validated", "CURRENT_BUILD unvalidated")
    require(current.get("device_pass_inferred") is False, "invalid device-pass claim")
    require(tuple(sorted(current["lineages"])) == tuple(sorted(LINEAGES)), "lineage set changed")
    require(set(current["targets"]) == set(EXPECTED_INTEGRATED), "component set changed")
    for label, value in current["lineages"].items():
        require(value.get("targets") == current["targets"], f"target mismatch for {label}")
    for component, commit in EXPECTED_INTEGRATED.items():
        entry = current["targets"][component]
        require(entry.get("commit") == commit, f"integrated {component} changed; re-review")
        require(isinstance(entry.get("url"), str) and entry["url"].startswith("https://"),
                f"untrusted upstream URL: {component}")
        require(re.fullmatch(r"refs/heads/[A-Za-z0-9_./-]+", entry.get("ref", "")) is not None
                and ".." not in entry["ref"], f"untrusted upstream ref: {component}")
    require(current["targets"]["resukisu"].get("uapi") == 5, "UAPI5 baseline changed")
    require(current["targets"]["nomount"].get("version") == "20", "baseline NoMount version changed")
    return current


def check_project_identity(repo: Path) -> str:
    require(os.environ.get("GITHUB_REPOSITORY", REPOSITORY) == REPOSITORY,
            "wrong GitHub repository")
    sha = command("git", "-C", str(repo), "rev-parse", "HEAD")
    require(re.fullmatch(r"[0-9a-f]{40}", sha) is not None, "invalid repository SHA")
    require(os.environ.get("GITHUB_SHA", sha) == sha, "wrong checkout SHA")
    require(not command("git", "-C", str(repo), "status", "--porcelain", "--untracked-files=all"),
            "repository checkout dirty")
    return sha


def write_report(root: Path, report: dict):
    folder = root / "report"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "NOMOUNT21_R2.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


def initialize_workspace(repo: Path, root: Path) -> Path:
    """Accept only the workflow's empty pre-created report directory.

    GitHub Actions creates ``<work>/report`` ahead of the preflight so failure
    reports can be uploaded.  Every other existing workspace entry is still
    rejected, and neither the workspace nor report may be symlinks.
    """
    require(not root.is_symlink(), "workspace symlink rejected")
    real_repo = repo.resolve(strict=True)
    real_root = root.resolve()
    require(not real_root.is_relative_to(real_repo),
            "temporary workspace must be OUTSIDE repository")
    if real_root.exists():
        require(real_root.is_dir(), "workspace is not a directory")
        entries = list(real_root.iterdir())
        require(all(entry.name == "report" for entry in entries),
                "workspace already populated")
        report = real_root / "report"
        if entries:
            require(not report.is_symlink() and report.is_dir(),
                    "unsafe pre-created report directory")
            require(not any(report.iterdir()),
                    "pre-created report directory is not empty")
    else:
        real_root.mkdir(parents=True, exist_ok=False)
    return real_root


def prepare(repo: Path, root: Path) -> dict:
    repo = repo.resolve(strict=True)
    root = initialize_workspace(repo, root)
    report = {"schema": 1, "project": REPOSITORY, "kernel": KERNEL,
              "status": "BLOCKED", "trial_kind": "isolated-nomount21",
              "repository_written": False, "current_build_modified": False,
              "upstream_bakasu_imported": False, "kernel_build_performed": False,
              "device_validation_performed": False, "can_flash": False,
              "source_preflight": False, "compile_opt_in_only": True}
    try:
        sha = check_project_identity(repo)
        current = validate_contract(repo)
        report["checked_main_commit"] = sha
        report["integrated_targets"] = {k: v["commit"] for k, v in current["targets"].items()}
        _cfg, _fleet = engine.check_repo()
        bundle = root / "bundle"
        bundle.mkdir()
        targets = {"schema": 1, "repository_sha": sha,
                   "golden_sha256": engine.digest(repo / engine.config()["golden_contract"]),
                   "lineages": [KERNEL], "components": {},
                   "candidate_manual_build": True, "isolated_nomount21_trial": True,
                   "device_pass_inferred": False}
        symlinks = {}
        for component in ("resukisu", "susfs", "nomount"):
            old = current["targets"][component]
            url, ref = old["url"], old["ref"]
            remote = tracked_head(url, ref)
            wanted = PINNED_NOMOUNT21 if component == "nomount" else old["commit"]
            if component == "nomount":
                require(remote == PINNED_NOMOUNT21,
                        "NoMount head moved: repeat upstream source audit before building")
                require(wanted != old["commit"], "NoMount21 equals frozen version20")
            donor = bundle / component
            engine.checkout(url, wanted, donor, full=True)
            require(command("git", "-C", str(donor), "rev-parse", "HEAD") == wanted,
                    f"{component} checkout mismatch")
            require(subprocess.run(["git", "-C", str(donor), "merge-base", "--is-ancestor",
                                    old["commit"], remote], capture_output=True).returncode == 0,
                    f"{component} remote history rewound")
            symlinks[component] = check_symlinks(donor)
            values = dict(old)
            if component == "nomount":
                values.update(commit=wanted, version="21",
                              version_kind="base-version-dynamic-commit-count")
                values.pop("ahead", None)  # never re-use the historical count as new delta
                values.pop("base", None)   # never re-use the historical stable pin
                old_header = (repo / "third_party/current/nomount/kernel/src/nomount.h").read_text()
                new_header = (donor / "kernel/src/nomount.h").read_text()
                report["nomount_wire_abi"] = abi_guard(old_header, new_header)
                kernel_src = donor / "kernel/src"
                require({p.name for p in kernel_src.iterdir()} ==
                        {"Kconfig", "Makefile", "nomount.c", "nomount.h"},
                        "NoMount21 kernel source layout changed")
            elif component == "resukisu":
                require(components.checked_uapi(donor) == 5, "frozen ReSukiSU UAPI5 check failed")
                # The imported BakaSU new head has a SUSFS build blocker; don't import it.
                suspect = donor / "kernel/tools/susfs_compat.mk"
                require(not suspect.is_file() or
                        "$(error Please wait susfs update.)" not in suspect.read_text(),
                        "the pinned legacy ReSukiSU unexpectedly contains the SUSFS blocker")
            targets["components"][component] = values
            report.setdefault("component_identity", {})[component] = {
                "url": url, "ref": ref, "integrated": old["commit"],
                "trial": wanted, "remote_head_at_run": remote}
        report["snapshot_symlinks"] = symlinks
        engine.write_json(bundle / "targets.json", targets)

        # Perform actual, safe source integration into RUNNER_TEMP only.
        import veux_source_transport as transport
        import veux_device_fixes as fixes
        import veux_rpm_fixes as rpm
        import veux_rpm24 as rpm24
        import veux_wakeup_fixes as wakeup
        preflight = root / "source-check" / KERNEL
        preflight.mkdir(parents=True)
        state = transport.materialize(KERNEL, preflight)
        src = Path(state["source"])
        engine.apply_update(src, state, bundle, preflight)
        integrated_header = (src / "fs/nomount/nomount.h").read_text()
        require("#define NOMOUNT_BASE_VERSION \"21\"" in integrated_header,
                "NoMount21 missing from integrated VEUX 5.4 source")
        proof = fixes.apply(src, KERNEL, preflight)
        fixes.verify_source(src, KERNEL, proof)
        rpm_proof = rpm.apply(src, KERNEL, preflight)
        rpm.verify_source(src, KERNEL, rpm_proof)
        rpm24.apply(src, KERNEL, preflight)
        wakeup_proof = wakeup.apply(src, KERNEL, preflight)
        wakeup.verify_source(src, KERNEL, wakeup_proof)
        report["source_preflight"] = True
        report["status"] = "SOURCE_PREFLIGHT_PASS"
        report["notice"] = "Manual build may be attempted; source PASS is NOT compile/device PASS"
        report["needs_kernel_rebuild"] = True
        report["compilation_performed_in_preflight"] = False
        # Untrusted source snapshots must not be copied into repository or release.
        shutil.rmtree(root / "source-check", ignore_errors=True)
        write_report(root, report)
        print("VEUX_NOMOUNT21_SOURCE_PREFLIGHT=PASS")
        print("REPOSITORY_WRITE=NO")
        print("KERNEL_BUILD=NO")
        print("DEVICE_PASS=NO")
        return report
    except Exception as exc:
        report["reason"] = str(exc)
        report["traceback_tail"] = "".join(traceback.format_exception(exc))[-5000:]
        write_report(root, report)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("prepare", nargs="?", choices=["prepare"], default="prepare")
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--work", required=True, type=Path)
    args = parser.parse_args()
    try:
        prepare(args.repo, args.work)
        return 0
    except (TrialBlocked, engine.Blocked, OSError, KeyError, ValueError,
            subprocess.SubprocessError) as exc:
        print("NOMOUNT21_TRIAL_BLOCKED: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
