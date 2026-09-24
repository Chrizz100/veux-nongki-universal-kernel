#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError as exc:
    raise SystemExit("PyYAML is required: python3 -m pip install PyYAML") from exc

SHA40 = re.compile(r"^[0-9a-f]{40}$")
KERNEL = re.compile(r"^5\.4\.\d+$")
BASELINE_ROLES = {"golden", "derive"}
PORT_STATUS = {"full-pass", "pending", "candidate", "validated"}


def die(message: str) -> "None":
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def require_mapping(obj, where: str) -> dict:
    if not isinstance(obj, dict):
        die(f"{where} must be a mapping")
    return obj


def require_bool(obj: dict, key: str, where: str) -> bool:
    value = obj.get(key)
    if not isinstance(value, bool):
        die(f"{where}.{key} must be true or false")
    return value


def require_string(obj: dict, key: str, where: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip():
        die(f"{where}.{key} must be a non-empty string")
    return value.strip()


def validate_feature(features: dict, name: str, config_path: Path) -> dict:
    where = f"{config_path}:{name}"
    feature = require_mapping(features.get(name), where)
    enabled = require_bool(feature, "enabled", where)
    if enabled:
        version = require_string(feature, "version", where)
        commit = require_string(feature, "commit", where).lower()
        if not SHA40.fullmatch(commit):
            die(f"{where}.commit must be an exact 40-hex commit SHA")
    else:
        version = str(feature.get("version") or "disabled")
        commit = str(feature.get("commit") or "")
    result = {"enabled": enabled, "version": version, "commit": commit}
    if name == "resukisu":
        uapi = feature.get("uapi")
        if enabled and (not isinstance(uapi, int) or uapi < 1):
            die(f"{where}.uapi must be a positive integer")
        result["uapi"] = uapi if enabled else None
    return result


def validate_baseline(repo_root: Path, doc: dict, config_path: Path, verify_paths: bool) -> dict:
    b = require_mapping(doc.get("baseline"), f"{config_path}:baseline")
    baseline_id = require_string(b, "id", f"{config_path}:baseline")
    manifest = require_string(b, "manifest", f"{config_path}:baseline")
    role = require_string(b, "role", f"{config_path}:baseline")
    status = require_string(b, "port_status", f"{config_path}:baseline")
    from_kernel = require_string(b, "from_kernel", f"{config_path}:baseline")
    if role not in BASELINE_ROLES:
        die(f"{config_path}: baseline.role must be one of {sorted(BASELINE_ROLES)}")
    if status not in PORT_STATUS:
        die(f"{config_path}: baseline.port_status must be one of {sorted(PORT_STATUS)}")
    if from_kernel != "5.4.274":
        die(f"{config_path}: baseline.from_kernel must be '5.4.274'")
    if verify_paths and not (repo_root / manifest).is_file():
        die(f"{config_path}: golden manifest does not exist: {manifest}")
    return {
        "baseline_id": baseline_id,
        "baseline_manifest": manifest,
        "baseline_role": role,
        "port_status": status,
        "from_kernel": from_kernel,
    }


def validate_config(repo_root: Path, config_path: Path, verify_paths: bool) -> dict:
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except Exception as exc:
        die(f"cannot parse {config_path}: {exc}")
    doc = require_mapping(raw, str(config_path))

    allowed = {
        "schema", "kernel", "enabled", "device", "platform", "target",
        "baseline", "legacy_authority", "features", "outputs", "validation"
    }
    unknown = sorted(set(doc) - allowed)
    if unknown:
        die(f"{config_path} contains unknown top-level keys: {', '.join(unknown)}")

    if doc.get("schema") != 1:
        die(f"{config_path}: schema must be 1")

    kernel = require_string(doc, "kernel", str(config_path))
    if not KERNEL.fullmatch(kernel):
        die(f"{config_path}: unsupported kernel label {kernel!r}")
    if config_path.parent.name != kernel:
        die(f"{config_path}: kernel value must match parent directory {config_path.parent.name!r}")

    enabled = require_bool(doc, "enabled", str(config_path))
    device = require_string(doc, "device", str(config_path))
    platform = require_string(doc, "platform", str(config_path))
    target = require_string(doc, "target", str(config_path))
    if device != "veux":
        die(f"{config_path}: device must be 'veux'")
    if platform.lower() != "sm6375":
        die(f"{config_path}: platform must be 'sm6375'")

    baseline = validate_baseline(repo_root, doc, config_path, verify_paths)

    authority = require_mapping(doc.get("legacy_authority"), f"{config_path}:legacy_authority")
    workflow = require_string(authority, "workflow", f"{config_path}:legacy_authority")
    if not workflow.startswith(".github/workflows/") or not workflow.endswith((".yml", ".yaml")):
        die(f"{config_path}: legacy authority must point to a workflow YAML")
    if verify_paths and not (repo_root / workflow).is_file():
        die(f"{config_path}: authority workflow does not exist: {workflow}")

    features = require_mapping(doc.get("features"), f"{config_path}:features")
    if set(features) != {"resukisu", "susfs", "nomount"}:
        die(f"{config_path}: features must contain exactly resukisu, susfs, nomount")
    resukisu = validate_feature(features, "resukisu", config_path)
    susfs = validate_feature(features, "susfs", config_path)
    nomount = validate_feature(features, "nomount", config_path)

    outputs = require_mapping(doc.get("outputs"), f"{config_path}:outputs")
    ak3 = require_bool(outputs, "ak3", f"{config_path}:outputs")
    boot_img = require_bool(outputs, "boot_img", f"{config_path}:outputs")
    if not (ak3 or boot_img):
        die(f"{config_path}: at least one output must be enabled")

    validation = require_mapping(doc.get("validation"), f"{config_path}:validation")
    for key in ("compile", "package", "static_boot", "device"):
        require_bool(validation, key, f"{config_path}:validation")

    if baseline["baseline_role"] == "golden":
        if kernel != "5.4.274":
            die(f"{config_path}: only 5.4.274 may be the golden baseline")
        if baseline["port_status"] != "full-pass":
            die(f"{config_path}: golden baseline must have port_status=full-pass")
        if not validation["device"]:
            die(f"{config_path}: golden baseline must record device=true")
    else:
        if validation["device"]:
            die(f"{config_path}: derived pending/candidate lineages may not claim device=true")

    return {
        "kernel": kernel,
        "config": config_path.relative_to(repo_root).as_posix(),
        "device": device,
        "platform": platform.lower(),
        "target": target,
        "authority_workflow": workflow,
        "resukisu_version": resukisu["version"],
        "resukisu_commit": resukisu["commit"],
        "resukisu_uapi": resukisu.get("uapi"),
        "susfs_version": susfs["version"],
        "susfs_commit": susfs["commit"],
        "nomount_enabled": nomount["enabled"],
        "nomount_version": nomount["version"],
        "nomount_commit": nomount["commit"],
        "ak3": ak3,
        "boot_img": boot_img,
        "enabled": enabled,
        **baseline,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Discover and validate VEUX kernel lineage build profiles")
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--skip-repo-path-check", action="store_true")
    args = parser.parse_args()

    root = Path(args.repo_root).resolve()
    candidates = sorted(root.glob("lineages/*/build.yml"), key=lambda p: p.parent.name)
    if not candidates:
        die("no lineages/*/build.yml files found")

    rows = [validate_config(root, p, not args.skip_repo_path_check) for p in candidates]
    kernels = [row["kernel"] for row in rows]
    if len(kernels) != len(set(kernels)):
        die("duplicate kernel versions discovered")

    baseline_ids = {row["baseline_id"] for row in rows}
    manifests = {row["baseline_manifest"] for row in rows}
    if len(baseline_ids) != 1 or len(manifests) != 1:
        die("all enabled lineages must reference one identical golden baseline")

    golden = [row for row in rows if row["baseline_role"] == "golden"]
    if len(golden) != 1 or golden[0]["kernel"] != "5.4.274":
        die("exactly one golden baseline is required and it must be 5.4.274")

    enabled = [row for row in rows if row["enabled"]]
    if not enabled:
        die("all discovered kernel profiles are disabled")

    matrix = {"include": enabled}
    compact = json.dumps(matrix, separators=(",", ":"), sort_keys=True)
    pretty = json.dumps(matrix, indent=2, sort_keys=True)
    print(pretty)

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as fh:
            fh.write(f"matrix={compact}\n")
            fh.write(f"count={len(enabled)}\n")
            fh.write(f"baseline_id={golden[0]['baseline_id']}\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
