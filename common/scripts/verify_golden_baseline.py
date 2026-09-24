#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

import yaml

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA64 = re.compile(r"^[0-9a-f]{64}$")


def die(msg: str) -> "None":
    print(f"GOLDEN_BASELINE_ERROR: {msg}", file=sys.stderr)
    raise SystemExit(1)


def load_yaml(path: Path) -> dict:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        die(f"cannot parse {path}: {exc}")
    if not isinstance(doc, dict):
        die(f"{path} must contain a mapping")
    return doc


def req_map(d: dict, key: str) -> dict:
    v = d.get(key)
    if not isinstance(v, dict):
        die(f"{key} must be a mapping")
    return v


def req_str(d: dict, key: str) -> str:
    v = d.get(key)
    if not isinstance(v, str) or not v.strip():
        die(f"{key} must be a non-empty string")
    return v.strip()


def git_blob(path: Path) -> str:
    p = subprocess.run(
        ["git", "hash-object", str(path)],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
    )
    if p.returncode != 0:
        die(f"git hash-object failed for {path}: {p.stderr.strip()}")
    return p.stdout.strip()


def github_json(url: str, token: str) -> dict:
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "veux-golden-baseline-verifier",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read().decode("utf-8"))
    except Exception as exc:
        die(f"GitHub API request failed: {url}: {exc}")
    if not isinstance(data, dict):
        die(f"GitHub API response is not an object: {url}")
    return data


def validate_manifest(root: Path, manifest_path: Path) -> dict:
    m = load_yaml(manifest_path)
    if m.get("schema") != 1:
        die("golden manifest schema must be 1")

    golden_id = req_str(m, "id")
    if req_str(m, "device") != "veux":
        die("golden device must be veux")
    if req_str(m, "platform").lower() != "sm6375":
        die("golden platform must be sm6375")
    if req_str(m, "kernel") != "5.4.274":
        die("golden kernel must be 5.4.274")

    wf = req_map(m, "workflow")
    wf_path = root / req_str(wf, "path")
    if not wf_path.is_file():
        die(f"golden workflow missing: {wf_path}")
    expected_blob = req_str(wf, "blob").lower()
    if not SHA40.fullmatch(expected_blob):
        die("golden workflow blob is not 40-hex")
    actual_blob = git_blob(wf_path)
    if actual_blob != expected_blob:
        die(f"golden workflow blob drift: expected {expected_blob}, got {actual_blob}")

    head = req_str(wf, "run_head_sha").lower()
    if not SHA40.fullmatch(head):
        die("golden run_head_sha is not 40-hex")
    if wf.get("conclusion") != "success":
        die("golden workflow conclusion must be success")
    if not isinstance(wf.get("run_id"), int) or wf["run_id"] <= 0:
        die("golden run_id must be positive")

    art = req_map(m, "artifact")
    digest = req_str(art, "digest")
    if not digest.startswith("sha256:") or not SHA64.fullmatch(digest[7:]):
        die("golden artifact digest must be sha256:<64hex>")
    if not isinstance(art.get("id"), int) or art["id"] <= 0:
        die("golden artifact id must be positive")
    if not isinstance(art.get("size_bytes"), int) or art["size_bytes"] <= 0:
        die("golden artifact size_bytes must be positive")
    if not SHA64.fullmatch(req_str(art, "ak3_sha256")):
        die("golden AK3 sha256 must be 64-hex")

    image = req_map(m, "image")
    if image.get("bytes") != 29846016:
        die(f"unexpected golden Image size: {image.get('bytes')}")
    if req_str(image, "sha256") != "6702b0edee8b08ed33620c58de43f7273d67d92fef25e0301d0b1b198777216e":
        die("golden Image SHA256 drift")

    components = req_map(m, "components")
    rs = req_map(components, "resukisu")
    sf = req_map(components, "susfs")
    nm = req_map(components, "nomount")
    ak = req_map(components, "anykernel3")
    expected = {
        "rs_version": "35170",
        "rs_commit": "9be0f347f38e790c846915bd5f9c24b337f85c4e",
        "sf_version": "2.3.0",
        "sf_commit": "04a9d713106191ba98be680bd7ad9547ab1de964",
        "nm_version": "2.0.0",
        "nm_commit": "b8d268353b4e7ecc53c67d1816a626b7d6579201",
        "ak_commit": "af770f7b16cf8f8eb7c68614b2a693b3b361c90c",
    }
    got = {
        "rs_version": str(rs.get("version")),
        "rs_commit": str(rs.get("commit")),
        "sf_version": str(sf.get("version")),
        "sf_commit": str(sf.get("commit")),
        "nm_version": str(nm.get("version")),
        "nm_commit": str(nm.get("commit")),
        "ak_commit": str(ak.get("commit")),
    }
    if got != expected:
        die(f"golden component drift: {got!r}")

    delta = req_map(m, "golden_delta")
    if delta.get("scope") != ["fs/open.c", "fs/stat.c"]:
        die("golden delta scope drift")
    if req_str(delta, "patch_sha256") != "1db14b7e33ab127968f19a203544ed95570f15d96d4930fb15808be59df5e6c3":
        die("golden fast-fail patch SHA256 drift")

    ci = req_map(m, "ci_evidence")
    if ci.get("static_green") is not True or ci.get("compile_pass") is not True or ci.get("package_pass") is not True:
        die("golden CI core gates must be true")
    if ci.get("device_pass_recorded_in_ci") is not False:
        die("historical CI must remain explicit: DEVICE_PASS was not recorded in CI")

    device = req_map(m, "device_validation")
    if device.get("status") != "FULL_PASS":
        die("golden external device status must be FULL_PASS")
    if device.get("automated_verification") is not False:
        die("device FULL_PASS must not be presented as CI-automated")

    return m


def validate_profiles(root: Path, manifest: dict, manifest_rel: str) -> list[dict]:
    golden_id = manifest["id"]
    rows = []
    for p in sorted(root.glob("lineages/*/build.yml"), key=lambda x: x.parent.name):
        d = load_yaml(p)
        b = req_map(d, "baseline")
        if b.get("id") != golden_id:
            die(f"{p}: baseline id mismatch")
        if b.get("manifest") != manifest_rel:
            die(f"{p}: baseline manifest path mismatch")
        if b.get("from_kernel") != "5.4.274":
            die(f"{p}: baseline.from_kernel must be 5.4.274")
        k = str(d.get("kernel"))
        role = b.get("role")
        status = b.get("port_status")
        validation = req_map(d, "validation")
        if k == "5.4.274":
            if role != "golden" or status != "full-pass" or validation.get("device") is not True:
                die("5.4.274 must be the only golden/full-pass/device=true profile")
            features = req_map(d, "features")
            rs, sf, nm = (req_map(features, x) for x in ("resukisu", "susfs", "nomount"))
            if (str(rs.get("version")), str(rs.get("commit")), rs.get("uapi")) != (
                "35170", "9be0f347f38e790c846915bd5f9c24b337f85c4e", 4
            ):
                die("5.4.274 ReSukiSU state does not match golden baseline")
            if (str(sf.get("version")), str(sf.get("commit"))) != (
                "2.3.0", "04a9d713106191ba98be680bd7ad9547ab1de964"
            ):
                die("5.4.274 SUSFS state does not match golden baseline")
            if nm.get("enabled") is not True or (str(nm.get("version")), str(nm.get("commit"))) != (
                "2.0.0", "b8d268353b4e7ecc53c67d1816a626b7d6579201"
            ):
                die("5.4.274 NoMount state does not match golden baseline")
        else:
            if role != "derive":
                die(f"{p}: non-golden lineage must use baseline.role=derive")
            if status not in {"pending", "candidate", "validated"}:
                die(f"{p}: invalid derive port_status={status!r}")
            if validation.get("device") is True:
                die(f"{p}: derived lineage may not claim device=true before a real device pass")
        rows.append({"kernel": k, "role": role, "port_status": status})
    if len(rows) < 2:
        die("expected golden baseline plus at least one derived lineage")
    return rows


def validate_online(manifest: dict) -> None:
    token = os.environ.get("GITHUB_TOKEN", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if not token or not repo:
        die("--online requires GITHUB_TOKEN and GITHUB_REPOSITORY")

    wf = manifest["workflow"]
    run = github_json(f"https://api.github.com/repos/{repo}/actions/runs/{wf['run_id']}", token)
    checks = {
        "id": wf["run_id"],
        "status": "completed",
        "conclusion": "success",
        "head_sha": wf["run_head_sha"],
        "path": wf["path"],
    }
    for key, expected in checks.items():
        if run.get(key) != expected:
            die(f"online run mismatch {key}: expected {expected!r}, got {run.get(key)!r}")

    art = manifest["artifact"]
    data = github_json(
        f"https://api.github.com/repos/{repo}/actions/runs/{wf['run_id']}/artifacts?per_page=100",
        token,
    )
    artifacts = data.get("artifacts") or []
    matches = [x for x in artifacts if x.get("id") == art["id"]]
    if matches:
        a = matches[0]
        for key, expected in (
            ("name", art["name"]),
            ("size_in_bytes", art["size_bytes"]),
            ("digest", art["digest"]),
        ):
            if a.get(key) != expected:
                die(f"online artifact mismatch {key}: expected {expected!r}, got {a.get(key)!r}")
        print(f"GOLDEN_ARTIFACT_LIVE={'NO' if a.get('expired') else 'YES'}")
    else:
        # Artifacts expire. Their disappearance must not invalidate the immutable
        # workflow/run/Image/AK3 hashes pinned in the manifest.
        print("GOLDEN_ARTIFACT_LIVE=EXPIRED_OR_UNAVAILABLE")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", default=".")
    ap.add_argument("--manifest", default="common/contracts/GOLDEN_BASELINE.yml")
    ap.add_argument("--online", action="store_true")
    args = ap.parse_args()

    root = Path(args.repo_root).resolve()
    manifest_path = (root / args.manifest).resolve()
    manifest = validate_manifest(root, manifest_path)
    rows = validate_profiles(root, manifest, args.manifest)

    if args.online:
        validate_online(manifest)

    derive = [r for r in rows if r["role"] == "derive"]
    matrix = {"include": derive}
    compact = json.dumps(matrix, separators=(",", ":"), sort_keys=True)

    print(f"GOLDEN_BASELINE_ID={manifest['id']}")
    print("GOLDEN_WORKFLOW_BLOB=PASS")
    print("GOLDEN_COMPONENT_PINS=PASS")
    print("GOLDEN_CI_EVIDENCE=PASS")
    print("GOLDEN_DEVICE_ACCEPTANCE=FULL_PASS_EXTERNAL")
    print(f"DERIVED_LINEAGES={len(derive)}")
    print("GOLDEN_BASELINE_VERDICT=PASS")

    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as f:
            f.write(f"golden_id={manifest['id']}\n")
            f.write(f"port_matrix={compact}\n")
            f.write(f"port_count={len(derive)}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
