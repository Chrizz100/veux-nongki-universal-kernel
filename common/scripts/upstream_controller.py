#!/usr/bin/env python3
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
import tempfile

import yaml

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA64 = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_COMPONENTS = {"resukisu", "susfs", "nomount"}


def die(msg: str) -> "None":
    print(f"UPSTREAM_ERROR: {msg}", file=sys.stderr)
    raise SystemExit(1)


def run(args: list[str], cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    p = subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and p.returncode:
        if p.stdout:
            print(p.stdout, file=sys.stderr, end="")
        if p.stderr:
            print(p.stderr, file=sys.stderr, end="")
        die(f"command failed rc={p.returncode}: {' '.join(args)}")
    return p


def load_yaml(path: Path) -> dict:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        die(f"cannot parse {path}: {exc}")
    if not isinstance(doc, dict):
        die(f"{path} must contain a YAML mapping")
    return doc


def req_str(d: dict, key: str, where: str) -> str:
    v = d.get(key)
    if not isinstance(v, str) or not v.strip():
        die(f"{where}.{key} must be a non-empty string")
    return v.strip()


def req_map(d: dict, key: str, where: str) -> dict:
    v = d.get(key)
    if not isinstance(v, dict):
        die(f"{where}.{key} must be a mapping")
    return v


def safe_rel(s: str, where: str) -> str:
    p = Path(s)
    if p.is_absolute() or ".." in p.parts or ".git" in p.parts:
        die(f"{where} must be a safe relative path: {s!r}")
    if not p.parts:
        die(f"{where} must not be empty")
    return p.as_posix()


def manifests(root: Path) -> dict[str, dict]:
    base = root / "common/upstream"
    paths = sorted(base.glob("*/manifest.yml"))
    if not paths:
        die("no common/upstream/*/manifest.yml files found")
    out: dict[str, dict] = {}
    for path in paths:
        d = load_yaml(path)
        where = path.relative_to(root).as_posix()
        allowed = {"schema", "component", "sources", "track", "stable", "promotion", "snapshot"}
        unknown = sorted(set(d) - allowed)
        if unknown:
            die(f"{where}: unknown keys: {', '.join(unknown)}")
        if d.get("schema") != 1:
            die(f"{where}: schema must be 1")
        comp = req_str(d, "component", where)
        if path.parent.name != comp:
            die(f"{where}: component must match directory name")
        if comp in out:
            die(f"duplicate component manifest: {comp}")

        sources = d.get("sources")
        if not isinstance(sources, list) or not sources:
            die(f"{where}.sources must be a non-empty list")
        clean_sources = []
        for i, url in enumerate(sources):
            if not isinstance(url, str) or not url.startswith("https://") or not url.endswith(".git"):
                die(f"{where}.sources[{i}] must be an HTTPS .git URL")
            clean_sources.append(url)

        track = req_map(d, "track", where)
        ref = req_str(track, "ref", f"{where}.track")
        if not ref.startswith(("refs/heads/", "refs/tags/")):
            die(f"{where}.track.ref must be refs/heads/... or refs/tags/...")

        stable = req_map(d, "stable", where)
        version = req_str(stable, "version", f"{where}.stable")
        commit = req_str(stable, "commit", f"{where}.stable").lower()
        if not SHA40.fullmatch(commit):
            die(f"{where}.stable.commit must be an exact 40-hex SHA")
        if comp == "resukisu":
            uapi = stable.get("uapi")
            if not isinstance(uapi, int) or uapi < 1:
                die(f"{where}.stable.uapi must be a positive integer")

        promotion = req_map(d, "promotion", where)
        if promotion.get("automatic") is not False:
            die(f"{where}: promotion.automatic must remain false")
        if promotion.get("require_build_all_green") is not True:
            die(f"{where}: promotion.require_build_all_green must be true")

        snap = req_map(d, "snapshot", where)
        destination = safe_rel(req_str(snap, "destination", f"{where}.snapshot"), f"{where}.snapshot.destination")
        if destination != f"third_party/{comp}":
            die(f"{where}: snapshot.destination must be third_party/{comp}")
        inc = snap.get("include")
        if not isinstance(inc, list) or not inc:
            die(f"{where}.snapshot.include must be a non-empty list")
        includes = [safe_rel(str(x), f"{where}.snapshot.include") for x in inc]
        if "LICENSE" not in includes:
            die(f"{where}: LICENSE must be included in the source snapshot")

        out[comp] = {
            "path": where,
            "component": comp,
            "sources": clean_sources,
            "track_ref": ref,
            "stable_version": version,
            "stable_commit": commit,
            "stable_uapi": stable.get("uapi"),
            "destination": destination,
            "include": includes,
        }

    if set(out) != EXPECTED_COMPONENTS:
        die(f"expected manifests {sorted(EXPECTED_COMPONENTS)}, got {sorted(out)}")
    return out


def validate_golden_alignment(root: Path, comps: dict[str, dict]) -> None:
    path = root / "common/contracts/GOLDEN_BASELINE.yml"
    if not path.is_file():
        die("common/contracts/GOLDEN_BASELINE.yml is missing")
    g = load_yaml(path)
    c = req_map(g, "components", str(path))
    for comp in sorted(EXPECTED_COMPONENTS):
        gd = req_map(c, comp, f"{path}:components")
        md = comps[comp]
        if str(gd.get("version")) != md["stable_version"]:
            die(f"golden {comp} version differs from central upstream stable pin")
        if str(gd.get("commit")).lower() != md["stable_commit"]:
            die(f"golden {comp} commit differs from central upstream stable pin")
    rs = req_map(c, "resukisu", f"{path}:components")
    if rs.get("uapi") != comps["resukisu"]["stable_uapi"]:
        die("golden ReSukiSU UAPI differs from central upstream manifest")


def candidate_contract(root: Path, kernel: str) -> dict:
    path = root / f"common/contracts/CANDIDATE_{kernel}.yml"
    if not path.is_file():
        die(f"{kernel}: candidate status requires {path.relative_to(root)}")
    d = load_yaml(path)
    if d.get("schema") != 1 or str(d.get("kernel")) != kernel or d.get("status") != "candidate":
        die(f"{path}: invalid candidate contract identity")
    wf = req_map(d, "workflow", str(path))
    wf_path = req_str(wf, "path", f"{path}:workflow")
    wf_blob = req_str(wf, "blob", f"{path}:workflow").lower()
    if not SHA40.fullmatch(wf_blob):
        die(f"{path}: workflow.blob must be 40 hex")
    if not (root / wf_path).is_file():
        die(f"{path}: referenced workflow is missing: {wf_path}")
    actual_blob = run(["git", "hash-object", str(root / wf_path)]).stdout.strip()
    if actual_blob != wf_blob:
        die(f"{path}: candidate workflow blob drift: expected {wf_blob}, got {actual_blob}")
    if wf.get("conclusion") != "success":
        die(f"{path}: candidate workflow conclusion must be success")
    if not isinstance(wf.get("run_id"), int) or wf["run_id"] <= 0:
        die(f"{path}: workflow.run_id must be positive")
    head = str(wf.get("run_head_sha", "")).lower()
    if not SHA40.fullmatch(head):
        die(f"{path}: workflow.run_head_sha must be 40 hex")

    art = req_map(d, "artifact", str(path))
    digest = req_str(art, "digest", f"{path}:artifact")
    if not digest.startswith("sha256:") or not SHA64.fullmatch(digest[7:]):
        die(f"{path}: artifact digest must be sha256:<64hex>")
    if not isinstance(art.get("id"), int) or art["id"] <= 0:
        die(f"{path}: artifact.id must be positive")

    val = req_map(d, "validation", str(path))
    expected = {
        "compile_pass": True,
        "package_pass": False,
        "static_boot_path_pass": False,
        "device_pass": False,
    }
    for k, v in expected.items():
        if val.get(k) is not v:
            die(f"{path}: validation.{k} must be {str(v).lower()}")
    return d


def validate_profiles(root: Path, comps: dict[str, dict], kernel_only: str | None = None) -> list[dict]:
    rows = []
    paths = sorted(root.glob("lineages/*/build.yml"), key=lambda p: p.parent.name)
    if not paths:
        die("no lineages/*/build.yml files found")
    for path in paths:
        d = load_yaml(path)
        kernel = str(d.get("kernel"))
        if kernel_only and kernel != kernel_only:
            continue
        b = req_map(d, "baseline", str(path))
        status = str(b.get("port_status"))
        role = str(b.get("role"))
        feat = req_map(d, "features", str(path))
        validation = req_map(d, "validation", str(path))
        if validation.get("device") is True and role != "golden":
            die(f"{path}: non-golden profile may not claim device=true")

        promoted = (role == "golden") or (status in {"candidate", "validated"})
        if promoted:
            for comp in sorted(EXPECTED_COMPONENTS):
                fd = req_map(feat, comp, f"{path}:features")
                md = comps[comp]
                if fd.get("enabled") is not True:
                    die(f"{path}: promoted profile must enable {comp}")
                if str(fd.get("version")) != md["stable_version"]:
                    die(f"{path}: {comp} version must match central stable pin")
                if str(fd.get("commit")).lower() != md["stable_commit"]:
                    die(f"{path}: {comp} commit must match central stable pin")
            rs = req_map(feat, "resukisu", f"{path}:features")
            if rs.get("uapi") != comps["resukisu"]["stable_uapi"]:
                die(f"{path}: ReSukiSU UAPI must match central stable pin")

        if status == "candidate":
            contract = candidate_contract(root, kernel)
            cc = req_map(contract, "components", f"candidate {kernel}")
            for comp in sorted(EXPECTED_COMPONENTS):
                ccd = req_map(cc, comp, f"candidate {kernel}:components")
                md = comps[comp]
                if str(ccd.get("version")) != md["stable_version"]:
                    die(f"candidate {kernel}: {comp} version drift")
                if str(ccd.get("commit")).lower() != md["stable_commit"]:
                    die(f"candidate {kernel}: {comp} commit drift")

        rows.append({
            "kernel": kernel,
            "role": role,
            "port_status": status,
            "promoted_pin_alignment": "PASS" if promoted else "PENDING_ALLOWED",
        })

    if kernel_only and not rows:
        die(f"kernel profile not found: {kernel_only}")
    return rows


def ls_remote(sources: list[str], ref: str) -> tuple[str, str]:
    errors = []
    for url in sources:
        p = run(["git", "ls-remote", url, ref], check=False)
        if p.returncode == 0:
            lines = [x for x in p.stdout.splitlines() if x.strip()]
            if len(lines) == 1:
                sha = lines[0].split()[0].lower()
                if SHA40.fullmatch(sha):
                    return url, sha
            errors.append(f"{url}: ref not uniquely resolved")
        else:
            errors.append(f"{url}: rc={p.returncode}")
    die("all upstream sources failed: " + "; ".join(errors))


def resolve(root: Path, comps: dict[str, dict]) -> dict:
    result = {"schema": 1, "components": {}, "updates_found": False}
    for comp in sorted(comps):
        m = comps[comp]
        source, head = ls_remote(m["sources"], m["track_ref"])
        changed = head != m["stable_commit"]
        result["updates_found"] = result["updates_found"] or changed
        result["components"][comp] = {
            "source": source,
            "track_ref": m["track_ref"],
            "stable_version": m["stable_version"],
            "stable_commit": m["stable_commit"],
            "remote_head": head,
            "update_available": changed,
        }
    return result


def snapshot_one(root: Path, m: dict) -> None:
    comp = m["component"]
    with tempfile.TemporaryDirectory(prefix=f"veux-{comp}-") as td:
        repo = Path(td) / "repo"
        run(["git", "init", "-q", str(repo)])
        fetched_source = None
        for source in m["sources"]:
            p = run(
                ["git", "-C", str(repo), "fetch", "-q", "--no-tags", "--depth=1", source, m["stable_commit"]],
                check=False,
            )
            if p.returncode == 0:
                fetched_source = source
                break
            p = run(
                ["git", "-C", str(repo), "fetch", "-q", "--no-tags", source, m["track_ref"]],
                check=False,
            )
            if p.returncode == 0:
                chk = run(["git", "-C", str(repo), "cat-file", "-e", f"{m['stable_commit']}^{{commit}}"], check=False)
                if chk.returncode == 0:
                    fetched_source = source
                    break
        if fetched_source is None:
            die(f"{comp}: cannot fetch stable commit from any configured source")

        run(["git", "-C", str(repo), "checkout", "-q", "--detach", m["stable_commit"]])
        head = run(["git", "-C", str(repo), "rev-parse", "HEAD"]).stdout.strip()
        if head != m["stable_commit"]:
            die(f"{comp}: checked out HEAD mismatch")

        dest = root / m["destination"]
        if dest.exists():
            shutil.rmtree(dest)
        dest.mkdir(parents=True)

        for rel in m["include"]:
            src = repo / rel
            if not src.exists():
                die(f"{comp}: required snapshot path missing upstream: {rel}")
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            if src.is_dir():
                shutil.copytree(src, target, symlinks=True)
            else:
                shutil.copy2(src, target)

        provenance = {
            "schema": 1,
            "component": comp,
            "source": fetched_source,
            "track_ref": m["track_ref"],
            "version": m["stable_version"],
            "commit": m["stable_commit"],
        }
        if comp == "resukisu":
            provenance["uapi"] = m["stable_uapi"]
        (dest / "_VEUX_SOURCE.yml").write_text(
            yaml.safe_dump(provenance, sort_keys=False),
            encoding="utf-8",
        )

        lines = []
        for p in sorted(dest.rglob("*")):
            if p.is_file() and p.name != "SHA256SUMS.txt":
                h = hashlib.sha256(p.read_bytes()).hexdigest()
                lines.append(f"{h}  {p.relative_to(dest).as_posix()}")
        (dest / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"SNAPSHOT_{comp.upper()}=PASS")


def selftest() -> None:
    with tempfile.TemporaryDirectory(prefix="veux-upstream-selftest-") as td:
        root = Path(td)
        for comp, commit, version, extra in (
            ("resukisu", "1"*40, "35170", "  uapi: 4\n"),
            ("susfs", "2"*40, "2.3.0", ""),
            ("nomount", "3"*40, "2.0.0", ""),
        ):
            d = root / f"common/upstream/{comp}"
            d.mkdir(parents=True, exist_ok=True)
            text = f"""schema: 1
component: "{comp}"
sources:
  - "https://example.invalid/{comp}.git"
track:
  ref: "refs/heads/main"
stable:
  version: "{version}"
  commit: "{commit}"
{extra}promotion:
  automatic: false
  require_build_all_green: true
snapshot:
  destination: "third_party/{comp}"
  include:
    - "LICENSE"
"""
            (d / "manifest.yml").write_text(text, encoding="utf-8")
        got = manifests(root)
        if set(got) != EXPECTED_COMPONENTS:
            die("selftest manifest discovery failed")
        if SHA40.fullmatch("bad"):
            die("selftest SHA validator is broken")
    print("UPSTREAM_CONTROLLER_SELFTEST=PASS")


def main() -> int:
    ap = argparse.ArgumentParser(description="VEUX central upstream and build-all controller")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("selftest")

    p = sub.add_parser("validate")
    p.add_argument("--repo-root", default=".")

    p = sub.add_parser("resolve")
    p.add_argument("--repo-root", default=".")
    p.add_argument("--report", default="")
    p.add_argument("--github-output", action="store_true")

    p = sub.add_parser("profiles")
    p.add_argument("--repo-root", default=".")
    p.add_argument("--kernel", default="")

    p = sub.add_parser("snapshot")
    p.add_argument("--repo-root", default=".")
    p.add_argument("--component", default="all", choices=["all", "resukisu", "susfs", "nomount"])

    args = ap.parse_args()

    if args.cmd == "selftest":
        selftest()
        return 0

    root = Path(args.repo_root).resolve()
    comps = manifests(root)

    if args.cmd == "validate":
        validate_golden_alignment(root, comps)
        validate_profiles(root, comps)
        print("UPSTREAM_MANIFESTS=PASS")
        print("GOLDEN_UPSTREAM_ALIGNMENT=PASS")
        print("PROFILE_UPSTREAM_ALIGNMENT=PASS")
        return 0

    if args.cmd == "profiles":
        rows = validate_profiles(root, comps, args.kernel or None)
        print(json.dumps(rows, indent=2, sort_keys=True))
        print("PROFILE_CONTRACTS=PASS")
        return 0

    if args.cmd == "resolve":
        validate_golden_alignment(root, comps)
        validate_profiles(root, comps)
        report = resolve(root, comps)
        text = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.report:
            Path(args.report).write_text(text, encoding="utf-8")
        print(text, end="")
        if args.github_output:
            out = os.environ.get("GITHUB_OUTPUT")
            if not out:
                die("--github-output requires GITHUB_OUTPUT")
            with open(out, "a", encoding="utf-8") as f:
                f.write(f"updates_found={'true' if report['updates_found'] else 'false'}\n")
                for comp, row in sorted(report["components"].items()):
                    f.write(f"{comp}_head={row['remote_head']}\n")
        return 0

    if args.cmd == "snapshot":
        validate_golden_alignment(root, comps)
        names = sorted(comps) if args.component == "all" else [args.component]
        for name in names:
            snapshot_one(root, comps[name])
        print("UPSTREAM_SNAPSHOTS=PASS")
        return 0

    die(f"unknown command: {args.cmd}")


if __name__ == "__main__":
    raise SystemExit(main())
