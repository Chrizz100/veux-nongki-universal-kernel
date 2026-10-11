#!/usr/bin/env python3
"""Prepare a reviewed, fail-closed VEUX V4 engine migration; never modify the input repository.

The input engine Git blob is pinned to the exact source verified at
Chrizz100/veux-nongki-universal-kernel main 805231204f078b3e3634a51ca4919b1d26d34fcd.
The output is a COMPLETE replacement Python file under --output, plus evidence.

This migration does NOT approve a BakaSU+SUSFS kernel build or NoMount 21 ABI.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import py_compile
import re
import tempfile

EXPECTED_ENGINE_BLOB = '318d2d15a1928ab44f5b5b2b1c750a0e5316f83a'
EXPECTED_RESOLVER_BLOB = '2aca5f795c2576eadc4d0b7eca68805b191bcf16'
EXPECTED_INTEGRATED = {
    'resukisu': '8770c7e324a22895703c4916b8a16520e0b81c79',
    'susfs': '5326e21a7eb232f9e21debdd5164e99bee3d1e2f',
    'nomount': 'c5fad9d8f97c5a207f7342fd91789449915ea047',
}
EXPECTED_UAPI = 5
ENGINE_PATH = Path('common/scripts/veux_update_engine.py')
RESOLVER_PATH = Path('common/scripts/veux_current_components.py')
CURRENT_PATH = Path('common/contracts/CURRENT_BUILD.json')
MARKER = '# VEUX_V4_ENGINE_COMPAT_R1: CURRENT_BUILD-authoritative UAPI5/NoMount21 fail-closed resolver'


class MigrationBlocked(RuntimeError):
    pass


def insist(yes: bool, msg: str) -> None:
    if not yes:
        raise MigrationBlocked(msg)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob(data: bytes) -> str:
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def under(root: Path, rel: Path) -> Path:
    insist(not rel.is_absolute() and '..' not in rel.parts, f'bad relative path: {rel}')
    result = root / rel
    insist(not result.is_symlink(), f'refuse symlink at source: {rel}')
    insist(result.resolve().is_relative_to(root.resolve()), f'path escapes project: {rel}')
    return result


def inspect_inputs(repo: Path) -> dict:
    insist(repo.is_dir(), 'repository is not a directory')
    engine = under(repo, ENGINE_PATH)
    resolver = under(repo, RESOLVER_PATH)
    contract = under(repo, CURRENT_PATH)
    for name, p, expected in (
        ('engine', engine, EXPECTED_ENGINE_BLOB),
        ('UAPI5 resolver', resolver, EXPECTED_RESOLVER_BLOB),
    ):
        insist(p.is_file(), f'missing {name}: {p}')
        found = git_blob(p.read_bytes())
        insist(found == expected,
               f'{name} Git blob changed: {found} != {expected}. DO NOT replace unknown source.')
    obj = json.loads(contract.read_text())
    insist(obj.get('status') == 'compile-package-static-validated',
           'validated CURRENT_BUILD status missing')
    insist(obj.get('device_pass_inferred') is False, 'invalid device flag')
    insist(set(obj.get('targets', {})) == set(EXPECTED_INTEGRATED),
           'component set differs')
    insist(set(obj.get('lineages', {})) ==
           {'5.4.274', '5.4.292', '5.4.293', '5.4.300', '5.4.301', '5.4.302'},
           'unexpected kernel lineage set')
    for name, commit in EXPECTED_INTEGRATED.items():
        row = obj['targets'][name]
        insist(row.get('commit') == commit, f'CURRENT_BUILD {name} changed; migration requires re-review')
        insist(isinstance(row.get('url'), str) and row['url'].startswith('https://'),
               f'CURRENT_BUILD {name}: missing URL')
        insist(re.fullmatch(r'refs/heads/[A-Za-z0-9._/-]+', row.get('ref', '')) is not None,
               f'CURRENT_BUILD {name}: invalid upstream ref')
    insist(obj['targets']['resukisu']['uapi'] == EXPECTED_UAPI, 'kernel UAPI is not 5')
    for label in obj['lineages']:
        insist(obj['lineages'][label]['targets'] == obj['targets'],
               f'{label}: lineage/component target mismatch')
    return obj


NEW_RESOLVER = '''def resolve(work):
    """Resolve only FROM CURRENT_BUILD integration; fail closed on unreviewed changes."""
    cfg, fleet = check_repo()
    current = json.loads((REPO / "common/contracts/CURRENT_BUILD.json").read_text())
    require(current.get("status") == "compile-package-static-validated", "CURRENT_BUILD is unvalidated")
    require(current.get("device_pass_inferred") is False, "CURRENT_BUILD wrongly asserts device PASS")
    require(set(current.get("targets", {})) == set(COMPONENTS), "CURRENT_BUILD targets mismatch")
    require(set(current.get("lineages", {})) == set(fleet["lineages"]), "CURRENT_BUILD lineages mismatch")
    for label, row in current["lineages"].items():
        require(row.get("targets") == current["targets"], f"inconsistent CURRENT_BUILD lineage {label}")
    work.mkdir(parents=True, exist_ok=False)
    result = {"schema": 1, "repository_sha": git(REPO, "rev-parse", "HEAD"),
              "golden_sha256": digest(REPO / cfg["golden_contract"]),
              "lineages": sorted(fleet["lineages"]), "components": {},
              "comparison_contract": "common/contracts/CURRENT_BUILD.json",
              "compatibility_review_required": False, "build_approved": False}
    errors = []
    for component in COMPONENTS:
        old = current["targets"][component]
        url = old["url"]
        ref = old["ref"]
        integrated = old["commit"]
        require(SHA.fullmatch(integrated), f"invalid CURRENT_BUILD {component} commit")
        require(ref.startswith("refs/heads/") and ".." not in ref,
                f"invalid CURRENT_BUILD {component} ref")
        remote = run(["git", "ls-remote", "--exit-code", "--refs", url, ref], timeout=90)
        lines = remote.splitlines()
        require(len(lines) == 1, f"ambiguous {component} upstream ref")
        parts = lines[0].split()
        require(len(parts) == 2 and SHA.fullmatch(parts[0]) and parts[1] == ref,
                f"invalid {component} upstream identity")
        target = parts[0]
        donor = work / component
        checkout(url, target, donor, full=True)
        # Reject history rewrites and all changes outside the tracked branch.
        require(git(donor, "cat-file", "-t", integrated) == "commit",
                f"integrated {component} commit is not available upstream")
        ancestor = run(["git", "-C", donor, "merge-base", "--is-ancestor", integrated, target],
                       timeout=90)  # raises Blocked on unrelated history
        _ = ancestor
        from pathlib import Path as _Path
        _root = donor.resolve(strict=True)
        # The official kernel/include/uapi -> ../../uapi link is safe.
        # A dangling/absolute/cyclic/outside link must never enter an overlay.
        for _item in donor.rglob("*"):
            if _item.is_symlink():
                _link = _Path(os.readlink(_item))
                require(not _link.is_absolute(), f"absolute upstream symlink: {_item}")
                try:
                    _destination = _item.resolve(strict=True)
                except (OSError, RuntimeError) as exc:
                    raise Blocked(f"broken or cyclic upstream symlink: {_item}") from exc
                require(_destination.is_relative_to(_root),
                        f"upstream symlink escapes repository: {_item} -> {_destination}")
        entry = {"commit": target, "url": url, "ref": ref,
                 "base": integrated,  # compatibility metadata, NOT a stale stable pin
                 "integrated_commit": integrated,
                 "ahead": int(git(donor, "rev-list", "--count", f"{integrated}..{target}"))}
        kernel_changed = git(donor, "diff", "--name-only", f"{integrated}..{target}", "--", "kernel/")
        entry["kernel_paths_changed"] = [x for x in kernel_changed.splitlines() if x.startswith("kernel/")]
        if component == "resukisu":
            critical = {"kernel/feature/selinux_hide.c", "kernel/selinux/sepolicy.c",
                        "kernel/Kbuild", "kernel/Kconfig", "kernel/tools/susfs_compat.mk",
                        "kernel/compat/kernel_compat.h", "kernel/hook/lsm_hooks.c"}
            if critical.intersection(entry["kernel_paths_changed"]):
                errors.append("BakaSU critical SELinux/SUSFS/kernel interface code changed "
                              "since CURRENT_BUILD; manual source review is required")
            from veux_current_components import checked_uapi
            kbuild = (donor / "kernel/Kbuild").read_text()
            require("expr 30000 + $(KSU_LOCAL_VERSION) + 700" in kbuild,
                    "ReSukiSU/BakaSU version formula changed")
            count = int(git(donor, "rev-list", "--count", target))
            new_uapi = checked_uapi(donor)  # frozen UAPI5/header/service event tests
            require(new_uapi == old["uapi"] == 5,
                    f"unreviewed ReSukiSU/BakaSU UAPI transition: {old['uapi']} -> {new_uapi}")
            entry.update(version=str(30700 + count), local_version=count,
                         tag=git(donor, "describe", "--tags", "--abbrev=0", target), uapi=new_uapi)
            compat = donor / "kernel/tools/susfs_compat.mk"
            if ("include $(KSU_SRC)/tools/susfs_compat.mk" in kbuild
                    and compat.is_file()
                    and "$(error Please wait susfs update.)" in compat.read_text()):
                errors.append("BakaSU upstream intentionally BLOCKS CONFIG_KSU_SUSFS: "
                              "Please wait susfs update; no kernel build or bypass allowed")
        elif component == "susfs":
            header = donor / "kernel_patches/include/linux/susfs.h"
            found = re.search(r'#define SUSFS_VERSION "v?([^\\"]+)"', header.read_text())
            require(found is not None, "SUSFS declared version missing")
            entry["version"] = found[1]
            if entry["version"] != str(old.get("version")):
                errors.append("SUSFS version changed; review 5.4 OPEN_REDIRECT/SRCU backports")
        else:
            header = (donor / "kernel/src/nomount.h").read_text()
            direct = re.search(r'#define\\s+NOMOUNT_VERSION\\s+"([^\\"]+)"', header)
            base = re.search(r'#define\\s+NOMOUNT_BASE_VERSION\\s+"([^\\"]+)"', header)
            if direct:
                entry.update(version=direct[1], version_kind="kernel-wire-version")
            elif base:
                entry.update(version=base[1], version_kind="base-version-dynamic-commit-count")
                entry["dynamic_commit_count"] = "NOMOUNT_COMMIT_COUNT" in header
                # No count is fabricated when the embedded source has no .git.
            else:
                raise Blocked("NoMount version macro no longer recognized")
            if entry["version"] != str(old.get("version")) or entry["version_kind"] != old.get("version_kind"):
                errors.append("NoMount 20 -> 21 ABI/version scheme changed; "
                              "compatibility review and compiled 5.4 runtime tests required")
        result["components"][component] = entry
        print(f"RESOLVED {component} {target} version={entry['version']} "
              f"delta_from_integrated={entry['ahead']}", flush=True)
    result["compatibility_review_required"] = bool(errors)
    result["review_reasons"] = errors
    # Keep source copies and machine-readable evidence even when blocked.
    write_json(work / "COMPATIBILITY-REVIEW.json", result)
    require(not errors, "V4 UPSTREAM BUILD BLOCKED: " + " | ".join(errors))
    result["build_approved"] = True  # only preflight; never means compile/device PASS
    write_json(work / "targets.json", result)
    return result


'''


def prepare(engine: str) -> str:
    insist(MARKER not in engine, 'engine migration already applied')
    # This is the single, exact resolver interface: all remaining code stays byte-for-byte.
    start = '\ndef resolve(work):\n'
    end = '\ndef parse_env(path):\n'
    insist(engine.count(start) == 1 and engine.count(end) == 1,
           'expected engine resolver boundaries missing/ambiguous')
    left = engine.index(start)
    right = engine.index(end, left + len(start))
    insist(left < right, 'unexpected function order')
    old = engine[left:right]
    for marker in (
        'base = m["stable"]["commit"]',
        'uapi=4',
        'KERNEL_SU_UAPI_VERSION = 4;',
        're.search(r\'#define NOMOUNT_VERSION',
    ):
        insist(marker in old, f'baseline resolver marker absent: {marker}')
    replacement = '\n' + MARKER + '\n' + NEW_RESOLVER
    data = engine[:left] + replacement + engine[right:]
    insist('def resolve(work):' in data, 'new engine resolver missing')
    insist(data.count(MARKER) == 1, 'migration marker mismatch')
    insist('Please wait susfs update' in data, 'SUSFS blocker lost')
    insist('from veux_current_components import checked_uapi' in data, 'UAPI5 gate lost')
    insist('NOMOUNT_BASE_VERSION' in data, 'NoMount 21 parser lost')
    return data


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    try:
        root = args.repo.resolve(strict=True)
        contract = inspect_inputs(root)
        out = args.output.resolve()
        insist(not out.is_relative_to(root), 'output directory must be OUTSIDE checkout; no repo mutation')
        insist(not out.exists() or not any(out.iterdir()), 'output already contains files')
        new = prepare((root / ENGINE_PATH).read_text())
        output_file = out / ENGINE_PATH
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(new)
        with tempfile.TemporaryDirectory() as tmp:
            py_compile.compile(str(output_file), cfile=str(Path(tmp)/'engine.pyc'), doraise=True)
        actual = git_blob(output_file.read_bytes())
        evidence = {
            'schema': 1,
            'input_engine_git_blob': EXPECTED_ENGINE_BLOB,
            'output_engine_git_blob': actual,
            'output_engine_sha256': sha256(output_file.read_bytes()),
            'current_build_targets': {k: v['commit'] for k, v in contract['targets'].items()},
            'branch_and_url_from_current_build': True,
            'uapi_5_compat': True,
            'nomount_21_version_macro_supported': True,
            'susfs_buildblock_preserved': True,
            'kernel_build_approved': False,
            'kernel_build_performed': False,
            'device_pass_inferred': False,
            'repository_modified': False,
            'preflight_scope': 'static source migration and Python compilation',
        }
        (out / 'VEUX_V4_ENGINE_MIGRATION_R1.json').write_text(json.dumps(evidence, indent=2, sort_keys=True)+'\n')
        print('SOURCE_PIN=PASS')
        print('CURRENT_BUILD=PASS')
        print('PYTHON_COMPILE=PASS')
        print('COMPATIBILITY_GUARDS=PASS')
        print('OUTPUT_ENGINE_GIT_BLOB='+actual)
        print('REPOSITORY_MODIFIED=NO')
        print('KERNEL_BUILD_APPROVED=NO')
        return 0
    except (MigrationBlocked, OSError, ValueError, KeyError, SyntaxError, py_compile.PyCompileError) as exc:
        print('MIGRATION_BLOCKED: '+str(exc), file=__import__('sys').stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
