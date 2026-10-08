#!/usr/bin/env python3
"""One integration engine with authenticated legacy SUSFS migration.

Lineage numbers select source recipes only. Device PASS is never inferred.

Source recipes reconstruct historical, authenticated host integrations. No legacy
updater is used for the new targets. All writes occur below an explicit work dir.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
import zipfile

from ruamel.yaml import YAML

COMPONENTS = ("resukisu", "susfs", "nomount")
HERE = Path(__file__).resolve()
REPO = HERE.parents[2]
SHA = re.compile(r"[0-9a-f]{40}\Z")


class Blocked(RuntimeError):
    pass


def require(ok, reason):
    if not ok:
        raise Blocked(reason)


def yaml_read(path):
    loader = YAML(typ="safe")
    loader.version = (1, 2)
    loader.allow_duplicate_keys = False
    return loader.load(Path(path).read_text())


def digest(path):
    with Path(path).open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def blob(path):
    data = Path(path).read_bytes()
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    temp.replace(path)


def run(argv, cwd=None, env=None, log=None, timeout=1800):
    argv = [str(x) for x in argv]
    if log:
        with Path(log).open("w") as f:
            p = subprocess.run(argv, cwd=cwd, env=env, stdout=f,
                               stderr=subprocess.STDOUT, timeout=timeout)
        require(p.returncode == 0, f"command failed ({p.returncode}); log={log}")
        return ""
    p = subprocess.run(argv, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout)
    require(p.returncode == 0, f"{argv[0]} failed ({p.returncode}): {p.stderr[-3000:]}")
    return p.stdout.strip()


def git(repo, *args):
    return run(["git", "-C", repo, *args])


def inside(path, base):
    require(Path(path).resolve().is_relative_to(Path(base).resolve()), f"path escapes workspace: {path}")
    return Path(path)


def config():
    return json.loads((REPO / "common/update/source-recipes.json").read_text())


def check_repo():
    cfg = config()
    fleet = yaml_read(REPO / cfg["fleet_contract"])
    require(set(fleet["lineages"]) == set(cfg["lineages"]), "source recipe/fleet mismatch")
    for label, row in fleet["lineages"].items():
        profile = REPO / "lineages" / label / "build.yml"
        require(blob(profile) == row["profile_blob"], f"profile drift: {label}")
        rec = cfg["lineages"][label]
        require(blob(REPO / rec["workflow"]) == rec["blob"], f"source authority drift: {label}")
        dtb = rec["dtb"]
        require(dtb["reference"] in ("pinned", "native-source"), f"invalid DTB policy: {label}")
        require(not Path(dtb["path"]).is_absolute() and ".." not in Path(dtb["path"]).parts,
                f"invalid DTB path: {label}")
        if dtb["reference"] == "pinned":
            require(re.fullmatch(r"[0-9a-f]{64}", dtb["sha256"]), f"invalid DTB pin: {label}")
    return cfg, fleet


def checkout(url, commit, dest, full=False):
    require(SHA.fullmatch(commit), "checkout requires an exact commit")
    require(not dest.exists(), f"checkout destination exists: {dest}")
    if full:
        run(["git", "clone", "--quiet", url, dest])
    else:
        dest.mkdir(parents=True)
        git(dest, "init", "-q")
        git(dest, "remote", "add", "origin", url)
        git(dest, "fetch", "--quiet", "--depth=1", "origin", commit)
    git(dest, "checkout", "--quiet", "--detach", commit)
    require(git(dest, "rev-parse", "HEAD") == commit, "checkout identity mismatch")


def source_checkout(opts, recipe, env, ctx, outputs, dest):
    repo_name = expression(opts["repository"], env, ctx, outputs)
    ref = expression(opts.get("ref", ""), env, ctx, outputs)
    commit = ref
    if not SHA.fullmatch(ref):
        pins = [p for p in recipe.get("checkouts", [])
                if p["repository"] == repo_name and p["ref"] == ref]
        require(len(pins) == 1, f"unmapped source checkout: {repo_name}@{ref}")
        commit = pins[0]["commit"]
    require(SHA.fullmatch(commit), f"invalid source checkout pin: {repo_name}@{ref}")
    # Preserve the historical recipe's full-history requirement.
    checkout(f"https://github.com/{repo_name}.git", commit, dest,
             full=str(opts.get("fetch-depth", 1)) == "0")


def resolve(work):
    cfg, fleet = check_repo()
    work.mkdir(parents=True, exist_ok=False)
    result = {"schema": 1, "repository_sha": git(REPO, "rev-parse", "HEAD"),
              "golden_sha256": digest(REPO / cfg["golden_contract"]),
              "lineages": sorted(fleet["lineages"]), "components": {}}
    for component in COMPONENTS:
        m = yaml_read(REPO / f"common/upstream/{component}/manifest.yml")
        failures = []
        for url in m["sources"]:
            try:
                value = run(["git", "ls-remote", "--exit-code", url, m["track"]["ref"]], timeout=90)
                lines = value.splitlines()
                require(len(lines) == 1, "upstream ref is ambiguous")
                target, ref = lines[0].split()
                require(SHA.fullmatch(target) and ref == m["track"]["ref"], "invalid upstream identity")
                break
            except (Blocked, subprocess.TimeoutExpired) as exc:
                failures.append(str(exc))
        else:
            raise Blocked(f"cannot resolve {component}: {failures}")
        donor = work / component
        checkout(url, target, donor, full=True)
        base = m["stable"]["commit"]
        git(donor, "merge-base", "--is-ancestor", base, target)
        entry = {"commit": target, "base": base, "url": url, "ref": ref,
                 "ahead": int(git(donor, "rev-list", "--count", f"{base}..{target}"))}
        if component == "resukisu":
            count = int(git(donor, "rev-list", "--count", target))
            kbuild = (donor / "kernel/Kbuild").read_text()
            require("expr 30000 + $(KSU_LOCAL_VERSION) + 700" in kbuild, "ReSukiSU version formula changed")
            entry.update(version=str(30700 + count), local_version=count,
                         tag=git(donor, "describe", "--tags", "--abbrev=0", target), uapi=4)
            require("KERNEL_SU_UAPI_VERSION = 4;" in (donor / "uapi/supercall.h").read_text(), "UAPI changed")
        elif component == "susfs":
            match = re.search(r'#define SUSFS_VERSION "v?([^\"]+)"', (donor / "kernel_patches/include/linux/susfs.h").read_text())
            require(match, "SUSFS version missing")
            entry["version"] = match[1]
        else:
            match = re.search(r'#define NOMOUNT_VERSION "([^\"]+)"', (donor / "kernel/src/nomount.h").read_text())
            require(match, "NoMount version missing")
            # The kernel wire version is not a semantic module version.
            entry.update(version=match[1], version_kind="kernel-wire-version")
        result["components"][component] = entry
        print(f"RESOLVED {component} {target} version={entry['version']} delta={entry['ahead']}", flush=True)
    write_json(work / "targets.json", result)
    return result


def parse_env(path):
    if not path.exists():
        return {}
    lines = iter(path.read_text().splitlines())
    data = {}
    for line in lines:
        if "<<" in line:
            key, marker = line.split("<<", 1)
            chunks = []
            for following in lines:
                if following == marker:
                    break
                chunks.append(following)
            else:
                raise Blocked("unterminated environment heredoc")
            data[key] = "\n".join(chunks)
        elif "=" in line:
            key, value = line.split("=", 1)
            data[key] = value
        else:
            require(not line.strip(), "malformed environment record")
    return data


def expression(value, env, ctx, outputs):
    def replace(match):
        key = match[1].strip()
        if key in ctx:
            return ctx[key]
        if key.startswith("env.") and key[4:] in env:
            return env[key[4:]]
        m = re.fullmatch(r"steps\.([\w-]+)\.outputs\.([\w-]+)", key)
        if m and m[1] in outputs and m[2] in outputs[m[1]]:
            return outputs[m[1]][m[2]]
        raise Blocked(f"unresolved source expression: {key}")
    return re.sub(r"\$\{\{(.*?)\}\}", replace, str(value))


def env_map(mapping, env, ctx, outputs):
    result = dict(env)
    for key, value in mapping.items():
        result[str(key)] = expression(value, result, ctx, outputs)
    return result


def make_parts(args, cwd):
    source = Path(cwd)
    variables, options, targets = [], [], []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-C", "--directory"):
            i += 1
            source = (source / args[i]).resolve()
        elif arg.startswith("-C"):
            source = (source / arg[2:]).resolve()
        elif "=" in arg and not arg.startswith("-"):
            variables.append(arg)
        elif arg in ("-j", "--jobs"):
            if i + 1 < len(args) and args[i+1].isdigit():
                i += 1
        elif arg.startswith(("-j", "--jobs=")):
            pass
        elif arg.startswith("-"):
            require(arg in ("-s", "--silent", "--no-print-directory"), f"unsupported make option {arg}")
            options.append(arg)
        else:
            targets.append(arg)
        i += 1
    return source, variables, options, targets


def capture_make(args):
    source, variables, options, targets = make_parts(args, Path.cwd())
    build = bool(set(targets) & {"Image", "Image.gz", "vmlinux", "all", "dtbs"}) or not targets
    if not build:
        allowed = {"kernelversion", "kernelrelease", "olddefconfig", "prepare", "clean", "mrproper", "scripts"}
        require(all(t in allowed or t.endswith("_defconfig") for t in targets), f"unknown make target: {targets}")
        os.execv("/usr/bin/make", ["/usr/bin/make", *args])
    require("Image" in targets, f"expected Image build boundary, got {targets}")
    inside(source, os.environ["VEUX_SOURCE_WORK"])
    # Capture only build variables, never credentials or the complete environment.
    keep = {"PATH", "ARCH", "CC", "LD", "LLVM", "LLVM_IAS", "CLANG_TRIPLE", "CROSS_COMPILE",
            "CROSS_COMPILE_ARM32", "KCFLAGS", "SOURCE_DATE_EPOCH", "KBUILD_FIXED_SCM_SUFFIX"}
    build_env = {k: v for k, v in os.environ.items() if k in keep or k.startswith("KBUILD_BUILD_")}
    write_json(Path(os.environ["VEUX_CAPTURE"]), {"source": str(source), "variables": variables,
               "options": options, "targets": targets, "cwd": str(Path.cwd()), "env": build_env})
    # Stop the entire source step before it can execute historical post-build gates.
    os.killpg(os.getpgrp(), signal.SIGSTOP)
    raise Blocked("source build boundary unexpectedly resumed")


def transport_curl(args):
    """Reuse the proven immutable clang mirror only for its exact archive URL."""
    cfg = config()["toolchain_transport"]
    if cfg["url"] not in args:
        os.execv("/usr/bin/curl", ["/usr/bin/curl", *args])
    outputs = [args[i + 1] for i, arg in enumerate(args[:-1]) if arg in ("-o", "--output")]
    require(len(outputs) == 1, "clang request needs one explicit output path")
    output = Path(outputs[0]).resolve()
    require(any(output.is_relative_to(Path(os.environ[key]).resolve())
                for key in ("VEUX_SOURCE_WORK", "VEUX_TRANSPORT_WORK")), "clang output escapes temporary workspace")
    try:
        p = subprocess.run(["/usr/bin/curl", *args], timeout=600)
        if p.returncode == 0:
            return
    except subprocess.TimeoutExpired:
        pass
    mirror = Path(os.environ["VEUX_TRANSPORT_WORK"]) / "clang-mirror"
    mirror.mkdir()
    git(mirror, "init", "-q")
    git(mirror, "remote", "add", "origin", cfg["repo"])
    git(mirror, "config", "remote.origin.promisor", "true")
    git(mirror, "config", "remote.origin.partialclonefilter", "blob:none")
    git(mirror, "fetch", "--quiet", "--depth=1", "--filter=blob:none", "origin", cfg["commit"])
    require(git(mirror, "rev-parse", "FETCH_HEAD") == cfg["commit"], "clang mirror commit mismatch")
    require(git(mirror, "rev-parse", "FETCH_HEAD^{tree}") == cfg["root_tree"], "clang mirror tree mismatch")
    require(git(mirror, "rev-parse", "FETCH_HEAD:" + cfg["subdir"]) == cfg["subtree"], "clang subtree mismatch")
    git(mirror, "sparse-checkout", "init", "--cone")
    git(mirror, "sparse-checkout", "set", cfg["subdir"])
    git(mirror, "checkout", "--quiet", "--detach", "FETCH_HEAD")
    git(mirror, "archive", "--format=tar.gz", "--output=" + str(output), cfg["commit"] + ":" + cfg["subdir"])
    require(output.stat().st_size > 0, "empty clang archive")
    print("CLANG_TRANSPORT=AUTHENTICATED_GITHUB_MIRROR", flush=True)


def materialize(label, work):
    cfg, _ = check_repo()
    require(label in cfg["lineages"], "unknown lineage")
    rec = cfg["lineages"][label]
    doc = yaml_read(REPO / rec["workflow"])
    require(len(doc["jobs"]) == 1, "source recipe must contain one job")
    job = next(iter(doc["jobs"].values()))
    source_work = work / "source-work"
    source_work.mkdir()
    temp = work / "source-temp"
    temp.mkdir()
    wrappers = temp / "bin"
    wrappers.mkdir()
    wrapper = wrappers / "make"
    wrapper.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " " + shlex.quote(str(HERE)) + ' capture-make -- "$@"\n')
    wrapper.chmod(0o755)
    curl = wrappers / "curl"
    curl.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " " + shlex.quote(str(HERE)) + ' transport-curl -- "$@"\n')
    curl.chmod(0o755)
    capture = temp / "capture.json"
    ctx = {"github.workspace": str(source_work), "runner.temp": str(temp),
           "github.run_id": os.environ.get("GITHUB_RUN_ID", "0"),
           "github.sha": git(REPO, "rev-parse", "HEAD"),
           "github.repository": "Chrizz100/veux-nongki-universal-kernel",
           "github.ref": "refs/heads/main"}
    env = dict(os.environ, GITHUB_WORKSPACE=str(source_work), RUNNER_TEMP=str(temp),
               GITHUB_REPOSITORY=ctx["github.repository"], GITHUB_SHA=ctx["github.sha"],
               GITHUB_RUN_ID=ctx["github.run_id"], GITHUB_REF=ctx["github.ref"],
               VEUX_CAPTURE=str(capture), VEUX_SOURCE_WORK=str(source_work), VEUX_TRANSPORT_WORK=str(temp), PYTHONDONTWRITEBYTECODE="1")
    outputs = {}
    env = env_map(doc.get("env", {}), env, ctx, outputs)
    env = env_map(job.get("env", {}), env, ctx, outputs)
    for index, step in enumerate(job["steps"]):
        name = step.get("name", str(index))
        condition = str(step.get("if", "success()")).replace(" ", "")
        if "failure()" in condition and "always()" not in condition:
            continue
        require(condition in ("success()", "always()", "${{success()}}", "${{always()}}"), f"source condition unsupported: {condition}")
        step_env = env_map(step.get("env", {}), env, ctx, outputs)
        if "uses" in step:
            if step["uses"].startswith("actions/checkout@"):
                opts = step.get("with", {})
                repo_name = expression(opts.get("repository", ctx["github.repository"]), step_env, ctx, outputs)
                dest = inside(source_work / expression(opts.get("path", ""), step_env, ctx, outputs), source_work)
                if repo_name == ctx["github.repository"]:
                    require(not (dest / ".git").exists(), "duplicate project checkout")
                    clone = temp / f"project-checkout-{index}"
                    run(["git", "clone", "--quiet", "--no-hardlinks", REPO, clone])
                    for p in clone.rglob("*"):
                        if p.is_file():
                            existing = dest / p.relative_to(clone)
                            require(not existing.exists(), f"checkout collision: {existing}")
                    shutil.copytree(clone, dest, dirs_exist_ok=True, symlinks=True)
                else:
                    source_checkout(opts, rec, step_env, ctx, outputs, dest)
                continue
            raise Blocked(f"reached action before source build boundary: {step['uses']}")
        require("run" in step, f"unsupported source step: {name}")
        # Dependencies belong to the outer workflow; source steps must not mutate the runner.
        script = expression(step["run"], step_env, ctx, outputs)
        if "apt-get install" in script:
            require("make " not in script and "git clone" not in script, "mixed dependency/source step")
            continue
        print(f"SOURCE {label}: {name}", flush=True)
        files = {k: temp / f"{index}-{k}" for k in ("GITHUB_ENV", "GITHUB_OUTPUT", "GITHUB_PATH", "GITHUB_STEP_SUMMARY")}
        step_env.update({k: str(v) for k, v in files.items()})
        step_env["PATH"] = str(wrappers) + os.pathsep + step_env["PATH"]
        sh = temp / f"step-{index}.sh"
        sh.write_text(script)
        run(["bash", "-n", sh])
        wd = step.get("working-directory", job.get("defaults", {}).get("run", {}).get("working-directory", "."))
        cwd = inside(source_work / expression(wd, step_env, ctx, outputs), source_work)
        log = work / f"source-{index}.log"
        with log.open("w") as out:
            proc = subprocess.Popen(["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", sh],
                                    cwd=cwd, env=step_env, stdout=out, stderr=subprocess.STDOUT, start_new_session=True)
            deadline = time.monotonic() + 1800
            last_notice = time.monotonic()
            try:
                while proc.poll() is None:
                    if capture.exists():
                        os.killpg(proc.pid, signal.SIGKILL)
                        proc.wait()
                        state = json.loads(capture.read_text())
                        state["recipe"] = rec
                        write_json(work / "source.json", state)
                        return state
                    require(time.monotonic() < deadline, f"source step timeout: {name}; log={log}")
                    if time.monotonic() - last_notice >= 30:
                        print(f"SOURCE {label}: {name}; log bytes={log.stat().st_size}", flush=True)
                        last_notice = time.monotonic()
                    time.sleep(0.2)
            finally:
                if proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
        require(proc.returncode == 0, f"source step failed: {name}; log={log}")
        env.update(parse_env(files["GITHUB_ENV"]))
        if files["GITHUB_PATH"].exists():
            env["PATH"] = os.pathsep.join(files["GITHUB_PATH"].read_text().splitlines() + [env["PATH"]])
        if step.get("id"):
            outputs[step["id"]] = parse_env(files["GITHUB_OUTPUT"])
    raise Blocked("source workflow ended without an authenticated build boundary")


def replace_once(text, old, new, description):
    require(text.count(old) == 1, f"preimage mismatch: {description}; matches={text.count(old)}")
    return text.replace(old, new, 1)


def normalized_resukisu(donor, entry, dest):
    dest.mkdir()
    for part in ("kernel", "uapi"):
        shutil.copytree(donor / part, dest / part, symlinks=True)
    shutil.copy2(donor / "LICENSE", dest / "LICENSE")
    p = dest / "kernel/Kbuild"
    text = p.read_text()
    start = '$(shell cd $(KSU_SRC); [ -f ../.git/shallow ] && $(GIT_BIN) fetch --unshallow)\n'
    end = 'KSU_BRANCH_NAME := $(shell cd $(KSU_SRC); $(GIT_BIN) branch --show-current 2>/dev/null || echo "unknown")\n'
    require(text.count(start) == text.count(end) == 1, "Kbuild identity block changed")
    a, b = text.index(start), text.index(end) + len(end)
    replacement = (f"KSU_LOCAL_VERSION := {entry['local_version']}\nKSU_VERSION := {entry['version']}\n"
                   f"KSU_TAG_NAME := {entry['tag']}\nKSU_COMMIT_SHA := {entry['commit'][:8]}\n"
                   f"KSU_BRANCH_NAME := {entry['ref'].removeprefix('refs/heads/')}\n")
    text = text[:a] + replacement + text[b:]
    text = replace_once(text, "kernelsu-objs += feature/module_load_filter.o\n", "", "module filter Kbuild")
    p.write_text(text)
    p = dest / "kernel/core/init.c"
    text = p.read_text()
    for old in ('#include "feature/module_load_filter.h"\n',
                'char ksu_block_modules[256];\nmodule_param_string(block_modules, ksu_block_modules, sizeof(ksu_block_modules), 0);\nMODULE_PARM_DESC(block_modules, "Comma-separated preset module names to acknowledge without loading");\n\n',
                "        ksu_module_load_filter_hook_init();\n\n", "    ksu_module_load_filter_hook_exit();\n"):
        text = replace_once(text, old, "", "module filter init")
    p.write_text(text)
    for name in ("module_load_filter.c", "module_load_filter.h"):
        (dest / "kernel/feature" / name).unlink()
    for p in dest.rglob("*"):
        if p.is_file():
            require(b"module_load_filter" not in p.read_bytes(), f"module filter remains: {p}")
    return dest


def topology(src):
    build = src / "drivers/kernelsu"
    require(build.is_dir(), "detected layout: missing drivers/kernelsu; expected a bound ReSukiSU subtree")
    canonical = build.resolve()
    require(canonical.is_relative_to(src.resolve()), "KernelSU symlink escapes source tree")
    require((canonical / "Kbuild").is_file(), "KernelSU Kbuild missing")
    roots = [p for p in (src / "KernelSU", src / ".resukisu") if (p / "kernel/Kbuild").is_file()]
    if build.is_symlink():
        vendor = canonical.parent
        require(canonical.name == "kernel" and (vendor / "uapi/supercall.h").is_file(), "unknown linked KernelSU layout")
        require(all((p / "kernel").resolve() == canonical for p in roots), "multiple divergent KernelSU source roots")
        return vendor, []
    require(len(roots) == 1, "unresolved physical KernelSU build directory")
    vendor = roots[0]
    require(tree_hashes(vendor / "kernel") == tree_hashes(build), "KernelSU physical mirror is divergent")
    return vendor, [build]


def tree_hashes(root):
    return {p.relative_to(root).as_posix(): digest(p) for p in root.rglob("*") if p.is_file() and ".git" not in p.relative_to(root).parts}


def merge_file(local, base, target, work):
    if base == target:
        return
    require(local.is_file(), f"missing host file: {local}")
    before = local.read_bytes()
    if before == target:
        return
    if before == base:
        local.write_bytes(target)
        return
    with tempfile.TemporaryDirectory(dir=work) as td:
        a, b, c = [Path(td) / x for x in ("local", "base", "target")]
        a.write_bytes(before); b.write_bytes(base); c.write_bytes(target)
        p = subprocess.run(["git", "merge-file", "-p", str(a), str(b), str(c)], capture_output=True)
        require(p.returncode == 0, f"BLOCKED three-way host conflict: {local}; preserve local compatibility, do not overwrite")
        local.write_bytes(p.stdout)


def patch_images(text):
    """Read unified-patch hunk images without treating patch metadata as code."""
    result = {}
    current = None
    hunk = None
    for line in text.splitlines(keepends=True):
        if line.startswith("diff --git "):
            current = line.split()[3].removeprefix("b/")
            result[current] = []
            hunk = None
        elif line.startswith("@@ "):
            require(current is not None, "patch hunk without path")
            hunk = {"before": [], "after": []}
            result[current].append(hunk)
        elif hunk is not None and line[:1] in (" ", "+", "-"):
            if line[:1] in (" ", "-"):
                hunk["before"].append(line[1:])
            if line[:1] in (" ", "+"):
                hunk["after"].append(line[1:])
    return result


def apply_host_delta(path, old, new):
    """Apply unique changed preimages, independent of surrounding 5.4 layout.

    Historical ports relocate whole functions. Unchanged GKI context must not
    force those functions back to their 5.10 positions. Ambiguous edits block.
    """
    text = path.read_text()
    edits = []
    for tag, a, b, c, d in difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        before, after = "".join(old[a:b]), "".join(new[c:d])
        if not before:
            require(a > 0 and b < len(old), f"unanchored host insertion: {path}")
            before = old[a - 1] + old[b]
            after = old[a - 1] + after + old[b]
        require(text.count(before) == 1, f"ambiguous or changed host preimage: {path}: {before[:100]!r}")
        start = text.index(before)
        edits.append((start, start + len(before), after))
    edits.sort()
    require(all(a[1] <= b[0] for a, b in zip(edits, edits[1:])), f"overlapping host edits: {path}")
    for start, end, after in reversed(edits):
        text = text[:start] + after + text[end:]
    path.write_text(text)


def integrate_susfs(src, donor, base, target, work):
    kind = validate_susfs_base(src, donor, base, target)
    if kind == "legacy":
        migration = config()["susfs_migration"]
        patch = REPO / migration["patch"]
        run(["git", "apply", "--check", "--whitespace=nowarn", patch], cwd=src)
        run(["git", "apply", "--whitespace=nowarn", patch], cwd=src)
    changed = git(donor, "diff", "--name-only", base, target, "--", "kernel_patches").splitlines()
    host_patch = "kernel_patches/50_add_susfs_in_gki-android13-5.10.patch"
    alternate = "kernel_patches/KernelSU/10_enable_susfs_for_ksu.patch"
    for name in changed:
        if name.startswith(("kernel_patches/fs/", "kernel_patches/include/")):
            old = subprocess.check_output(["git", "-C", str(donor), "show", f"{base}:{name}"])
            new = (donor / name).read_bytes()
            merge_file(inside(src / name.removeprefix("kernel_patches/"), src), old, new, work)
        elif name == host_patch:
            old = patch_images(git(donor, "show", f"{base}:{name}") + "\n")
            new = patch_images((donor / name).read_text())
            require(old.keys() == new.keys(), "SUSFS host patch adds/removes an unknown host path")
            for rel in old:
                require(len(old[rel]) == len(new[rel]), f"SUSFS hunk topology changed: {rel}")
                for a, b in zip(old[rel], new[rel]):
                    require(a["before"] == b["before"], f"SUSFS upstream base changed: {rel}")
                    if a["after"] == b["after"]:
                        continue
                    apply_host_delta(inside(src / rel, src), a["after"], b["after"])
        elif name == alternate:
            # This is the alternative upstream KernelSU port, not the native
            # ReSukiSU SUSFS backend. Require its produced additions unchanged.
            old = git(donor, "show", f"{base}:{name}")
            new = (donor / name).read_text()
            additions = lambda t: [l for l in t.splitlines() if l.startswith("+") and not l.startswith("+++")]
            require(additions(old) == additions(new), "alternative KernelSU SUSFS semantics changed; review native ReSukiSU backend")
        else:
            raise Blocked(f"unclassified SUSFS kernel delta: {name}")


def validate_susfs_base(src, donor, base, target):
    migration = config()["susfs_migration"]
    legacy = all((src / p).is_file() and digest(src / p) == value
                 for p, value in migration["legacy_sha256"].items())
    if legacy:
        require(base == migration["base"], "legacy migration base changed")
        require(digest(REPO / migration["patch"]) == migration["patch_sha256"], "SUSFS migration patch drift")
        for rel, expected in migration["base_sha256"].items():
            data = subprocess.check_output(["git", "-C", str(donor), "show", f"{base}:kernel_patches/{rel}"])
            require(hashlib.sha256(data).hexdigest() == expected, f"SUSFS migration donor drift: {rel}")
        return "legacy"
    pinned_c = git(donor, "show", f"{base}:kernel_patches/fs/susfs.c")
    actual_c = (src / "fs/susfs.c").read_text()
    markers = ("susfs_is_inode_sus_kstat", "susfs_sus_kstat_spoof_vfs_statfs", "statfs_by_dentry")
    missing = [name for name in markers if name in pinned_c and name not in actual_c]
    require(not missing,
            "SUSFS_BASE_API_MISMATCH: detected legacy SUSFS host with local backports; "
            f"declared base={base}; missing={missing}; "
            "expected transformation=shared legacy-to-current SUSFS migration preserving "
            "OPEN_REDIRECT and Non-GKI compatibility; unresolved difference=older SUS_KSTAT/statfs API. "
            "No upstream-pin promotion is permitted.")
    return "current"


def apply_update(src, source_state, bundle, work):
    targets = json.loads((bundle / "targets.json").read_text())
    rec = source_state["recipe"]
    for component, entry in targets["components"].items():
        require(git(bundle / component, "rev-parse", "HEAD") == entry["commit"], f"donor drift: {component}")
        require(not git(bundle / component, "status", "--porcelain"), f"dirty donor: {component}")
    # Check the actual source ABI before changing even a temporary component.
    validate_susfs_base(src, bundle / "susfs", rec["baseline_susfs"], targets["components"]["susfs"]["commit"])
    vendor, mirrors = topology(src)
    print(f"LAYOUT vendor={vendor.relative_to(src)} mirrors={len(mirrors)}", flush=True)
    require("config KSU_SUSFS" in (vendor / "kernel/Kconfig").read_text(), "existing native SUSFS Kconfig missing")
    if "golden_transform" in rec:
        transform = rec["golden_transform"]
        for rel, expected in transform["before"].items():
            require(digest(src / rel) == expected, f"golden source preimage drift: {rel}")
        script = REPO / transform["path"]
        require(digest(script) == transform["sha256"], "golden transform drift")
        require(src.name == "kernel", "golden source recipe path changed")
        run([sys.executable, script], cwd=src.parent)
        for rel, expected in transform["after"].items():
            require(digest(src / rel) == expected, f"golden source postimage drift: {rel}")
    staged = normalized_resukisu(bundle / "resukisu", targets["components"]["resukisu"], work / "resukisu-stage")
    require((vendor / ".git").exists(), "ReSukiSU git plumbing missing")
    for part in ("kernel", "uapi"):
        dest = inside(vendor / part, src)
        require(not dest.is_symlink(), "unexpected vendor subtree symlink")
        shutil.rmtree(dest)
        shutil.copytree(staged / part, dest, symlinks=True)
    shutil.copy2(staged / "LICENSE", vendor / "LICENSE")
    for mirror in mirrors:
        shutil.rmtree(mirror)
        shutil.copytree(vendor / "kernel", mirror, symlinks=True)
    nm = src / "fs/nomount"
    nm_donor = bundle / "nomount/kernel/src"
    require(set(p.name for p in nm_donor.iterdir()) == {"Kconfig", "Makefile", "nomount.c", "nomount.h"}, "NoMount source layout changed")
    if nm.exists():
        require(not nm.is_symlink(), "NoMount symlink unsupported")
        old_nm = REPO / "third_party/nomount/kernel/src"
        require(tree_hashes(nm) == tree_hashes(old_nm), "unrecognized existing NoMount modifications")
        shutil.rmtree(nm)
    shutil.copytree(nm_donor, nm)
    for rel, line in (("fs/Kconfig", 'source "fs/nomount/Kconfig"'), ("fs/Makefile", "obj-$(CONFIG_NOMOUNT) += nomount/")):
        p = src / rel
        text = p.read_text()
        require(text.count(line) <= 1, f"duplicate NoMount binding: {rel}")
        if line not in text:
            p.write_text(text.rstrip() + "\n\n" + line + "\n")
    integrate_susfs(src, bundle / "susfs", rec["baseline_susfs"], targets["components"]["susfs"]["commit"], work)
    require(tree_hashes(vendor / "kernel") == tree_hashes(staged / "kernel"), "staged ReSukiSU parity failed")
    require(tree_hashes(nm) == tree_hashes(nm_donor), "NoMount parity failed")
    topology(src)
    for p in src.rglob("*"):
        require(p.suffix not in (".rej", ".orig"), f"unresolved patch output: {p}")
    write_json(work / "integration.json", {"targets": targets["components"], "vendor": str(vendor.relative_to(src)),
               "device_pass": False, "integration": "PASS"})
    print("INTEGRATION=PASS", flush=True)
    return targets


def validate_build_config(conf, enabled, disabled):
    require(all(f"CONFIG_{k}=y" in conf for k in enabled), "required feature dropped by olddefconfig")
    # Kconfig omits invisible children when their parent hook is disabled.
    # Both an absent symbol and '# ... is not set' mean disabled.
    require(not any(line.startswith(tuple(f"CONFIG_{k}=" for k in disabled))
                    for line in conf), "conflicting hook configuration")


def prepare_dtb_reference(label, state, work, jobs):
    """Record a DTB reference before modifying the authenticated source."""
    recipe = config()["lineages"][label]
    spec = recipe["dtb"]
    reference = {"kernel": label, "mode": spec["reference"], "path": spec["path"],
                 "source_recipe_blob": recipe["blob"]}
    require(not Path(spec["path"]).is_absolute() and ".." not in Path(spec["path"]).parts,
            "invalid DTB path")
    if spec["reference"] == "pinned":
        reference["sha256"] = spec["sha256"]
    else:
        require(spec["reference"] == "native-source", "unsupported DTB reference policy")
        src = Path(state["source"])
        values = dict(v.split("=", 1) for v in state["variables"])
        require("O" in values, "native DTB reference needs an explicit output directory")
        out = inside((src / values["O"]).resolve(), work)
        conf = out / ".config"
        reference["config_sha256"] = digest(conf)
        env = dict(os.environ, **state["env"])
        env.pop("VEUX_CAPTURE", None)
        env["PATH"] = os.pathsep.join(p for p in env["PATH"].split(os.pathsep)
                                      if p != str(work / "source-temp/bin"))
        base = ["/usr/bin/make", "-C", str(src), *[f"{k}={v}" for k, v in values.items()]]
        print(f"DTB {label}: build authenticated native reference before update", flush=True)
        run([*base, f"-j{jobs}", "dtbs"], env=env, log=work / "dtb-reference.log")
        require(digest(conf) == reference["config_sha256"], "native DTB build changed baseline config")
        dtb = inside(out / spec["path"], out)
        require(dtb.is_file() and dtb.stat().st_size > 0, "native reference DTB missing")
        reference["sha256"] = digest(dtb)
    require(re.fullmatch(r"[0-9a-f]{64}", reference["sha256"]), "invalid DTB reference hash")
    write_json(work / "DTB-REFERENCE.json", reference)
    print(f"DTB {label}: mode={reference['mode']} expected={reference['sha256']}", flush=True)
    return reference


def verify_dtb(label, dtb, reference, work):
    recipe = config()["lineages"][label]
    spec = recipe["dtb"]
    require(reference["kernel"] == label and reference["source_recipe_blob"] == recipe["blob"]
            and reference["mode"] == spec["reference"] and reference["path"] == spec["path"],
            "DTB reference belongs to a different source")
    if spec["reference"] == "pinned":
        require(reference["sha256"] == spec["sha256"], "pinned DTB reference changed")
    actual = digest(dtb) if dtb.is_file() else None
    evidence = dict(reference, expected_sha256=reference["sha256"], actual_sha256=actual,
                    match=actual == reference["sha256"])
    write_json(work / "DTB-CHECK.json", evidence)
    require(evidence["match"], f"VEUX DTB regression: kernel={label}; mode={reference['mode']}; "
            f"expected={reference['sha256']}; actual={actual}; evidence={work / 'DTB-CHECK.json'}")
    print(f"DTB {label}=PASS sha256={actual}", flush=True)


def preserve_diagnostics(stage, public, diag):
    """Keep exact gate evidence, including earlier successes, after a failure."""
    diag.mkdir(parents=True, exist_ok=True)
    for name in ("BLOCKED.json", "DTB-REFERENCE.json", "DTB-CHECK.json",
                 "build-result.json", "integration.json"):
        if (stage / name).is_file():
            shutil.copy2(stage / name, diag / name)
    for name in ("RESULT.json", "STATIC-RESULT.json", "PACKAGE-STATUS.json"):
        if (public / name).is_file():
            shutil.copy2(public / name, diag / name)


def resukisu_image_identity(entry):
    """Return the target's tag/commit marker, independent of project branding.

    The normalized build writes these values from the same target metadata.
    No historical version, engine digest, or project name is prescribed here.
    """
    require(isinstance(entry, dict), "invalid KernelSU target metadata")
    tag = entry.get("tag")
    commit = entry.get("commit")
    require(isinstance(tag, str) and
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", tag),
            "missing or unsafe KernelSU target tag")
    require(isinstance(commit, str) and
            re.fullmatch(r"[0-9a-f]{40}", commit),
            "invalid KernelSU target commit")
    return f"{tag}-{commit[:8]}".encode("ascii")


def compile_kernel(label, state, targets, work, jobs):
    src = Path(state["source"])
    values = dict(v.split("=", 1) for v in state["variables"])
    require("O" in values, "captured compile has no explicit output directory")
    old_out = (src / values["O"]).resolve()
    inside(old_out, work)
    out = work / "build"
    out.mkdir()
    shutil.copy2(old_out / ".config", out / ".config")
    values["O"] = str(out)
    env = dict(os.environ, **state["env"])
    env.pop("VEUX_CAPTURE", None)
    env["PATH"] = os.pathsep.join(p for p in env["PATH"].split(os.pathsep) if p != str(work / "source-temp/bin"))
    base = ["/usr/bin/make", "-C", str(src), *[f"{k}={v}" for k, v in values.items()]]
    configure = [src / "scripts/config", "--file", out / ".config"]
    enabled = ["KSU", "KSU_SUSFS", "KSU_SUSFS_SUS_PATH", "KSU_SUSFS_SUS_MOUNT", "KSU_SUSFS_SUS_KSTAT",
               "KSU_SUSFS_SPOOF_UNAME", "KSU_SUSFS_ENABLE_LOG", "KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS",
               "KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG", "KSU_SUSFS_OPEN_REDIRECT", "KSU_SUSFS_SUS_MAP",
               "THREAD_INFO_IN_TASK", "NOMOUNT"]
    disabled = ["KSU_TRACEPOINT_HOOK", "KSU_MANUAL_HOOK", "KSU_MANUAL_HOOK_AUTO_SETUID_HOOK",
                "KSU_MANUAL_HOOK_AUTO_INITRC_HOOK", "KSU_MANUAL_HOOK_AUTO_INPUT_HOOK"]
    for key in enabled:
        configure.extend(["--enable", key])
    for key in disabled:
        configure.extend(["--disable", key])
    run(configure, cwd=src, env=env)
    run([*base, "olddefconfig"], env=env, log=work / "configure.log")
    conf = (out / ".config").read_text().splitlines()
    validate_build_config(conf, enabled, disabled)
    actual_version = run(["/usr/bin/make", "-s", "-C", src, "kernelversion"], env=env)
    require(actual_version == label, f"native kernel version mismatch: {actual_version}")
    print(f"BUILD {label} started (jobs={jobs})", flush=True)
    log = work / "compile.log"
    run([*base, f"-j{jobs}", "Image", "dtbs"], env=env, log=log, timeout=10800)
    text = log.read_text(errors="replace")
    require(not re.search(r"fatal error:|error:|undefined reference", text), "compile log contains errors")
    warnings = len(re.findall(r"\bwarning:", text))
    limit = config()["lineages"][label]["warning_limit"]
    require(warnings <= limit, f"warning regression: {warnings} > {limit}; log={log}")
    image = out / "arch/arm64/boot/Image"
    dtb = inside(out / config()["lineages"][label]["dtb"]["path"], out)
    require(image.is_file() and image.stat().st_size > 1024*1024, "kernel Image missing")
    verify_dtb(label, dtb, state["dtb_reference"], work)
    # Built-in LTO flattens composite objects into built-in.a; kernelsu.o need
    # not exist even when all ReSukiSU objects are present in the final Image.
    for obj in ("fs/nomount/nomount.o", "fs/susfs.o", "drivers/kernelsu/core/init.o",
                "drivers/kernelsu/built-in.a"):
        require((out / obj).is_file(), f"required compiled object missing: {obj}")
    data = image.read_bytes()
    for marker in (resukisu_image_identity(targets['components']['resukisu']), targets["components"]["resukisu"]["commit"][:8].encode(), b"susfs:", b"NoMount:"):
        require(marker in data, f"Image identity missing: {marker!r}")
    release = run([*base, "-s", "kernelrelease"], env=env).splitlines()[-1]
    require(release.startswith(label + "-"), "kernelrelease identity changed")
    result = {"kernel": label, "kernelrelease": release, "image_sha256": digest(image),
              "image_bytes": image.stat().st_size, "dtb_sha256": digest(dtb),
              "dtb_reference": state["dtb_reference"],
              "warnings": warnings, "compile": True, "device": False}
    write_json(work / "build-result.json", result)
    print(f"BUILD {label}=PASS image={result['image_sha256']}", flush=True)
    return image, result


def download(url, dest, expected):
    run(["curl", "--fail", "--location", "--silent", "--show-error", "--retry", "3", "--max-time", "300", url, "-o", dest], timeout=1000)
    require(digest(dest) == expected, f"download hash mismatch: {dest.name}")


def package_kernel(image, targets, result, work, public):
    from veux_release import identity
    ak = config()["ak3"]
    source = work / "ak3"
    checkout(ak["repo"], ak["commit"], source)
    require(git(source, "rev-parse", "HEAD^{tree}") == ak["tree"], "AK3 tree mismatch")
    c = targets["components"]
    release_name = identity(result["kernel"], c)
    script = ("# AnyKernel3 Ramdisk Mod Script\n# osm0sis @ xda-developers\n"
              "properties() { '\n" + f"kernel.string={release_name}\n" +
              "do.devicecheck=1\ndo.modules=0\ndo.systemless=1\ndo.cleanup=1\ndo.cleanuponabort=0\n"
              "device.name1=veux\nsupported.versions=13\nsupported.patchlevels=\n'; }\n"
              "BLOCK=boot;\nIS_SLOT_DEVICE=1;\nSLOT_SELECT=active;\nRAMDISK_COMPRESSION=auto;\n"
              "PATCH_VBMETA_FLAG=0;\n. tools/ak3-core.sh;\ndump_boot;\nwrite_boot;\n")
    sh = work / "anykernel.sh"
    sh.write_text(script)
    run(["bash", "-n", sh])
    files = {"Image": (image.read_bytes(), 0o644), "anykernel.sh": (script.encode(), 0o755)}
    for directory in ("tools", "META-INF"):
        for p in (source / directory).rglob("*"):
            if p.is_file() and not p.name.endswith("placeholder"):
                require(not p.is_symlink(), "AK3 symlink unexpected")
                files[p.relative_to(source).as_posix()] = (p.read_bytes(), p.stat().st_mode & 0o777)
    for p in source.glob("LICENSE*"):
        if p.is_file():
            files[p.name] = (p.read_bytes(), 0o644)
    for rel in ("tools/ak3-core.sh", "META-INF/com/google/android/update-binary", "META-INF/com/google/android/updater-script"):
        require(rel in files, f"AK3 file missing: {rel}")
    name = release_name + "_AnyKernel.zip"
    package = public / name
    def write(path):
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
            for rel, (data, mode) in sorted(files.items()):
                info = zipfile.ZipInfo(rel, (2024, 12, 5, 14, 48, 0))
                info.create_system = 3
                info.external_attr = (0o100000 | mode) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                z.writestr(info, data)
    write(package)
    second = work / "package-repeat.zip"
    write(second)
    require(digest(package) == digest(second), "package is not deterministic")
    with zipfile.ZipFile(package) as z:
        require(z.testzip() is None, "invalid package CRC")
        require(z.read("Image") == image.read_bytes(), "package Image mismatch")
        require(len(z.namelist()) == len(set(z.namelist())), "duplicate package members")
    result.update(package=True, package_file=name, package_sha256=digest(package))
    write_json(public / "PACKAGE-STATUS.json", result)
    print(f"PACKAGE {result['kernel']}=PASS", flush=True)
    return package


def avb_metadata(text):
    fields = {}
    for key in ("Algorithm", "Partition Name", "Hash Algorithm", "Salt"):
        matches = re.findall(r"^\s*" + key + r":\s*(\S+)\s*$", text, re.M)
        require(len(matches) == 1, f"ambiguous AVB {key}")
        fields[key] = matches[0]
    props = re.findall(r"^\s*Prop:\s+(.+?)\s+->\s+'(.*)'\s*$", text, re.M)
    require(props, "missing AVB properties")
    # The authenticated stock-derived image repeats security_patch with the
    # same value. Preserve that descriptor multiplicity instead of rejecting
    # it or silently dropping metadata. Conflicting duplicate values block.
    require(all(len({value for name, value in props if name == key}) == 1
                for key in {name for name, _ in props}), "conflicting AVB properties")
    fields["props"] = sorted(props)
    require(fields["Algorithm"] == "NONE" and fields["Partition Name"] == "boot" and fields["Hash Algorithm"] == "sha256", "AVB policy mismatch")
    require(re.fullmatch(r"[a-fA-F0-9]+", fields["Salt"]), "invalid AVB salt")
    return fields


def static_boot(image, result, work):
    cfg = config()["static"]
    root = work / "static"
    root.mkdir()
    base = root / "base.img"
    download(cfg["BASE_BOOT_URL"], base, cfg["BASE_BOOT_SHA256"])
    require(base.stat().st_size == int(cfg["BOOT_PARTITION_SIZE"]), "base boot partition size mismatch")
    apk = root / "magisk.apk"
    download(cfg["MAGISK_APK_URL"], apk, cfg["MAGISK_APK_SHA256"])
    mb = root / "magiskboot"
    with zipfile.ZipFile(apk) as z:
        names = [n for n in z.namelist() if re.fullmatch(r"lib/x86_64/(lib)?magiskboot(\.so)?", n)]
        require(len(names) == 1, "MagiskBoot payload ambiguous")
        mb.write_bytes(z.read(names[0]))
    mb.chmod(0o755)
    avb = root / "avb"
    checkout(cfg["AVB_REPO"], cfg["AVB_COMMIT"], avb)
    tool = [sys.executable, avb / "avbtool.py"]
    meta = avb_metadata(run([*tool, "info_image", "--image", base]))
    page = int(cfg["BOOT_PAGE_SIZE"])
    original = base.read_bytes()
    header = bytearray(original[:page])
    require(header[:8] == b"ANDROID!", "boot magic mismatch")
    old_kernel, ramdisk = struct.unpack_from("<II", header, 8)
    require(struct.unpack_from("<I", header, 40)[0] == int(cfg["EXPECTED_HEADER_VERSION"]), "header version mismatch")
    require(old_kernel == int(cfg["BASE_KERNEL_BYTES"]) and ramdisk > 0, "base component size mismatch")
    align = lambda n: ((n + page - 1) // page) * page
    kernel_data = image.read_bytes()
    raw_ramdisk = original[page + align(old_kernel):page + align(old_kernel) + ramdisk]
    require(hashlib.sha256(original[page:page+old_kernel]).hexdigest() == cfg["BASE_KERNEL_SHA256"], "base kernel hash mismatch")
    require(hashlib.sha256(raw_ramdisk).hexdigest() == cfg["RAW_STOCK_RAMDISK_SHA256"], "raw ramdisk hash mismatch")
    struct.pack_into("<I", header, 8, len(kernel_data))
    final = root / "boot.img"
    final.write_bytes(header + kernel_data + b"\0" * (align(len(kernel_data)) - len(kernel_data)) + raw_ramdisk + b"\0" * (align(ramdisk) - ramdisk))
    props = [arg for key, value in meta["props"] for arg in ("--prop", f"{key}:{value}")]
    run([*tool, "add_hash_footer", "--image", final, "--partition_name", "boot", "--partition_size", cfg["BOOT_PARTITION_SIZE"],
         "--hash_algorithm", "sha256", "--algorithm", "NONE", "--salt", meta["Salt"], *props])
    require(final.stat().st_size == int(cfg["BOOT_PARTITION_SIZE"]), "final partition size mismatch")
    require(avb_metadata(run([*tool, "info_image", "--image", final])) == meta, "AVB metadata changed")
    output = run([*tool, "verify_image", "--image", final], cwd=root)
    require("Successfully verified footer" in output and "Traceback" not in output, "AVB verification evidence missing")
    (root / "AVB-VERIFY.txt").write_text(output + "\n")
    final_header = bytearray(final.read_bytes()[:page])
    final_header[8:12] = original[8:12]
    require(bytes(final_header) == original[:page], "header changed outside kernel_size")
    for mode, flags, ramdisk_hash in (("raw", ["-n", "-h"], cfg["RAW_STOCK_RAMDISK_SHA256"]),
                                      ("decoded", ["-h"], cfg["DECODED_STOCK_RAMDISK_SHA256"])):
        out = root / mode
        out.mkdir()
        run([mb, "unpack", *flags, final], cwd=out, log=root / f"unpack-{mode}.log")
        require(digest(out / "kernel") == result["image_sha256"], f"{mode} final kernel mismatch")
        require(digest(out / "ramdisk.cpio") == ramdisk_hash, f"{mode} final ramdisk changed")
    result.update(static_boot=True, static_boot_sha256=digest(final), device=False)
    print(f"STATIC {result['kernel']}=PASS; DEVICE_PASS=NO", flush=True)


def worker(label, bundle, work, public, jobs, repository_output=None):
    cfg, _ = check_repo()
    targets = json.loads((bundle / "targets.json").read_text())
    require(targets["repository_sha"] == git(REPO, "rev-parse", "HEAD"), "resolver/worker commit mismatch")
    require(digest(REPO / cfg["golden_contract"]) == targets["golden_sha256"], "Golden contract changed")
    require(label in targets["lineages"], "worker lineage not in resolver manifest")
    work.mkdir(parents=True, exist_ok=False)
    public.mkdir(parents=True, exist_ok=False)
    try:
        state = materialize(label, work)
        state["dtb_reference"] = prepare_dtb_reference(label, state, work, jobs)
        overlay_hash = None
        if repository_output is not None:
            from veux_release import inventory, replay_current, save_overlay
            src = Path(state["source"])
            before = inventory(src)
            if not replay_current(src, label, targets):
                apply_update(src, state, bundle, work)
            overlay_hash = save_overlay(src, before, repository_output / label, label, targets)
        else:
            apply_update(Path(state["source"]), state, bundle, work)
        image, result = compile_kernel(label, state, targets, work, jobs)
        package_kernel(image, targets, result, work, public)
        static_boot(image, result, work)
        from veux_release import publish_files
        publish_files(result, work, public, targets)
        if overlay_hash is not None:
            result['integration_overlay_sha256'] = overlay_hash
        result.update(repository_sha=targets["repository_sha"], targets=targets["components"],
                      target_manifest_sha256=digest(bundle / "targets.json"), device=False)
        write_json(public / "RESULT.json", result)
        if repository_output is None:
            write_json(public / "STATIC-RESULT.json", result)
        else:
            (public / "PACKAGE-STATUS.json").unlink()
        (public / "SHA256SUMS.txt").write_text("".join(f"{digest(p)}  {p.name}\n" for p in sorted(public.iterdir()) if p.is_file()))
    except Exception as exc:
        write_json(work / "BLOCKED.json", {"kernel": label, "reason": str(exc), "device": False})
        raise


def all_workers(bundle, work, public, jobs):
    """Sequential builds share one authenticated upstream bundle and keep six outputs."""
    require(not work.exists() and not public.exists(), "all-worker output directories must be new")
    work.mkdir(parents=True)
    public.mkdir(parents=True)
    targets = json.loads((bundle / "targets.json").read_text())
    for label in targets["lineages"]:
        stage = work / label
        dest = public / label
        try:
            worker(label, bundle, stage, dest, jobs)
        finally:
            # Preserve only compact diagnostics, never the captured environment or sources.
            diag = work / "diagnostics" / label
            diag.mkdir(parents=True, exist_ok=True)
            for p in stage.glob("*.log"):
                shutil.copy2(p, diag / p.name)
            preserve_diagnostics(stage, dest, diag)
        # These are our temporary build/source copies, not repository files.
        inside(stage, work)
        shutil.rmtree(stage)
    prepared = work / "promotion"
    prepare_promotion(bundle, public, prepared)
    for label in targets["lineages"]:
        shutil.copy2(prepared / "PROMOTION-READY.json", public / label / "PROMOTION-READY.json")
        folder = public / label
        (folder / "SHA256SUMS.txt").write_text("".join(f"{digest(p)}  {p.name}\n" for p in sorted(folder.iterdir()) if p.is_file() and p.name != "SHA256SUMS.txt"))


def prepare_promotion(bundle, artifacts, output):
    targets = json.loads((bundle / "targets.json").read_text())
    cfg, _ = check_repo()
    require(git(REPO, "rev-parse", "HEAD") == targets["repository_sha"], "promotion source head mismatch")
    require(digest(REPO / cfg["golden_contract"]) == targets["golden_sha256"], "Golden contract drift")
    rows = {}
    paths = list(artifacts.rglob("RESULT.json"))
    labels = [json.loads(p.read_text())["kernel"] for p in paths]
    require(len(labels) == len(set(labels)), "duplicate lineage results")
    for path in paths:
        row = json.loads(path.read_text())
        label = row["kernel"]
        require(label not in rows, f"duplicate result: {label}")
        require(row["repository_sha"] == targets["repository_sha"] and row["targets"] == targets["components"], "result provenance mismatch")
        require(row["target_manifest_sha256"] == digest(bundle / "targets.json"), "result target manifest mismatch")
        require(all(row.get(k) is True for k in ("compile", "package", "static_boot")), f"incomplete gates: {label}")
        require(row.get("device") is False, "automated device PASS prohibited")
        require(Path(row["package_file"]).name == row["package_file"], "invalid package filename")
        package = path.parent / row["package_file"]
        require(package.is_file(), "promotion package missing")
        require(digest(package) == row["package_sha256"], "promotion package hash mismatch")
        with zipfile.ZipFile(package) as z:
            require(hashlib.sha256(z.read("Image")).hexdigest() == row["image_sha256"], "promotion image hash mismatch")
        rows[label] = row
    require(set(rows) == set(targets["lineages"]) and len(rows) == 6, "promotion requires exactly six successful results")
    # Reviewable promotion evidence only. No write to main and no new branch.
    output.mkdir(parents=True, exist_ok=False)
    write_json(output / "PROMOTION-READY.json", {"status": "6/6-green-ready-for-review", "base_sha": targets["repository_sha"],
               "targets": targets["components"], "lineages": rows, "golden_preserved": True,
               "repository_mutation": False, "device_pass_inferred": False})
    print("ALL_SIX_COMPILE_PACKAGE_STATIC=PASS; PROMOTION_PREPARED=YES; REPOSITORY_MUTATION=NO")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("resolve")
    p.add_argument("--work", type=Path, required=True)
    for command in ("worker", "all"):
        p = sub.add_parser(command)
        if command == "worker":
            p.add_argument("--kernel", required=True)
        p.add_argument("--bundle", type=Path, required=True)
        p.add_argument("--work", type=Path, required=True)
        p.add_argument("--public", type=Path, required=True)
        p.add_argument("--jobs", type=int, default=min(os.cpu_count() or 2, 8))
    p = sub.add_parser("prepare-promotion")
    p.add_argument("--bundle", type=Path, required=True)
    p.add_argument("--artifacts", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    for command in ("capture-make", "transport-curl"):
        p = sub.add_parser(command)
        p.add_argument("args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        if args.command == "capture-make":
            capture_make(args.args[1:] if args.args[:1] == ["--"] else args.args)
        elif args.command == "transport-curl":
            transport_curl(args.args[1:] if args.args[:1] == ["--"] else args.args)
        elif args.command == "resolve":
            resolve(args.work.resolve())
        elif args.command == "worker":
            require(args.jobs > 0, "build jobs must be positive")
            worker(args.kernel, args.bundle.resolve(), args.work.resolve(), args.public.resolve(), args.jobs)
        elif args.command == "all":
            require(args.jobs > 0, "build jobs must be positive")
            all_workers(args.bundle.resolve(), args.work.resolve(), args.public.resolve(), args.jobs)
        else:
            prepare_promotion(args.bundle.resolve(), args.artifacts.resolve(), args.output.resolve())
    except (Blocked, OSError, subprocess.SubprocessError, ValueError, KeyError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
