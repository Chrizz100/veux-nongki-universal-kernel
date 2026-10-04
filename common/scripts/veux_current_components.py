#!/usr/bin/env python3
"""Current-component resolver with reviewed ReSukiSU UAPI 5 support.

Retains the legacy resolver's commit, ancestry, version and layout checks.
UAPI 5 additionally authenticates and host-tests the new services event.
The frozen legacy engine and V4 workflow remain unchanged.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from veux_update_engine import (Blocked, COMPONENTS, REPO, SHA, check_repo,
    checkout, digest, git, require, run, write_json, yaml_read)

UAPI5_HEADER = 'ca897ddb31f0a910fb5eac0e4ad14d562a14af212243acdf1b5dd87f711a3618'
UAPI5_EVENT = '2e563f940387626538f02d21f7b36bf34c6a9f030904f260d8e287b9bd27cbb1'


def event_function(source):
    start = source.index('static int do_report_event(')
    end = source.index('\nstatic int do_set_sepolicy(', start)
    return source[start:end].rstrip() + '\n'


def event_host_test(function):
    code = r'''
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#define __user
#define CONFIG_KSU_SUSFS
#define pr_info(...) ((void)0)
enum { EVENT_POST_FS_DATA=1, EVENT_BOOT_COMPLETED=2,
       EVENT_MODULE_MOUNTED=3, EVENT_SERVICES=4 };
struct ksu_report_event_cmd { uint32_t event; };
static bool ksu_late_loaded;
static int fail_copy, post, boot, mounted, monitor, checks;
static int copy_from_user(void *dest, void *arg, size_t size) {
 if (fail_copy) return 1;
 memcpy(dest,arg,size); return 0;
}
static void on_post_fs_data(void) { post++; }
static void on_boot_completed(void) { boot++; }
static void on_module_mounted(void) { mounted++; }
static void susfs_start_sdcard_monitor_fn(void) { monitor++; }
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"event FAIL %d\n",__LINE__); return 1; } checks++; } while (0)
''' + function + r'''
int main(void) {
 struct ksu_report_event_cmd cmd={EVENT_SERVICES};
 fail_copy=1; CHECK(do_report_event(&cmd)==-EFAULT); fail_copy=0;
 CHECK(do_report_event(&cmd)==1); CHECK(do_report_event(&cmd)==0);
 CHECK(post==0 && boot==0 && mounted==0 && monitor==0);
 cmd.event=EVENT_POST_FS_DATA; CHECK(do_report_event(&cmd)==0); CHECK(post==1);
 cmd.event=EVENT_SERVICES; CHECK(do_report_event(&cmd)==1); CHECK(do_report_event(&cmd)==0);
 cmd.event=EVENT_POST_FS_DATA; CHECK(do_report_event(&cmd)==0); CHECK(post==1);
 cmd.event=EVENT_SERVICES; CHECK(do_report_event(&cmd)==1); CHECK(do_report_event(&cmd)==0);
 cmd.event=EVENT_BOOT_COMPLETED; CHECK(do_report_event(&cmd)==0); CHECK(boot==1 && monitor==1);
 CHECK(do_report_event(&cmd)==0); CHECK(boot==1 && monitor==1);
 cmd.event=EVENT_MODULE_MOUNTED; CHECK(do_report_event(&cmd)==0); CHECK(mounted==1);
 cmd.event=999; CHECK(do_report_event(&cmd)==0); CHECK(mounted==1 && post==1 && boot==1);
 printf("UAPI5_EVENT_HOST_ASSERTIONS=%d; PASS\n",checks); return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='resukisu-uapi5-') as tmp:
        root = Path(tmp)
        (root / 'test.c').write_text(code)
        run(['gcc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
             root / 'test.c', '-o', root / 'test'])
        print(run([root / 'test']), flush=True)


def checked_uapi(donor):
    header = (donor / 'uapi/supercall.h').read_text()
    versions = re.findall(r'^static const __u32 KERNEL_SU_UAPI_VERSION = ([0-9]+);$', header, re.M)
    require(len(versions) == 1, 'ambiguous ReSukiSU UAPI')
    version = int(versions[0])
    require(version in (4, 5), 'unreviewed ReSukiSU UAPI: ' + str(version))
    if version == 5:
        require(digest(donor / 'uapi/supercall.h') == UAPI5_HEADER,
                'UAPI 5 header differs from reviewed upstream 8770c7e3')
        function = event_function((donor / 'kernel/supercall/dispatch.c').read_text())
        require(hashlib.sha256(function.encode()).hexdigest() == UAPI5_EVENT,
                'UAPI 5 event behavior differs from reviewed upstream 8770c7e3')
        event_host_test(function)
    return version

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
                         tag=git(donor, "describe", "--tags", "--abbrev=0", target), uapi=checked_uapi(donor))
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    try:
        resolve(args.work)
    except (Blocked, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print('BLOCKED: ' + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
