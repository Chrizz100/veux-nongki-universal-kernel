#!/usr/bin/env python3
"""VEUX 5.4.274 P2 -> P3 (CASS-only de-integration, SOURCE ONLY).

Creates a fail-closed, git-apply-verifiable patch from the exact, immutable
KSU2-P2-v5 clean source. Never modifies source tree, builds, flashes, or pushes.
It is *not* the missing Xiaomi WALT backport and never claims stock PASS.
"""
from __future__ import annotations
import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

P2_SOURCE_TREE = '16ce899d4549819d42d76b423ebcbd51f1b82a61'
P2_SOURCE_COMMIT = '61bb08ca2bffba1745bd4ee8a5118ed54a2f8f6e'
P2_CI_RUN = 33832342297
P2_CI_ARTIFACT_SHA256 = '54d6e4d6c5d9656f0222dc77ab79e4eb3925fa3b4b709e9d2ad9bea125907b45'
P2_CONFIG_SHA256 = 'f6a4c78bf637bbf89b5e3a3059cf9d1651e43189a6ac459e806fa289d8628f9d'
P2_IMAGE_SHA256 = '9d2c4c83469c9c55e1a5cd8838fb7ba10e24a551650dedf122fbde5f7bf398ca'

MODIFY = (
    'arch/arm64/configs/veux_defconfig',
    'init/Kconfig',
    'kernel/sched/fair.c',
    'kernel/sched/rt.c',
)
DELETE = ('kernel/sched/cass.c', 'kernel/sched/cass_rt.h')
SENSITIVE = set(MODIFY + DELETE)
CASS_KCONFIG_RE = re.compile(r'\nconfig SCHED_CASS\n.*?(?=\nconfig SCHED_AUTOGROUP\n)', re.S)
CASS_FAIR = ("#ifdef CONFIG_SCHED_CASS\n"
             "#include \"cass.c\"\n"
             "\n"
             "/* Use CASS. A dummy wrapper ensures the replaced function is still \"used\". */\n"
             "static inline void *select_task_rq_fair_dummy(void)\n"
             "{\n"
             "\treturn (void *)select_task_rq_fair;\n"
             "}\n"
             "#define select_task_rq_fair cass_select_task_rq_fair\n"
             "#endif /* CONFIG_SCHED_CASS */\n"
             "\n")

class Blocked(RuntimeError):
    pass

def require(condition: bool, description: str) -> None:
    if not condition:
        raise Blocked(description)

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def gitblob(data: bytes) -> str:
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()

def run_git(root: Path, *args: str) -> str:
    p = subprocess.run(['git', '-C', str(root), *args], capture_output=True, text=True,
                       timeout=45, check=False)
    require(p.returncode == 0, 'GIT_FAILED '+repr(args)+' '+p.stderr[-220:])
    return p.stdout.strip()

def validate_source(root: Path, expected_tree: str = P2_SOURCE_TREE) -> dict:
    root = root.resolve(strict=True)
    require(root.is_dir(), 'INPUT_IS_NOT_DIRECTORY')
    require(run_git(root, 'rev-parse', '--show-toplevel') == str(root), 'NOT_GIT_ROOT')
    require(run_git(root, 'status', '--porcelain', '--untracked-files=all') == '', 'SOURCE_DIRTY')
    tree = run_git(root, 'rev-parse', 'HEAD^{tree}')
    require(tree == expected_tree, 'P2_TREE_MISMATCH '+tree)
    makefile = read_checked(root, 'Makefile').decode('utf-8')
    parts = []
    for key in ('VERSION', 'PATCHLEVEL', 'SUBLEVEL'):
        result = re.findall(r'^'+key+r'\s*=\s*(\d+)\s*$', makefile, re.M)
        require(len(result) == 1, 'KERNEL_VERSION_PART_MISSING '+key)
        parts.append(result[0])
    require('.'.join(parts) == '5.4.274', 'NOT_LINUX_5_4_274')
    for residue in ('drivers/kernelsu', 'KernelSU', '.resukisu', 'fs/susfs.c',
                    'include/linux/susfs.h', 'fs/nomount'):
        require(not (root/residue).exists(), 'ROOT_SUSFS_NOMOUNT_RESIDUE '+residue)
    require(not (root/'kernel/sched/walt').exists(), 'WALT_ALREADY_PRESENT_DO_NOT_REMOVE_CASS_BLINDLY')
    # Do not delete CASS if other kernel implementation paths depend on it.
    p = subprocess.run(['git','-C',str(root),'grep','-l','-E',
                        'CONFIG_SCHED_CASS|cass_select_task_rq|cass_rt[.]h|[\"]cass[.]c[\"]',
                        '--','arch/arm64/configs','init','kernel','include','drivers'],
                       capture_output=True, text=True, check=False, timeout=60)
    require(p.returncode in (0,1), 'CASS_REFERENCE_SCAN_FAILED')
    unexpected = set(p.stdout.splitlines()) - SENSITIVE
    require(not unexpected, 'UNREVIEWED_CASS_DEPENDENCIES '+','.join(sorted(unexpected)))
    return {'kernel':'5.4.274', 'source_tree':tree, 'source_commit':run_git(root,'rev-parse','HEAD'),
            'root_source_absent':True, 'walt_currently_absent':True,
            'cass_reference_paths':sorted(p.stdout.splitlines())}

def read_checked(root: Path, rel: str) -> bytes:
    path = root/rel
    require(path.is_file() and not path.is_symlink(), 'MISSING_OR_SYMLINK_FILE '+rel)
    require(path.resolve().is_relative_to(root.resolve()), 'PATH_ESCAPE '+rel)
    raw = path.read_bytes()
    require(raw and b'\r' not in raw and raw.endswith(b'\n'), 'NOT_NORMALIZED_TEXT '+rel)
    return raw

def once(data: str, old: str, new: str, field: str) -> str:
    require(data.count(old) == 1, 'MISSING_OR_AMBIGUOUS_'+field)
    return data.replace(old, new, 1)

def transform(before: dict[str, bytes]) -> dict[str, bytes | None]:
    """Edit exactly six 5.4.274 P2 paths; fail closed on any anchor drift."""
    require(set(before) == SENSITIVE, 'INPUT_PATH_SCOPE_MISMATCH')
    text = {p:before[p].decode('utf-8',errors='strict') for p in before}
    config = text['arch/arm64/configs/veux_defconfig']
    # There is no WALT yet, so do not turn CONFIG_SCHED_WALT on and fake stock.
    config = once(config,'CONFIG_SCHED_CASS=y\n','', 'CASS_DEFCONFIG')
    require('CONFIG_SCHED_WALT=' not in config, 'WALT_CONFIG_ALREADY_PRESENT')
    kcfg = text['init/Kconfig']
    match = CASS_KCONFIG_RE.findall(kcfg)
    require(len(match) == 1 and 'Capacity Aware Superset Scheduler' in match[0] and
            'hierarchy of criteria' in match[0], 'CASS_KCONFIG_BLOCK_DRIFT')
    kcfg = CASS_KCONFIG_RE.sub('\n', kcfg, count=1)
    fair = once(text['kernel/sched/fair.c'], CASS_FAIR, '', 'CASS_FAIR_HOOK')
    rt = once(text['kernel/sched/rt.c'], '#include "cass_rt.h"\n', '', 'CASS_RT_HOOK')
    after = {'arch/arm64/configs/veux_defconfig':config.encode(),
             'init/Kconfig':kcfg.encode(),
             'kernel/sched/fair.c':fair.encode(),
             'kernel/sched/rt.c':rt.encode(),
             'kernel/sched/cass.c':None, 'kernel/sched/cass_rt.h':None}
    for path, raw in after.items():
        if raw is not None:
            require(raw != before[path] and b'\r' not in raw, 'UNEXPECTED_UNCHANGED_FILE '+path)
            if path.startswith('kernel/') or path=='init/Kconfig' or path.startswith('arch/'):
                require(b'CONFIG_SCHED_CASS' not in raw and b'cass_select_task_rq' not in raw and
                        b'"cass.c"' not in raw and b'"cass_rt.h"' not in raw,
                        'CASS_REMAINS_'+path)
    return after

def unified_patch(before: dict[str, bytes], after: dict[str, bytes | None]) -> bytes:
    out = []
    for rel in sorted(before):
        old = before[rel]; new = after[rel]
        oldtxt = old.decode('utf-8')
        newtxt = '' if new is None else new.decode('utf-8')
        oldblob = gitblob(old)[:12]
        newblob = '000000000000' if new is None else gitblob(new)[:12]
        out.append(f'diff --git a/{rel} b/{rel}\n')
        if new is None:
            out.append('deleted file mode 100644\n')
            out.append(f'index {oldblob}..000000000000\n')
        else:
            out.append(f'index {oldblob}..{newblob} 100644\n')
        out.extend(difflib.unified_diff(oldtxt.splitlines(keepends=True),
                                        newtxt.splitlines(keepends=True),
                                        fromfile='a/'+rel,
                                        tofile='/dev/null' if new is None else 'b/'+rel,
                                        n=3))
    return ''.join(out).encode()

def audit_patch(before: dict[str, bytes], after: dict[str, bytes | None], patch: bytes) -> None:
    """Actually run git apply --check and git apply against a temporary tracked mini-tree."""
    with tempfile.TemporaryDirectory(prefix='veux-p2-patch-gate-') as td:
        temp=Path(td)
        subprocess.run(['git','init','-q',str(temp)],check=True,stdout=subprocess.DEVNULL)
        for rel,raw in before.items():
            f=temp/rel;f.parent.mkdir(parents=True,exist_ok=True);f.write_bytes(raw)
        subprocess.run(['git','-C',str(temp),'add','-A'],check=True)
        patchfile=Path(td+'.patch')
        try:
            patchfile.write_bytes(patch)
            for args in (['git','-C',str(temp),'apply','--check','--whitespace=error',str(patchfile)],
                         ['git','-C',str(temp),'apply','--whitespace=error',str(patchfile)]):
                result=subprocess.run(args,text=True,capture_output=True,check=False,timeout=30)
                require(result.returncode==0, 'PATCH_APPLY_FAILED '+result.stderr[-450:])
        finally:
            patchfile.unlink(missing_ok=True)
        for rel,new in after.items():
            f=temp/rel
            require((not f.exists()) if new is None else f.is_file() and f.read_bytes()==new,
                    'PATCH_POSTIMAGE_WRONG '+rel)

def prepare(root: Path, dest: Path, *, expected_tree: str=P2_SOURCE_TREE) -> dict:
    root=root.resolve(strict=True)
    dest=dest.resolve()
    require(not dest.exists(), 'DESTINATION_EXISTS')
    require(not dest.is_relative_to(root), 'OUTPUT_INSIDE_SOURCE')
    require(root != dest, 'OUTPUT_IS_SOURCE')
    source = validate_source(root,expected_tree=expected_tree)
    before={rel:read_checked(root,rel) for rel in SENSITIVE}
    after=transform(before)
    patch=unified_patch(before,after)
    audit_patch(before,after,patch)
    require(run_git(root, 'status', '--porcelain','--untracked-files=all') == '',
            'SOURCE_CHANGED_BY_PREPARATION')
    require(run_git(root,'rev-parse','HEAD^{tree}') == expected_tree,
            'SOURCE_TREE_CHANGED_BY_PREPARATION')
    changed={rel:{'before_sha256':sha256(raw),
                  'after_sha256':sha256(after[rel]) if after[rel] is not None else None,
                  'type':'delete' if after[rel] is None else 'modify'}
             for rel,raw in sorted(before.items())}
    record={
      'purpose':'VEUX 5.4.274 P2 -> P3 CASS de-integration (source only)',
      'source_gate':source, 'change_gate':changed,
      'patch_sha256':sha256(patch),
      'patch_git_apply_check':'PASS', 'patch_git_apply_and_byte_readback':'PASS',
      'source_unchanged':True, 'git_push':False,
      'linux_source_version':'5.4.274', 'kernelSU':False, 'susfs':False,
      'cass_source_footprint_after_patch':False,
      'walt_integrated':False, 'xiaomi_stock_abi_pass':False,
      'build_pass':False,'device_pass':False,'boot_image_created':False,
      'status':'SOURCE_ONLY_P3_PREPARATION_NOT_FLASHABLE',
      'next_gate':'REBASE_XIAOMI_WALT_TO_5_4_274_WITH_ALL_DEPENDENCIES_AND_REAL_BUILD',
    }
    dest.mkdir(parents=True)
    (dest/'P2_TO_P3_REMOVE_CASS.patch').write_bytes(patch)
    (dest/'SOURCE_PREP_REPORT.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
    (dest/'INTEGRITY_SHA256SUMS.txt').write_text('\n'.join(
         f'{sha256((dest/p).read_bytes())}  {p}'
         for p in ('P2_TO_P3_REMOVE_CASS.patch','SOURCE_PREP_REPORT.json'))+'\n')
    return record

def main() -> None:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--p2-source',required=True,type=Path,
                    help='Exact KSU2-P2-v5 5.4.274 clean Git source; NOT vendor 5.4.268')
    ap.add_argument('--output',required=True,type=Path,help='NEW directory outside source tree')
    ns=ap.parse_args()
    try:
        p=prepare(ns.p2_source,ns.output)
    except (Blocked,OSError,UnicodeError) as exc:
        ap.exit(2,'STOP: '+str(exc)+'\n')
    print('P2_SOURCE_TREE=PASS; CASS_REMOVAL_PATCH=VERIFIED; BUILD=BLOCKED; WALT_PORT=OPEN')
    print('PATCH_SHA256='+p['patch_sha256'])

if __name__=='__main__':
    main()
