#!/usr/bin/env python3
"""VEUX Linux-5.4-only BakaSU SELinux hook restoration error guard.

Never alters Git history or donor sources.  Called ONLY on the disposable
5.4.274 worker source after the pinned 35222 + fa12 / R4-compat backport.
Does not change SUSFS/NoMount, SELinux policy, kernel config or setprocattr
runtime compatibility. All changes are exact-token replacements with a pinned
preimage SHA256.  A source-only pass is NOT a compiled kernel/device pass.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re

# Verified actual R4 source-audit effective SHA256 from GitHub Run 38290011987.
R4_EFFECTIVE_BAKASU_SHA256 = '5e40cb29c74fbca6b2b15072e395fb971932894eebe9f846f970a7de139c0a8f'
RELATIVE = 'KernelSU/kernel/feature/selinux_hide.c'

class UnsafeSource(RuntimeError):
    pass

def demand(value: bool, error: str):
    if not value:
        raise UnsafeSource(error)

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

# All six replacements match one and only one occurrence in the pinned R4 C
# file. This procedure does not infer the complete 5.4 SELinux ABI.
REPLACEMENTS = (
    (
        'static void ksu_selinux_hide_unhook()\n{\n    int ret;',
        'static int ksu_selinux_hide_unhook()\n{\n    int ret;',
        'unhook_result_type',
    ),
    (
        '''        orig_context_write = NULL;
        if (ret) {
            pr_err("selinux_hide: exit: patch_text context_write err: %d\\n", ret);
        }''',
        '''        if (ret) {
            pr_err("selinux_hide: exit: patch_text context_write err: %d\\n", ret);
            return ret;
        }
        orig_context_write = NULL;''',
        'context_write_restore',
    ),
    (
        '''        orig_access_write = NULL;
        if (ret) {
            pr_err("selinux_hide: exit: patch_text access_write err: %d\\n", ret);
        }''',
        '''        if (ret) {
            pr_err("selinux_hide: exit: patch_text access_write err: %d\\n", ret);
            return ret;
        }
        orig_access_write = NULL;''',
        'access_write_restore',
    ),
    (
        '''        ksu_orig_setprocattr = NULL;
        if (ret) {
            pr_err("selinux_hide: exit: patch_text setprocattr err: %d\\n", ret);
        }''',
        '''        if (ret) {
            pr_err("selinux_hide: exit: patch_text setprocattr err: %d\\n", ret);
            return ret;
        }
        ksu_orig_setprocattr = NULL;''',
        'setprocattr_restore',
    ),
    (
        '''#endif
}

extern void ksu_register_setprocattr_lsm_hook();
#else
#define ksu_selinux_hide_unhook()                                                                                      \\
    do {                                                                                                               \\
    } while (0)
#endif // #ifndef KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE''',
        '''#endif
    return 0;
}

extern void ksu_register_setprocattr_lsm_hook();
#else
#define ksu_selinux_hide_unhook() (0)
#endif // #ifndef KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE''',
        'unhook_return_and_susfs_compat',
    ),
    (
        '''unhook:
#endif
    ksu_selinux_hide_unhook();
    return -ENOSYS;''',
        '''unhook:
#endif
    ret = ksu_selinux_hide_unhook();
    if (ret) {
        /* Keep the feature visible if any installed hook failed to restore. */
        pr_err("selinux_hide: partial init rollback failed: %d\\n", ret);
        ksu_selinux_hide_running = true;
        ksu_selinux_hide_enabled = true;
        return ret;
    }
    return -ENOSYS;''',
        'enable_failure_rollback',
    ),
    (
        '''static void ksu_selinux_hide_disable()
{
    pr_info("selinux_hide: exit selinux hide\\n");

    ksu_selinux_hide_unhook();
}''',
        '''static int ksu_selinux_hide_disable()
{
    pr_info("selinux_hide: exit selinux hide\\n");

    return ksu_selinux_hide_unhook();
}''',
        'disable_result_propagation',
    ),
    (
        '''static int selinux_hide_feature_set(u64 value)
{
    bool enable = value != 0;
    int ret = 0;
    pr_info("selinux_hide: set to %d\\n", enable);
    mutex_lock(&selinux_hide_mutex);
    ksu_selinux_hide_enabled = enable;
    if (enable) {
        if (!ksu_selinux_hide_running) {
            ret = ksu_selinux_hide_enable();
            if (!ret) {
                ksu_selinux_hide_running = true;
            }
        }
    } else {
        if (ksu_selinux_hide_running) {
            ksu_selinux_hide_disable();
            ksu_selinux_hide_running = false;
        }
    }
    mutex_unlock(&selinux_hide_mutex);
    return ret;
}''',
        '''static int selinux_hide_feature_set(u64 value)
{
    bool enable = value != 0;
    bool previously_enabled;
    int ret = 0;
    pr_info("selinux_hide: set to %d\\n", enable);
    mutex_lock(&selinux_hide_mutex);
    previously_enabled = ksu_selinux_hide_enabled;
    ksu_selinux_hide_enabled = enable;
    if (enable) {
        if (!ksu_selinux_hide_running) {
            ret = ksu_selinux_hide_enable();
            if (!ret)
                ksu_selinux_hide_running = true;
        }
    } else if (ksu_selinux_hide_running) {
        ret = ksu_selinux_hide_disable();
        if (!ret)
            ksu_selinux_hide_running = false;
    }
    if (ret) {
        /* An incomplete unhook is never reported as a successful disable. */
        ksu_selinux_hide_enabled = ksu_selinux_hide_running || previously_enabled;
    }
    mutex_unlock(&selinux_hide_mutex);
    return ret;
}''',
        'disable_state_and_error_propagation',
    ),
    (
        '''void __exit ksu_selinux_hide_exit()
{
    mutex_lock(&selinux_hide_mutex);
    if (ksu_selinux_hide_running) {
        ksu_selinux_hide_disable();
        ksu_selinux_hide_running = false;
    }
    mutex_unlock(&selinux_hide_mutex);
    ksu_unregister_feature_handler(KSU_FEATURE_SELINUX_HIDE);''',
        '''void __exit ksu_selinux_hide_exit()
{
    int restore_error = 0;
    mutex_lock(&selinux_hide_mutex);
    if (ksu_selinux_hide_running) {
        restore_error = ksu_selinux_hide_disable();
        if (!restore_error)
            ksu_selinux_hide_running = false;
    }
    mutex_unlock(&selinux_hide_mutex);
    if (restore_error) {
        /* Do not free fake_status while a hook may still reference it. */
        pr_err("selinux_hide: exit aborted after hook-restore failure: %d\\n", restore_error);
        return;
    }
    ksu_unregister_feature_handler(KSU_FEATURE_SELINUX_HIDE);''',
        'exit_page_lifetime_guard',
    ),
)

def rewrite_effective_r4(data: bytes, *, enforce_sha: bool = True) -> tuple[bytes, dict]:
    """Pure source transformation. Tests use enforce_sha=False on C fixtures."""
    if enforce_sha:
        demand(sha(data) == R4_EFFECTIVE_BAKASU_SHA256,
               'R4_BAKASU_EFFECTIVE_SOURCE_DRIFT got='+sha(data))
    try:
        before = data.decode('utf-8', errors='strict')
    except UnicodeDecodeError as exc:
        raise UnsafeSource('R4_BAKASU_NOT_UTF8') from exc
    demand('goto call_orig;' in before and 'VEUX 5.4: preserve the stock' in before,
           'R4_5_4_SETPROCATTR_FALLBACK_NOT_PRESENT')
    demand(before.count('static void ksu_selinux_hide_unhook()') == 1,
           'EXPECTED_LEGACY_54_UNHOOK_NOT_UNIQUE')
    target=before
    for old,new,label in REPLACEMENTS:
        demand(old != new and target.count(old)==1,
               'UNHOOK_SOURCE_ANCHOR_DRIFT '+label+' count='+str(target.count(old)))
        target=target.replace(old,new,1)
    demand(target != before, 'NO_UNHOOK_SOURCE_CHANGE')
    # This protects unrelated code from accidental changes in the transformer.
    restored=target
    for old,new,label in reversed(REPLACEMENTS):
        demand(restored.count(new)==1,'UNHOOK_INVERSE_AMBIGUOUS '+label)
        restored=restored.replace(new,old,1)
    demand(restored == before,'UNHOOK_UNRELATED_SOURCE_MUTATION')
    demand(target.count('static int ksu_selinux_hide_unhook()')==1,
           'UNHOOK_RETURN_MISSING')
    demand(target.count('if (ret) {\n        /* An incomplete unhook')==1,
           'UNHOOK_DISABLE_ERROR_GUARD_MISSING')
    demand(target.count('ksu_selinux_hide_running = false;') >= 1,
           'UNHOOK_RUNNING_STATE_LOST')
    payload=target.encode('utf-8')
    return payload, {'before_sha256': sha(data),'after_sha256': sha(payload),
                     'changed_sections':[label for _,_,label in REPLACEMENTS],
                     'r4_effective_source_pinned':enforce_sha,
                     'protects_original_pointers_after_restore_error':True,
                     'reports_error_to_feature_set':True,
                     'preserves_fake_status_when_exit_restore_fails':True,
                     'selinux_enforcing_unchanged':True,
                     'setprocattr_r4_fallback_unchanged':True,
                     'kernel_build':False,'device_pass':False,'promotion':False}

def apply_source_guard(src: Path, report: Path) -> dict:
    """Update *only* one effective C file in the disposable 5.4 worker source."""
    root=src.resolve(strict=True)
    demand(root.name=='kernel', 'NOT_A_DISPOSABLE_KERNEL_SOURCE')
    mk=root/'Makefile'
    demand(mk.is_file() and not mk.is_symlink(),'KERNEL_MAKEFILE_INVALID')
    m=mk.read_text()
    demand(re.search(r'(?m)^VERSION\s*=\s*5\s*$',m) is not None and
           re.search(r'(?m)^PATCHLEVEL\s*=\s*4\s*$',m) is not None,
           'NON_5_4_KERNEL_BLOCKED')
    built=root/'drivers/kernelsu'
    vendor=root/'KernelSU/kernel'
    demand(built.exists() and vendor.is_dir() and
           built.resolve(strict=True)==vendor.resolve(strict=True),
           'INTEGRATED_KERNELSU_TREE_MISMATCH')
    dest=root/RELATIVE
    demand(dest.is_file() and not dest.is_symlink() and
           dest.resolve(strict=True).is_relative_to(root),
           'BAKASU_SOURCE_MISSING_OR_UNSAFE')
    demand(not report.exists() and not report.resolve().is_relative_to(root),
           'REPORT_MUST_BE_OUTSIDE_KERNEL_TREE')
    previous=dest.read_bytes()
    payload,proof=rewrite_effective_r4(previous)
    demand(dest.read_bytes()==previous,'CONCURRENT_BAKASU_SOURCE_CHANGE')
    try:
        dest.write_bytes(payload)
        demand(dest.read_bytes()==payload,'BAKASU_UNHOOK_WRITEBACK_MISMATCH')
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps(proof,indent=2,sort_keys=True)+'\n')
    except Exception:
        if dest.exists() and dest.read_bytes()!=previous:
            dest.write_bytes(previous)
        raise
    print('VEUX_BAKASU_UNHOOK_R1_SOURCE=PASS; KERNEL_BUILD=NO; DEVICE_PASS=NO; NO_SUSFS_UPDATE',flush=True)
    return proof
