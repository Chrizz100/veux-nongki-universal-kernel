#!/usr/bin/env python3
"""VEUX 5.4.274: restore verified legacy *validation* before stock setprocattr.

R3 fa12 manual creds/SELinux transition broke Termux. R4 preserved stock
setprocattr, but its unconditional legacy return also removed the backup
policy validation that existed in BakaSU 35222. This is a source-only
candidate; no claim of detector results or device runtime PASS.

Apply *after* BakaSU fa12 + R4 + Unhook R1 + D726. The only edit is the
R4 kernel<5.10 compatibility body. No SUSFS/NoMount pins, vendor modules,
SELinux policy, or kernel Makefile modified.
"""
from __future__ import annotations
import hashlib
import json
import re
from pathlib import Path

# From genuine GitHub run 38447173158, audited BAKASU-CONTEXT-HASH-D726-R3.json.
PINNED_D726_HOOK_SHA256 = '0bcacdecd4579dd48c3dcde89fd9c5c9b9afcf422df6c840ad6116a0b06cd3b8'
TARGET = 'KernelSU/kernel/feature/selinux_hide.c'
OLD = '''#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
    /* VEUX 5.4: preserve the stock, enforcing SELinux process SID transition.
     * The fa12 manual SID/credential path regressed Android app execve on VEUX.
     * This fallback is limited to the legacy kernel; no allow/deny is bypassed.
     */
    goto call_orig;
#endif'''
NEW = r'''#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
    /* VEUX 5.4 source-only parity candidate:
     * Preserve the known-good stock enforcing SID transition (R4), but
     * restore the BakaSU-35222 backup-policy validation *before* calling it.
     * Do not use the fa12 manual prepare_creds/commit_creds path on 5.4.
     * No additional SELinux permission is granted by this check.
     */
    if (size && value && ((char *)value)[0] && ((char *)value)[0] != '\n') {
        char *str = value;
        size_t check_size = size;
        u32 validated_sid = SECSID_NULL;
        int validation_error;

        if (str[check_size - 1] == '\n') {
            str[check_size - 1] = '\0';
            check_size--;
        }
#if defined(KSU_COMPAT_USE_SELINUX_STATE)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0) || defined(KSU_COMPAT_SIDTAB_AS_REFERENCE)
        validation_error = ksu_security_context_to_sid(
            &selinux_state.ss->policydb, selinux_state.ss->sidtab,
            backup_policydb, backup_sidtab, str, check_size,
            &validated_sid, SECSID_NULL, GFP_KERNEL, NULL, NULL);
#else
        validation_error = ksu_security_context_to_sid(
            &selinux_state.ss->policydb, &selinux_state.ss->sidtab,
            backup_policydb, backup_sidtab, str, check_size,
            &validated_sid, SECSID_NULL, GFP_KERNEL, NULL, NULL);
#endif
#else
        validation_error = ksu_security_context_to_sid(
            &policydb, sidtab_ptr, backup_policydb, backup_sidtab,
            str, check_size, &validated_sid, SECSID_NULL,
            GFP_KERNEL, NULL, NULL);
#endif
        if (validation_error) {
            u32 caller_sid = current_sid();
            int permission_error = ksu_avc_has_perm_compat(
                caller_sid, caller_sid, SECCLASS_PROCESS,
                PROCESS__SETCURRENT, NULL);
            return permission_error ? permission_error : validation_error;
        }
    }
    goto call_orig;
#endif'''

class ParityBlocked(RuntimeError):
    pass

def require(cond: bool, message: str) -> None:
    if not cond:
        raise ParityBlocked(message)

def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def rewrite(data: bytes, *, exact_pin: bool = True) -> tuple[bytes, dict]:
    """Pure, reversible, one-hunk edit of the *effective* pinned C source."""
    if exact_pin:
        require(digest(data)==PINNED_D726_HOOK_SHA256,
                'D726_EFFECTIVE_HOOK_SHA_DRIFT expected='+PINNED_D726_HOOK_SHA256+' got='+digest(data))
    try:
        src=data.decode('utf-8',errors='strict')
    except UnicodeDecodeError as exc:
        raise ParityBlocked('NON_UTF8_BAKASU_SOURCE') from exc
    require(src.count(OLD)==1, 'R4_LEGACY_FALLBACK_NOT_UNIQUE_OR_MISSING')
    require('ksu_security_context_to_sid(' in src,
            'FA12_BACKUP_POLICY_PARSER_NOT_PRESENT')
    require('context_add_hash(' in src,
            'D726_CONTEXT_ADD_HASH_FIX_NOT_PRESENT')
    require('static int ksu_selinux_hide_unhook()' in src,
            'UNHOOK_R1_FIX_NOT_PRESENT')
    updated=src.replace(OLD,NEW,1)
    require(updated.count(NEW)==1 and updated.replace(NEW,OLD,1)==src,
            'NONREVERSIBLE_OR_UNRELATED_PATCH')
    require(updated.count('goto call_orig;')==src.count('goto call_orig;'),
            'STOCK_RUNTIME_FALLBACK_MISSING')
    require(updated.count('commit_creds(new);')==src.count('commit_creds(new);'),
            'FA12_OTHER_CODE_DRIFT')
    require(updated.count('context_add_hash(')==src.count('context_add_hash('),
            'D726_POLICY_HASH_DRIFT')
    result=updated.encode('utf-8')
    proof={'schema':1,'scope':'Linux 5.4.274 only, source-only candidate',
           'before_sha256':digest(data),'after_sha256':digest(result),
           'pinned_from_run':38447173158,
           'paths_changed':[TARGET],
           'policy_validation_before_stock_handler':True,
           'stock_setprocattr_runtime_callback_retained':True,
           'original_5_4_R4_fallback_preserved':True,
           'fa12_manual_credential_change_not_used_in_5_4_path':True,
           'd726_hash_calls_preserved':True,
           'no_susfs_pin_update':True,'no_root_promotion':True,
           'kernel_build':False,'device_pass':False,
           'detector_pass_claimed':False}
    return result,proof

def apply_legacy_policy_parity(src: Path, report: Path) -> dict:
    root=src.resolve(strict=True)
    require(root.name=='kernel', 'NOT_A_KERNEL_SOURCE_ROOT')
    makefile=root/'Makefile'
    require(makefile.is_file() and not makefile.is_symlink(), 'KERNEL_MAKEFILE_MISSING')
    text=makefile.read_text()
    require(bool(re.search(r'^VERSION\s*=\s*5\s*$',text,re.M)) and
            bool(re.search(r'^PATCHLEVEL\s*=\s*4\s*$',text,re.M)),
            'KERNEL_NOT_5_4')
    actual=root/TARGET
    require(actual.is_file() and not actual.is_symlink() and
            actual.resolve(strict=True).is_relative_to(root),
            'UNSAFE_OR_MISSING_BAKASU_SOURCE')
    require(not report.exists() and not report.is_symlink() and
            not report.resolve().is_relative_to(root),
            'UNSAFE_REPORT_LOCATION')
    previous=actual.read_bytes()
    candidate,proof=rewrite(previous,exact_pin=True)
    require(actual.read_bytes()==previous,'CONCURRENT_SOURCE_CHANGE')
    try:
        actual.write_bytes(candidate)
        require(actual.read_bytes()==candidate,'SOURCE_WRITE_VERIFY_FAILED')
        report.parent.mkdir(parents=True,exist_ok=True)
        report.write_text(json.dumps(proof,indent=2,sort_keys=True)+'\n')
    except BaseException:
        if actual.is_file() and actual.read_bytes()!=previous:
            actual.write_bytes(previous)
        raise
    print('VEUX_54_SELINUX_BACKUP_POLICY_PARITY=SOURCE_STAGED; '
          'STOCK_SETPROCATTR=RETAINED; R4_RUNTIME=RETAINED; '
          'KERNEL_BUILD=NO; DEVICE_PASS=NO',flush=True)
    return proof
