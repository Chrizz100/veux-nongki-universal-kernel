#!/usr/bin/env bash
set -euo pipefail

EXPECT_CLEAN=0
if [[ "${1:-}" == "--expect-clean" ]]; then
  EXPECT_CLEAN=1
  shift
fi

[[ $# -eq 1 ]] || {
  echo "Usage: $0 [--expect-clean] <kernel-root>" >&2
  exit 2
}

ROOT="$(cd "$1" && pwd)"
cd "$ROOT"

ksu_dirs=0
for d in KernelSU drivers/kernelsu kernel/kernelsu; do
  [[ -e "$d" ]] && ksu_dirs=$((ksu_dirs + 1))
done

ksu_kconfig_refs="$({
  [[ -d drivers ]] && grep -RIn --exclude-dir=.git --exclude-dir=out --exclude-dir='out-*' \
    -E 'source[[:space:]]+"(drivers/)?kernelsu/Kconfig"|source[[:space:]]+".*KernelSU.*Kconfig"' drivers 2>/dev/null || :
  [[ -f Kconfig ]] && grep -nE \
    'source[[:space:]]+"(drivers/)?kernelsu/Kconfig"|source[[:space:]]+".*KernelSU.*Kconfig"' Kconfig 2>/dev/null || :
} | wc -l)"

ksu_make_refs="$({
  [[ -d drivers ]] && grep -RIn --exclude-dir=.git --exclude-dir=out --exclude-dir='out-*' \
    -E 'CONFIG_KSU.*(kernelsu|KernelSU)|obj-\$\(CONFIG_KSU\)' drivers 2>/dev/null || :
  [[ -f Makefile ]] && grep -nE 'CONFIG_KSU.*(kernelsu|KernelSU)|obj-\$\(CONFIG_KSU\)' Makefile 2>/dev/null || :
} | wc -l)"

susfs_files=0
for f in fs/susfs.c include/linux/susfs.h include/linux/susfs_def.h; do
  [[ -e "$f" ]] && susfs_files=$((susfs_files + 1))
done

susfs_symbols="$({
  for d in fs include kernel security; do
    [[ -e "$d" ]] && grep -RIl --exclude-dir=.git --exclude-dir=out --exclude-dir='out-*' \
      -E 'CONFIG_KSU_SUSFS|susfs_|SUSFS_' "$d" 2>/dev/null || :
  done
} | sort -u | wc -l)"

module_filter="$({
  for d in KernelSU drivers kernel; do
    [[ -e "$d" ]] && grep -RIl --exclude-dir=.git --exclude-dir=out --exclude-dir='out-*' \
      -E 'module_load_filter|ksu_block_modules|block_modules' "$d" 2>/dev/null || :
  done
} | sort -u | wc -l)"

echo "KSU_DIR_COUNT=$ksu_dirs"
echo "KSU_KCONFIG_REFERENCE_COUNT=$ksu_kconfig_refs"
echo "KSU_MAKE_REFERENCE_COUNT=$ksu_make_refs"
echo "SUSFS_CORE_FILE_COUNT=$susfs_files"
echo "SUSFS_SYMBOL_FILE_COUNT=$susfs_symbols"
echo "MODULE_LOAD_FILTER_FILE_COUNT=$module_filter"

conflict=0
if (( ksu_dirs > 1 )); then
  echo "ERROR: multiple KernelSU directory candidates detected" >&2
  conflict=1
fi
if (( ksu_kconfig_refs > 1 )); then
  echo "ERROR: multiple KernelSU Kconfig references detected" >&2
  conflict=1
fi
if (( module_filter > 0 )); then
  echo "ERROR: excluded module_load_filter contract detected" >&2
  conflict=1
fi
if (( EXPECT_CLEAN == 1 )); then
  if (( ksu_dirs > 0 || ksu_kconfig_refs > 0 || ksu_make_refs > 0 || susfs_files > 0 || susfs_symbols > 0 )); then
    echo "ERROR: target is not clean for a fresh integration" >&2
    conflict=1
  fi
fi

if (( conflict != 0 )); then
  echo "AUDIT_EXISTING_INTEGRATION=FAIL"
  exit 20
fi

echo "AUDIT_EXISTING_INTEGRATION=PASS"
