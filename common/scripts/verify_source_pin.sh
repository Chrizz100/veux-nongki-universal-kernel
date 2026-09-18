#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 4 ]] || { echo "Usage: $0 <kernel-root> <expected-commit> <expected-kernelversion> <defconfig-name>" >&2; exit 2; }
ROOT="$(cd "$1" && pwd)"; EXPECTED_COMMIT="$2"; EXPECTED_VERSION="$3"; DEFCONFIG="$4"; DEFCONFIG_PATH="$ROOT/arch/arm64/configs/$DEFCONFIG"
git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo "ERROR: not a git worktree" >&2; exit 10; }
ACTUAL_COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
[[ "$ACTUAL_COMMIT" == "$EXPECTED_COMMIT" ]] || { echo "ERROR: commit mismatch" >&2; exit 11; }
ACTUAL_VERSION="$(make -s -C "$ROOT" kernelversion)"
[[ "$ACTUAL_VERSION" == "$EXPECTED_VERSION" ]] || { echo "ERROR: kernelversion mismatch: $ACTUAL_VERSION" >&2; exit 12; }
[[ -f "$DEFCONFIG_PATH" ]] || { echo "ERROR: defconfig missing" >&2; exit 13; }
echo "SOURCE_PIN=PASS"; echo "COMMIT=$ACTUAL_COMMIT"; echo "KERNELVERSION=$ACTUAL_VERSION"; echo "DEFCONFIG=$DEFCONFIG"; echo "DEFCONFIG_SHA256=$(sha256sum "$DEFCONFIG_PATH"|awk '{print $1}')"
grep '^CONFIG_LOCALVERSION=' "$DEFCONFIG_PATH" | head -n1 || echo "CONFIG_LOCALVERSION=ABSENT"
