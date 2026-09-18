#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 2 ]] || { echo "Usage: $0 <kernel-root> <patch-file>" >&2; exit 2; }
ROOT="$(cd "$1" && pwd)"; PATCH="$(realpath "$2")"
[[ -s "$PATCH" ]] || { echo "ERROR: patch missing/empty" >&2; exit 10; }
git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo "ERROR: not a git worktree" >&2; exit 11; }
cd "$ROOT"
if find . -type f \( -name '*.rej' -o -name '*.orig' \) -print -quit | grep -q .; then echo "ERROR: pre-existing reject/orig files" >&2; exit 12; fi
git apply --check --whitespace=error --binary "$PATCH"
git apply --whitespace=error --binary "$PATCH"
git diff --check
if find . -type f \( -name '*.rej' -o -name '*.orig' \) -print -quit | grep -q .; then echo "ERROR: reject/orig files after patch" >&2; exit 13; fi
echo "STRICT_PATCH_APPLY=PASS"; echo "PATCH=$(basename "$PATCH")"; echo "PATCH_SHA256=$(sha256sum "$PATCH"|awk '{print $1}')"
