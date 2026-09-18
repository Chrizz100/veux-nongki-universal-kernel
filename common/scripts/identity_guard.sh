#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 4 ]] || { echo "Usage: $0 <snapshot|verify> <kernel-root> <defconfig-name> <snapshot-file>" >&2; exit 2; }
MODE="$1"; ROOT="$(cd "$2" && pwd)"; DEFCONFIG="$3"; SNAPSHOT="$4"; [[ "$SNAPSHOT" = /* ]] || SNAPSHOT="$(pwd)/$SNAPSHOT"
collect(){ cd "$ROOT"; { for f in Makefile localversion scripts/setlocalversion "arch/arm64/configs/$DEFCONFIG"; do if [[ -f "$f" ]]; then sha256sum "$f"; else printf 'ABSENT  %s\n' "$f"; fi; done; }|LC_ALL=C sort; }
case "$MODE" in
 snapshot) mkdir -p "$(dirname "$SNAPSHOT")"; collect > "$SNAPSHOT"; echo "IDENTITY_SNAPSHOT=PASS";;
 verify) [[ -f "$SNAPSHOT" ]] || { echo "ERROR: snapshot missing" >&2; exit 10; }; tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT; collect > "$tmp"; diff -u "$SNAPSHOT" "$tmp" >/dev/null || { echo "IDENTITY_GUARD=FAIL" >&2; exit 11; }; echo "IDENTITY_GUARD=PASS";;
 *) exit 2;;
esac
