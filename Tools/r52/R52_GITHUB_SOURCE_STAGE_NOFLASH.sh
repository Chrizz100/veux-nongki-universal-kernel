#!/usr/bin/env bash
# Execute only on a manually selected GitHub Ubuntu Actions runner.
# Validates genuine BakaSU replay and generates a partial native 5.4 SUSFS patch.
# NO KERNEL BUILD / NO FLASH / NO WRITE TO REPO.
set -Eeuo pipefail
umask 077
fail() { printf 'R52_STAGE_BLOCKED=%s\n' "$1" >&2; exit 3; }
: "${GITHUB_WORKSPACE:?Missing workspace}"
: "${RUNNER_TEMP:?Missing runner temp}"
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_OS:-}" == Linux ]] || fail NON_GITHUB_RUNNER
[[ "${GITHUB_REPOSITORY:-}" == 'Chrizz100/veux-nongki-universal-kernel' ]] || fail WRONG_REPOSITORY
[[ "${GITHUB_REF:-}" == refs/heads/main ]] || fail WRONG_REF
REPO="$GITHUB_WORKSPACE"
[[ "$(git -C "$REPO" rev-parse HEAD)" == "${GITHUB_SHA:-}" ]] || fail CHECKOUT_COMMIT_CHANGED
[[ -z "$(git -C "$REPO" status --porcelain --untracked-files=all)" ]] || fail REPO_DIRTY
R41="$REPO/VEUX_R41_NOMOUNT_SOURCE_MAIN.zip"
[[ -f "$R41" && ! -L "$R41" ]] || fail R41_MISSING
printf '%s  %s\n' 'e9ea57fc1feb8d4d0e840a61b21174ad1d83d496216794bd9285b40f17026bff' "$R41" | sha256sum -c --strict || fail R41_SHA_MISMATCH
T="$REPO/tools/r52"
for item in R51_BAKASU_REPLAY_NOFLASH.py R51_SELFTEST.py R51_SUSFS_NATIVE54_SOURCE_GATE.py r52_native54_susfs_port.py; do
    [[ -f "$T/$item" && ! -L "$T/$item" ]] || fail MISSING_SCRIPT
    python3 -I - "$T/$item" <<'PY_R52_AST' || fail SCRIPT_SYNTAX
import ast, pathlib, sys
p=pathlib.Path(sys.argv[1]); ast.parse(p.read_text(),filename=str(p))
PY_R52_AST
 done
STAGE=$(mktemp -d "$RUNNER_TEMP/veux-r52-XXXXXX")
export R51_R41_PACKAGE="$R41" R52_R41_PATH="$R41"
python3 -B "$T/R51_SELFTEST.py" > "$STAGE/R51_SELFTEST_LOG.txt" 2>&1 || fail R51_SELFTEST_FAILED
python3 -B -m unittest discover -s "$REPO/tests/r52" -p 'test_r52_native54.py' -v > "$STAGE/R52_SELFTEST_LOG.txt" 2>&1 || fail R52_SELFTEST_FAILED
# GitLab must be genuinely reachable. An outdated snapshot is not build-ready.
SUSFS=$(timeout 60 git ls-remote https://gitlab.com/simonpunk/susfs4ksu.git refs/heads/gki-android13-5.10) || fail GITLAB_FETCH_FAILED
[[ "${SUSFS%%$'\t'*}" == '937232ce8c4bdcbe4216e99a1b3d7b5cf633f7c6' ]] || fail SUSFS_HEAD_ADVANCED_REVIEW_REQUIRED
BAKA=$(timeout 60 git ls-remote https://github.com/Baka-SU/BakaSU.git refs/heads/main) || fail BAKASU_REF_UNAVAILABLE
[[ "${BAKA%%$'\t'*}" == '516d3e87fbc986ccefdde2c2765f1700612441a9' ]] || fail BAKASU_HEAD_ADVANCED_REVIEW_REQUIRED
# Isolate all Git objects, especially the user-preserved local CASS port.
python3 -I - "$R41" "$STAGE/r13.bundle" <<'PY_R52_BUNDLE'
from pathlib import Path
from zipfile import ZipFile
import hashlib,sys
z=ZipFile(sys.argv[1]); p=Path(sys.argv[2]); data=z.read('r13/data/BAKASU_R13.bundle')
assert hashlib.sha256(data).hexdigest()=='ea9ba0a45d6cc1ea985268ba9cd886f847e1fb4965a2df665518dfd1f4b83b57'
p.write_bytes(data)
print('R52_R13_BAKASU_BUNDLE=VERIFIED')
PY_R52_BUNDLE
# Full Git history needed to prove the real version number; do not use shallow clone.
git clone --quiet --no-tags https://github.com/Baka-SU/BakaSU.git "$STAGE/official"
[[ "$(git -C "$STAGE/official" rev-parse HEAD)" == '516d3e87fbc986ccefdde2c2765f1700612441a9' ]] || fail BAKASU_CLONE_DRIFT
git clone --quiet --no-hardlinks "$STAGE/official" "$STAGE/local"
git -C "$STAGE/local" fetch --no-tags --quiet "$STAGE/r13.bundle" refs/heads/veux-r13-selinux54
git -C "$STAGE/local" checkout --quiet --detach d2537b13ab15fce72e8c0d99e7788805f071aeb4
python3 -B "$T/R51_BAKASU_REPLAY_NOFLASH.py" \
 --local-port "$STAGE/local" --upstream "$STAGE/official" \
 --output "$STAGE/BAKASU_CANDIDATE_UNBUILT" --r41 "$R41" \
 --receipt "$STAGE/R52_BAKASU_REAL_REPLAY.json" || fail BAKASU_REAL_GIT_REPLAY_FAILED
# The source candidate MUST return a non-zero intentional gate (2) until the
# 5.4 SELinux/KernelSU host hooks, headers and their compiler checks exist.
set +e
python3 -B "$T/r52_native54_susfs_port.py" \
 --r41 "$R41" --repository "$REPO" --output "$STAGE/R52_PARTIAL_SUSFS_PORT"
rc=$?
set -e
[[ "$rc" -eq 2 ]] || fail SUSFS_EXPECTED_PARTIAL_GATE_NOT_MET
python3 -I - "$STAGE" <<'PY_R52_VALIDATE'
import json,sys
from pathlib import Path
p=Path(sys.argv[1]); s=json.loads((p/'R52_PARTIAL_SUSFS_PORT/R52_SOURCE_RECEIPT.json').read_text())
b=json.loads((p/'R52_BAKASU_REAL_REPLAY.json').read_text())
assert s['status']=='PINNED_SOURCE_PARTIAL_NATIVE54_PORT_PASS__SELINUX_HOST_GATES_BLOCKED__NO_BUILD_NO_FLASH'
assert all(v is False for v in s['gates'].values())
assert b['genuine_git_commit_count']==4559 and b['calculated_source_version']==35259
assert b['kernel_compiled'] is False and b['flash_allowed'] is False
receipt={'schema':'VEUX_R52_REAL_SOURCE_STAGING_V1','status':'PINNED_BAKASU_REPLAY_PASS__SUSFS_NATIVE54_HOST_HOOKS_BLOCKED__NO_KERNEL_BUILD_NO_FLASH',
 'bakasu_commit':b['result_commit'],'bakasu_tree':b['result_tree'],'bakasu_version':35259,
 'susfs_commit':s['official_head'],'susfs_partial_candidate_sha256':s['native54_partial_candidate_sha256'],
 'source_integration_partially_complete':True,'kernel_compiled':False,'flash_allowed':False,'build_allowed':False}
(p/'R52_STAGE_RECEIPT.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
print(receipt['status'])
PY_R52_VALIDATE
[[ -z "$(git -C "$REPO" status --porcelain --untracked-files=all)" ]] || fail REPOSITORY_CHANGED
printf 'R52_SOURCE_STAGE=DIAGNOSTIC_PASS\nR52_KERNEL_BUILD_ALLOWED=NO\nR52_FLASH_ALLOWED=NO\nR52_REPORT_DIRECTORY=%s\n' "$STAGE"
