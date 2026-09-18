#!/usr/bin/env bash
set -euo pipefail

# VEUX 5.4.292 ReSukiSU + SUSFS 2.3.0 compile V3
# Stage: fail-closed SUSFS backport + inline-hook compile only.
# No AK3 packaging and no device-pass claim in this stage.

SOURCE_REPO="https://github.com/UEDestroyer/kernel_xiaomi_veux.git"
SOURCE_COMMIT="fb3bbb10bc0480282c01b88ccaf39c0145cd9f51"
EXPECTED_KERNEL_VERSION="5.4.292"
DEFCONFIG="veux_defconfig"

RESUKISU_REPO="https://github.com/ReSukiSU/ReSukiSU.git"
RESUKISU_COMMIT="6ec8d9a8a8be30878c388504cacf8ae7849c757b"

DONOR_REPO="https://github.com/JackA1ltman/NonGKI_Kernel_Build_2nd.git"
DONOR_COMMIT="f15603b246d7ce6008af8bdefa0a34b3df28326a"

SUSFS_REPO="https://gitlab.com/simonpunk/susfs4ksu.git"
SUSFS_BRANCH="gki-android13-5.10"
SUSFS_COMMIT="04a9d713106191ba98be680bd7ad9547ab1de964"
EXPECTED_SUSFS_VERSION="v2.3.0"

TOOLCHAIN_COMMIT="d19c99c180cfa21504426915d765b5e7adf878b6"
TOOLCHAIN_DIRNAME="clang-r547379"
TOOLCHAIN_BUILD_ID="13065274"
TOOLCHAIN_ARCHIVE_URL="https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86/+archive/${TOOLCHAIN_COMMIT}/${TOOLCHAIN_DIRNAME}.tar.gz"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INTEGRATOR="$PROJECT_ROOT/lineages/5.4.292/SUSFS_INTEGRATE_V3.py"
INTEGRATOR_EXPECTED_SHA256="30e3fdb83a6af207e07154d38a4e62b4c017dd1defbfcfd40d49de2d09b78027"

WORK_ROOT="${1:-$PROJECT_ROOT/.work/5.4.292-susfs-v3}"
SRC="$WORK_ROOT/kernel"
RS="$WORK_ROOT/ReSukiSU"
DONOR="$WORK_ROOT/NonGKI_Kernel_Build_2nd"
SUSFS="$WORK_ROOT/susfs4ksu"
TC="$WORK_ROOT/$TOOLCHAIN_DIRNAME"
OUT="$WORK_ROOT/out"
RESULTS="$WORK_ROOT/results"
TC_ARCHIVE="$WORK_ROOT/${TOOLCHAIN_DIRNAME}-${TOOLCHAIN_COMMIT}.tar.gz"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: required tool missing: $1" >&2
    exit 10
  }
}

for tool in git curl tar make sha256sum awk grep sed nproc tee wc tr python3; do
  need "$tool"
done

mkdir -p "$WORK_ROOT" "$RESULTS"

[[ -f "$INTEGRATOR" ]] || { echo "ERROR: integrator missing: $INTEGRATOR" >&2; exit 11; }
ACTUAL_INTEGRATOR_SHA256="$(sha256sum "$INTEGRATOR" | awk '{print $1}')"
[[ "$ACTUAL_INTEGRATOR_SHA256" == "$INTEGRATOR_EXPECTED_SHA256" ]] || {
  echo "ERROR: integrator SHA-256 mismatch" >&2
  echo "EXPECTED=$INTEGRATOR_EXPECTED_SHA256" >&2
  echo "ACTUAL=$ACTUAL_INTEGRATOR_SHA256" >&2
  exit 12
}
python3 -m py_compile "$INTEGRATOR"
python3 "$INTEGRATOR" --selftest | tee "$RESULTS/integrator-selftest.txt"
for gate in \
  'DONOR_STATFS_SEMANTIC_FIX=PASS' \
  'UPSTREAM_STATFS_COMPILE_FIX_BACKPORT=PASS' \
  'SUSFS_5_4_CORE_COHERENCE=PASS' \
  'VEUX_DIVERGENT_PREIMAGE_CONTRACT=PASS' \
  'HOOK_SURFACE_PREIMAGE_CONTRACT=PASS' \
  'RESUKISU_IDENTITY_CONTRACT=PASS' \
  'VEUX_DIVERGENT_OUTER_PORT=PASS' \
  'RUN35344193301_REGRESSION=PASS' \
  'RUN35346290137_REGRESSION=PASS' \
  'EXECVEAT_POST_HOOK_REPAIR=PASS' \
  'EXECVEAT_POST_HOOK_SUCCESS_PATH=PASS' \
  'SYS_READ_ABI_REPAIR=PASS' \
  'REBOOT_SUPERCALL_FLOW_REPAIR=PASS' \
  'MODULE_LOAD_FILTER_EXCLUSION=PASS' \
  'DUPLICATE_GUARD=PASS' \
  'SELFTEST=PASS'
do
  grep -Fxq "$gate" "$RESULTS/integrator-selftest.txt" || {
    echo "ERROR: missing integrator selftest gate: $gate" >&2
    exit 13
  }
done

rm -rf "$SRC" "$RS" "$DONOR" "$SUSFS" "$TC" "$OUT"
rm -f "$TC_ARCHIVE"
mkdir -p "$SRC" "$RS" "$DONOR" "$SUSFS" "$TC" "$OUT" "$RESULTS"

fetch_exact_shallow() {
  local dir="$1" repo="$2" commit="$3" label="$4"
  git -C "$dir" init -q
  git -C "$dir" remote add origin "$repo"
  git -C "$dir" fetch -q --depth=1 origin "$commit"
  git -C "$dir" checkout -q --detach FETCH_HEAD
  local actual
  actual="$(git -C "$dir" rev-parse HEAD)"
  [[ "$actual" == "$commit" ]] || { echo "ERROR: $label commit mismatch: $actual" >&2; exit 20; }
  [[ -z "$(git -C "$dir" status --porcelain)" ]] || { echo "ERROR: $label checkout dirty" >&2; exit 21; }
}

echo "=== Fetch exact kernel source ==="
fetch_exact_shallow "$SRC" "$SOURCE_REPO" "$SOURCE_COMMIT" "kernel"

echo "=== Fetch exact full ReSukiSU history ==="
git -C "$RS" init -q
git -C "$RS" remote add origin "$RESUKISU_REPO"
git -C "$RS" fetch -q --tags origin "$RESUKISU_COMMIT"
git -C "$RS" checkout -q --detach FETCH_HEAD
[[ "$(git -C "$RS" rev-parse HEAD)" == "$RESUKISU_COMMIT" ]] || { echo "ERROR: ReSukiSU commit mismatch" >&2; exit 22; }
[[ -z "$(git -C "$RS" status --porcelain)" ]] || { echo "ERROR: ReSukiSU checkout dirty" >&2; exit 23; }
[[ ! -f "$RS/.git/shallow" ]] || { echo "ERROR: ReSukiSU checkout unexpectedly shallow" >&2; exit 24; }

{
  echo "KCONFIG_BLOB=$(git -C "$RS" rev-parse HEAD:kernel/Kconfig)"
  echo "KBUILD_BLOB=$(git -C "$RS" rev-parse HEAD:kernel/Kbuild)"
  echo "INLINE_HOOK_CHECK_BLOB=$(git -C "$RS" rev-parse HEAD:kernel/tools/inline_hook_check.mk)"
  echo "SUSFS_COMPAT_BLOB=$(git -C "$RS" rev-parse HEAD:kernel/tools/susfs_compat.mk)"
  echo "STATIC_EXPORT_CHECK_BLOB=$(git -C "$RS" rev-parse HEAD:kernel/tools/static_export_check.mk)"
  echo "UAPI_SUPERCALL_BLOB=$(git -C "$RS" rev-parse HEAD:uapi/supercall.h)"
} | tee "$RESULTS/resukisu-contract-blobs.txt"
grep -Fxq 'KCONFIG_BLOB=0174d2de5614fefca9c6dec7a31295b2b4d27085' "$RESULTS/resukisu-contract-blobs.txt" || { echo "ERROR: ReSukiSU Kconfig blob drift" >&2; exit 24; }
grep -Fxq 'KBUILD_BLOB=a990e9b120bb74af2cedd5333d5d23574a4bab52' "$RESULTS/resukisu-contract-blobs.txt" || { echo "ERROR: ReSukiSU Kbuild blob drift" >&2; exit 24; }
grep -Fxq 'INLINE_HOOK_CHECK_BLOB=3335953704a513b7b77b47776007b7ca8549bb94' "$RESULTS/resukisu-contract-blobs.txt" || { echo "ERROR: ReSukiSU inline-hook checker blob drift" >&2; exit 24; }
grep -Fxq 'SUSFS_COMPAT_BLOB=904bad1c251314c5addca6dec944f586a9c602e1' "$RESULTS/resukisu-contract-blobs.txt" || { echo "ERROR: ReSukiSU susfs_compat blob drift" >&2; exit 24; }
grep -Fxq 'STATIC_EXPORT_CHECK_BLOB=cc97681f9327e796270f6d33ed3c658a76bd4dbe' "$RESULTS/resukisu-contract-blobs.txt" || { echo "ERROR: ReSukiSU static-export checker blob drift" >&2; exit 24; }
grep -Fxq 'UAPI_SUPERCALL_BLOB=25ab7976aca568a286b500ded32a36c0454f3916' "$RESULTS/resukisu-contract-blobs.txt" || { echo "ERROR: ReSukiSU UAPI blob drift" >&2; exit 24; }
echo "RESUKISU_CHECKER_BLOB_CONTRACT=PASS" | tee -a "$RESULTS/resukisu-contract-blobs.txt"
echo "RESUKISU_UAPI_BLOB_CONTRACT=PASS" | tee -a "$RESULTS/resukisu-contract-blobs.txt"

echo "=== Fetch exact 5.4 donor ==="
fetch_exact_shallow "$DONOR" "$DONOR_REPO" "$DONOR_COMMIT" "donor"

echo "=== Fetch official SUSFS branch and exact pinned commit ==="
git -C "$SUSFS" init -q
git -C "$SUSFS" remote add origin "$SUSFS_REPO"
git -C "$SUSFS" fetch -q --depth=128 origin "refs/heads/$SUSFS_BRANCH"
git -C "$SUSFS" cat-file -e "$SUSFS_COMMIT^{commit}" || {
  echo "ERROR: pinned SUSFS commit is not present in fetched official branch history" >&2
  exit 25
}
git -C "$SUSFS" merge-base --is-ancestor "$SUSFS_COMMIT" FETCH_HEAD || {
  echo "ERROR: pinned SUSFS commit is not an ancestor of official branch $SUSFS_BRANCH" >&2
  exit 25
}
git -C "$SUSFS" checkout -q --detach "$SUSFS_COMMIT"
[[ "$(git -C "$SUSFS" rev-parse HEAD)" == "$SUSFS_COMMIT" ]] || { echo "ERROR: SUSFS commit mismatch" >&2; exit 25; }
[[ -z "$(git -C "$SUSFS" status --porcelain)" ]] || { echo "ERROR: SUSFS checkout dirty" >&2; exit 25; }

grep -Fxq '#define SUSFS_VERSION "v2.3.0"' "$SUSFS/kernel_patches/include/linux/susfs.h" || {
  echo "ERROR: SUSFS upstream version mismatch" >&2
  exit 25
}
echo "SUSFS_OFFICIAL_BRANCH_PIN=PASS" | tee "$RESULTS/susfs-official-pin.txt"

printf '%s\n' \
  "SOURCE_COMMIT=$SOURCE_COMMIT" \
  "RESUKISU_COMMIT=$RESUKISU_COMMIT" \
  "RESUKISU_VERSION=35154" \
  "RESUKISU_UAPI=4" \
  "DONOR_COMMIT=$DONOR_COMMIT" \
  "SUSFS_REPO=$SUSFS_REPO" \
  "SUSFS_BRANCH=$SUSFS_BRANCH" \
  "SUSFS_COMMIT=$SUSFS_COMMIT" \
  "SUSFS_VERSION=$EXPECTED_SUSFS_VERSION" \
  > "$RESULTS/source-pins.txt"

echo "=== Apply fail-closed SUSFS 2.3.0 + ReSukiSU integration ==="
python3 "$INTEGRATOR" "$SRC" "$RS" "$DONOR" "$SUSFS" 2>&1 | tee "$RESULTS/integration.log"
for gate in \
  'SUSFS_HOST_INTEGRATION=PASS' \
  'RESUKISU_GIT_WORKTREE_LAYOUT=PASS' \
  'HOST_DELTA_GUARD=PASS' \
  'RESUKISU_DELTA_GUARD=PASS' \
  'DONOR_STATFS_SEMANTIC_FIX=PASS' \
  'UPSTREAM_STATFS_COMPILE_FIX_BACKPORT=PASS' \
  'SUSFS_5_4_CORE_COHERENCE=PASS' \
  'VEUX_DIVERGENT_PREIMAGE_GATE=PASS' \
  'HOOK_SURFACE_PREIMAGE_GATE=PASS' \
  'VEUX_DIVERGENT_OUTER_PORT=PASS' \
  'RESUKISU_STATIC_KEY_ABI=PASS' \
  'RESUKISU_VERSION=35154' \
  'RESUKISU_UAPI=4' \
  'ARM64_THREAD_INFO_CONTRACT=PASS' \
  'SELINUX_STATIC_EXPORT_CONTRACT=PASS' \
  'RUN35344193301_REGRESSION=PASS' \
  'RUN35346290137_REGRESSION=PASS' \
  'EXECVEAT_POST_HOOK_GATE=PASS' \
  'EXECVEAT_POST_HOOK_SUCCESS_PATH=PASS' \
  'SYS_READ_ABI_GATE=PASS' \
  'REBOOT_SUPERCALL_FLOW_GATE=PASS' \
  'OPEN_REDIRECT_RETRY_FIX=PASS' \
  'SUS_MOUNT_CLONE_RACE_FIX=PASS' \
  'MODULE_LOAD_FILTER=EXCLUDED' \
  'HOOK_MODE=SUSFS_INLINE' \
  'SUSFS_VERSION=v2.3.0' \
  'SUSFS_CODE_BASE=PINNED_5_4_DONOR_PORT' \
  'SUSFS_UPSTREAM_REFERENCE_COMMIT=04a9d713106191ba98be680bd7ad9547ab1de964'
do
  grep -Fxq "$gate" "$RESULTS/integration.log" || {
    echo "ERROR: missing integration gate: $gate" >&2
    exit 26
  }
done

[[ -L "$SRC/drivers/kernelsu" ]] || { echo "ERROR: drivers/kernelsu is not a symlink" >&2; exit 27; }
[[ -d "$SRC/.resukisu/.git" ]] || { echo "ERROR: vendored ReSukiSU git metadata missing" >&2; exit 28; }
[[ "$(git -C "$SRC/.resukisu" rev-parse HEAD)" == "$RESUKISU_COMMIT" ]] || { echo "ERROR: vendored ReSukiSU commit mismatch" >&2; exit 29; }

# Capture identity-critical source inputs after the intentional integration
# delta and before configuration/compilation. The build must not mutate them.
bash "$PROJECT_ROOT/common/scripts/identity_guard.sh" \
  snapshot "$SRC" "$DEFCONFIG" "$RESULTS/identity-before-build.sha256"

if grep -RIn --exclude-dir=.git -E 'module_load_filter|ksu_block_modules|block_modules' \
    "$SRC/.resukisu/kernel" > "$RESULTS/module-filter-scan.txt"; then
  echo "ERROR: module_load_filter references remain" >&2
  cat "$RESULTS/module-filter-scan.txt" >&2
  exit 30
fi
: > "$RESULTS/module-filter-scan.txt"
echo "MODULE_LOAD_FILTER_SCAN=PASS" | tee -a "$RESULTS/module-filter-scan.txt"

echo "=== Fetch exact clang-r547379 ==="
curl --fail --location --retry 3 --retry-delay 2 "$TOOLCHAIN_ARCHIVE_URL" -o "$TC_ARCHIVE"
[[ -s "$TC_ARCHIVE" ]] || { echo "ERROR: toolchain archive missing or empty" >&2; exit 31; }
sha256sum "$TC_ARCHIVE" | tee "$RESULTS/toolchain-archive.sha256"
tar -xzf "$TC_ARCHIVE" -C "$TC"
TC_BIN="$TC/bin"
[[ -x "$TC_BIN/clang" ]] || { echo "ERROR: clang missing" >&2; exit 32; }
[[ -x "$TC_BIN/ld.lld" ]] || { echo "ERROR: ld.lld missing" >&2; exit 33; }
[[ -f "$TC/BUILD_INFO" ]] || { echo "ERROR: BUILD_INFO missing" >&2; exit 34; }
grep -Fq '"bid": "13065274"' "$TC/BUILD_INFO" || { echo "ERROR: unexpected toolchain build id" >&2; exit 35; }
grep -Fq '"branch": "aosp-llvm-r547379-release"' "$TC/BUILD_INFO" || { echo "ERROR: unexpected toolchain branch" >&2; exit 36; }

export PATH="$TC_BIN:$PATH"
export ARCH=arm64
clang --version | tee "$RESULTS/clang-version.txt"
ld.lld --version | tee "$RESULTS/lld-version.txt"

echo "=== Configure VEUX + ReSukiSU SUSFS inline-hook stage ==="
make -C "$SRC" O="$OUT" ARCH=arm64 CC=clang LD=ld.lld LLVM=1 LLVM_IAS=1 "$DEFCONFIG" \
  2>&1 | tee "$RESULTS/defconfig.log"
[[ -f "$OUT/.config" ]] || { echo "ERROR: generated .config missing" >&2; exit 40; }
[[ -x "$SRC/scripts/config" ]] || { echo "ERROR: scripts/config missing or not executable" >&2; exit 41; }

"$SRC/scripts/config" --file "$OUT/.config" \
  --enable KSU \
  --disable KSU_TRACEPOINT_HOOK \
  --disable KSU_MANUAL_HOOK \
  --disable KSU_MANUAL_HOOK_AUTO_SETUID_HOOK \
  --disable KSU_MANUAL_HOOK_AUTO_INITRC_HOOK \
  --disable KSU_MANUAL_HOOK_AUTO_INPUT_HOOK \
  --enable KSU_SUSFS \
  --enable KSU_SUSFS_SUS_PATH \
  --enable KSU_SUSFS_SUS_MOUNT \
  --enable KSU_SUSFS_SUS_KSTAT \
  --enable KSU_SUSFS_SPOOF_UNAME \
  --enable KSU_SUSFS_ENABLE_LOG \
  --enable KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS \
  --enable KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG \
  --enable KSU_SUSFS_OPEN_REDIRECT \
  --enable KSU_SUSFS_SUS_MAP \
  --enable THREAD_INFO_IN_TASK

make -C "$SRC" O="$OUT" ARCH=arm64 CC=clang LD=ld.lld LLVM=1 LLVM_IAS=1 olddefconfig \
  2>&1 | tee "$RESULTS/olddefconfig.log"

for expected in \
  'CONFIG_KSU=y' \
  'CONFIG_KSU_SUSFS=y' \
  'CONFIG_KSU_SUSFS_SUS_PATH=y' \
  'CONFIG_KSU_SUSFS_SUS_MOUNT=y' \
  'CONFIG_KSU_SUSFS_SUS_KSTAT=y' \
  'CONFIG_KSU_SUSFS_SPOOF_UNAME=y' \
  'CONFIG_KSU_SUSFS_ENABLE_LOG=y' \
  'CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS=y' \
  'CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG=y' \
  'CONFIG_KSU_SUSFS_OPEN_REDIRECT=y' \
  'CONFIG_KSU_SUSFS_SUS_MAP=y' \
  'CONFIG_THREAD_INFO_IN_TASK=y' \
  'CONFIG_64BIT=y'
do
  grep -Fxq "$expected" "$OUT/.config" || {
    echo "ERROR: missing config: $expected" >&2
    exit 42
  }
done

grep -Fxq '# CONFIG_KSU_TRACEPOINT_HOOK is not set' "$OUT/.config" || { echo "ERROR: tracepoint hook unexpectedly enabled" >&2; exit 43; }
grep -Fxq '# CONFIG_KSU_MANUAL_HOOK is not set' "$OUT/.config" || { echo "ERROR: manual hook unexpectedly enabled" >&2; exit 44; }

sha256sum "$OUT/.config" | tee "$RESULTS/generated-config.sha256"
grep -E '^CONFIG_KSU|^# CONFIG_KSU' "$OUT/.config" | tee "$RESULTS/ksu-config.txt"

NATIVE_KERNELVERSION="$(make -s -C "$SRC" kernelversion)"
[[ "$NATIVE_KERNELVERSION" == "$EXPECTED_KERNEL_VERSION" ]] || { echo "ERROR: native kernelversion changed" >&2; exit 45; }
KERNELRELEASE_PRE="$(make -s -C "$SRC" O="$OUT" ARCH=arm64 CC=clang LD=ld.lld LLVM=1 LLVM_IAS=1 kernelrelease)"
case "$KERNELRELEASE_PRE" in 5.4.292*) ;; *) echo "ERROR: unexpected prebuild kernelrelease: $KERNELRELEASE_PRE" >&2; exit 46;; esac
printf '%s\n' "$KERNELRELEASE_PRE" | tee "$RESULTS/kernelrelease-prebuild.txt"

echo "=== Compile ReSukiSU + SUSFS 2.3.0 Image ==="
make -C "$SRC" -j"$(nproc)" O="$OUT" \
  ARCH=arm64 \
  CC=clang \
  CLANG_TRIPLE=aarch64-linux-gnu- \
  CROSS_COMPILE=aarch64-linux-gnu- \
  CROSS_COMPILE_ARM32=arm-linux-gnueabi- \
  LD=ld.lld \
  LLVM=1 \
  LLVM_IAS=1 \
  Image \
  2>&1 | tee "$RESULTS/build.log"

IMAGE="$OUT/arch/arm64/boot/Image"
[[ -s "$IMAGE" ]] || { echo "ERROR: Image missing or empty" >&2; exit 50; }
[[ -s "$OUT/fs/susfs.o" ]] || { echo "ERROR: fs/susfs.o missing; SUSFS was not compiled" >&2; exit 51; }

git -C "$SRC" diff --check
git -C "$SRC/.resukisu" diff --check
if find "$SRC" -type f \( -name '*.rej' -o -name '*.orig' \) -print -quit | grep -q .; then
  echo "ERROR: reject/orig files after integration/build" >&2
  exit 52
fi

bash "$PROJECT_ROOT/common/scripts/audit_existing_integration.sh" "$SRC" \
  | tee "$RESULTS/post-build-integration-audit.txt"

# Identity-critical source inputs must remain intact after build.
bash "$PROJECT_ROOT/common/scripts/identity_guard.sh" \
  verify "$SRC" "$DEFCONFIG" "$RESULTS/identity-before-build.sha256" \
  | tee "$RESULTS/identity-after-build.txt"

KERNELRELEASE="$(make -s -C "$SRC" O="$OUT" ARCH=arm64 CC=clang LD=ld.lld LLVM=1 LLVM_IAS=1 kernelrelease)"
case "$KERNELRELEASE" in 5.4.292*) ;; *) echo "ERROR: unexpected final kernelrelease: $KERNELRELEASE" >&2; exit 53;; esac

IMAGE_SHA256="$(sha256sum "$IMAGE" | awk '{print $1}')"
IMAGE_SIZE="$(wc -c < "$IMAGE" | tr -d ' ')"
CONFIG_SHA256="$(sha256sum "$OUT/.config" | awk '{print $1}')"
WARNINGS="$(grep -Ec '(^|[[:space:]])warning:' "$RESULTS/build.log" || true)"
ERRORS="$(grep -Eic '(^|[[:space:]])error:|undefined reference|fatal error:|make(\[[0-9]+\])?: \*\*\*' "$RESULTS/build.log" || true)"
[[ "$ERRORS" == "0" ]] || { echo "ERROR: fatal/error signature count is $ERRORS despite make exit status" >&2; exit 54; }

{
  echo "SUSFS_COMPILE=PASS"
  echo "RESUKISU_COMPILE=PASS"
  echo "HOST_INTEGRATION=PASS"
  echo "RESUKISU_GIT_WORKTREE_LAYOUT=PASS"
  echo "HOST_DELTA_GUARD=PASS"
  echo "RESUKISU_DELTA_GUARD=PASS"
  echo "RESUKISU_CHECKER_BLOB_CONTRACT=PASS"
  echo "RESUKISU_UAPI_BLOB_CONTRACT=PASS"
  echo "DONOR_STATFS_SEMANTIC_FIX=PASS"
  echo "UPSTREAM_STATFS_COMPILE_FIX_BACKPORT=PASS"
  echo "SUSFS_5_4_CORE_COHERENCE=PASS"
  echo "VEUX_DIVERGENT_PREIMAGE_GATE=PASS"
  echo "HOOK_SURFACE_PREIMAGE_GATE=PASS"
  echo "VEUX_DIVERGENT_OUTER_PORT=PASS"
  echo "RESUKISU_STATIC_KEY_ABI=PASS"
  echo "RESUKISU_VERSION=35154"
  echo "RESUKISU_UAPI=4"
  echo "ARM64_THREAD_INFO_CONTRACT=PASS"
  echo "SELINUX_STATIC_EXPORT_CONTRACT=PASS"
  echo "RUN35344193301_REGRESSION=PASS"
  echo "RUN35346290137_REGRESSION=PASS"
  echo "EXECVEAT_POST_HOOK_GATE=PASS"
  echo "EXECVEAT_POST_HOOK_SUCCESS_PATH=PASS"
  echo "SYS_READ_ABI_GATE=PASS"
  echo "REBOOT_SUPERCALL_FLOW_GATE=PASS"
  echo "OPEN_REDIRECT_RETRY_FIX=PASS"
  echo "SUS_MOUNT_CLONE_RACE_FIX=PASS"
  echo "MODULE_LOAD_FILTER=EXCLUDED"
  echo "HOOK_MODE=SUSFS_INLINE"
  echo "SUSFS_VERSION=$EXPECTED_SUSFS_VERSION"
  echo "SUSFS_CODE_BASE=PINNED_5_4_DONOR_PORT"
  echo "SUSFS_UPSTREAM_REFERENCE_COMMIT=$SUSFS_COMMIT"
  echo
  echo "SOURCE_COMMIT=$SOURCE_COMMIT"
  echo "RESUKISU_COMMIT=$RESUKISU_COMMIT"
  echo "DONOR_COMMIT=$DONOR_COMMIT"
  echo "SUSFS_COMMIT=$SUSFS_COMMIT"
  echo "KERNELVERSION=$NATIVE_KERNELVERSION"
  echo "KERNELRELEASE=$KERNELRELEASE"
  echo "DEFCONFIG=$DEFCONFIG"
  echo "CONFIG_SHA256=$CONFIG_SHA256"
  echo "INTEGRATOR_SHA256=$ACTUAL_INTEGRATOR_SHA256"
  echo "WARNINGS=$WARNINGS"
  echo "ERROR_SIGNATURES=$ERRORS"
  echo
  echo "IMAGE=$IMAGE"
  echo "IMAGE_SIZE=$IMAGE_SIZE"
  echo "IMAGE_SHA256=$IMAGE_SHA256"
  echo
  echo "PACKAGE_PASS=NO"
  echo "STATIC_BOOT_PATH_PASS=NO"
  echo "DEVICE_PASS=NO"
} | tee "$RESULTS/SUSFS_RESULT.txt"

(
  cd "$RESULTS"
  find . -type f ! -name SHA256SUMS.txt -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 sha256sum > SHA256SUMS.txt
  sha256sum -c SHA256SUMS.txt
)

echo "SUSFS V3 compile finished successfully."
echo "Result: $RESULTS/SUSFS_RESULT.txt"
