#!/usr/bin/env bash
set -euo pipefail

# VEUX 5.4.292 native baseline build V3
# No ReSukiSU, no SUSFS, no lineage patches, no AnyKernel3 packaging.
# Fail-closed and identity-preserving.

SOURCE_REPO="https://github.com/UEDestroyer/kernel_xiaomi_veux.git"
SOURCE_COMMIT="fb3bbb10bc0480282c01b88ccaf39c0145cd9f51"
EXPECTED_KERNEL_VERSION="5.4.292"
DEFCONFIG="veux_defconfig"

TOOLCHAIN_COMMIT="d19c99c180cfa21504426915d765b5e7adf878b6"
TOOLCHAIN_DIRNAME="clang-r547379"
TOOLCHAIN_BUILD_ID="13065274"
TOOLCHAIN_LLVM_PROJECT_REVISION="b718bcaf8c198c82f3021447d943401e3ab5bd54"
TOOLCHAIN_ARCHIVE_URL="https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86/+archive/${TOOLCHAIN_COMMIT}/${TOOLCHAIN_DIRNAME}.tar.gz"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK_ROOT="${1:-$PROJECT_ROOT/.work/5.4.292-baseline-v3}"
SRC="$WORK_ROOT/kernel"
TC="$WORK_ROOT/$TOOLCHAIN_DIRNAME"
OUT="$WORK_ROOT/out"
RESULTS="$WORK_ROOT/results"
TC_ARCHIVE="$WORK_ROOT/${TOOLCHAIN_DIRNAME}-${TOOLCHAIN_COMMIT}.tar.gz"

mkdir -p "$WORK_ROOT" "$RESULTS"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: required tool missing: $1" >&2
    exit 10
  }
}

for tool in git curl tar make sha256sum awk grep sed nproc tee wc tr; do
  need "$tool"
done

echo "=== VEUX 5.4.292 NATIVE BASELINE V3 ==="
echo "SOURCE_REPO=$SOURCE_REPO"
echo "SOURCE_COMMIT=$SOURCE_COMMIT"
echo "EXPECTED_KERNEL_VERSION=$EXPECTED_KERNEL_VERSION"
echo "DEFCONFIG=$DEFCONFIG"
echo "TOOLCHAIN_COMMIT=$TOOLCHAIN_COMMIT"
echo "TOOLCHAIN_DIRNAME=$TOOLCHAIN_DIRNAME"
echo "TOOLCHAIN_BUILD_ID=$TOOLCHAIN_BUILD_ID"
echo "TOOLCHAIN_LLVM_PROJECT_REVISION=$TOOLCHAIN_LLVM_PROJECT_REVISION"

rm -rf "$SRC" "$TC" "$OUT"
rm -f "$TC_ARCHIVE"
mkdir -p "$SRC" "$TC" "$OUT" "$RESULTS"

echo
echo "=== Fetch exact kernel source ==="
git -C "$SRC" init -q
git -C "$SRC" remote add origin "$SOURCE_REPO"
git -C "$SRC" fetch -q --depth=1 origin "$SOURCE_COMMIT"
git -C "$SRC" checkout -q --detach FETCH_HEAD

ACTUAL_SOURCE_COMMIT="$(git -C "$SRC" rev-parse HEAD)"
[[ "$ACTUAL_SOURCE_COMMIT" == "$SOURCE_COMMIT" ]] || {
  echo "ERROR: kernel source commit mismatch" >&2
  exit 20
}

[[ -z "$(git -C "$SRC" status --porcelain)" ]] || {
  echo "ERROR: kernel source checkout is not clean" >&2
  exit 21
}

echo
echo "=== Verify source pin with common gate ==="
bash "$PROJECT_ROOT/common/scripts/verify_source_pin.sh" \
  "$SRC" \
  "$SOURCE_COMMIT" \
  "$EXPECTED_KERNEL_VERSION" \
  "$DEFCONFIG" \
  | tee "$RESULTS/source-pin.txt"

echo
echo "=== Verify clean pre-integration state ==="
bash "$PROJECT_ROOT/common/scripts/audit_existing_integration.sh" \
  --expect-clean \
  "$SRC" \
  | tee "$RESULTS/pre-integration-audit.txt"

echo
echo "=== Snapshot native identity ==="
bash "$PROJECT_ROOT/common/scripts/identity_guard.sh" \
  snapshot \
  "$SRC" \
  "$DEFCONFIG" \
  "$RESULTS/identity-before.sha256"

echo
echo "=== Fetch exact clang-r547379 subdirectory archive ==="
curl --fail --location --retry 3 --retry-delay 2 \
  "$TOOLCHAIN_ARCHIVE_URL" \
  -o "$TC_ARCHIVE"

[[ -s "$TC_ARCHIVE" ]] || {
  echo "ERROR: toolchain archive missing or empty" >&2
  exit 30
}

sha256sum "$TC_ARCHIVE" | tee "$RESULTS/toolchain-archive.sha256"
tar -xzf "$TC_ARCHIVE" -C "$TC"

TC_BIN="$TC/bin"

[[ -x "$TC_BIN/clang" ]] || {
  echo "ERROR: clang missing: $TC_BIN/clang" >&2
  exit 31
}
[[ -x "$TC_BIN/ld.lld" ]] || {
  echo "ERROR: ld.lld missing: $TC_BIN/ld.lld" >&2
  exit 32
}
[[ -f "$TC/BUILD_INFO" ]] || {
  echo "ERROR: BUILD_INFO missing from toolchain archive" >&2
  exit 33
}

grep -Fq '"bid": "13065274"' "$TC/BUILD_INFO" || {
  echo "ERROR: unexpected toolchain BUILD_INFO build id" >&2
  exit 34
}
grep -Fq '"branch": "aosp-llvm-r547379-release"' "$TC/BUILD_INFO" || {
  echo "ERROR: unexpected toolchain BUILD_INFO branch" >&2
  exit 35
}

sha256sum "$TC/BUILD_INFO" | tee "$RESULTS/toolchain-build-info.sha256"

export PATH="$TC_BIN:$PATH"
export ARCH=arm64

clang --version | tee "$RESULTS/clang-version.txt"
ld.lld --version | tee "$RESULTS/lld-version.txt"

clang --version | grep -Eq 'clang version 20\.0\.0|Android .*clang version 20\.0\.0' || {
  echo "ERROR: clang 20.0.0 not confirmed" >&2
  exit 36
}

echo
echo "=== Configure untouched VEUX source ==="
make -C "$SRC" O="$OUT" ARCH=arm64 \
  CC=clang LD=ld.lld LLVM=1 LLVM_IAS=1 \
  "$DEFCONFIG" \
  2>&1 | tee "$RESULTS/defconfig.log"

[[ -f "$OUT/.config" ]] || {
  echo "ERROR: generated .config missing" >&2
  exit 40
}

sha256sum "$SRC/arch/arm64/configs/$DEFCONFIG" \
  | tee "$RESULTS/defconfig-source.sha256"
sha256sum "$OUT/.config" \
  | tee "$RESULTS/generated-config.sha256"

NATIVE_KERNELVERSION="$(make -s -C "$SRC" kernelversion)"
[[ "$NATIVE_KERNELVERSION" == "$EXPECTED_KERNEL_VERSION" ]] || {
  echo "ERROR: native kernelversion changed" >&2
  exit 41
}

PREBUILD_KERNELRELEASE="$(
  make -s -C "$SRC" O="$OUT" ARCH=arm64 \
    CC=clang LD=ld.lld LLVM=1 LLVM_IAS=1 \
    kernelrelease
)"
case "$PREBUILD_KERNELRELEASE" in
  5.4.292*) ;;
  *)
    echo "ERROR: unexpected prebuild kernelrelease: $PREBUILD_KERNELRELEASE" >&2
    exit 42
    ;;
esac
printf '%s\n' "$PREBUILD_KERNELRELEASE" | tee "$RESULTS/kernelrelease-prebuild.txt"

echo
echo "=== Compile untouched 5.4.292 baseline ==="
# Important: do not use the source tree's default "all" target here.
# With CONFIG_BUILD_ARM64_DT_OVERLAY=y this lineage appends dtbo.img/dtb.img,
# while its arch/arm64/boot/Makefile has no dtbo.img build rule.
# For the native kernel baseline we intentionally build the kernel Image target.
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

[[ -s "$IMAGE" ]] || {
  echo "ERROR: kernel Image missing or empty" >&2
  exit 50
}

echo
echo "=== Verify identity and clean source after build ==="
bash "$PROJECT_ROOT/common/scripts/identity_guard.sh" \
  verify \
  "$SRC" \
  "$DEFCONFIG" \
  "$RESULTS/identity-before.sha256" \
  | tee "$RESULTS/identity-after.txt"

[[ -z "$(git -C "$SRC" status --porcelain)" ]] || {
  echo "ERROR: source worktree changed during baseline build" >&2
  git -C "$SRC" status --short >&2
  exit 51
}

KERNELRELEASE="$(
  make -s -C "$SRC" O="$OUT" ARCH=arm64 \
    CC=clang LD=ld.lld LLVM=1 LLVM_IAS=1 \
    kernelrelease
)"
case "$KERNELRELEASE" in
  5.4.292*) ;;
  *)
    echo "ERROR: unexpected final kernelrelease: $KERNELRELEASE" >&2
    exit 52
    ;;
esac

IMAGE_SHA256="$(sha256sum "$IMAGE" | awk '{print $1}')"
IMAGE_SIZE="$(wc -c < "$IMAGE" | tr -d ' ')"
DEFCONFIG_SHA256="$(sha256sum "$SRC/arch/arm64/configs/$DEFCONFIG" | awk '{print $1}')"
TC_ARCHIVE_SHA256="$(sha256sum "$TC_ARCHIVE" | awk '{print $1}')"
TC_BUILD_INFO_SHA256="$(sha256sum "$TC/BUILD_INFO" | awk '{print $1}')"

{
  echo "BASELINE_COMPILE=PASS"
  echo "BASELINE_TARGET=Image"
  echo "DEFAULT_ALL_DTBO_TARGET=INTENTIONALLY_NOT_USED"
  echo "SOURCE_PIN=PASS"
  echo "EXISTING_INTEGRATION_AUDIT=PASS"
  echo "DEFCONFIG=PASS"
  echo "IMAGE_PRESENT=PASS"
  echo "KERNELRELEASE_NATIVE_5_4_292=PASS"
  echo "IDENTITY_GUARD=PASS"
  echo
  echo "SOURCE_REPO=$SOURCE_REPO"
  echo "SOURCE_COMMIT=$ACTUAL_SOURCE_COMMIT"
  echo "KERNELVERSION=$NATIVE_KERNELVERSION"
  echo "KERNELRELEASE=$KERNELRELEASE"
  echo "DEFCONFIG=$DEFCONFIG"
  echo "DEFCONFIG_SHA256=$DEFCONFIG_SHA256"
  echo
  echo "TOOLCHAIN_NAME=$TOOLCHAIN_DIRNAME"
  echo "TOOLCHAIN_CANONICAL_COMMIT=$TOOLCHAIN_COMMIT"
  echo "TOOLCHAIN_BUILD_ID=$TOOLCHAIN_BUILD_ID"
  echo "TOOLCHAIN_LLVM_PROJECT_REVISION=$TOOLCHAIN_LLVM_PROJECT_REVISION"
  echo "TOOLCHAIN_ARCHIVE_SHA256=$TC_ARCHIVE_SHA256"
  echo "TOOLCHAIN_BUILD_INFO_SHA256=$TC_BUILD_INFO_SHA256"
  echo
  echo "IMAGE=$IMAGE"
  echo "IMAGE_SIZE=$IMAGE_SIZE"
  echo "IMAGE_SHA256=$IMAGE_SHA256"
  echo
  echo "RESUKISU=NOT_PRESENT"
  echo "SUSFS=NOT_PRESENT"
  echo "LINEAGE_PATCHES=NONE"
  echo "PACKAGE=NOT_CREATED"
  echo "STATIC_BOOT_PATH=NOT_RUN"
  echo "DEVICE_PASS=NO"
} | tee "$RESULTS/BASELINE_RESULT.txt"

echo
echo "=== Result manifest ==="
(
  cd "$RESULTS"
  find . -type f ! -name SHA256SUMS.txt -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 sha256sum > SHA256SUMS.txt
  sha256sum -c SHA256SUMS.txt
)

echo
echo "Baseline V3 compile finished successfully."
echo "Result: $RESULTS/BASELINE_RESULT.txt"
