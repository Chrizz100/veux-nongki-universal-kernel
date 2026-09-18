#!/usr/bin/env bash
set -euo pipefail

# VEUX 5.4.292 native baseline build
# No ReSukiSU, no SUSFS, no AnyKernel3 packaging, no source patching.

SOURCE_REPO="https://github.com/UEDestroyer/kernel_xiaomi_veux.git"
SOURCE_COMMIT="fb3bbb10bc0480282c01b88ccaf39c0145cd9f51"
EXPECTED_KERNEL_VERSION="5.4.292"
DEFCONFIG="veux_defconfig"

TOOLCHAIN_REPO="https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86"
TOOLCHAIN_COMMIT="b2f65ea82667366e23657e4999751180e4030f5b"
TOOLCHAIN_DIRNAME="clang-r547379"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK_ROOT="${1:-$PROJECT_ROOT/.work/5.4.292-baseline}"
SRC="$WORK_ROOT/kernel"
TC_REPO="$WORK_ROOT/aosp-clang"
TC_BIN="$TC_REPO/$TOOLCHAIN_DIRNAME/bin"
OUT="$WORK_ROOT/out"
RESULTS="$WORK_ROOT/results"

mkdir -p "$WORK_ROOT" "$RESULTS"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: required tool missing: $1" >&2
    exit 10
  }
}

for tool in git make sha256sum awk grep sed nproc tee; do
  need "$tool"
done

echo "=== VEUX 5.4.292 NATIVE BASELINE ==="
echo "SOURCE_REPO=$SOURCE_REPO"
echo "SOURCE_COMMIT=$SOURCE_COMMIT"
echo "EXPECTED_KERNEL_VERSION=$EXPECTED_KERNEL_VERSION"
echo "DEFCONFIG=$DEFCONFIG"
echo "TOOLCHAIN_REPO=$TOOLCHAIN_REPO"
echo "TOOLCHAIN_COMMIT=$TOOLCHAIN_COMMIT"
echo "TOOLCHAIN_DIRNAME=$TOOLCHAIN_DIRNAME"

rm -rf "$SRC" "$TC_REPO" "$OUT"

echo
echo "=== Fetch exact kernel source ==="
git init -q "$SRC"
git -C "$SRC" remote add origin "$SOURCE_REPO"
git -C "$SRC" fetch --depth=1 origin "$SOURCE_COMMIT"
git -C "$SRC" checkout -q --detach FETCH_HEAD

ACTUAL_SOURCE_COMMIT="$(git -C "$SRC" rev-parse HEAD)"
[[ "$ACTUAL_SOURCE_COMMIT" == "$SOURCE_COMMIT" ]] || {
  echo "ERROR: kernel source commit mismatch" >&2
  exit 20
}

echo
echo "=== Verify source pin with project common gate ==="
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
echo "=== Fetch exact AOSP clang revision ==="
git init -q "$TC_REPO"
git -C "$TC_REPO" remote add origin "$TOOLCHAIN_REPO"
git -C "$TC_REPO" config core.sparseCheckout true
printf '/%s/\n' "$TOOLCHAIN_DIRNAME" > "$TC_REPO/.git/info/sparse-checkout"
git -C "$TC_REPO" fetch --depth=1 origin "$TOOLCHAIN_COMMIT"
git -C "$TC_REPO" checkout -q --detach FETCH_HEAD

ACTUAL_TC_COMMIT="$(git -C "$TC_REPO" rev-parse HEAD)"
[[ "$ACTUAL_TC_COMMIT" == "$TOOLCHAIN_COMMIT" ]] || {
  echo "ERROR: toolchain commit mismatch" >&2
  exit 30
}

[[ -x "$TC_BIN/clang" ]] || {
  echo "ERROR: clang missing: $TC_BIN/clang" >&2
  exit 31
}
[[ -x "$TC_BIN/ld.lld" ]] || {
  echo "ERROR: ld.lld missing: $TC_BIN/ld.lld" >&2
  exit 32
}

export PATH="$TC_BIN:$PATH"
export ARCH=arm64

clang --version | tee "$RESULTS/clang-version.txt"
ld.lld --version | tee "$RESULTS/lld-version.txt"

echo
echo "=== Configure native VEUX baseline ==="
make -C "$SRC" O="$OUT" ARCH=arm64 "$DEFCONFIG" \
  2>&1 | tee "$RESULTS/defconfig.log"

[[ -f "$OUT/.config" ]] || {
  echo "ERROR: generated .config missing" >&2
  exit 40
}

sha256sum "$SRC/arch/arm64/configs/$DEFCONFIG" \
  | tee "$RESULTS/defconfig-source.sha256"
sha256sum "$OUT/.config" \
  | tee "$RESULTS/generated-config.sha256"

echo
echo "=== Build untouched 5.4.292 baseline ==="
make -C "$SRC" -j"$(nproc)" O="$OUT" \
  ARCH=arm64 \
  CC=clang \
  CLANG_TRIPLE=aarch64-linux-gnu- \
  CROSS_COMPILE=aarch64-linux-gnu- \
  CROSS_COMPILE_ARM32=arm-linux-gnueabi- \
  LD=ld.lld \
  LLVM=1 \
  LLVM_IAS=1 \
  2>&1 | tee "$RESULTS/build.log"

IMAGE="$OUT/arch/arm64/boot/Image"
[[ -s "$IMAGE" ]] || {
  echo "ERROR: kernel Image missing or empty" >&2
  exit 50
}

echo
echo "=== Verify source identity remained unchanged ==="
bash "$PROJECT_ROOT/common/scripts/identity_guard.sh" \
  verify \
  "$SRC" \
  "$DEFCONFIG" \
  "$RESULTS/identity-before.sha256" \
  | tee "$RESULTS/identity-after.txt"

KERNELRELEASE="$(
  make -s -C "$SRC" O="$OUT" ARCH=arm64 kernelrelease
)"

IMAGE_SHA256="$(sha256sum "$IMAGE" | awk '{print $1}')"
IMAGE_SIZE="$(wc -c < "$IMAGE" | tr -d ' ')"

{
  echo "BASELINE_COMPILE=PASS"
  echo "SOURCE_REPO=$SOURCE_REPO"
  echo "SOURCE_COMMIT=$ACTUAL_SOURCE_COMMIT"
  echo "KERNELVERSION=$EXPECTED_KERNEL_VERSION"
  echo "KERNELRELEASE=$KERNELRELEASE"
  echo "DEFCONFIG=$DEFCONFIG"
  echo "TOOLCHAIN_REPO=$TOOLCHAIN_REPO"
  echo "TOOLCHAIN_COMMIT=$ACTUAL_TC_COMMIT"
  echo "TOOLCHAIN_DIRNAME=$TOOLCHAIN_DIRNAME"
  echo "IMAGE=$IMAGE"
  echo "IMAGE_SIZE=$IMAGE_SIZE"
  echo "IMAGE_SHA256=$IMAGE_SHA256"
  echo "RESUKISU=NOT_PRESENT"
  echo "SUSFS=NOT_PRESENT"
  echo "PACKAGE=NOT_CREATED"
  echo "STATIC_BOOT_PATH=NOT_RUN"
  echo "DEVICE_PASS=NO"
} | tee "$RESULTS/BASELINE_RESULT.txt"

echo
echo "Baseline compile finished successfully."
echo "Result: $RESULTS/BASELINE_RESULT.txt"
