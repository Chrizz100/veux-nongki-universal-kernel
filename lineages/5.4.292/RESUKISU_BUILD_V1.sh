#!/usr/bin/env bash
set -euo pipefail

# VEUX 5.4.292 ReSukiSU compile V1
# Stage: ReSukiSU only, manual hooks, module_load_filter excluded.
# SUSFS is intentionally NOT integrated in this stage.

SOURCE_REPO="https://github.com/UEDestroyer/kernel_xiaomi_veux.git"
SOURCE_COMMIT="fb3bbb10bc0480282c01b88ccaf39c0145cd9f51"
EXPECTED_KERNEL_VERSION="5.4.292"
DEFCONFIG="veux_defconfig"

RESUKISU_REPO="https://github.com/ReSukiSU/ReSukiSU.git"
RESUKISU_COMMIT="6ec8d9a8a8be30878c388504cacf8ae7849c757b"

TOOLCHAIN_COMMIT="d19c99c180cfa21504426915d765b5e7adf878b6"
TOOLCHAIN_DIRNAME="clang-r547379"
TOOLCHAIN_BUILD_ID="13065274"
TOOLCHAIN_LLVM_PROJECT_REVISION="b718bcaf8c198c82f3021447d943401e3ab5bd54"
TOOLCHAIN_ARCHIVE_URL="https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86/+archive/${TOOLCHAIN_COMMIT}/${TOOLCHAIN_DIRNAME}.tar.gz"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INTEGRATOR="$PROJECT_ROOT/lineages/5.4.292/RESUKISU_INTEGRATE_V1.py"
INTEGRATOR_EXPECTED_SHA256="98c780eb6eddb07b1ff0456f0e79fa47b3c8912d135a21889596038a43d65290"

WORK_ROOT="${1:-$PROJECT_ROOT/.work/5.4.292-resukisu-v1}"
SRC="$WORK_ROOT/kernel"
RS="$WORK_ROOT/ReSukiSU"
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

for tool in git curl tar make sha256sum awk grep sed nproc tee wc tr python3; do
  need "$tool"
done

[[ -f "$INTEGRATOR" ]] || {
  echo "ERROR: integrator missing: $INTEGRATOR" >&2
  exit 11
}
ACTUAL_INTEGRATOR_SHA256="$(sha256sum "$INTEGRATOR" | awk '{print $1}')"
[[ "$ACTUAL_INTEGRATOR_SHA256" == "$INTEGRATOR_EXPECTED_SHA256" ]] || {
  echo "ERROR: integrator SHA-256 mismatch" >&2
  echo "EXPECTED=$INTEGRATOR_EXPECTED_SHA256" >&2
  echo "ACTUAL=$ACTUAL_INTEGRATOR_SHA256" >&2
  exit 12
}

python3 -m py_compile "$INTEGRATOR"
python3 "$INTEGRATOR" --selftest | tee "$RESULTS/integrator-selftest.txt"
grep -Fxq 'SELFTEST=PASS' "$RESULTS/integrator-selftest.txt"

rm -rf "$SRC" "$RS" "$TC" "$OUT"
rm -f "$TC_ARCHIVE"
mkdir -p "$SRC" "$RS" "$TC" "$OUT" "$RESULTS"

echo "=== Fetch exact kernel source ==="
git -C "$SRC" init -q
git -C "$SRC" remote add origin "$SOURCE_REPO"
git -C "$SRC" fetch -q --depth=1 origin "$SOURCE_COMMIT"
git -C "$SRC" checkout -q --detach FETCH_HEAD

ACTUAL_SOURCE_COMMIT="$(git -C "$SRC" rev-parse HEAD)"
[[ "$ACTUAL_SOURCE_COMMIT" == "$SOURCE_COMMIT" ]] || {
  echo "ERROR: source commit mismatch" >&2
  exit 20
}
[[ -z "$(git -C "$SRC" status --porcelain)" ]] || {
  echo "ERROR: source checkout not clean" >&2
  exit 21
}

echo "=== Fetch exact ReSukiSU ==="
git -C "$RS" init -q
git -C "$RS" remote add origin "$RESUKISU_REPO"
git -C "$RS" fetch -q --depth=1 origin "$RESUKISU_COMMIT"
git -C "$RS" checkout -q --detach FETCH_HEAD

ACTUAL_RESUKISU_COMMIT="$(git -C "$RS" rev-parse HEAD)"
[[ "$ACTUAL_RESUKISU_COMMIT" == "$RESUKISU_COMMIT" ]] || {
  echo "ERROR: ReSukiSU commit mismatch" >&2
  exit 22
}
[[ -z "$(git -C "$RS" status --porcelain)" ]] || {
  echo "ERROR: ReSukiSU checkout not clean" >&2
  exit 23
}

echo "=== Apply fail-closed ReSukiSU host integration ==="
python3 "$INTEGRATOR" "$SRC" "$RS" | tee "$RESULTS/integration.log"
grep -Fxq 'RESUKISU_HOST_INTEGRATION=PASS' "$RESULTS/integration.log"
grep -Fxq 'MODULE_LOAD_FILTER=EXCLUDED' "$RESULTS/integration.log"
grep -Fxq 'SUSFS=NOT_PRESENT' "$RESULTS/integration.log"

bash "$PROJECT_ROOT/common/scripts/identity_guard.sh" \
  snapshot "$SRC" "$DEFCONFIG" "$RESULTS/identity-before-build.sha256"

if grep -RIn --exclude-dir=.git -E 'module_load_filter|ksu_block_modules|block_modules' \
    "$SRC/drivers/kernelsu" > "$RESULTS/module-filter-scan.txt"; then
  echo "ERROR: module_load_filter references remain" >&2
  cat "$RESULTS/module-filter-scan.txt" >&2
  exit 24
fi
: > "$RESULTS/module-filter-scan.txt"
echo "MODULE_LOAD_FILTER_SCAN=PASS" | tee -a "$RESULTS/module-filter-scan.txt"

echo "=== Fetch exact clang-r547379 ==="
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
[[ -x "$TC_BIN/clang" ]] || { echo "ERROR: clang missing" >&2; exit 31; }
[[ -x "$TC_BIN/ld.lld" ]] || { echo "ERROR: ld.lld missing" >&2; exit 32; }
[[ -f "$TC/BUILD_INFO" ]] || { echo "ERROR: BUILD_INFO missing" >&2; exit 33; }

grep -Fq '"bid": "13065274"' "$TC/BUILD_INFO" || {
  echo "ERROR: unexpected toolchain build id" >&2
  exit 34
}
grep -Fq '"branch": "aosp-llvm-r547379-release"' "$TC/BUILD_INFO" || {
  echo "ERROR: unexpected toolchain branch" >&2
  exit 35
}

export PATH="$TC_BIN:$PATH"
export ARCH=arm64

clang --version | tee "$RESULTS/clang-version.txt"
ld.lld --version | tee "$RESULTS/lld-version.txt"

echo "=== Configure VEUX + ReSukiSU manual-hook stage ==="
make -C "$SRC" O="$OUT" ARCH=arm64 \
  CC=clang LD=ld.lld LLVM=1 LLVM_IAS=1 \
  "$DEFCONFIG" \
  2>&1 | tee "$RESULTS/defconfig.log"

[[ -f "$OUT/.config" ]] || {
  echo "ERROR: generated .config missing" >&2
  exit 40
}
[[ -x "$SRC/scripts/config" ]] || {
  echo "ERROR: scripts/config missing or not executable" >&2
  exit 41
}

"$SRC/scripts/config" --file "$OUT/.config" \
  --enable KSU \
  --enable KSU_MANUAL_HOOK \
  --enable KSU_MANUAL_HOOK_AUTO_SETUID_HOOK \
  --enable KSU_MANUAL_HOOK_AUTO_INITRC_HOOK \
  --enable KSU_MANUAL_HOOK_AUTO_INPUT_HOOK \
  --disable KSU_TRACEPOINT_HOOK \
  --disable KSU_SUSFS

make -C "$SRC" O="$OUT" ARCH=arm64 \
  CC=clang LD=ld.lld LLVM=1 LLVM_IAS=1 \
  olddefconfig \
  2>&1 | tee "$RESULTS/olddefconfig.log"

for expected in \
  'CONFIG_KSU=y' \
  'CONFIG_KSU_MANUAL_HOOK=y' \
  'CONFIG_KSU_MANUAL_HOOK_AUTO_SETUID_HOOK=y' \
  'CONFIG_KSU_MANUAL_HOOK_AUTO_INITRC_HOOK=y' \
  'CONFIG_KSU_MANUAL_HOOK_AUTO_INPUT_HOOK=y'
do
  grep -Fxq "$expected" "$OUT/.config" || {
    echo "ERROR: missing config: $expected" >&2
    exit 42
  }
done

grep -Fxq '# CONFIG_KSU_TRACEPOINT_HOOK is not set' "$OUT/.config" || {
  echo "ERROR: tracepoint hook unexpectedly enabled" >&2
  exit 43
}
grep -Fxq '# CONFIG_KSU_SUSFS is not set' "$OUT/.config" || {
  echo "ERROR: SUSFS unexpectedly enabled" >&2
  exit 44
}

sha256sum "$OUT/.config" | tee "$RESULTS/generated-config.sha256"
grep -E '^CONFIG_KSU|^# CONFIG_KSU' "$OUT/.config" \
  | tee "$RESULTS/ksu-config.txt"

NATIVE_KERNELVERSION="$(make -s -C "$SRC" kernelversion)"
[[ "$NATIVE_KERNELVERSION" == "$EXPECTED_KERNEL_VERSION" ]] || {
  echo "ERROR: native kernelversion changed" >&2
  exit 45
}

KERNELRELEASE_PRE="$(
  make -s -C "$SRC" O="$OUT" ARCH=arm64 \
    CC=clang LD=ld.lld LLVM=1 LLVM_IAS=1 \
    kernelrelease
)"
case "$KERNELRELEASE_PRE" in
  5.4.292*) ;;
  *)
    echo "ERROR: unexpected prebuild kernelrelease: $KERNELRELEASE_PRE" >&2
    exit 46
    ;;
esac
printf '%s\n' "$KERNELRELEASE_PRE" | tee "$RESULTS/kernelrelease-prebuild.txt"

echo "=== Compile ReSukiSU-only Image ==="
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
  echo "ERROR: Image missing or empty" >&2
  exit 50
}

git -C "$SRC" diff --check

if find "$SRC" -type f \( -name '*.rej' -o -name '*.orig' \) -print -quit | grep -q .; then
  echo "ERROR: reject/orig files after integration/build" >&2
  exit 51
fi

# Integration must remain exactly one KSU integration and no module filter.
bash "$PROJECT_ROOT/common/scripts/audit_existing_integration.sh" "$SRC" \
  | tee "$RESULTS/post-build-integration-audit.txt"

bash "$PROJECT_ROOT/common/scripts/identity_guard.sh" \
  verify "$SRC" "$DEFCONFIG" "$RESULTS/identity-before-build.sha256" \
  | tee "$RESULTS/identity-after-build.txt"

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
CONFIG_SHA256="$(sha256sum "$OUT/.config" | awk '{print $1}')"
INTEGRATOR_SHA256="$ACTUAL_INTEGRATOR_SHA256"

{
  echo "RESUKISU_COMPILE=PASS"
  echo "HOST_INTEGRATION=PASS"
  echo "MODULE_LOAD_FILTER=EXCLUDED"
  echo "HOOK_MODE=MANUAL"
  echo "SUSFS=NOT_PRESENT"
  echo
  echo "SOURCE_COMMIT=$ACTUAL_SOURCE_COMMIT"
  echo "RESUKISU_COMMIT=$ACTUAL_RESUKISU_COMMIT"
  echo "KERNELVERSION=$NATIVE_KERNELVERSION"
  echo "KERNELRELEASE=$KERNELRELEASE"
  echo "DEFCONFIG=$DEFCONFIG"
  echo "CONFIG_SHA256=$CONFIG_SHA256"
  echo "INTEGRATOR_SHA256=$INTEGRATOR_SHA256"
  echo
  echo "IMAGE=$IMAGE"
  echo "IMAGE_SIZE=$IMAGE_SIZE"
  echo "IMAGE_SHA256=$IMAGE_SHA256"
  echo
  echo "PACKAGE_PASS=NO"
  echo "STATIC_BOOT_PATH_PASS=NO"
  echo "DEVICE_PASS=NO"
} | tee "$RESULTS/RESUKISU_RESULT.txt"

(
  cd "$RESULTS"
  find . -type f ! -name SHA256SUMS.txt -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 sha256sum > SHA256SUMS.txt
  sha256sum -c SHA256SUMS.txt
)

echo "ReSukiSU-only compile finished successfully."
echo "Result: $RESULTS/RESUKISU_RESULT.txt"
