#!/system/bin/sh
# VEUX_RMNET_PACKAGE_V1
# Runs inside the ordinary AnyKernel installation BEFORE write_boot.
# Writes only our data companion. No ROM modifications and no module load here.
set -eu
umask 077
OWNER_UID=0
BASE=/data/adb/veux-rmnet
COMMON=/data/adb/boot-completed.d
KSUD=/data/adb/ksud
BB=/data/adb/ksu/bin/busybox
SOURCE=${1:?missing package directory}
[ "$(id -u)" = "$OWNER_UID" ] || exit 1
[ -d /data/adb ] && [ ! -L /data/adb ] && [ -w /data/adb ] || exit 1
[ "$(stat -c %u /data/adb)" = "$OWNER_UID" ] || exit 1
[ -x "$KSUD" ] && [ ! -L "$KSUD" ] && [ -x "$BB" ] || exit 1
"$KSUD" resetprop --help 2>&1 | grep -q -- '--wait' || exit 1
"$BB" --list | grep -qx flock || exit 1
for file in launcher.sh runtime.sh install.sh identity.txt SHA256SUMS rmnet_offload.ko rmnet_shs.ko; do
    [ -f "$SOURCE/$file" ] && [ ! -L "$SOURCE/$file" ] || exit 1
done
(cd "$SOURCE" && sha256sum -c SHA256SUMS >/dev/null) || exit 1
notes=
format=
while IFS='=' read -r key value; do
    case "$key" in
        KERNEL_NOTES_SHA256) [ -z "$notes" ] || exit 1; notes=$value;;
        FORMAT) [ -z "$format" ] || exit 1; format=$value;;
    esac
done < "$SOURCE/identity.txt"
[ "$format" = veux-rmnet-v1 ] || exit 1
case "$notes" in ''|*[!0-9a-f]*) exit 1;; esac
[ "${#notes}" = 64 ] || exit 1
# Never follow unexpected links, reuse another package's launcher, or replace
# a generation that differs. Identical repeated installation is a no-op.
for directory in "$BASE" "$COMMON"; do
    [ ! -L "$directory" ] || exit 1
    if [ -e "$directory" ]; then
        [ -d "$directory" ] && [ "$(stat -c %u "$directory")" = "$OWNER_UID" ] || exit 1
        case "$(stat -c %a "$directory")" in 700|750|755) ;; *) exit 1;; esac
    fi
done
LAUNCHER="$COMMON/50-veux-rmnet.sh"
[ ! -L "$LAUNCHER" ] || exit 1
if [ -e "$LAUNCHER" ]; then
    [ -f "$LAUNCHER" ] && grep -q '^# VEUX_RMNET_PACKAGE_V1' "$LAUNCHER" || exit 1
    cmp -s "$SOURCE/launcher.sh" "$LAUNCHER" || exit 1
fi
[ -e "$BASE" ] || mkdir -m 700 "$BASE"
[ -e "$COMMON" ] || mkdir -m 700 "$COMMON"
[ ! -L "$BASE/install.lock" ] || exit 1
exec 8>"$BASE/install.lock"
"$BB" flock -n 8 || exit 1
# Recheck the shared launcher under the installation lock.
[ ! -L "$LAUNCHER" ] || exit 1
if [ -e "$LAUNCHER" ]; then
    [ -f "$LAUNCHER" ] && cmp -s "$SOURCE/launcher.sh" "$LAUNCHER" || exit 1
fi
DEST="$BASE/$notes"
[ ! -L "$DEST" ] || exit 1
if [ -e "$DEST" ]; then
    [ -d "$DEST" ] || exit 1
    for file in launcher.sh runtime.sh install.sh identity.txt SHA256SUMS rmnet_offload.ko rmnet_shs.ko; do
        [ -f "$DEST/$file" ] && [ ! -L "$DEST/$file" ] || exit 1
        cmp -s "$SOURCE/$file" "$DEST/$file" || exit 1
    done
else
    STAGE="$BASE/.install-$$"
    mkdir -m 700 "$STAGE"
    trap 'rm -rf "$STAGE"' EXIT
    trap 'exit 1' HUP INT TERM
    for file in launcher.sh runtime.sh install.sh identity.txt SHA256SUMS rmnet_offload.ko rmnet_shs.ko; do
        cp "$SOURCE/$file" "$STAGE/$file"
        chmod 600 "$STAGE/$file"
    done
    chmod 700 "$STAGE/launcher.sh" "$STAGE/runtime.sh" "$STAGE/install.sh"
    (cd "$STAGE" && sha256sum -c SHA256SUMS >/dev/null) || exit 1
    mv "$STAGE" "$DEST"
    trap - EXIT HUP INT TERM
fi
if [ ! -e "$LAUNCHER" ]; then
    TEMP="$COMMON/.veux-rmnet-$$"
    [ ! -e "$TEMP" ] && [ ! -L "$TEMP" ] || exit 1
    cp "$SOURCE/launcher.sh" "$TEMP"
    chmod 700 "$TEMP"
    mv "$TEMP" "$LAUNCHER"
fi
echo 'RMNET_DATA_STAGED=PASS; RUNNING_KERNEL_UNCHANGED=YES; ACTIVATION=NEXT_MATCHING_BOOT'
