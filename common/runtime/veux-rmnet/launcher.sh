#!/system/bin/sh
# VEUX_RMNET_PACKAGE_V1 - kernel companion, not a module-manager module.
PATH=/system/bin:/system/xbin:/vendor/bin
export PATH
BASE=/data/adb/veux-rmnet
BB=/data/adb/ksu/bin/busybox
OWNER_UID=0
[ "$(id -u)" = "$OWNER_UID" ] || exit 1
[ -x "$BB" ] && [ ! -L "$BB" ] || exit 1
[ ! -L /data/adb ] && [ ! -L "$BASE" ] && [ -d "$BASE" ] || exit 1
[ "$(stat -c %u "$BASE")" = "$OWNER_UID" ] || exit 1
[ "$(getprop sys.boot_completed)" = 1 ] || exit 0
line=$(sha256sum /sys/kernel/notes) || exit 1
notes=${line%% *}
case "$notes" in ''|*[!0-9a-f]*) exit 1;; esac
[ "${#notes}" = 64 ] || exit 1
GEN="$BASE/$notes"
[ -d "$GEN" ] && [ ! -L "$GEN" ] || exit 0
[ -f "$GEN/runtime.sh" ] && [ ! -L "$GEN/runtime.sh" ] || exit 1
[ "$(stat -c %u "$GEN/runtime.sh")" = "$OWNER_UID" ] || exit 1
[ ! -f "$BASE/disabled" ] || exit 0
exec "$BB" sh "$GEN/runtime.sh" start
