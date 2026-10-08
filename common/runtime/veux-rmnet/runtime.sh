#!/system/bin/sh
# VEUX_RMNET_PACKAGE_V1
# Called solely by the existing KernelSU boot-completed.d stage (SafeMode-aware).
# resetprop is used ONLY with --wait; it never sets or deletes any property.
PATH=/system/bin:/system/xbin:/vendor/bin
export PATH
LC_ALL=C
export LC_ALL
umask 077
OWNER_UID=0
BASE=/data/adb/veux-rmnet
BB=/data/adb/ksu/bin/busybox
KSUD=/data/adb/ksud
SYS=/sys
GEN=${0%/*}
LOG="$GEN/runtime.log"

hash_file() {
    value=$(sha256sum "$1") || return 1
    value=${value%% *}
    case "$value" in ''|*[!0-9a-f]*) return 1;; esac
    [ "${#value}" = 64 ] || return 1
    printf '%s\n' "$value"
}

identity() {
    # Strict key-value parsing: never execute the metadata as shell code.
    count=0
    while IFS='=' read -r key value; do
        if [ "$key" = "$1" ]; then
            count=$((count + 1))
            result=$value
        fi
    done < "$GEN/identity.txt"
    [ "$count" -eq 1 ] || return 1
    printf '%s\n' "$result"
}

owned_file() {
    [ -f "$1" ] && [ ! -L "$1" ] || return 1
    [ "$(stat -c %u "$1")" = "$OWNER_UID" ] || return 1
    case "$(stat -c %a "$1")" in 600|644|700|755) return 0;; *) return 1;; esac
}

validate() {
    [ "$(id -u)" = "$OWNER_UID" ] || return 1
    [ -d "$GEN" ] && [ ! -L "$GEN" ] && [ ! -L "$BASE" ] || return 1
    [ "${GEN%/*}" = "$BASE" ] || return 1
    for name in identity.txt SHA256SUMS runtime.sh launcher.sh install.sh rmnet_offload.ko rmnet_shs.ko; do
        owned_file "$GEN/$name" || return 1
    done
    (cd "$GEN" && sha256sum -c SHA256SUMS >/dev/null 2>&1) || return 1
    [ "$(identity FORMAT)" = veux-rmnet-v1 ] || return 1
    [ "$(uname -r)" = "$(identity KERNEL_RELEASE)" ] || return 1
    notes=$(hash_file "$SYS/kernel/notes") || return 1
    [ "$notes" = "$(identity KERNEL_NOTES_SHA256)" ] && [ "${GEN##*/}" = "$notes" ] || return 1
    [ -x "$KSUD" ] && [ ! -L "$KSUD" ] && [ -x "$BB" ] || return 1
    "$KSUD" resetprop --help 2>&1 | grep -q -- '--wait' || return 1
    "$BB" --list | grep -qx flock || return 1
}

module_matches() {
    name=$1
    case "$name" in rmnet_offload) key=OFFLOAD_NOTE_SHA256;; rmnet_shs) key=SHS_NOTE_SHA256;; *) return 1;; esac
    [ "$(cat "$SYS/module/$name/initstate" 2>/dev/null)" = live ] || return 1
    actual=$(hash_file "$SYS/module/$name/notes/.note.gnu.build-id" 2>/dev/null) || return 1
    [ "$actual" = "$(identity "$key")" ]
}

reconcile() {
    name=$1
    wanted=$2
    case "$name" in rmnet_offload|rmnet_shs) ;; *) return 1;; esac
    case "$wanted" in 0|1) ;; *) echo "$name=UNDEFINED_PROPERTY; NO_CHANGE"; return 0;; esac
    [ ! -f "$BASE/disabled" ] || return 1
    if [ -d "$SYS/module/$name" ]; then
        module_matches "$name" || { echo "$name=FOREIGN_OR_TRANSITIONING_MODULE; NO_CHANGE"; return 1; }
        if [ "$wanted" = 0 ]; then
            if /system/bin/rmmod "$name"; then
                [ ! -d "$SYS/module/$name" ] || { echo "$name=UNLOAD_NOT_CONFIRMED"; return 1; }
                echo "$name=UNLOADED"
            else
                # A concurrent ROM removal can win the race. Never use -f.
                [ ! -d "$SYS/module/$name" ] || { echo "$name=UNLOAD_FAILED_OR_BUSY"; return 1; }
            fi
        fi
        return 0
    fi
    [ "$wanted" = 1 ] || return 0
    [ -e "$SYS/class/net/rmnet_data0" ] || { echo "$name=WAITING_FOR_INTERFACE"; return 1; }
    if /system/bin/insmod "$GEN/$name.ko"; then
        module_matches "$name" || { echo "$name=LOAD_NOT_CONFIRMED"; return 1; }
        echo "$name=LIVE"
    else
        module_matches "$name" || { echo "$name=LOAD_FAILED"; return 1; }
    fi
}

watch_property() {
    name=$1
    property=$2
    while [ ! -f "$BASE/disabled" ]; do
        [ "$(getprop sys.boot_completed)" = 1 ] || return 0
        wanted=$(getprop "$property")
        # Each watcher owns one module. ROM and our commands may race;
        # postconditions, not an EEXIST/ENOENT return alone, decide the result.
        reconcile "$name" "$wanted"
        "$KSUD" resetprop --wait --timeout 300 "$property" "$wanted"
        rc=$?
        case "$rc" in
            0|2) ;; # property changed / bounded idle wait expired
            *) echo "$name=PROPERTY_WAIT_FAILED; STOPPING"; return 1;;
        esac
    done
}

start() {
    validate || { echo 'VEUX_RMNET=VALIDATION_FAILED; NO_MODULE_LOAD' >&2; return 1; }
    [ "$(getprop sys.boot_completed)" = 1 ] || return 0
    [ ! -f "$BASE/disabled" ] || return 0
    [ ! -L "$BASE/runtime.lock" ] || return 1
    exec 9>"$BASE/runtime.lock" || return 1
    "$BB" flock -n 9 || return 0
    [ ! -L "$LOG" ] && [ ! -L "$LOG.old" ] || return 1
    [ ! -f "$LOG" ] || mv "$LOG" "$LOG.old"
    exec >>"$LOG" 2>&1
    echo 'VEUX_RMNET=START; PROPERTY_WRITES=NO; FORCE_LOAD=NO'
    # Bounded wait after boot, not an init-blocking early-boot script.
    i=0
    while [ ! -e "$SYS/class/net/rmnet_data0" ] && [ "$i" -lt 30 ]; do
        sleep 2
        i=$((i + 1))
    done
    # Preserve the tested initial order. The subsequent watchers are independent.
    reconcile rmnet_offload "$(getprop persist.vendor.data.offload_ko_load)"
    reconcile rmnet_shs "$(getprop persist.vendor.data.shs_ko_load)"
    watch_property rmnet_offload persist.vendor.data.offload_ko_load &
    offload_pid=$!
    watch_property rmnet_shs persist.vendor.data.shs_ko_load &
    shs_pid=$!
    trap 'kill "$offload_pid" "$shs_pid" 2>/dev/null; wait; exit 0' TERM INT
    wait "$offload_pid"
    offload_rc=$?
    wait "$shs_pid"
    shs_rc=$?
    [ "$offload_rc" -eq 0 ] && [ "$shs_rc" -eq 0 ]
}

case "${1:-}" in
    start) start;;
    reconcile)
        validate || exit 1
        [ "$(getprop sys.boot_completed)" = 1 ] || exit 0
        case "${2:-}" in
            rmnet_offload) reconcile "$2" "$(getprop persist.vendor.data.offload_ko_load)";;
            rmnet_shs) reconcile "$2" "$(getprop persist.vendor.data.shs_ko_load)";;
            *) exit 1;;
        esac;;
    *) echo 'Use: runtime.sh start|reconcile rmnet_offload|rmnet_shs' >&2; exit 1;;
esac
