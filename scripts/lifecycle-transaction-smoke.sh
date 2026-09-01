#!/usr/bin/env sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=${TMPDIR:-/tmp}/devicelane-lifecycle-$$
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

DEVICELANE_LIFECYCLE_SOURCE_ONLY=1 . "$ROOT/scripts/setup-linux.sh"
validate_systemd_path '/tmp/space path'
for unsafe_path in '/tmp/double"quote' '/tmp/back\slash' '/tmp/percent%path'; do
    if validate_systemd_path "$unsafe_path" >/dev/null 2>&1; then echo "unsafe systemd path accepted" >&2; exit 1; fi
done
newline_path='/tmp/line
break'
if validate_systemd_path "$newline_path" >/dev/null 2>&1; then echo "newline systemd path accepted" >&2; exit 1; fi
SERVICE_PATH="$TMP/linux-service"
UNIT_PATH="$TMP/linux-unit"
BINARY_STAGE="$TMP/linux-service.next"
UNIT_STAGE="$TMP/linux-unit.next"
BINARY_BACKUP="$TMP/linux-service.previous"
UNIT_BACKUP="$TMP/linux-unit.previous"
printf old >"$SERVICE_PATH"; printf old-unit >"$UNIT_PATH"
printf new >"$BINARY_STAGE"; printf new-unit >"$UNIT_STAGE"
systemctl() {
    case "$*" in
        *is-active*) return 0 ;;
        *restart*) [ "$(cat "$SERVICE_PATH")" != new ] ;;
        *) return 0 ;;
    esac
}
if activate_linux_service; then echo "Linux activation unexpectedly succeeded" >&2; exit 1; fi
[ "$(cat "$SERVICE_PATH")" = old ]
[ "$(cat "$UNIT_PATH")" = old-unit ]

printf old >"$SERVICE_PATH"; printf old-unit >"$UNIT_PATH"
printf new >"$BINARY_STAGE"; printf new-unit >"$UNIT_STAGE"
systemctl() { case "$*" in *is-active*) return 0 ;; *restart*) return 1 ;; *) return 0 ;; esac; }
if activate_linux_service; then echo "Linux broken rollback unexpectedly succeeded" >&2; exit 1; fi
[ -f "$BINARY_BACKUP" ]
[ -f "$UNIT_BACKUP" ]

DEVICELANE_LIFECYCLE_SOURCE_ONLY=1 . "$ROOT/scripts/setup-mac.sh"
DAEMON_SERVICE=gui/501/dev.devicelane.service
DAEMON_LOG_DIR="$TMP/mac-logs"
DAEMON_PROGRAM_PATH="$TMP/mac-service"
DAEMON_PLIST_PATH="$TMP/mac.plist"
DAEMON_PROGRAM_STAGE="$TMP/mac-service.next"
DAEMON_PLIST_STAGE="$TMP/mac.plist.next"
DAEMON_PROGRAM_BACKUP="$TMP/mac-service.previous"
DAEMON_PLIST_BACKUP="$TMP/mac.plist.previous"
launchctl() { echo "$*" >>"$TMP/mac-launchctl.log"; return 0; }
if mac_service_status >"$TMP/mac-status"; then echo "absent macOS service reported installed" >&2; exit 1; fi
grep -q 'Installed=false' "$TMP/mac-status"
if mac_enable_autostart >/dev/null 2>&1; then echo "absent macOS autostart enabled" >&2; exit 1; fi
[ ! -f "$TMP/mac-launchctl.log" ]
printf old >"$DAEMON_PROGRAM_PATH"; printf old-plist >"$DAEMON_PLIST_PATH"
printf new >"$DAEMON_PROGRAM_STAGE"; printf new-plist >"$DAEMON_PLIST_STAGE"
launchctl() {
    case "$1" in
        print) return 0 ;;
        bootstrap) [ "$(cat "$DAEMON_PROGRAM_PATH")" != new ] ;;
        *) return 0 ;;
    esac
}
if activate_mac_service; then echo "macOS activation unexpectedly succeeded" >&2; exit 1; fi
[ "$(cat "$DAEMON_PROGRAM_PATH")" = old ]
[ "$(cat "$DAEMON_PLIST_PATH")" = old-plist ]
printf old >"$DAEMON_PROGRAM_PATH"; printf old-plist >"$DAEMON_PLIST_PATH"
printf new >"$DAEMON_PROGRAM_STAGE"; printf new-plist >"$DAEMON_PLIST_STAGE"
launchctl() { case "$1" in print) return 0 ;; bootstrap) return 1 ;; *) return 0 ;; esac; }
if activate_mac_service; then echo "macOS broken rollback unexpectedly succeeded" >&2; exit 1; fi
[ -f "$DAEMON_PROGRAM_BACKUP" ]
[ -f "$DAEMON_PLIST_BACKUP" ]
printf 'transaction rollback verified\n'
