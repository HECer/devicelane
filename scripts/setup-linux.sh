#!/usr/bin/env sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
HOME_DIR=${HOME:-}
MODE=install
while [ "$#" -gt 0 ]; do
    case "$1" in
        --install) MODE=install ;; --repair) MODE=repair ;; --status) MODE=status ;;
        --autostart-enable) MODE=autostart-enable ;; --autostart-disable) MODE=autostart-disable ;;
        --logs) MODE=logs ;; --uninstall) MODE=uninstall ;;
        --home) shift; HOME_DIR=${1:?--home requires a value} ;;
        *) echo "usage: setup-linux.sh [--install|--repair|--status|--autostart-enable|--autostart-disable|--logs|--uninstall] [--home DIRECTORY]" >&2; exit 2 ;;
    esac
    shift
done
[ -n "$HOME_DIR" ] || { echo "home directory is required" >&2; exit 2; }
case "$HOME_DIR" in /*) ;; *) HOME_DIR="$(pwd)/$HOME_DIR" ;; esac
PROGRAM_DIR="$HOME_DIR/.local/lib/devicelane/bin"
SERVICE_PATH="$PROGRAM_DIR/devicelane-service"
IDENTITY_DIR="$HOME_DIR/.local/share/devicelane/identity"
STATE_DIR="$HOME_DIR/.local/state/devicelane"
RUNTIME_BASE="${XDG_RUNTIME_DIR:-$STATE_DIR/runtime}"
RUNTIME_DIR="$RUNTIME_BASE/devicelane"
LOG_DIR="$STATE_DIR/logs"
UNIT_DIR="$HOME_DIR/.config/systemd/user"
UNIT_PATH="$HOME_DIR/.config/systemd/user/devicelane.service"
require_systemd() {
    if ! command -v systemctl >/dev/null 2>&1 || ! systemctl --user show-environment >/dev/null 2>&1; then
        echo "systemd --user is unavailable; run $SERVICE_PATH --identity $IDENTITY_DIR --runtime-dir $RUNTIME_DIR --log-dir $LOG_DIR --foreground" >&2
        exit 1
    fi
}

validate_systemd_path() {
    value=$1
    newline='
'
    case "$value" in
        *"$newline"*) echo "systemd path contains newline" >&2; return 1 ;;
        *'"'*) echo "systemd path contains double quote" >&2; return 1 ;;
        *'\'*) echo "systemd path contains backslash" >&2; return 1 ;;
        *'%'*) echo "systemd path contains percent" >&2; return 1 ;;
    esac
}

rollback_linux_service() {
    ROLLBACK_FAILED=false
    if ! systemctl --user stop devicelane.service >/dev/null 2>&1; then echo "rollback error: stop replacement" >&2; ROLLBACK_FAILED=true; fi
    if [ "$HAD_BINARY" = true ]; then
        if ! cp -p "$BINARY_BACKUP" "$SERVICE_PATH"; then echo "rollback error: restore binary" >&2; ROLLBACK_FAILED=true; fi
    elif ! rm -f "$SERVICE_PATH"; then echo "rollback error: remove replacement binary" >&2; ROLLBACK_FAILED=true; fi
    if [ "$HAD_UNIT" = true ]; then
        if ! cp -p "$UNIT_BACKUP" "$UNIT_PATH"; then echo "rollback error: restore unit" >&2; ROLLBACK_FAILED=true; fi
    elif ! rm -f "$UNIT_PATH"; then echo "rollback error: remove replacement unit" >&2; ROLLBACK_FAILED=true; fi
    if ! systemctl --user daemon-reload; then echo "rollback error: daemon-reload" >&2; ROLLBACK_FAILED=true; fi
    if [ "$WAS_ENABLED" = true ]; then
        if ! systemctl --user enable devicelane.service; then echo "rollback error: restore autostart" >&2; ROLLBACK_FAILED=true; fi
    elif ! systemctl --user disable devicelane.service; then echo "rollback error: restore autostart" >&2; ROLLBACK_FAILED=true; fi
    if [ "$WAS_ACTIVE" = true ]; then
        if ! systemctl --user restart devicelane.service; then echo "rollback error: restart" >&2; ROLLBACK_FAILED=true; fi
        if ! systemctl --user is-active --quiet devicelane.service; then echo "rollback error: health verification" >&2; ROLLBACK_FAILED=true; fi
    fi
    [ "$ROLLBACK_FAILED" = false ]
}

activate_linux_service() {
    HAD_BINARY=false; HAD_UNIT=false; WAS_ACTIVE=false; WAS_ENABLED=false
    if [ -e "$BINARY_BACKUP" ] || [ -e "$UNIT_BACKUP" ]; then
        echo "refusing to overwrite existing DeviceLane recovery artifacts" >&2
        return 1
    fi
    [ -f "$SERVICE_PATH" ] && { cp -p "$SERVICE_PATH" "$BINARY_BACKUP"; HAD_BINARY=true; }
    [ -f "$UNIT_PATH" ] && { cp -p "$UNIT_PATH" "$UNIT_BACKUP"; HAD_UNIT=true; }
    systemctl --user is-active --quiet devicelane.service && WAS_ACTIVE=true || true
    systemctl --user is-enabled --quiet devicelane.service && WAS_ENABLED=true || true
    if ! (
        { [ "$WAS_ACTIVE" = false ] || systemctl --user stop devicelane.service; } &&
        mv -f "$BINARY_STAGE" "$SERVICE_PATH" &&
        mv -f "$UNIT_STAGE" "$UNIT_PATH" &&
        systemctl --user daemon-reload &&
        systemctl --user restart devicelane.service &&
        { if [ "$HAD_UNIT" = false ] || [ "$WAS_ENABLED" = true ]; then systemctl --user enable devicelane.service; else systemctl --user disable devicelane.service; fi; } &&
        systemctl --user is-active --quiet devicelane.service
    ); then
        if rollback_linux_service; then
            rm -f "$BINARY_BACKUP" "$UNIT_BACKUP"
        else
            echo "DeviceLane rollback could not restore a healthy service; backups were retained" >&2
        fi
        rm -f "$BINARY_STAGE" "$UNIT_STAGE"
        return 1
    fi
    if ! rm -f "$BINARY_BACKUP" "$UNIT_BACKUP"; then
        echo "cleanup error: recovery artifacts were retained" >&2
        return 1
    fi
}

if [ "${DEVICELANE_LIFECYCLE_SOURCE_ONLY:-0}" = 1 ]; then return 0; fi
case "$MODE" in
    status)
        require_systemd
        [ -f "$UNIT_PATH" ] && INSTALLED=true || INSTALLED=false
        systemctl --user is-active --quiet devicelane.service && RUNNING=true || RUNNING=false
        AUTOSTART=$(systemctl --user is-enabled devicelane.service 2>/dev/null || true)
        printf 'Installed=%s\nRunning=%s\nAutostart=%s\nLogs=%s\n' "$INSTALLED" "$RUNNING" "$AUTOSTART" "$LOG_DIR"
        exit ;;
    autostart-enable) require_systemd; systemctl --user enable --now devicelane.service; exit ;;
    autostart-disable) require_systemd; systemctl --user disable --now devicelane.service; exit ;;
    logs) require_systemd; journalctl --user-unit devicelane.service; exit ;;
    uninstall)
        command -v systemctl >/dev/null 2>&1 && systemctl --user disable --now devicelane.service >/dev/null 2>&1 || true
        rm -f "$UNIT_PATH" "$SERVICE_PATH"
        command -v systemctl >/dev/null 2>&1 && systemctl --user daemon-reload >/dev/null 2>&1 || true
        echo "DeviceLane service removed. Identity and logs were preserved."
        exit ;;
esac
require_systemd
validate_systemd_path "$PROGRAM_DIR"
validate_systemd_path "$IDENTITY_DIR"
validate_systemd_path "$RUNTIME_DIR"
validate_systemd_path "$LOG_DIR"
validate_systemd_path "$UNIT_PATH"
mkdir -p "$PROGRAM_DIR" "$IDENTITY_DIR" "$STATE_DIR" "$RUNTIME_DIR" "$LOG_DIR" "$UNIT_DIR"
chmod 700 "$PROGRAM_DIR" "$IDENTITY_DIR" "$STATE_DIR" "$RUNTIME_DIR" "$LOG_DIR" "$UNIT_DIR"
cd "$ROOT"
cargo build --release --bin devicelane-service
BINARY_STAGE="$SERVICE_PATH.next"
BINARY_BACKUP="$SERVICE_PATH.previous"
UNIT_STAGE="$UNIT_PATH.next"
UNIT_BACKUP="$UNIT_PATH.previous"
install -m 700 target/release/devicelane-service "$BINARY_STAGE"
trap 'rm -f "$BINARY_STAGE" "$UNIT_STAGE"' EXIT HUP INT TERM
cat >"$UNIT_STAGE" <<EOF
[Unit]
Description=DeviceLane per-user daemon
After=network-online.target
[Service]
Type=simple
ExecStart="$SERVICE_PATH" --identity "$IDENTITY_DIR" --runtime-dir "$RUNTIME_DIR" --log-dir "$LOG_DIR" --role workstation --foreground
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
[Install]
WantedBy=default.target
EOF
chmod 600 "$UNIT_STAGE"
activate_linux_service
trap - EXIT HUP INT TERM
echo "DeviceLane service installed or repaired."
echo "Identity: $IDENTITY_DIR"
echo "Logs: $LOG_DIR"
