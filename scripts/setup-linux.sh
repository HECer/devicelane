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
mkdir -p "$PROGRAM_DIR" "$IDENTITY_DIR" "$STATE_DIR" "$RUNTIME_DIR" "$LOG_DIR" "$UNIT_DIR"
chmod 700 "$PROGRAM_DIR" "$IDENTITY_DIR" "$STATE_DIR" "$RUNTIME_DIR" "$LOG_DIR" "$UNIT_DIR"
cd "$ROOT"
cargo build --release --bin devicelane-service
install -m 700 target/release/devicelane-service "$SERVICE_PATH"
UNIT_STAGE="$UNIT_PATH.next"
trap 'rm -f "$UNIT_STAGE"' EXIT HUP INT TERM
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
mv "$UNIT_STAGE" "$UNIT_PATH"
trap - EXIT HUP INT TERM
systemctl --user daemon-reload
systemctl --user enable --now devicelane.service
echo "DeviceLane service installed or repaired."
echo "Identity: $IDENTITY_DIR"
echo "Logs: $LOG_DIR"
