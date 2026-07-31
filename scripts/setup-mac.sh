#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
HOME_DIR=${HOME:-}
MODE=install
DRY_RUN=false
PAIR_ADDRESS=

while [ "$#" -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=true ;;
        --upgrade) MODE=upgrade ;;
        --status) MODE=status ;;
        --uninstall) MODE=uninstall ;;
        --pair-address)
            shift
            PAIR_ADDRESS=$1
            ;;
        --home)
            shift
            HOME_DIR=$1
            ;;
        *)
            echo "usage: setup-mac.sh [--dry-run] [--upgrade|--status|--uninstall] [--pair-address HOST:PORT] [--home DIRECTORY]" >&2
            exit 2
            ;;
    esac
    shift
done

if [ -z "$HOME_DIR" ]; then
    echo "home directory is required" >&2
    exit 2
fi
case "$HOME_DIR" in
    /*) ;;
    *) HOME_DIR="$(pwd)/$HOME_DIR" ;;
esac

PROGRAM_DIR="$HOME_DIR/.local/lib/device-development-mesh"
PROGRAM_PATH="$PROGRAM_DIR/bin/mesh-agent"
CLI_PATH="$PROGRAM_DIR/bin/mesh-cli"
IDENTITY_DIR="$HOME_DIR/Library/Application Support/DeviceDevelopmentMesh/identity"
AUDIT_DIR="$HOME_DIR/Library/Application Support/DeviceDevelopmentMesh/audit"
WORKSPACE_DIR="$HOME_DIR/Library/Application Support/DeviceDevelopmentMesh/workspaces"
LOG_DIR="$HOME_DIR/Library/Logs/DeviceDevelopmentMesh"
DIAGNOSTIC_BUNDLE="$LOG_DIR/diagnostics"
PLIST_PATH="$HOME_DIR/Library/LaunchAgents/dev.mesh.agent.plist"
SERVICE="gui/$(id -u)/dev.mesh.agent"
NEXT_COMMAND="mesh-registry pair --listen 0.0.0.0:7445 --identity .mesh/registry"

redact() {
    sed -E 's/(pairing_code|private_key|signing_secret|token)([=:][^ ,}]*)/\1=[REDACTED]/g'
}

xml_escape() {
    sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

if [ "$DRY_RUN" = true ]; then
    printf 'NEXT_CONTROLLER_COMMAND=%s\n' "$NEXT_COMMAND"
    printf 'DIAGNOSTIC_BUNDLE=%s\n' "$DIAGNOSTIC_BUNDLE"
    exit
fi

if [ "$MODE" = status ]; then
    launchctl print "$SERVICE"
    exit
fi

if [ "$MODE" = uninstall ]; then
    launchctl bootout "$SERVICE" >/dev/null 2>&1 || true
    rm -f "$PLIST_PATH"
    rm -f "$PROGRAM_PATH" "$CLI_PATH"
    rmdir "$PROGRAM_DIR/bin" "$PROGRAM_DIR" >/dev/null 2>&1 || true
    exit
fi

mkdir -p "$PROGRAM_DIR/bin" "$IDENTITY_DIR" "$AUDIT_DIR" "$WORKSPACE_DIR" "$LOG_DIR" "$DIAGNOSTIC_BUNDLE" "$(dirname "$PLIST_PATH")"
chmod 700 "$PROGRAM_DIR" "$PROGRAM_DIR/bin" "$IDENTITY_DIR" "$AUDIT_DIR" "$WORKSPACE_DIR" "$LOG_DIR" "$DIAGNOSTIC_BUNDLE"

cd "$ROOT"
cargo build --workspace --release >/dev/null
install -m 700 target/release/mesh-agent "$PROGRAM_PATH"
install -m 700 target/release/mesh-cli "$CLI_PATH"
"$CLI_PATH" doctor --identity "$IDENTITY_DIR" | redact >"$DIAGNOSTIC_BUNDLE/doctor.json"
chmod 600 "$DIAGNOSTIC_BUNDLE/doctor.json"

if [ -n "$PAIR_ADDRESS" ]; then
    "$PROGRAM_PATH" pair --address "$PAIR_ADDRESS" --identity "$IDENTITY_DIR" >/dev/null
fi

PLIST_PROGRAM_PATH=$(printf '%s' "$PROGRAM_PATH" | xml_escape)
PLIST_IDENTITY_DIR=$(printf '%s' "$IDENTITY_DIR" | xml_escape)
PLIST_WORKSPACE_DIR=$(printf '%s' "$WORKSPACE_DIR" | xml_escape)
PLIST_LOG_DIR=$(printf '%s' "$LOG_DIR" | xml_escape)
cat >"$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>dev.mesh.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>$PLIST_PROGRAM_PATH</string>
    <string>--registry</string>
    <string>127.0.0.1:7443</string>
    <string>--identity</string>
    <string>$PLIST_IDENTITY_DIR</string>
    <string>--id</string>
    <string>mac-agent</string>
    <string>--os</string>
    <string>macos</string>
    <string>--arch</string>
    <string>$(uname -m)</string>
    <string>--capability</string>
    <string>process.start@1</string>
    <string>--device</string>
    <string>none:ios:disconnected</string>
    <string>--heartbeat-ms</string>
    <string>1000</string>
    <string>--workspace-root</string>
    <string>$PLIST_WORKSPACE_DIR</string>
  </array>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>ThrottleInterval</key>
  <integer>10</integer>
  <key>StandardOutPath</key>
  <string>$PLIST_LOG_DIR/agent.log</string>
  <key>StandardErrorPath</key>
  <string>$PLIST_LOG_DIR/agent-error.log</string>
</dict>
</plist>
EOF
chmod 600 "$PLIST_PATH"

launchctl bootout "$SERVICE" >/dev/null 2>&1 || true
launchctl bootstrap "gui/$(id -u)" "$PLIST_PATH"
launchctl kickstart -k "$SERVICE"
launchctl print "$SERVICE" | redact >"$DIAGNOSTIC_BUNDLE/status.txt"
chmod 600 "$DIAGNOSTIC_BUNDLE/status.txt"

printf 'NEXT_CONTROLLER_COMMAND=%s\n' "$NEXT_COMMAND"
printf 'DIAGNOSTIC_BUNDLE=%s\n' "$DIAGNOSTIC_BUNDLE"
