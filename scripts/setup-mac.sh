#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
HOME_DIR=${HOME:-}
MODE=install
DAEMON_MODE=
DRY_RUN=false
PAIR_ADDRESS=
CONTROLLER_HOST=127.0.0.1
if [ "${MESH_BOOTSTRAP_TEST_MODE:-0}" = 1 ]; then
    XCRUN=${MESH_XCRUN:-/usr/bin/xcrun}
    PLUTIL=${MESH_PLUTIL:-/usr/bin/plutil}
else
    XCRUN=/usr/bin/xcrun
    PLUTIL=/usr/bin/plutil
fi

while [ "$#" -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=true ;;
        --upgrade) MODE=upgrade ;;
        --install) DAEMON_MODE=install ;;
        --repair) DAEMON_MODE=repair ;;
        --autostart-enable) DAEMON_MODE=autostart-enable ;;
        --autostart-disable) DAEMON_MODE=autostart-disable ;;
        --logs) DAEMON_MODE=logs ;;
        --status) DAEMON_MODE=status ;;
        --uninstall) MODE=uninstall ;;
        --pair-address)
            shift
            PAIR_ADDRESS=$1
            ;;
        --controller)
            shift
            CONTROLLER_HOST=$1
            ;;
        --home)
            shift
            HOME_DIR=$1
            ;;
        *)
            echo "usage: setup-mac.sh [--dry-run] [--install|--repair|--status|--autostart-enable|--autostart-disable|--logs|--upgrade|--uninstall] [--controller HOST] [--pair-address HOST:PORT] [--home DIRECTORY]" >&2
            exit 2
            ;;
    esac
    shift
done

case "$CONTROLLER_HOST" in
    ''|*[!A-Za-z0-9._:-]*)
        echo "controller must be a host name or IP address" >&2
        exit 2
        ;;
esac
case "$CONTROLLER_HOST" in
    *:*) CONTROLLER_ENDPOINT="[$CONTROLLER_HOST]" ;;
    *) CONTROLLER_ENDPOINT="$CONTROLLER_HOST" ;;
esac
REGISTRY_ADDRESS="$CONTROLLER_ENDPOINT:7443"
if [ -z "$PAIR_ADDRESS" ]; then
    PAIR_ADDRESS="$CONTROLLER_ENDPOINT:7445"
fi

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
HARDWARE_GATE_DIR="$PROGRAM_DIR/hardware-gate"
HARDWARE_GATE_PATH="$HARDWARE_GATE_DIR/mac-hardware-gate.sh"
IDENTITY_DIR="$HOME_DIR/Library/Application Support/DeviceDevelopmentMesh/identity"
PEER_ID_PATH="$IDENTITY_DIR/peer-id"
AUDIT_DIR="$HOME_DIR/Library/Application Support/DeviceDevelopmentMesh/audit"
WORKSPACE_DIR="$HOME_DIR/Library/Application Support/DeviceDevelopmentMesh/workspaces"
LOG_DIR="$HOME_DIR/Library/Logs/DeviceDevelopmentMesh"
DIAGNOSTIC_BUNDLE="$LOG_DIR/diagnostics"
PLIST_PATH="$HOME_DIR/Library/LaunchAgents/dev.mesh.agent.plist"
PLIST_STAGE="$PLIST_PATH.next"
SERVICE="gui/$(id -u)/dev.mesh.agent"
DAEMON_PROGRAM_DIR="$HOME_DIR/.local/lib/devicelane/bin"
DAEMON_PROGRAM_PATH="$DAEMON_PROGRAM_DIR/devicelane-service"
DAEMON_IDENTITY_DIR="$HOME_DIR/Library/Application Support/DeviceLane/identity"
DAEMON_STATE_DIR="$HOME_DIR/Library/Application Support/DeviceLane/state"
DAEMON_RUNTIME_DIR="$DAEMON_STATE_DIR/runtime"
DAEMON_LOG_DIR="$HOME_DIR/Library/Logs/DeviceLane"
DAEMON_PLIST_PATH="$HOME_DIR/Library/LaunchAgents/dev.devicelane.service.plist"
DAEMON_SERVICE="gui/$(id -u)/dev.devicelane.service"
PAIR_COMMAND="mesh-registry pair --listen 0.0.0.0:7445 --identity .mesh/registry"

redact() {
    sed -E 's/(pairing_code|private_key|signing_secret|token)([=:][^ ,}]*)/\1=[REDACTED]/g'
}

xml_escape() {
    sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

rollback_mac_service() {
    ROLLBACK_FAILED=false
    if ! launchctl bootout "$DAEMON_SERVICE" >/dev/null 2>&1; then echo "rollback error: stop replacement" >&2; ROLLBACK_FAILED=true; fi
    if [ "$HAD_DAEMON_PROGRAM" = true ]; then
        if ! cp -p "$DAEMON_PROGRAM_BACKUP" "$DAEMON_PROGRAM_PATH"; then echo "rollback error: restore daemon binary" >&2; ROLLBACK_FAILED=true; fi
    elif ! rm -f "$DAEMON_PROGRAM_PATH"; then echo "rollback error: remove replacement daemon" >&2; ROLLBACK_FAILED=true; fi
    if [ "$HAD_DAEMON_PLIST" = true ]; then
        if ! cp -p "$DAEMON_PLIST_BACKUP" "$DAEMON_PLIST_PATH"; then echo "rollback error: restore LaunchAgent" >&2; ROLLBACK_FAILED=true; fi
    elif ! rm -f "$DAEMON_PLIST_PATH"; then echo "rollback error: remove replacement LaunchAgent" >&2; ROLLBACK_FAILED=true; fi
    if [ "$WAS_DAEMON_LOADED" = true ]; then
        if ! launchctl enable "$DAEMON_SERVICE"; then echo "rollback error: enable restored service" >&2; ROLLBACK_FAILED=true; fi
        if ! launchctl bootstrap "gui/$(id -u)" "$DAEMON_PLIST_PATH"; then echo "rollback error: bootstrap restored service" >&2; ROLLBACK_FAILED=true; fi
        if ! launchctl kickstart -k "$DAEMON_SERVICE"; then echo "rollback error: restart" >&2; ROLLBACK_FAILED=true; fi
        if ! launchctl print "$DAEMON_SERVICE" >/dev/null; then echo "rollback error: health verification" >&2; ROLLBACK_FAILED=true; fi
    fi
    if [ "$WAS_DAEMON_DISABLED" = true ]; then
        if ! launchctl disable "$DAEMON_SERVICE"; then echo "rollback error: restore launchd override" >&2; ROLLBACK_FAILED=true; fi
    elif ! launchctl enable "$DAEMON_SERVICE"; then echo "rollback error: restore launchd override" >&2; ROLLBACK_FAILED=true; fi
    [ "$ROLLBACK_FAILED" = false ]
}

activate_mac_service() {
    HAD_DAEMON_PROGRAM=false; HAD_DAEMON_PLIST=false; WAS_DAEMON_LOADED=false; WAS_DAEMON_DISABLED=false
    if [ -e "$DAEMON_PROGRAM_BACKUP" ] || [ -e "$DAEMON_PLIST_BACKUP" ]; then
        echo "refusing to overwrite existing DeviceLane recovery artifacts" >&2
        return 1
    fi
    [ -f "$DAEMON_PROGRAM_PATH" ] && { cp -p "$DAEMON_PROGRAM_PATH" "$DAEMON_PROGRAM_BACKUP"; HAD_DAEMON_PROGRAM=true; }
    [ -f "$DAEMON_PLIST_PATH" ] && { cp -p "$DAEMON_PLIST_PATH" "$DAEMON_PLIST_BACKUP"; HAD_DAEMON_PLIST=true; }
    launchctl print "$DAEMON_SERVICE" >/dev/null 2>&1 && WAS_DAEMON_LOADED=true || true
    launchctl print-disabled "gui/$(id -u)" 2>/dev/null | grep -q '"dev.devicelane.service" => true' && WAS_DAEMON_DISABLED=true || true
    if ! (
        { [ "$WAS_DAEMON_LOADED" = false ] || launchctl bootout "$DAEMON_SERVICE"; } &&
        mv -f "$DAEMON_PROGRAM_STAGE" "$DAEMON_PROGRAM_PATH" &&
        mv -f "$DAEMON_PLIST_STAGE" "$DAEMON_PLIST_PATH" &&
        launchctl enable "$DAEMON_SERVICE" &&
        launchctl bootstrap "gui/$(id -u)" "$DAEMON_PLIST_PATH" &&
        launchctl kickstart -k "$DAEMON_SERVICE" &&
        launchctl print "$DAEMON_SERVICE" >/dev/null &&
        { if [ "$HAD_DAEMON_PLIST" = true ] && [ "$WAS_DAEMON_DISABLED" = true ]; then launchctl disable "$DAEMON_SERVICE"; else launchctl enable "$DAEMON_SERVICE"; fi; }
    ); then
        if rollback_mac_service; then
            rm -f "$DAEMON_PROGRAM_BACKUP" "$DAEMON_PLIST_BACKUP"
        else
            echo "DeviceLane rollback could not restore a healthy service; backups were retained" >&2
        fi
        rm -f "$DAEMON_PROGRAM_STAGE" "$DAEMON_PLIST_STAGE"
        return 1
    fi
    if ! rm -f "$DAEMON_PROGRAM_BACKUP" "$DAEMON_PLIST_BACKUP"; then
        echo "cleanup error: recovery artifacts were retained" >&2
        return 1
    fi
}

mac_service_status() {
    if [ ! -f "$DAEMON_PLIST_PATH" ]; then
        printf 'Installed=false\nRunning=false\nAutostart=unavailable\nLogs=%s\n' "$DAEMON_LOG_DIR"
        return 1
    fi
    launchctl print "$DAEMON_SERVICE" >/dev/null 2>&1 && RUNNING=true || RUNNING=false
    if launchctl print-disabled "gui/$(id -u)" | grep -q '"dev.devicelane.service" => true'; then AUTOSTART=disabled; else AUTOSTART=enabled; fi
    printf 'Installed=true\nRunning=%s\nAutostart=%s\nLogs=%s\n' "$RUNNING" "$AUTOSTART" "$DAEMON_LOG_DIR"
}

mac_enable_autostart() {
    [ -f "$DAEMON_PLIST_PATH" ] || { echo "DeviceLane service is not installed" >&2; return 1; }
    launchctl enable "$DAEMON_SERVICE"
    if launchctl print "$DAEMON_SERVICE" >/dev/null 2>&1; then
        : "already loaded"
    else
        launchctl bootstrap "gui/$(id -u)" "$DAEMON_PLIST_PATH"
    fi
    launchctl kickstart -k "$DAEMON_SERVICE"
    launchctl print "$DAEMON_SERVICE" >/dev/null
}

if [ "${DEVICELANE_LIFECYCLE_SOURCE_ONLY:-0}" = 1 ]; then return 0; fi

if [ "$DRY_RUN" = true ]; then
    printf 'NEXT_CONTROLLER_COMMAND=%s\n' "$PAIR_COMMAND"
    printf 'DIAGNOSTIC_BUNDLE=%s\n' "$DIAGNOSTIC_BUNDLE"
    exit
fi

if [ -n "$DAEMON_MODE" ]; then
    case "$DAEMON_MODE" in
        status)
            mac_service_status; exit ;;
        autostart-enable)
            mac_enable_autostart; exit ;;
        autostart-disable) launchctl bootout "$DAEMON_SERVICE" >/dev/null 2>&1 || true; launchctl disable "$DAEMON_SERVICE"; exit ;;
        logs) printf '%s\n' "$DAEMON_LOG_DIR"; exit ;;
    esac
    mkdir -p "$DAEMON_PROGRAM_DIR" "$DAEMON_IDENTITY_DIR" "$DAEMON_STATE_DIR" "$DAEMON_RUNTIME_DIR" "$DAEMON_LOG_DIR" "$(dirname "$DAEMON_PLIST_PATH")"
    chmod 700 "$DAEMON_PROGRAM_DIR" "$DAEMON_IDENTITY_DIR" "$DAEMON_STATE_DIR" "$DAEMON_RUNTIME_DIR" "$DAEMON_LOG_DIR"
    if [ -n "${DEVICELANE_SERVICE_BINARY:-}" ]; then
        [ "${DEVICELANE_SERVICE_BINARY#/}" != "$DEVICELANE_SERVICE_BINARY" ] || { echo "bundled service path must be absolute" >&2; exit 1; }
        [ -f "$DEVICELANE_SERVICE_BINARY" ] && [ ! -L "$DEVICELANE_SERVICE_BINARY" ] || { echo "bundled service is unavailable" >&2; exit 1; }
        DAEMON_BUILD_PATH=$DEVICELANE_SERVICE_BINARY
    else
        cd "$ROOT"
        cargo build --release --bin devicelane-service >/dev/null
        DAEMON_BUILD_PATH=target/release/devicelane-service
    fi
    DAEMON_PROGRAM_STAGE="$DAEMON_PROGRAM_PATH.next"
    DAEMON_PROGRAM_BACKUP="$DAEMON_PROGRAM_PATH.previous"
    DAEMON_PLIST_BACKUP="$DAEMON_PLIST_PATH.previous"
    install -m 700 "$DAEMON_BUILD_PATH" "$DAEMON_PROGRAM_STAGE"
    DAEMON_PLIST_STAGE="$DAEMON_PLIST_PATH.next"
    DAEMON_PLIST_PROGRAM_PATH=$(printf '%s' "$DAEMON_PROGRAM_PATH" | xml_escape)
    DAEMON_PLIST_IDENTITY_DIR=$(printf '%s' "$DAEMON_IDENTITY_DIR" | xml_escape)
    DAEMON_PLIST_RUNTIME_DIR=$(printf '%s' "$DAEMON_RUNTIME_DIR" | xml_escape)
    DAEMON_PLIST_LOG_DIR=$(printf '%s' "$DAEMON_LOG_DIR" | xml_escape)
    trap 'rm -f "$DAEMON_PROGRAM_STAGE" "$DAEMON_PLIST_STAGE"' EXIT HUP INT TERM
    cat >"$DAEMON_PLIST_STAGE" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>dev.devicelane.service</string>
<key>ProgramArguments</key><array>
<string>$DAEMON_PLIST_PROGRAM_PATH</string><string>--identity</string><string>$DAEMON_PLIST_IDENTITY_DIR</string>
<string>--runtime-dir</string><string>$DAEMON_PLIST_RUNTIME_DIR</string><string>--log-dir</string><string>$DAEMON_PLIST_LOG_DIR</string>
<string>--role</string><string>workstation</string><string>--foreground</string>
</array>
<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
<key>RunAtLoad</key><true/>
<key>StandardOutPath</key><string>$DAEMON_PLIST_LOG_DIR/service.log</string>
<key>StandardErrorPath</key><string>$DAEMON_PLIST_LOG_DIR/service-error.log</string>
</dict></plist>
EOF
    chmod 600 "$DAEMON_PLIST_STAGE"
    "$PLUTIL" -lint "$DAEMON_PLIST_STAGE" >/dev/null
    activate_mac_service
    trap - EXIT HUP INT TERM
    exit
fi

if [ "$MODE" = status ]; then
    launchctl print "$SERVICE"
    exit
fi

if [ "$MODE" = uninstall ]; then
    launchctl bootout "$DAEMON_SERVICE" >/dev/null 2>&1 || true
    rm -f "$DAEMON_PLIST_PATH" "$DAEMON_PROGRAM_PATH"
    launchctl bootout "$SERVICE" >/dev/null 2>&1 || true
    rm -f "$PLIST_PATH"
    rm -f "$PROGRAM_PATH" "$CLI_PATH"
    rm -rf "$HARDWARE_GATE_DIR"
    rmdir "$PROGRAM_DIR/bin" "$PROGRAM_DIR" >/dev/null 2>&1 || true
    echo "DeviceLane services removed. Identity and logs were preserved."
    exit
fi

case "$CONTROLLER_HOST" in
    127.*|localhost|0.0.0.0|::1)
        echo "production controller must not use loopback" >&2
        exit 2
        ;;
esac

if [ ! -x "$XCRUN" ]; then
    echo "unable to resolve required Apple tool: xcrun" >&2
    exit 1
fi
if [ ! -x "$PLUTIL" ]; then
    echo "unable to validate LaunchAgent: plutil" >&2
    exit 1
fi
if [ "${MESH_BOOTSTRAP_TEST_MODE:-0}" = 1 ]; then
    DEVELOPER_DIR=${MESH_DEVELOPER_DIR:-}
else
    DEVELOPER_DIR=$(/usr/bin/xcode-select -p) ||
        { echo "unable to resolve active Xcode developer directory" >&2; exit 1; }
fi
case "$DEVELOPER_DIR" in
    /*) ;;
    *) echo "unable to resolve active Xcode developer directory" >&2; exit 1 ;;
esac
XCODEBUILD=$("$XCRUN" --find xcodebuild) ||
    { echo "unable to resolve required Apple tool: xcodebuild" >&2; exit 1; }
DEVICECTL=$("$XCRUN" --find devicectl) ||
    { echo "unable to resolve required Apple tool: devicectl" >&2; exit 1; }
SIMCTL=$("$XCRUN" --find simctl) ||
    { echo "unable to resolve required Apple tool: simctl" >&2; exit 1; }
XCRESULTTOOL=$("$XCRUN" --find xcresulttool) ||
    { echo "unable to resolve required Apple tool: xcresulttool" >&2; exit 1; }
XCTRACE=$("$XCRUN" --find xctrace) ||
    { echo "unable to resolve required Apple tool: xctrace" >&2; exit 1; }
LLDB_DAP=$("$XCRUN" --find lldb-dap) ||
    { echo "unable to resolve required Apple tool: lldb-dap" >&2; exit 1; }
for APPLE_TOOL_PATH in \
    "$XCODEBUILD" "$DEVICECTL" "$SIMCTL" "$XCRESULTTOOL" "$XCTRACE" "$LLDB_DAP"
do
    case "$APPLE_TOOL_PATH" in
        /*) ;;
        *)
            echo "unable to resolve required Apple tool: non-absolute path" >&2
            exit 1
            ;;
    esac
    if ! test -x "$APPLE_TOOL_PATH"; then
        echo "unable to resolve required Apple tool: $APPLE_TOOL_PATH" >&2
        exit 1
    fi
done

mkdir -p "$PROGRAM_DIR/bin" "$IDENTITY_DIR" "$AUDIT_DIR" "$WORKSPACE_DIR" "$LOG_DIR" "$DIAGNOSTIC_BUNDLE" "$(dirname "$PLIST_PATH")"
chmod 700 "$PROGRAM_DIR" "$PROGRAM_DIR/bin" "$IDENTITY_DIR" "$AUDIT_DIR" "$WORKSPACE_DIR" "$LOG_DIR" "$DIAGNOSTIC_BUNDLE"

cd "$ROOT"
cargo build --release --locked --bin mesh-agent --bin mesh-cli >/dev/null
install -m 700 target/release/mesh-agent "$PROGRAM_PATH"
install -m 700 target/release/mesh-cli "$CLI_PATH"
rm -rf "$HARDWARE_GATE_DIR.next"
mkdir "$HARDWARE_GATE_DIR.next"
cp scripts/mac-hardware-gate.sh "$HARDWARE_GATE_DIR.next/mac-hardware-gate.sh"
cp -R hardware/DeviceMeshGate "$HARDWARE_GATE_DIR.next/DeviceMeshGate"
chmod 700 "$HARDWARE_GATE_DIR.next" "$HARDWARE_GATE_DIR.next/mac-hardware-gate.sh"
chmod -R go-rwx "$HARDWARE_GATE_DIR.next/DeviceMeshGate"
rm -rf "$HARDWARE_GATE_DIR"
mv "$HARDWARE_GATE_DIR.next" "$HARDWARE_GATE_DIR"

if [ "${MESH_BOOTSTRAP_TEST_MODE:-0}" = 1 ]; then
    REQUESTED_PEER_ID=${MESH_PEER_ID:-mac-agent-smoke}
else
    REQUESTED_PEER_ID="mac-agent-$(/usr/bin/uuidgen | tr '[:upper:]' '[:lower:]')"
fi
PAIRED_DURING_MIGRATION=false
if [ -f "$PEER_ID_PATH" ]; then
    PEER_ID=$(cat "$PEER_ID_PATH")
else
    PEER_ID=$("$PROGRAM_PATH" peer-id --identity "$IDENTITY_DIR" --peer-id "$REQUESTED_PEER_ID")
    case "$PEER_ID" in
        mac-agent-*) ;;
        *)
            MIGRATION_IDENTITY_DIR="$IDENTITY_DIR.migration"
            if [ -e "$MIGRATION_IDENTITY_DIR" ]; then
                echo "remove the incomplete identity migration directory and rerun setup" >&2
                exit 1
            fi
            mkdir "$MIGRATION_IDENTITY_DIR"
            chmod 700 "$MIGRATION_IDENTITY_DIR"
            PEER_ID=$("$PROGRAM_PATH" peer-id --identity "$MIGRATION_IDENTITY_DIR" --peer-id "$REQUESTED_PEER_ID")
            "$PROGRAM_PATH" pair --address "$PAIR_ADDRESS" --identity "$MIGRATION_IDENTITY_DIR" --peer-id "$PEER_ID" >/dev/null
            LEGACY_IDENTITY_DIR="$IDENTITY_DIR.legacy-$(date +%Y%m%d%H%M%S)"
            mv "$IDENTITY_DIR" "$LEGACY_IDENTITY_DIR"
            mv "$MIGRATION_IDENTITY_DIR" "$IDENTITY_DIR"
            PEER_ID_PATH="$IDENTITY_DIR/peer-id"
            PAIRED_DURING_MIGRATION=true
            ;;
    esac
    case "$PEER_ID" in
        mac-agent-*) ;;
        *) echo "invalid migrated Mac agent peer identity" >&2; exit 1 ;;
    esac
    case "$PEER_ID" in
        *[!a-z0-9-]*) echo "invalid migrated Mac agent peer identity" >&2; exit 1 ;;
    esac
    (umask 077 && printf '%s\n' "$PEER_ID" >"$PEER_ID_PATH")
fi
case "$PEER_ID" in
    mac-agent-*) ;;
    *) echo "invalid persisted Mac agent peer identity" >&2; exit 1 ;;
esac
case "$PEER_ID" in
    *[!a-z0-9-]*) echo "invalid persisted Mac agent peer identity" >&2; exit 1 ;;
esac
ACTUAL_PEER_ID=$("$PROGRAM_PATH" peer-id --identity "$IDENTITY_DIR" --peer-id "$PEER_ID")
if [ "$ACTUAL_PEER_ID" != "$PEER_ID" ]; then
    echo "persisted peer identity does not match the agent certificate" >&2
    exit 1
fi
chmod 600 "$PEER_ID_PATH"

if [ "$PAIRED_DURING_MIGRATION" = false ] && [ ! -f "$IDENTITY_DIR/trust/registry.der" ]; then
    "$PROGRAM_PATH" pair --address "$PAIR_ADDRESS" --identity "$IDENTITY_DIR" --peer-id "$PEER_ID" >/dev/null
fi
"$CLI_PATH" doctor --identity "$IDENTITY_DIR" | redact >"$DIAGNOSTIC_BUNDLE/doctor.json"
chmod 600 "$DIAGNOSTIC_BUNDLE/doctor.json"
RUN_COMMAND="mesh-registry --listen 0.0.0.0:7443 --identity .mesh/registry --offline-after-ms 5000 --agent-peer $PEER_ID"

PLIST_PROGRAM_PATH=$(printf '%s' "$PROGRAM_PATH" | xml_escape)
PLIST_IDENTITY_DIR=$(printf '%s' "$IDENTITY_DIR" | xml_escape)
PLIST_WORKSPACE_DIR=$(printf '%s' "$WORKSPACE_DIR" | xml_escape)
PLIST_LOG_DIR=$(printf '%s' "$LOG_DIR" | xml_escape)
PLIST_REGISTRY_ADDRESS=$(printf '%s' "$REGISTRY_ADDRESS" | xml_escape)
PLIST_XCODEBUILD=$(printf '%s' "$XCODEBUILD" | xml_escape)
PLIST_DEVICECTL=$(printf '%s' "$DEVICECTL" | xml_escape)
PLIST_SIMCTL=$(printf '%s' "$SIMCTL" | xml_escape)
PLIST_XCRESULTTOOL=$(printf '%s' "$XCRESULTTOOL" | xml_escape)
PLIST_XCTRACE=$(printf '%s' "$XCTRACE" | xml_escape)
PLIST_LLDB_DAP=$(printf '%s' "$LLDB_DAP" | xml_escape)
PLIST_HARDWARE_GATE_PATH=$(printf '%s' "$HARDWARE_GATE_PATH" | xml_escape)
PLIST_PEER_ID=$(printf '%s' "$PEER_ID" | xml_escape)
trap 'rm -f "$PLIST_STAGE"' EXIT HUP INT TERM
cat >"$PLIST_STAGE" <<EOF
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
    <string>$PLIST_REGISTRY_ADDRESS</string>
    <string>--identity</string>
    <string>$PLIST_IDENTITY_DIR</string>
    <string>--peer-id</string>
    <string>$PLIST_PEER_ID</string>
    <string>--id</string>
    <string>$PLIST_PEER_ID</string>
    <string>--os</string>
    <string>macos</string>
    <string>--arch</string>
    <string>$(uname -m)</string>
    <string>--xcodebuild</string>
    <string>$PLIST_XCODEBUILD</string>
    <string>--devicectl</string>
    <string>$PLIST_DEVICECTL</string>
    <string>--simctl</string>
    <string>$PLIST_SIMCTL</string>
    <string>--xcresulttool</string>
    <string>$PLIST_XCRESULTTOOL</string>
    <string>--xctrace</string>
    <string>$PLIST_XCTRACE</string>
    <string>--lldb-dap</string>
    <string>$PLIST_LLDB_DAP</string>
    <string>--hardware-gate</string>
    <string>$PLIST_HARDWARE_GATE_PATH</string>
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
chmod 600 "$PLIST_STAGE"
"$CLI_PATH" validate-launch-agent \
    --plist "$PLIST_STAGE" \
    --controller-host "$CONTROLLER_HOST" \
    --developer-dir "$DEVELOPER_DIR" \
    --tool "$XCODEBUILD" \
    --tool "$DEVICECTL" \
    --tool "$SIMCTL" \
    --tool "$XCRESULTTOOL" \
    --tool "$XCTRACE" \
    --tool "$LLDB_DAP"
"$PLUTIL" -lint "$PLIST_STAGE" >/dev/null
mv "$PLIST_STAGE" "$PLIST_PATH"
trap - EXIT HUP INT TERM

launchctl bootout "$SERVICE" >/dev/null 2>&1 || true
launchctl bootstrap "gui/$(id -u)" "$PLIST_PATH"
launchctl kickstart -k "$SERVICE"
launchctl print "$SERVICE" | redact >"$DIAGNOSTIC_BUNDLE/status.txt"
chmod 600 "$DIAGNOSTIC_BUNDLE/status.txt"

printf 'NEXT_CONTROLLER_COMMAND=%s\n' "$RUN_COMMAND"
printf 'DIAGNOSTIC_BUNDLE=%s\n' "$DIAGNOSTIC_BUNDLE"
