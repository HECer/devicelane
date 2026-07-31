#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
HOME_DIR=${HOME:-}
MODE=install
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
        --status) MODE=status ;;
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
            echo "usage: setup-mac.sh [--dry-run] [--upgrade|--status|--uninstall] [--controller HOST] [--pair-address HOST:PORT] [--home DIRECTORY]" >&2
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
IDENTITY_DIR="$HOME_DIR/Library/Application Support/DeviceDevelopmentMesh/identity"
PEER_ID_PATH="$IDENTITY_DIR/peer-id"
AUDIT_DIR="$HOME_DIR/Library/Application Support/DeviceDevelopmentMesh/audit"
WORKSPACE_DIR="$HOME_DIR/Library/Application Support/DeviceDevelopmentMesh/workspaces"
LOG_DIR="$HOME_DIR/Library/Logs/DeviceDevelopmentMesh"
DIAGNOSTIC_BUNDLE="$LOG_DIR/diagnostics"
PLIST_PATH="$HOME_DIR/Library/LaunchAgents/dev.mesh.agent.plist"
PLIST_STAGE="$PLIST_PATH.next"
SERVICE="gui/$(id -u)/dev.mesh.agent"
PAIR_COMMAND="mesh-registry pair --listen 0.0.0.0:7445 --identity .mesh/registry"

redact() {
    sed -E 's/(pairing_code|private_key|signing_secret|token)([=:][^ ,}]*)/\1=[REDACTED]/g'
}

xml_escape() {
    sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

if [ "$DRY_RUN" = true ]; then
    printf 'NEXT_CONTROLLER_COMMAND=%s\n' "$PAIR_COMMAND"
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
cargo build --workspace --release >/dev/null
install -m 700 target/release/mesh-agent "$PROGRAM_PATH"
install -m 700 target/release/mesh-cli "$CLI_PATH"

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
