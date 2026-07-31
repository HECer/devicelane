#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -d "$SCRIPT_DIR/../hardware/DeviceMeshGate" ]; then
    PROJECT="$SCRIPT_DIR/../hardware/DeviceMeshGate/DeviceMeshGate.xcodeproj"
else
    PROJECT="$SCRIPT_DIR/DeviceMeshGate/DeviceMeshGate.xcodeproj"
fi
SCHEME=DeviceMeshGate
DEVICE_ID=
TEAM_ID=
OUTPUT_ROOT=${HOME:-}/Library/Logs/DeviceDevelopmentMesh/hardware-gates
JOB_ID="hardware-gate-$(date -u +%Y%m%dT%H%M%SZ)"
AGENT_PEER=local-mac-agent
ARCHIVE_STDOUT=false

repair() {
    printf 'hardware_gate_failed=%s\nnext_step=%s\n' "$1" "$2" >&2
    exit 1
}

if [ "${MESH_HARDWARE_GATE_TEST_MODE:-0}" != 0 ]; then
    repair mock_environment "Unset MESH_HARDWARE_GATE_TEST_MODE and run this gate on the real Mac."
fi

while [ "$#" -gt 0 ]; do
    case "$1" in
        --device) shift; DEVICE_ID=${1:-} ;;
        --team) shift; TEAM_ID=${1:-} ;;
        --output) shift; OUTPUT_ROOT=${1:-} ;;
        --job-id) shift; JOB_ID=${1:-} ;;
        --agent-peer) shift; AGENT_PEER=${1:-} ;;
        --archive-stdout) ARCHIVE_STDOUT=true ;;
        *) repair invalid_argument "Use --device UDID --team TEAM_ID --output DIRECTORY --job-id ID --agent-peer ID." ;;
    esac
    shift
done

[ "$(uname -s)" = Darwin ] || repair not_macos "Run scripts/mac-hardware-gate.sh on the paired Mac."
[ -d "$PROJECT" ] || repair missing_project "Re-run scripts/setup-mac.sh --upgrade on the Mac."
DEVELOPER_DIR=$(/usr/bin/xcode-select -p 2>/dev/null) || repair xcode_missing "Install Xcode, open it once, then run sudo xcode-select -s /Applications/Xcode.app/Contents/Developer."
XCODEBUILD=$(/usr/bin/xcrun --find xcodebuild 2>/dev/null) || repair xcodebuild_missing "Install the selected Xcode command-line tools."
DEVICECTL=$(/usr/bin/xcrun --find devicectl 2>/dev/null) || repair devicectl_missing "Select Xcode 15 or newer with sudo xcode-select -s."
XCRESULTTOOL=$(/usr/bin/xcrun --find xcresulttool 2>/dev/null) || repair xcresulttool_missing "Select a complete Xcode installation with sudo xcode-select -s."
for TOOL in "$XCODEBUILD" "$DEVICECTL" "$XCRESULTTOOL"; do
    case "$TOOL" in "$DEVELOPER_DIR"/*) ;; *) repair fake_tool "Select genuine Xcode tools under $DEVELOPER_DIR." ;; esac
    [ -x "$TOOL" ] || repair tool_not_executable "Repair the selected Xcode installation and retry."
done

PYTHON3=$(command -v python3 2>/dev/null || true)
[ -x "$PYTHON3" ] || repair python_missing "Install Python 3 on the Mac and retry."
mkdir -p "$OUTPUT_ROOT"
RUN_DIR="$OUTPUT_ROOT/$JOB_ID"
[ ! -e "$RUN_DIR" ] || repair output_exists "Choose a new --job-id or remove the previous incomplete gate directory."
mkdir -p "$RUN_DIR/evidence"
chmod 700 "$OUTPUT_ROOT" "$RUN_DIR" "$RUN_DIR/evidence"
DEVICES_JSON="$RUN_DIR/devices.raw.json"
DETAILS_JSON="$RUN_DIR/device-details.raw.json"

"$DEVICECTL" list devices --json-output "$DEVICES_JSON" >/dev/null 2>&1 || repair no_device "Connect and unlock the iPhone, tap Trust, enable Developer Mode, then retry."
if [ -z "$DEVICE_ID" ]; then
    DEVICE_ID=$($PYTHON3 - "$DEVICES_JSON" <<'PY'
import json, sys
data=json.load(open(sys.argv[1], encoding="utf-8"))
def walk(value):
    if isinstance(value, dict):
        product=" ".join(str(value.get(k,"")) for k in ("productType","deviceType","platform","name"))
        identifier=value.get("identifier") or value.get("udid") or value.get("deviceIdentifier")
        if identifier and "iphone" in product.lower():
            print(identifier); raise SystemExit
        for child in value.values(): walk(child)
    elif isinstance(value, list):
        for child in value: walk(child)
walk(data)
PY
    )
fi
[ -n "$DEVICE_ID" ] || repair no_physical_iphone "Connect and unlock a physical iPhone, tap Trust, and retry with --device UDID."
case "$DEVICE_ID" in *[!A-Za-z0-9._:-]*) repair invalid_device "Copy the identifier reported by xcrun devicectl list devices." ;; esac

"$DEVICECTL" device info details --device "$DEVICE_ID" --json-output "$DETAILS_JSON" >/dev/null 2>&1 || repair device_unavailable "Unlock the iPhone, tap Trust on both hosts, enable Settings > Privacy & Security > Developer Mode, and retry."
$PYTHON3 - "$DETAILS_JSON" "$RUN_DIR/evidence/device.json" <<'PY'
import hashlib, json, sys
source=json.load(open(sys.argv[1], encoding="utf-8"))
sensitive=("serial", "identifier", "udid", "wifi", "bluetooth", "token", "key")
def clean(value):
    if isinstance(value, dict):
        return {k: clean(v) for k,v in value.items() if not any(x in k.lower() for x in sensitive)}
    if isinstance(value, list): return [clean(v) for v in value]
    return value
json.dump(clean(source), open(sys.argv[2], "w", encoding="utf-8"), sort_keys=True, indent=2)
PY

IDENTITIES=$(security find-identity -v -p codesigning 2>/dev/null || true)
if [ -z "$TEAM_ID" ]; then
    TEAM_ID=$(printf '%s\n' "$IDENTITIES" | awk -F'[()]' '/Apple Development:/{print $2; exit}')
fi
[ -n "$TEAM_ID" ] || repair signing_missing "Sign in to Xcode with an Apple developer account and create an Apple Development certificate."
case "$TEAM_ID" in *[!A-Z0-9]*) repair signing_invalid "Pass the 10-character Apple development team identifier with --team." ;; esac
SIGN_IDENTITY=$(printf '%s\n' "$IDENTITIES" | awk -v team="($TEAM_ID)" 'index($0,"Apple Development:") && index($0,team) {sub(/^[^"]*"/,""); sub(/".*$/,""); print; exit}')
[ -n "$SIGN_IDENTITY" ] || repair signing_missing "Create an Apple Development certificate for team $TEAM_ID in Xcode and retry."
BUNDLE_ID="dev.mesh.hardware-gate.$TEAM_ID"

DERIVED_DATA="$RUN_DIR/DerivedData"
BUILD_RESULT="$RUN_DIR/evidence/Build.xcresult"
TEST_RESULT="$RUN_DIR/evidence/Test.xcresult"
DESTINATION="platform=iOS,id=$DEVICE_ID"
"$XCODEBUILD" -project "$PROJECT" -scheme "$SCHEME" -destination "$DESTINATION" -derivedDataPath "$DERIVED_DATA" -resultBundlePath "$BUILD_RESULT" -allowProvisioningUpdates -allowProvisioningDeviceRegistration DEVELOPMENT_TEAM="$TEAM_ID" CODE_SIGN_STYLE=Automatic build-for-testing >"$RUN_DIR/evidence/build.log" 2>&1 || repair signing_or_build_failed "Open the bundled project in Xcode, select team $TEAM_ID for both targets, resolve signing, and retry."
APP_PATH="$DERIVED_DATA/Build/Products/Debug-iphoneos/DeviceMeshGate.app"
[ -d "$APP_PATH" ] || repair app_missing "Inspect evidence/build.log, repair the Xcode build, and retry."

"$DEVICECTL" device install app --device "$DEVICE_ID" "$APP_PATH" >"$RUN_DIR/evidence/install.log" 2>&1 || repair install_failed "Unlock the trusted iPhone, confirm Developer Mode is enabled, and retry."
"$DEVICECTL" device process launch --device "$DEVICE_ID" --terminate-existing --console "$BUNDLE_ID" >"$RUN_DIR/evidence/device.log" 2>&1 &
LAUNCH_PID=$!
sleep 5
"$DEVICECTL" device process terminate --device "$DEVICE_ID" "$BUNDLE_ID" >>"$RUN_DIR/evidence/device.log" 2>&1 || true
wait "$LAUNCH_PID" || true
grep -q 'hardware gate app launched' "$RUN_DIR/evidence/device.log" || repair launch_failed "Keep the iPhone unlocked, verify the development app in Settings > Privacy & Security > Developer Mode, and retry."

"$XCODEBUILD" test-without-building -project "$PROJECT" -scheme "$SCHEME" -destination "$DESTINATION" -derivedDataPath "$DERIVED_DATA" -resultBundlePath "$TEST_RESULT" -allowProvisioningUpdates -allowProvisioningDeviceRegistration DEVELOPMENT_TEAM="$TEAM_ID" CODE_SIGN_STYLE=Automatic >"$RUN_DIR/evidence/test.log" 2>&1 || repair xcui_failed "Keep the iPhone unlocked and inspect evidence/test.log for the failing XCTest repair."
ATTACHMENTS="$RUN_DIR/evidence/attachments"
mkdir "$ATTACHMENTS"
"$XCRESULTTOOL" export attachments --path "$TEST_RESULT" --output-path "$ATTACHMENTS" >/dev/null 2>&1 || repair screenshot_export_failed "Update the selected Xcode and rerun the XCUI gate."
SCREENSHOT=$(find "$ATTACHMENTS" -type f -name '*.png' -print -quit)
[ -n "$SCREENSHOT" ] || repair screenshot_missing "Inspect Test.xcresult and ensure DeviceMeshGateUITests ran on the physical iPhone."
cp "$SCREENSHOT" "$RUN_DIR/evidence/screenshot.png"

DEVICE_AUDIT_ID=$(printf '%s' "$DEVICE_ID" | shasum -a 256 | awk '{print $1}')
XCODE_VERSION=$("$XCODEBUILD" -version | tr '\n' ' ' | sed 's/[[:space:]]*$//')
SDK_VERSION=$("$XCODEBUILD" -version -sdk iphoneos 2>&1 | tr '\n' ' ' | sed 's/[[:space:]]*$//')
DEVICECTL_VERSION=$("$DEVICECTL" --version 2>&1 | tr '\n' ' ' | sed 's/[[:space:]]*$//')
XCRESULTTOOL_VERSION=$("$XCRESULTTOOL" version 2>&1 | tr '\n' ' ' | sed 's/[[:space:]]*$//')
$PYTHON3 - "$RUN_DIR/evidence" "$DEVICE_ID" "$DEVICE_AUDIT_ID" "${HOME:-}" <<'PY'
import pathlib, sys
root=pathlib.Path(sys.argv[1]); device=sys.argv[2].encode(); audit=sys.argv[3].encode(); home=sys.argv[4].encode()
device_replacement=(audit*((len(device)//len(audit))+1))[:len(device)]
home_replacement=(b"/[HOME]" + b"_"*len(home))[:len(home)] if home else b""
for path in root.rglob("*"):
    if path.is_file():
        data=path.read_bytes().replace(device, device_replacement)
        if home: data=data.replace(home, home_replacement)
        path.write_bytes(data)
PY
"$XCRESULTTOOL" get test-results summary --path "$TEST_RESULT" >"$RUN_DIR/evidence/test-summary.json" 2>/dev/null || repair redaction_invalid "Update Xcode: this xcresult format could not be safely pseudonymized and revalidated."
"$XCRESULTTOOL" get build-results --path "$BUILD_RESULT" >"$RUN_DIR/evidence/build-summary.json" 2>/dev/null || repair redaction_invalid "Update Xcode: this build xcresult format could not be safely pseudonymized and revalidated."
$PYTHON3 - "$RUN_DIR/evidence/manifest.json" "$JOB_ID" "$AGENT_PEER" "$DEVICE_AUDIT_ID" "$TEAM_ID" "$XCODE_VERSION" "$SDK_VERSION" "$DEVICECTL_VERSION" "$XCRESULTTOOL_VERSION" <<'PY'
import json, sys
keys=("job_id","agent_peer","device_audit_id","team_id","xcode_version","sdk_version","devicectl_version","xcresulttool_version")
json.dump(dict(zip(keys,sys.argv[2:])), open(sys.argv[1],"w",encoding="utf-8"), sort_keys=True, indent=2)
PY
find "$RUN_DIR/evidence" -type f ! -name manifest.sha256 -exec shasum -a 256 {} \; | sed "s#$RUN_DIR/evidence/##" | LC_ALL=C sort >"$RUN_DIR/evidence/manifest.sha256"
/usr/bin/security cms -S -N "$SIGN_IDENTITY" -i "$RUN_DIR/evidence/manifest.sha256" -o "$RUN_DIR/evidence/manifest.cms" >/dev/null 2>&1 || repair evidence_signing_failed "Unlock the login keychain and allow security to use the Apple Development identity."
chmod -R go-rwx "$RUN_DIR"
ARCHIVE="$OUTPUT_ROOT/$JOB_ID.hardware-gate.tar.gz"
tar -C "$RUN_DIR" -czf "$ARCHIVE" evidence
chmod 600 "$ARCHIVE"
if [ "$ARCHIVE_STDOUT" = true ]; then
    printf 'hardware_gate_archive=%s device_audit_id=%s job_id=%s\n' "$ARCHIVE" "$DEVICE_AUDIT_ID" "$JOB_ID" >&2
    cat "$ARCHIVE"
else
    printf 'HARDWARE_GATE_ARCHIVE=%s\nDEVICE_AUDIT_ID=%s\nJOB_ID=%s\n' "$ARCHIVE" "$DEVICE_AUDIT_ID" "$JOB_ID"
fi
