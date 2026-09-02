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
MESH_CONTROLLER=
MESH_ENDPOINT=
WINDOWS_PRINCIPAL=
WINDOWS_SOURCE_HOST=
MESH_ACTIVITY_ID=
MESH_TIMEOUT_SECONDS=300
DEVICELANE_BINARY=
DEVICELANE_SHA256=
DEVICELANE_VERSION=
CONTROLLER_PEER_ID=

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
        --mesh-controller) shift; MESH_CONTROLLER=${1:-} ;;
        --mesh-endpoint) shift; MESH_ENDPOINT=${1:-} ;;
        --windows-principal) shift; WINDOWS_PRINCIPAL=${1:-} ;;
        --windows-source-host) shift; WINDOWS_SOURCE_HOST=${1:-} ;;
        --mesh-activity-id) shift; MESH_ACTIVITY_ID=${1:-} ;;
        --mesh-timeout-seconds) shift; MESH_TIMEOUT_SECONDS=${1:-} ;;
        --devicelane-binary) shift; DEVICELANE_BINARY=${1:-} ;;
        --devicelane-sha256) shift; DEVICELANE_SHA256=${1:-} ;;
        --devicelane-version) shift; DEVICELANE_VERSION=${1:-} ;;
        --controller-peer-id) shift; CONTROLLER_PEER_ID=${1:-} ;;
        --archive-stdout) ARCHIVE_STDOUT=true ;;
        *) repair invalid_argument "Use --device UDID --team TEAM_ID --output DIRECTORY --job-id ID --agent-peer ID and the documented --mesh-* arguments." ;;
    esac
    shift
done

run_mesh_gate() {
    [ "${DEVICELANE_REAL_MESH_GATE:-0}" = 1 ] || repair mesh_gate_not_authorized "Set DEVICELANE_REAL_MESH_GATE=1 only for a real paired Windows-to-Mac run."
    for value in "$MESH_CONTROLLER" "$MESH_ENDPOINT" "$WINDOWS_PRINCIPAL" "$WINDOWS_SOURCE_HOST" "$MESH_ACTIVITY_ID" "$CONTROLLER_PEER_ID"; do
        [ -n "$value" ] || repair mesh_gate_argument_missing "Pass the documented controller, endpoint, principal, source, activity, and controller-peer arguments."
    done
    case "$MESH_TIMEOUT_SECONDS" in ''|*[!0-9]*) repair invalid_mesh_timeout "Use a positive integer for --mesh-timeout-seconds." ;; esac
    [ "$MESH_TIMEOUT_SECONDS" -gt 0 ] || repair invalid_mesh_timeout "Use a positive integer for --mesh-timeout-seconds."
    [ -n "$DEVICELANE_BINARY" ] && [ -n "$DEVICELANE_SHA256" ] && [ -n "$DEVICELANE_VERSION" ] || repair unpinned_devicelane "Pass --devicelane-binary, --devicelane-sha256, and --devicelane-version from the approved build manifest."
    case "$DEVICELANE_BINARY" in /*) ;; *) repair unpinned_devicelane "Use an absolute path to the approved DeviceLane binary." ;; esac
    [ -x "$DEVICELANE_BINARY" ] && [ ! -L "$DEVICELANE_BINARY" ] || repair devicelane_cli_missing "Install the approved non-symlink DeviceLane binary."
    case "$DEVICELANE_SHA256" in *[!0-9a-f]*|'') repair invalid_devicelane_hash "Use the lowercase SHA-256 from the approved build manifest." ;; esac
    [ "${#DEVICELANE_SHA256}" -eq 64 ] || repair invalid_devicelane_hash "Use the 64-character lowercase SHA-256 from the approved build manifest."
    ACTUAL_SHA256=$(/usr/bin/shasum -a 256 "$DEVICELANE_BINARY" | /usr/bin/awk '{print $1}')
    [ "$ACTUAL_SHA256" = "$DEVICELANE_SHA256" ] || repair devicelane_hash_mismatch "Install the exact approved DeviceLane build."
    ACTUAL_VERSION=$($DEVICELANE_BINARY --version 2>/dev/null || true)
    [ "$ACTUAL_VERSION" = "$DEVICELANE_VERSION" ] || repair devicelane_version_mismatch "Install the exact approved DeviceLane version."
    DEVICELANE_CLI=$DEVICELANE_BINARY

    # All daemon replies stay in memory. Only an allow-listed, pseudonymized summary is written.
    # The command spellings below are also the operator contract for the physical gate:
    # devicelane mesh status --local --json; devicelane activities watch --local --json;
    # devicelane approvals list --local --json; devicelane audit list --local --json.
    "$PYTHON3" - "$DEVICELANE_CLI" "$MESH_ENDPOINT" "$MESH_CONTROLLER" "$CONTROLLER_PEER_ID" "$WINDOWS_PRINCIPAL" "$WINDOWS_SOURCE_HOST" "$MESH_ACTIVITY_ID" "$MESH_TIMEOUT_SECONDS" "$DEVICELANE_SHA256" "$DEVICELANE_VERSION" "$RUN_DIR/evidence/mesh-evidence.json" <<'PY'
import hashlib, json, select, subprocess, sys, time

cli, endpoint, controller, controller_peer, principal, source, activity_id, timeout_raw, binary_sha256, binary_version, output = sys.argv[1:]
timeout = int(timeout_raw)

def fail(code, message):
    print(f"hardware_gate_failed={code}\nnext_step={message}", file=sys.stderr)
    raise SystemExit(1)

def run(*parts):
    command = [cli, *parts, "--local", "--json", "--endpoint", endpoint]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
    if result.returncode:
        fail("mesh_command_failed", f"DeviceLane command failed: {' '.join(parts)}")
    try: return json.loads(result.stdout)
    except Exception: fail("mesh_invalid_json", f"DeviceLane returned invalid JSON: {' '.join(parts)}")

def watch_once(cursor):
    command = [cli, "activities", "watch", "--cursor", cursor, "--limit", "256", "--local", "--json", "--endpoint", endpoint]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    lines = []
    try:
        stop = time.monotonic() + 2
        while time.monotonic() < stop:
            ready, _, _ = select.select([process.stdout], [], [], 0.2)
            if not ready: continue
            line = process.stdout.readline()
            if not line: break
            try: lines.append(json.loads(line))
            except Exception: fail("mesh_invalid_watch_json", "DeviceLane activities watch returned invalid NDJSON.")
            if len(lines) >= 256: break
    finally:
        process.terminate()
        try: process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait()
    return lines

deadline = time.monotonic() + timeout
seen = {"approval": False, "running": False, "reconnecting": False, "resync": False, "terminal": False, "audit": False}
terminal_event = None
terminal_audit = None
metric_state = None
decision = None
status_scope = None
authenticated_controller = False
cursor = "1:0"
while time.monotonic() < deadline:
    status = run("mesh", "status", "--scope", "mesh")
    if status.get("type") == "dashboard_snapshot":
        status_scope = status.get("payload", {}).get("scope")
        for host in status.get("payload", {}).get("hosts", []):
            if (host.get("id") == controller_peer and host.get("trust") == "trusted"
                    and host.get("presence") in {"online", "busy"}):
                authenticated_controller = True

    approvals = run("approvals", "list")
    for item in approvals.get("payload", []):
        resources = item.get("resources", [])
        if (item.get("activity_id") == activity_id and item.get("principal_id") == principal
                and item.get("source_host_id") == source
                and {"workspace_read", "device_lease"}.issubset(set(resources))):
            seen["approval"] = True

    activities = run("activities", "list", "--cursor", cursor, "--limit", "256")
    payload = activities.get("payload", {})
    if payload.get("result") == "resync_required":
        reset = payload.get("oldest_available", {})
        revision = payload.get("snapshot_revision")
        snapshot = run("mesh", "status", "--scope", "mesh").get("payload", {})
        if not isinstance(revision, int) or snapshot.get("revision", -1) < revision:
            fail("resync_snapshot_stale", "Fetch a snapshot at or beyond the requested resync revision before resuming the event stream.")
        if not isinstance(reset.get("epoch"), int) or not isinstance(reset.get("sequence"), int):
            fail("resync_cursor_missing", "The daemon must return an explicit epoch and sequence for resynchronization.")
        cursor = f'{reset["epoch"]}:{reset["sequence"]}'
        seen["resync"] = True
        continue
    if payload.get("result") == "events":
        next_cursor = payload.get("next_cursor", {})
        if isinstance(next_cursor.get("epoch"), int) and isinstance(next_cursor.get("sequence"), int):
            cursor = f'{next_cursor["epoch"]}:{next_cursor["sequence"]}'
    watched = watch_once(cursor)
    streamed_events = [item for item in watched if isinstance(item, dict) and "activity_id" in item]
    for error in watched:
        if error.get("type") == "error" and error.get("payload", {}).get("code") == "resync_required":
            fail("watch_resync_without_cursor", "Recover resync through activities list so the snapshot revision and replacement epoch are explicit.")
    for event in [*payload.get("events", []), *streamed_events]:
        if event.get("activity_id") != activity_id: continue
        resources = set(event.get("resources", []))
        if not {"workspace_read", "device_lease"}.issubset(resources): continue
        state = event.get("state")
        seen["running"] |= state == "running"
        seen["reconnecting"] |= state == "reconnecting"
        if state in {"succeeded", "failed", "cancelled", "denied"}:
            seen["terminal"] = True; terminal_event = event
        decision = event.get("authorization", {}).get("effect", decision)
        metrics = event.get("metrics", {})
        values = list(metrics.values())
        if values and all((isinstance(v, dict) and ((isinstance(v.get("unavailable"), dict) and v["unavailable"].get("reason") == "observer_unavailable") or (isinstance(v.get("available"), dict) and v["available"].get("value", 0) > 0))) for v in values):
            metric_state = "nonzero_or_observer_unavailable"

    audit = run("audit", "list", "--limit", "256")
    for record in audit.get("payload", {}).get("items", []):
        if (record.get("activity_id") == activity_id and record.get("principal_id") == principal
                and record.get("source_host_id") == source
                and record.get("result") in {"succeeded", "failed", "cancelled", "denied"}):
            raw = json.dumps(record, sort_keys=True).lower()
            if not any(word in raw for word in ("private_key", "bearer ", "authorization:", "environment")):
                seen["audit"] = True; terminal_audit = record
    if all(seen.values()) and authenticated_controller and status_scope == "mesh" and metric_state and terminal_event:
        break
    time.sleep(1)

if not all(seen.values()):
    fail("mesh_observation_incomplete", "Keep the Windows operation and Mac approval UI active through disconnect/reconnect and completion.")
if status_scope != "mesh": fail("mesh_scope_unavailable", "Restore authenticated registry connectivity.")
if not authenticated_controller: fail("controller_session_unauthenticated", "Restore the paired controller identity and authenticated mesh session; TCP reachability is insufficient.")
if not metric_state: fail("observer_invalid", "Metrics must be nonzero or explicitly observer_unavailable.")
if decision != "allow": fail("approval_not_allowed", "Approve the exact Windows operation on the target Mac before it starts.")

expected_audit = {
    "activity_id": activity_id,
    "principal_id": principal,
    "source_host_id": source,
    "target_host_id": terminal_event.get("target_host_id"),
    "operation": terminal_event.get("operation"),
    "resources": sorted(terminal_event.get("resources", [])),
    "decision": decision,
    "terminal": terminal_event.get("state"),
    "redaction": None,
}
actual_audit = {
    "activity_id": terminal_audit.get("activity_id"),
    "principal_id": terminal_audit.get("principal_id"),
    "source_host_id": terminal_audit.get("source_host_id"),
    "target_host_id": terminal_audit.get("target_host_id"),
    "operation": terminal_audit.get("operation"),
    "resources": sorted(terminal_audit.get("resources", [])),
    "decision": terminal_audit.get("decision"),
    "terminal": terminal_audit.get("result"),
    "redaction": terminal_audit.get("redacted_message"),
}
if actual_audit != expected_audit:
    fail("audit_record_mismatch", "Preserve the exact target, principal, source, operation, resources, decision, activity, terminal result, and redaction across execution and audit.")
audit_digest = hashlib.sha256(json.dumps(actual_audit, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def pseudonym(value): return "sha256:" + hashlib.sha256(value.encode()).hexdigest()
evidence = {
    "schema": "devicelane.mesh-gate.redacted.v1",
    "redacted": True,
    "controller": pseudonym(controller),
    "controller_peer": pseudonym(controller_peer),
    "principal": pseudonym(principal),
    "source_host": pseudonym(source),
    "activity_id": pseudonym(activity_id),
    "resources": ["workspace_read", "device_lease"],
    "decision": decision,
    "states_observed": sorted(k for k, value in seen.items() if value),
    "metric_status": metric_state,
    "terminal_state": terminal_event.get("state"),
    "audit_record_digest": "sha256:" + audit_digest,
    "recovery": "resync_and_authenticated_reconnect_observed",
    "binary_sha256": binary_sha256,
    "binary_version": binary_version,
}
with open(output, "x", encoding="utf-8") as handle:
    json.dump(evidence, handle, sort_keys=True, indent=2)
PY
}

if [ "${DEVICELANE_REAL_MESH_GATE:-0}" = 1 ] || [ -n "$MESH_CONTROLLER$MESH_ENDPOINT$WINDOWS_PRINCIPAL$WINDOWS_SOURCE_HOST$MESH_ACTIVITY_ID" ]; then
    [ "$(uname -s)" = Darwin ] || repair not_macos "Run the physical mesh gate on the paired Mac."
    [ "$(uname -m)" = arm64 ] || repair wrong_architecture "Run the physical mesh gate on the approved Darwin arm64 Mac."
    PYTHON3=/usr/bin/python3
    [ -x "$PYTHON3" ] || repair python_missing "Install the Apple-provided Python 3 runtime and retry."
    mkdir -p "$OUTPUT_ROOT"
    RUN_DIR="$OUTPUT_ROOT/$JOB_ID"
    [ ! -e "$RUN_DIR" ] || repair output_exists "Choose a new --job-id; existing evidence is never overwritten."
    mkdir -m 700 -p "$RUN_DIR/evidence"
    run_mesh_gate
    [ "$(find "$RUN_DIR/evidence" -type f -print | wc -l | tr -d ' ')" = 1 ] || repair evidence_not_allowlisted "Delete the gate directory; only generated mesh-evidence.json may be retained."
    [ -f "$RUN_DIR/evidence/mesh-evidence.json" ] || repair evidence_not_allowlisted "Only generated mesh-evidence.json may be retained."
    chmod 600 "$RUN_DIR/evidence/mesh-evidence.json"
    printf 'mesh_hardware_gate_evidence=%s\n' "$RUN_DIR/evidence/mesh-evidence.json"
    exit 0
fi

[ "$(uname -s)" = Darwin ] || repair not_macos "Run scripts/mac-hardware-gate.sh on the paired Mac."
[ "$(uname -m)" = arm64 ] || repair wrong_architecture "Run this gate on the approved Darwin arm64 Mac."
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
if [ "${DEVICELANE_REAL_MESH_GATE:-0}" = 1 ] || [ -n "$MESH_CONTROLLER$MESH_ENDPOINT$WINDOWS_PRINCIPAL$WINDOWS_SOURCE_HOST$MESH_ACTIVITY_ID" ]; then
    run_mesh_gate
fi
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
