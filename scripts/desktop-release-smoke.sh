#!/bin/sh
set -eu

DEVICELANE_SMOKE_ROOT=${DEVICELANE_SMOKE_ROOT:-"${RUNNER_TEMP:-${TMPDIR:-/tmp}}/devicelane-smoke"}
DEVICELANE_SERVICE_BINARY=${DEVICELANE_SERVICE_BINARY:-"$(pwd)/target/release/devicelane-service"}
export DEVICELANE_SMOKE_ROOT DEVICELANE_SERVICE_BINARY
if [ "${1:-}" = --exercise-lifecycle ]; then
  case "$(uname -s)" in
    Darwin) identity="$HOME/Library/Application Support/DeviceLane/identity" ;;
    Linux)
      if command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
        identity="$HOME/.local/share/devicelane/identity"
      else
        identity="$DEVICELANE_SMOKE_ROOT/identity"
      fi
      ;;
    *) identity="$DEVICELANE_SMOKE_ROOT/identity" ;;
  esac
else
  identity="$DEVICELANE_SMOKE_ROOT/identity"
fi
marker="$identity/smoke.identity"

test -f "$DEVICELANE_SERVICE_BINARY" || { echo "DEVICELANE_SERVICE_BINARY is missing: $DEVICELANE_SERVICE_BINARY" >&2; exit 1; }
mkdir -p "$identity"
test -f "$marker" || printf '%s' identity-preservation-marker > "$marker"

# A production installation root must be signed/admin-owned: installation root must not be writable.
# Hash validation narrows accidental replacement but is not a TOCTOU security guarantee.
case "${1:-}" in
  --exercise-lifecycle)
    case "$(uname -s)" in
      Darwin) lifecycle=./scripts/setup-mac.sh ;;
      Linux)
        if ! command -v systemctl >/dev/null 2>&1 || ! systemctl --user show-environment >/dev/null 2>&1; then
          install_root="$DEVICELANE_SMOKE_ROOT/install"
          runtime="$DEVICELANE_SMOKE_ROOT/runtime"
          logs="$DEVICELANE_SMOKE_ROOT/logs"
          mkdir -p "$install_root" "$runtime" "$logs"
          install -m 700 "$DEVICELANE_SERVICE_BINARY" "$install_root/devicelane-service.next"
          mv "$install_root/devicelane-service.next" "$install_root/devicelane-service"
          printf enabled > "$DEVICELANE_SMOKE_ROOT/autostart"
          "$install_root/devicelane-service" --identity "$identity" --runtime-dir "$runtime" --log-dir "$logs" --role workstation --foreground >"$logs/service.log" 2>&1 &
          daemon_pid=$!
          trap 'kill "$daemon_pid" >/dev/null 2>&1 || true; wait "$daemon_pid" 2>/dev/null || true' EXIT HUP INT TERM
          attempt=0
          while [ "$attempt" -lt 50 ] && [ ! -S "$runtime/devicelane.sock" ]; do attempt=$((attempt + 1)); sleep 0.1; done
          ./target/release/devicelane status --local --endpoint "$runtime/devicelane.sock" --json >/dev/null
          install -m 700 "$DEVICELANE_SERVICE_BINARY" "$install_root/devicelane-service.next"
          mv "$install_root/devicelane-service.next" "$install_root/devicelane-service"
          test -f "$logs/service.log"
          printf disabled > "$DEVICELANE_SMOKE_ROOT/autostart"
          printf enabled > "$DEVICELANE_SMOKE_ROOT/autostart"
          kill "$daemon_pid"; wait "$daemon_pid" || true
          trap - EXIT HUP INT TERM
          rm -f "$install_root/devicelane-service" "$DEVICELANE_SMOKE_ROOT/autostart"
          test -f "$marker" || { echo "uninstall did not preserve identity" >&2; exit 1; }
          echo "DeviceLane Linux foreground fallback install/status/repair/logs/autostart/uninstall identity smoke passed."
          exit 0
        fi
        lifecycle=./scripts/setup-linux.sh
        ;;
      *) echo "unsupported smoke platform" >&2; exit 1 ;;
    esac
    sh "$lifecycle" --install
    sh "$lifecycle" --status
    ./target/release/devicelane status --local --json >/dev/null
    sh "$lifecycle" --repair
    sh "$lifecycle" --logs >/dev/null
    sh "$lifecycle" --autostart-disable
    sh "$lifecycle" --autostart-enable
    sh "$lifecycle" --uninstall
    ;;
esac
test -f "$marker" || { echo "uninstall did not preserve identity" >&2; exit 1; }
echo "DeviceLane Unix first-run install/status/repair/logs/autostart/uninstall identity smoke passed."
