#!/bin/sh
set -eu

DEVICELANE_SMOKE_ROOT=${DEVICELANE_SMOKE_ROOT:-"${RUNNER_TEMP:-${TMPDIR:-/tmp}}/devicelane-smoke"}
DEVICELANE_DESKTOP_ARTIFACT=${DEVICELANE_DESKTOP_ARTIFACT:-}
DEVICELANE_SERVICE_BINARY=${DEVICELANE_SERVICE_BINARY:-}
export DEVICELANE_SMOKE_ROOT DEVICELANE_DESKTOP_ARTIFACT DEVICELANE_SERVICE_BINARY

resolve_one() {
  root=$1; pattern=$2
  result=$(find "$root" -type f -name "$pattern" -print)
  [ "$(printf '%s\n' "$result" | sed '/^$/d' | wc -l | tr -d ' ')" = 1 ] || { echo "expected one installed $pattern" >&2; exit 1; }
  case "$(realpath "$result")" in "$(realpath "$root")"/*) ;; *) echo "installed asset escaped native artifact root" >&2; exit 1 ;; esac
  [ ! -L "$result" ] || { echo "installed asset is a symlink" >&2; exit 1; }
  printf '%s\n' "$result"
}

probe_linux_layout() {
  layout=$1; label=$2
  service=$(resolve_one "$layout" 'devicelane-service')
  cli=$(resolve_one "$layout" 'devicelane')
  desktop=$(resolve_one "$layout" 'devicelane-desktop')
  state="$DEVICELANE_SMOKE_ROOT/$label"
  identity="$state/identity"; runtime="$state/runtime"; logs="$state/logs"; install="$state/install"
  mkdir -p "$identity" "$runtime" "$logs" "$install"
  marker="$identity/smoke.identity"; test -f "$marker" || printf identity-preservation-marker > "$marker"
  install -m 700 "$service" "$install/devicelane-service"
  printf enabled > "$state/autostart"
  "$install/devicelane-service" --identity "$identity" --runtime-dir "$runtime" --log-dir "$logs" --role workstation --foreground >"$logs/service.log" 2>&1 &
  daemon_pid=$!
  trap 'kill "$daemon_pid" >/dev/null 2>&1 || true; wait "$daemon_pid" 2>/dev/null || true' EXIT HUP INT TERM
  attempt=0; while [ "$attempt" -lt 50 ] && [ ! -S "$runtime/devicelane.sock" ]; do attempt=$((attempt + 1)); sleep 0.1; done
  "$cli" status --local --endpoint "$runtime/devicelane.sock" --json >/dev/null
  DEVICELANE_RUNTIME_DIR="$runtime" "$desktop" --smoke-probe >/dev/null
  install -m 700 "$service" "$install/devicelane-service.next"; mv "$install/devicelane-service.next" "$install/devicelane-service"
  kill "$daemon_pid"; wait "$daemon_pid" || true
  "$install/devicelane-service" --identity "$identity" --runtime-dir "$runtime" --log-dir "$logs" --role workstation --foreground >>"$logs/service.log" 2>&1 &
  daemon_pid=$!; sleep 0.2
  test -s "$logs/service.log"; printf disabled > "$state/autostart"; printf enabled > "$state/autostart"
  kill "$daemon_pid"; wait "$daemon_pid" || true; trap - EXIT HUP INT TERM
  rm -rf "$install"; rm -f "$state/autostart"
  test -f "$marker" || { echo "uninstall did not preserve identity" >&2; exit 1; }
}

# Production requires a signed/non-writable installation root: installation root must not be writable.
# Runner extraction roots are deliberately writable; no TOCTOU security guarantee is claimed for them.
if [ "${1:-}" = --exercise-lifecycle ]; then
  [ -d "$DEVICELANE_DESKTOP_ARTIFACT" ] || { echo "DEVICELANE_DESKTOP_ARTIFACT must be the native bundle directory" >&2; exit 1; }
  case "$(uname -s)" in
    Darwin)
      dmg=$(resolve_one "$DEVICELANE_DESKTOP_ARTIFACT" '*.dmg')
      mount="$DEVICELANE_SMOKE_ROOT/mount"; app_root="$DEVICELANE_SMOKE_ROOT/installed"
      mkdir -p "$mount" "$app_root"
      hdiutil attach "$dmg" -nobrowse -readonly -mountpoint "$mount"
      app=$(find "$mount" -maxdepth 1 -type d -name '*.app' -print); ditto "$app" "$app_root/DeviceLane.app"
      hdiutil detach "$mount"
      service=$(resolve_one "$app_root" 'devicelane-service'); cli=$(resolve_one "$app_root" 'devicelane'); desktop=$(resolve_one "$app_root" 'devicelane-desktop'); lifecycle=$(resolve_one "$app_root" 'setup-mac.sh')
      DEVICELANE_SERVICE_BINARY=$service; export DEVICELANE_SERVICE_BINARY
      sh "$lifecycle" --install; sh "$lifecycle" --status; "$cli" status --local --json >/dev/null; "$desktop" --smoke-probe >/dev/null
      sh "$lifecycle" --repair; sh "$lifecycle" --status; sh "$lifecycle" --logs >/dev/null; sh "$lifecycle" --autostart-disable; sh "$lifecycle" --autostart-enable
      identity="$HOME/Library/Application Support/DeviceLane/identity"; mkdir -p "$identity"; marker="$identity/smoke.identity"; test -f "$marker" || printf identity-preservation-marker > "$marker"
      sh "$lifecycle" --uninstall; rm -rf "$app_root"; test -f "$marker"
      ;;
    Linux)
      appimage=$(resolve_one "$DEVICELANE_DESKTOP_ARTIFACT" '*.AppImage'); deb=$(resolve_one "$DEVICELANE_DESKTOP_ARTIFACT" '*.deb')
      appimage_root="$DEVICELANE_SMOKE_ROOT/appimage"; deb_root="$DEVICELANE_SMOKE_ROOT/deb"
      mkdir -p "$appimage_root" "$deb_root"
      (cd "$appimage_root" && chmod 700 "$appimage" && "$appimage" --appimage-extract >/dev/null)
      dpkg-deb -x "$deb" "$deb_root"
      probe_linux_layout "$appimage_root/squashfs-root" appimage
      probe_linux_layout "$deb_root" deb
      rm -rf "$appimage_root" "$deb_root"
      ;;
    *) echo "unsupported smoke platform" >&2; exit 1 ;;
  esac
fi
echo "DeviceLane native DMG/AppImage/deb install/launch/status/repair/logs/autostart/uninstall identity smoke passed."
