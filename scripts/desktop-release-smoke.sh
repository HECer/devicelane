#!/bin/sh
set -eu
smoke_base=$(realpath "${RUNNER_TEMP:-${TMPDIR:-/tmp}}")
if [ -n "${DEVICELANE_SMOKE_ROOT:-}" ]; then
  case "$DEVICELANE_SMOKE_ROOT" in /*) ;; *) echo "DEVICELANE_SMOKE_ROOT must be absolute" >&2; exit 1 ;; esac
  mkdir -p "$DEVICELANE_SMOKE_ROOT"; DEVICELANE_SMOKE_ROOT=$(realpath "$DEVICELANE_SMOKE_ROOT")
  case "$DEVICELANE_SMOKE_ROOT" in "$smoke_base"/*) ;; *) echo "smoke root escaped temporary scope" >&2; exit 1 ;; esac
else DEVICELANE_SMOKE_ROOT=$(mktemp -d "$smoke_base/devicelane-smoke.XXXXXX"); fi
DEVICELANE_DESKTOP_ARTIFACT=${DEVICELANE_DESKTOP_ARTIFACT:-}; DEVICELANE_SERVICE_BINARY=${DEVICELANE_SERVICE_BINARY:-}
mounted=; deb_installed=false; deb_package=
cleanup() {
  [ -z "$mounted" ] || hdiutil detach "$mounted" >/dev/null 2>&1 || true
  [ "$deb_installed" = false ] || sudo dpkg -r "$deb_package" >/dev/null 2>&1 || true
  case "$DEVICELANE_SMOKE_ROOT" in "$smoke_base"/devicelane-smoke.*) rm -rf "$DEVICELANE_SMOKE_ROOT" ;; esac
}
trap cleanup EXIT HUP INT TERM
export DEVICELANE_SMOKE_ROOT DEVICELANE_DESKTOP_ARTIFACT DEVICELANE_SERVICE_BINARY
resolve_one() {
  root=$1; pattern=$2; result=$(find "$root" -type f -name "$pattern" -print)
  [ "$(printf '%s\n' "$result" | sed '/^$/d' | wc -l | tr -d ' ')" = 1 ] || { echo "expected one installed $pattern" >&2; exit 1; }
  case "$(realpath "$result")" in "$(realpath "$root")"/*) ;; *) echo "installed asset escaped native artifact root" >&2; exit 1 ;; esac
  [ ! -L "$result" ] || { echo "installed asset is a symlink" >&2; exit 1; }; printf '%s\n' "$result"
}
make_fake_systemctl() {
  fake_bin=$1; fake_state=$2; mkdir -p "$fake_bin" "$fake_state"
  cat > "$fake_bin/systemctl" <<'EOF'
#!/bin/sh
set -eu
state=${FAKE_SYSTEMCTL_STATE:?}; [ "${1:-}" = --user ] && shift; command=${1:-}; shift || true
stop_service() { if [ -f "$state/pid" ]; then kill "$(cat "$state/pid")" >/dev/null 2>&1 || true; wait "$(cat "$state/pid")" 2>/dev/null || true; rm -f "$state/pid"; fi; }
start_service() { exec_line=$(sed -n 's/^ExecStart=//p' "$HOME/.config/systemd/user/devicelane.service"); sh -c "$exec_line" >>"$state/service.log" 2>&1 & echo $! > "$state/pid"; }
case "$command" in
 show-environment|daemon-reload) exit 0 ;; is-active) [ -f "$state/pid" ] && kill -0 "$(cat "$state/pid")" 2>/dev/null ;;
 is-enabled) [ -f "$state/enabled" ] && { echo enabled; exit 0; }; echo disabled; exit 1 ;;
 restart) stop_service; start_service ;; stop) stop_service ;;
 enable) touch "$state/enabled"; [ "${1:-}" != --now ] || { stop_service; start_service; } ;;
 disable) rm -f "$state/enabled"; [ "${1:-}" != --now ] || stop_service ;;
 *) echo "unsupported fake-systemctl command: $command" >&2; exit 1 ;; esac
EOF
  cat > "$fake_bin/journalctl" <<'EOF'
#!/bin/sh
cat "$FAKE_SYSTEMCTL_STATE/service.log" 2>/dev/null || true
EOF
  chmod 700 "$fake_bin/systemctl" "$fake_bin/journalctl"
}
run_lifecycle() { HOME=$home XDG_RUNTIME_DIR=$runtime FAKE_SYSTEMCTL_STATE=$state/systemctl PATH="$fake_bin:$PATH" DEVICELANE_SERVICE_BINARY=$service sh "$lifecycle" "$@" --home "$home"; }
probe_linux_layout() {
  layout=$1; label=$2; service=$(resolve_one "$layout" 'devicelane-service'); cli=$(resolve_one "$layout" 'devicelane'); desktop=$(resolve_one "$layout" 'devicelane-desktop'); lifecycle=$(resolve_one "$layout" 'setup-linux.sh')
  state="$DEVICELANE_SMOKE_ROOT/$label"; home="$state/home"; runtime="$state/runtime"; fake_bin="$state/fake-systemctl"; mkdir -p "$home" "$runtime"; make_fake_systemctl "$fake_bin" "$state/systemctl"
  marker="$home/.local/share/devicelane/identity/smoke.identity"; mkdir -p "$(dirname "$marker")"; printf identity-preservation-marker > "$marker"
  run_lifecycle --install; run_lifecycle --status
  attempt=0; while [ "$attempt" -lt 50 ] && [ ! -S "$runtime/devicelane/devicelane.sock" ]; do attempt=$((attempt + 1)); sleep 0.1; done
  "$cli" status --local --endpoint "$runtime/devicelane/devicelane.sock" --json >/dev/null; DEVICELANE_RUNTIME_DIR="$runtime/devicelane" "$desktop" --smoke-probe >/dev/null
  run_lifecycle --repair; run_lifecycle --logs >/dev/null; run_lifecycle --autostart-disable; run_lifecycle --autostart-enable; run_lifecycle --uninstall
  test -f "$marker" || { echo "uninstall did not preserve identity" >&2; exit 1; }
}
if [ "${1:-}" = --self-test ]; then
  state="$DEVICELANE_SMOKE_ROOT/self-test"; home="$state/home"; fake_bin="$state/fake-systemctl"; mkdir -p "$home/.config/systemd/user"; make_fake_systemctl "$fake_bin" "$state/systemctl"
  printf '[Service]\nExecStart=/bin/sh -c "sleep 30"\n' > "$home/.config/systemd/user/devicelane.service"
  HOME=$home FAKE_SYSTEMCTL_STATE=$state/systemctl "$fake_bin/systemctl" --user restart devicelane.service
  HOME=$home FAKE_SYSTEMCTL_STATE=$state/systemctl "$fake_bin/systemctl" --user is-active --quiet devicelane.service
  HOME=$home FAKE_SYSTEMCTL_STATE=$state/systemctl "$fake_bin/systemctl" --user enable devicelane.service
  HOME=$home FAKE_SYSTEMCTL_STATE=$state/systemctl "$fake_bin/systemctl" --user disable --now devicelane.service
  echo "Linux lifecycle adapter self-test passed"
  exit 0
fi
# Production requires a signed/non-writable installation root: installation root must not be writable.
# Runner extraction roots are deliberately writable; no TOCTOU security guarantee is claimed for them.
if [ "${1:-}" = --exercise-lifecycle ]; then
 [ -d "$DEVICELANE_DESKTOP_ARTIFACT" ] || { echo "DEVICELANE_DESKTOP_ARTIFACT must be the native bundle directory" >&2; exit 1; }
 case "$(uname -s)" in
  Darwin)
   dmg=$(resolve_one "$DEVICELANE_DESKTOP_ARTIFACT" '*.dmg'); mount_point="$DEVICELANE_SMOKE_ROOT/mount"; app_root="$DEVICELANE_SMOKE_ROOT/installed"; mkdir -p "$mount_point" "$app_root"
   hdiutil attach "$dmg" -nobrowse -readonly -mountpoint "$mount_point"; mounted=$mount_point; app=$(find "$mount_point" -maxdepth 1 -type d -name '*.app' -print); ditto "$app" "$app_root/DeviceLane.app"; hdiutil detach "$mount_point"; mounted=
   service=$(resolve_one "$app_root" 'devicelane-service'); cli=$(resolve_one "$app_root" 'devicelane'); desktop=$(resolve_one "$app_root" 'devicelane-desktop'); lifecycle=$(resolve_one "$app_root" 'setup-mac.sh')
   identity="$HOME/Library/Application Support/DeviceLane/identity"; mkdir -p "$identity"; marker="$identity/smoke.identity"; test -f "$marker" || printf identity-preservation-marker > "$marker"
   DEVICELANE_SERVICE_BINARY=$service; export DEVICELANE_SERVICE_BINARY; sh "$lifecycle" --install; sh "$lifecycle" --status; "$cli" status --local --json >/dev/null; "$desktop" --smoke-probe >/dev/null
   sh "$lifecycle" --repair; sh "$lifecycle" --status; sh "$lifecycle" --logs >/dev/null; sh "$lifecycle" --autostart-disable; sh "$lifecycle" --autostart-enable; sh "$lifecycle" --uninstall; test -f "$marker" ;;
  Linux)
   appimage=$(resolve_one "$DEVICELANE_DESKTOP_ARTIFACT" '*.AppImage'); deb=$(resolve_one "$DEVICELANE_DESKTOP_ARTIFACT" '*.deb'); appimage_root="$DEVICELANE_SMOKE_ROOT/appimage"; deb_root="$DEVICELANE_SMOKE_ROOT/deb"; mkdir -p "$appimage_root" "$deb_root"
   (cd "$appimage_root" && chmod 700 "$appimage" && "$appimage" --appimage-extract >/dev/null); dpkg-deb -x "$deb" "$deb_root"; probe_linux_layout "$appimage_root/squashfs-root" appimage; probe_linux_layout "$deb_root" deb
   if [ "${DEVICELANE_ALLOW_DPKG_SMOKE:-0}" = 1 ]; then
    [ "${DEVICELANE_HOSTED_CI:-0}" = 1 ] && [ "${GITHUB_ACTIONS:-false}" = true ] || { echo "dpkg smoke is restricted to hosted CI" >&2; exit 1; }
    deb_package=$(dpkg-deb -f "$deb" Package)
    if dpkg-query -W "$deb_package" >/dev/null 2>&1; then echo "refusing dpkg smoke because package is already installed" >&2; exit 1; fi
    deb_installed=true; sudo dpkg -i "$deb"; dpkg-query -W "$deb_package" >/dev/null; sudo dpkg -r "$deb_package"; deb_installed=false
   fi ;;
  *) echo "unsupported smoke platform" >&2; exit 1 ;; esac
fi
echo "DeviceLane native DMG/AppImage/deb install/launch/status/repair/logs/autostart/uninstall identity smoke passed."
