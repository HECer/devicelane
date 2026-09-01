#!/bin/sh
set -eu

first=$1
second=$2
kind=$3
root=${RUNNER_TEMP:-${TMPDIR:-/tmp}}/devicelane-repro-native
rm -rf "$root"; mkdir -p "$root/a" "$root/b"

one() {
  dir=$1; pattern=$2
  values=$(find "$dir" -type f -name "$pattern" -print)
  [ "$(printf '%s\n' "$values" | sed '/^$/d' | wc -l | tr -d ' ')" = 1 ] || { echo "expected exactly one $pattern in $dir" >&2; exit 1; }
  printf '%s\n' "$values"
}

case "$kind" in
  dmg)
    a=$(one "$first" '*.dmg'); b=$(one "$second" '*.dmg')
    mkdir -p "$root/mount-a" "$root/mount-b"
    hdiutil attach "$a" -nobrowse -readonly -mountpoint "$root/mount-a" >/dev/null
    hdiutil attach "$b" -nobrowse -readonly -mountpoint "$root/mount-b" >/dev/null
    ditto "$root/mount-a/DeviceLane.app" "$root/a/DeviceLane.app"
    ditto "$root/mount-b/DeviceLane.app" "$root/b/DeviceLane.app"
    hdiutil detach "$root/mount-a" >/dev/null; hdiutil detach "$root/mount-b" >/dev/null
    ;;
  linux)
    a=$(one "$first" '*.AppImage'); b=$(one "$second" '*.AppImage')
    (cd "$root/a" && chmod 700 "$a" && "$a" --appimage-extract >/dev/null)
    (cd "$root/b" && chmod 700 "$b" && "$b" --appimage-extract >/dev/null)
    da=$(one "$first" '*.deb'); db=$(one "$second" '*.deb')
    dpkg-deb -x "$da" "$root/a/deb"; dpkg-deb -x "$db" "$root/b/deb"
    ;;
  *) echo "unsupported payload kind: $kind" >&2; exit 1 ;;
esac

(cd "$root/a" && find . -type f -print0 | sort -z | xargs -0 sha256sum) > "$root/a.manifest"
(cd "$root/b" && find . -type f -print0 | sort -z | xargs -0 sha256sum) > "$root/b.manifest"
diff -u "$root/a.manifest" "$root/b.manifest"
echo "unsigned $kind normalized payloads are reproducible"
