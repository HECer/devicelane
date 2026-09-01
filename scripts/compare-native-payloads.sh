#!/bin/sh
set -eu

first=$1
second=$2
kind=$3
base=$(realpath "${RUNNER_TEMP:-${TMPDIR:-/tmp}}")
root=$(mktemp -d "$base/devicelane-repro-native.XXXXXX")
cleanup() {
  mount | grep -q " on $root/mount-a " && hdiutil detach "$root/mount-a" >/dev/null 2>&1 || true
  mount | grep -q " on $root/mount-b " && hdiutil detach "$root/mount-b" >/dev/null 2>&1 || true
  case "$root" in "$base"/devicelane-repro-native.*) rm -rf "$root" ;; *) echo "refusing unsafe cleanup" >&2 ;; esac
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$root/a" "$root/b"

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

manifest() {
  tree=$1; output=$2
  (cd "$tree" && find . -mindepth 1 -print | LC_ALL=C sort | while IFS= read -r path; do
    if [ -L "$path" ]; then type=symlink; link=$(readlink "$path"); hash=-
    elif [ -d "$path" ]; then type=directory; link=-; hash=-
    else type=file; link=-; hash=$(sha256sum "$path" | cut -d' ' -f1); fi
    if [ "$(uname -s)" = Darwin ]; then
      mode=$(stat -f '%Lp' "$path"); xattr=$(xattr -l "$path" 2>/dev/null | shasum -a 256 | cut -d' ' -f1)
    else
      mode=$(stat -c '%a' "$path"); xattr=$(getfattr -d -m- --absolute-names "$path" 2>/dev/null | sha256sum | cut -d' ' -f1)
    fi
    printf '%s type=%s mode=%s link=%s xattr=%s hash=%s\n' "$path" "$type" "$mode" "$link" "$xattr" "$hash"
  done) > "$output"
}
manifest "$root/a" "$root/a.manifest"
manifest "$root/b" "$root/b.manifest"
diff -u "$root/a.manifest" "$root/b.manifest"
echo "unsigned $kind normalized payloads are reproducible"
