#!/usr/bin/env bash
set -euo pipefail

rustc="$1"
shift
rustc_args=("$@")
crate_name=

for ((index = 0; index < ${#rustc_args[@]}; index++)); do
  case "${rustc_args[index]}" in
    --crate-name)
      if ((index + 1 < ${#rustc_args[@]})); then
        crate_name="${rustc_args[index + 1]}"
      fi
      ;;
    --crate-name=*) crate_name="${rustc_args[index]#*=}" ;;
  esac
done

case "$crate_name" in
  devicelane|devicelane_service|devicelane_desktop)
    exec "$rustc" "${rustc_args[@]}" \
      -C link-arg=-Wl,-reproducible \
      -C link-arg=-Wl,-no_adhoc_codesign \
      -C link-arg=-Wl,-no_uuid
    ;;
  *) exec "$rustc" "${rustc_args[@]}" ;;
esac
