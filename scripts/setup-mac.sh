#!/usr/bin/env sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
mkdir -p .mesh/registry .mesh/agent .mesh/cli .mesh/workspaces
cargo build --workspace
./target/debug/mesh-cli doctor --identity .mesh/cli
