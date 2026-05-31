#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$ROOT/src"
TOOLS_DIR="$ROOT/tools"
DIST_DIR="$ROOT/dist"

mkdir -p "$DIST_DIR" "$ROOT/author"

python3 "$TOOLS_DIR/gen_header.py"

gcc \
  -std=gnu11 \
  -O3 \
  -fPIE \
  -pie \
  -fno-stack-protector \
  -fno-ident \
  -fvisibility=hidden \
  -fno-asynchronous-unwind-tables \
  -fno-unwind-tables \
  -ffunction-sections \
  -fdata-sections \
  -Wall \
  -Wextra \
  -Wno-unused-parameter \
  -Wl,--build-id=none \
  -Wl,--gc-sections \
  "$SRC_DIR/vm.c" \
  -o "$DIST_DIR/0day"

strip -s -R .comment -R .note.ABI-tag -R .note.gnu.property "$DIST_DIR/0day"
dd if=/dev/zero of="$DIST_DIR/void.ns0" bs=4096 count=1 status=none

printf 'Built dist/0day and dist/void.ns0\n'
