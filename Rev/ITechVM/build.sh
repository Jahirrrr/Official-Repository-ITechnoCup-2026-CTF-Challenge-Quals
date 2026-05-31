#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SEED="0x6768"
BLF_SOURCE="$ROOT/../ctf-reverse-clfs6768/handout/client.blf"

if [[ -f "$BLF_SOURCE" ]]; then
    cp "$BLF_SOURCE" "$ROOT/handout/client.blf"
fi
env ITECHVM_SEED="$SEED" python3 "$ROOT/vendor/Compiler/compile.py" "$ROOT/src/flushlog.ivm" "$ROOT/handout/crackme.itech"
make -C "$ROOT/vendor/VM" clean all
cp "$ROOT/vendor/VM/dist/ItechVM" "$ROOT/handout/ItechVM"
chmod +x "$ROOT/handout/ItechVM"
cp "$ROOT/vendor/VM/dist/ItechVM" "$ROOT/solve/ItechVM"
cp "$ROOT/handout/crackme.itech" "$ROOT/solve/crackme.itech"
cp "$ROOT/handout/client.blf" "$ROOT/solve/client.blf"

echo "built handout with ItechVM seed $SEED"
