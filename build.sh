#!/usr/bin/env bash
# Assemble all PIC shellcode in src/ -> build/<name>.bin
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p build
for src in src/*.asm; do
  name="$(basename "${src%.asm}")"
  nasm -g -f bin -o "build/${name}.bin" "${src}"
  echo "assembled build/${name}.bin ($(stat -c%s "build/${name}.bin") bytes)"
done
