#!/usr/bin/env bash
# test_linux.sh — build + run the Linux artifact and verify the self-injected
# payload beacons correctly. This is the ground-truth test: a real static ELF is
# built, executed, and its stdout is checked byte-for-byte.
set -euo pipefail
cd "$(dirname "$0")/.."

bash build.sh >/dev/null
micromamba run -n mdev python tools/bin2c.py build/payload_linux.bin build/payload.h
gcc -static -O2 -Ibuild src/stage0/stage0.c -o build/sleepmask_linux

expected="sleepmask: armed | linux x86-64 | self-injected"
rc=0
out="$(./build/sleepmask_linux)" || rc=$?

echo "stdout: ${out}"
echo "exit:   ${rc}"

if [[ "$rc" -eq 0 && "$out" == "$expected" ]]; then
  echo "PASS (linux stage0 self-injection + beacon verified)"
else
  echo "FAIL"
  exit 1
fi
