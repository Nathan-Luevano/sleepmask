#!/usr/bin/env bash
# make_native_test.sh — produce the run-on-real-hardware test bundle.
#
# Builds the two harmless, self-contained test binaries (the Windows probe and
# the macOS beacon) and stages them together with a RUN-ME note in
# build/native-test/. That folder is the thing to copy onto a machine and run:
#
#   build/native-test/probe_windows.exe   -> run on Windows 11 (x64)
#   build/native-test/sleepmask_macho     -> run on macOS (x86-64 / Rosetta)
#   build/native-test/RUN-ME.txt          -> how to run + what to send back
#
# Run from anywhere:  bash tools/make_native_test.sh
set -euo pipefail
cd "$(dirname "$0")/.."
PY="micromamba run -n mdev python"

echo "== assemble all PIC blobs (nasm -f bin)"
bash build.sh

echo
echo "== build the two native test binaries"
$PY tools/mk_pe.py build/probe_windows.bin build/probe_windows.exe --console
$PY tools/mk_macho.py build/sleepmask_macho

echo
echo "== stage the bundle in build/native-test/"
rm -rf build/native-test
mkdir -p build/native-test
cp -p build/probe_windows.exe build/native-test/probe_windows.exe
cp -p build/sleepmask_macho build/native-test/sleepmask_macho
chmod +x build/native-test/sleepmask_macho

cat > build/native-test/RUN-ME.txt <<'RUNME'
sleepmask — native test bundle
==============================
Two harmless, self-contained test binaries. Run them on your own machine to
see whether the position-independent, zero-import, resolve-everything-at-
runtime shellcode concept actually works on a real OS loader. Both are
read-only about the outside world: no network, no other process touched, they
print a report and (on Windows) write one small text file, then exit 0.

WHAT IS IN HERE
---------------
  probe_windows.exe   Windows 11 x64  (the one to run on your PC)
  sleepmask_macho     macOS x86-64    (Intel, or Apple Silicon under Rosetta)

HOW TO RUN
----------
Windows 11 (x64):
  1. Open a terminal in the folder containing probe_windows.exe.
  2. Run:   .\probe_windows.exe
  3. Expected on stdout (a line per resolved syscall), then exit code 0:

       sleepmask probe - windows x64 (pic, no imports)
       ntdll base: 0x...
       NtTerminateCurrentProcessEx: 0x...
       NtWriteFile: 0x...
       NtCreateFile: 0x...
       NtClose: 0x...
       created sleepmask_probe.txt: 0x0000000000000000
       done - exit 0

     It also writes sleepmask_probe.txt next to itself with the same text.
     Windows SmartScreen may flag the unsigned exe -> "More info" ->
     "Run anyway".

macOS (Intel x86-64; Apple Silicon runs it under Rosetta):
  1. In a terminal:   chmod +x sleepmask_macho
  2. Run:             ./sleepmask_macho
  3. Expected on stdout, then exit code 0:

       sleepmask: armed | macos x86-64 | self-injected

     If Gatekeeper quarantines it:  xattr -d com.apple.quarantine sleepmask_macho

IF IT FAILS / MISFIRES
----------------------
- Windows: if it faults, the Windows Error Reporting dialog shows the exact
  faulting module offset. Screenshot it (or note the offset) and send it back.
- Windows: if stdout is empty but the process exited, cat sleepmask_probe.txt
  — the report is written there too.
- macOS: if it is killed (SIGKILL) before printing, it is Gatekeeper /
  signature related, not the code — try the xattr line above, or on Apple
  Silicon re-sign ad-hoc:  codesign -s - --force sleepmask_macho
- Send back: the exact command you ran, the full stdout/stderr, the exit code
  (echo $?), and the OS + architecture (winver / sysctl -n machdep.cpu.brand_string).

WHY THIS IS THE PROOF
-----------------------
These blobs import nothing. The Windows one finds its own syscall numbers by
walking the live PEB -> ntdll.dll export directory at runtime and reading the
numbers out of the export stub prologues — no import table, no hard-coded
syscall numbers, no CRT. If it prints the report and exits 0, the whole
resolve-at-runtime chain worked against the real Windows loader. The macOS one
uses XNU class-tagged syscalls the same way (write + exit) and exits 0.
RUNME

echo
echo "bundle ready:"
ls -l build/native-test/
echo
echo "copy the whole build/native-test/ folder to the target machine and run"
echo "the two binaries per RUN-ME.txt. Send the output back if a step fails."
