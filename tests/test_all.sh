#!/usr/bin/env bash
# test_all.sh — the full sleepmask deployable + host-coupling matrix, one command.
#
#   1. build           assemble every PIC blob (nasm -f bin)
#   2. linux           GROUND TRUTH: real static ELF, executed, stdout byte-checked
#   3. linux-coupled   host-coupling ground truth: append_elf.py onto a real host,
#                      executed on metal (PIE + -no-pie), beacon-first + exit 42
#   4. windows         PE32+ exe: static fields + independent parse + run from entry
#   5. windows-coupled append_pe.py onto a host PE; run in Unicorn (real + decoy nr)
#   6. macos           Mach-O: static fields + independent walk + run at base + slide
#   7. macos-coupled   append_macho.py onto a host Mach-O; run in Unicorn (base + slide)
#   8. harness         the raw windows blob in Unicorn (PEB walk, masked syscalls)
#
# Run from anywhere:  bash malware/sleepmask-loader/test_all.sh
# Exits 0 only if every layer passes.
set -uo pipefail
cd "$(dirname "$0")"

PY="micromamba run -n mdev python"
pass=()
fail=()

run_step() {
  local name="$1"; shift
  echo
  echo "=================================================================="
  echo "==> ${name}"
  echo "=================================================================="
  if "$@"; then
    pass+=("${name}")
  else
    fail+=("${name}")
  fi
}

# --- 1. build ----------------------------------------------------------------
run_step "build (nasm -f bin)" bash build.sh

# --- 2. linux deployable -----------------------------------------------------
run_step "linux (real ELF, executed)" bash test/test_linux.sh

# --- 3. linux host-coupling (ground truth, on metal) -------------------------
run_step "linux-coupled (append_elf, PIE + no-pie, on metal)" \
  bash test/test_append_linux.sh

# --- 4. windows deployable ---------------------------------------------------
run_step "windows (PE32+ + unicorn entry)" \
  ${PY} test/test_windows.py

# --- 5. windows host-coupling ------------------------------------------------
run_step "windows-coupled (append_pe + unicorn, real + decoy nr)" \
  ${PY} test/test_append_windows.py

# --- 6. macos deployable -----------------------------------------------------
run_step "macos (Mach-O + unicorn xnu)" \
  ${PY} test/test_macos.py

# --- 7. macos host-coupling --------------------------------------------------
run_step "macos-coupled (append_macho + unicorn, base + slide)" \
  ${PY} test/test_append_macos.py

# --- 8. raw blob harness -----------------------------------------------------
run_step "harness (raw blob, PEB walk)" \
  ${PY} test/run_harness.py

# --- summary ------------------------------------------------------------------
echo
echo "=================================================================="
echo "RESULTS"
echo "=================================================================="
for p in "${pass[@]}"; do echo "  PASS  ${p}"; done
for f in "${fail[@]}"; do echo "  FAIL  ${f}"; done
echo "------------------------------------------------------------------"
if [[ ${#fail[@]} -eq 0 ]]; then
  echo "ALL ${#pass[@]} LAYERS GREEN"
  exit 0
else
  echo "${#fail[@]} LAYER(S) FAILED"
  exit 1
fi
