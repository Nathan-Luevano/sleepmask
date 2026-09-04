#!/usr/bin/env bash
# test_append_linux.sh — the host-coupling ground truth.
#
# Builds a real host program (returns 42, prints one line), couples the
# stealth beacon to it with tools/append_elf.py, and executes the result on
# real metal. PASS requires, byte for byte:
#
#   * the beacon token on fd 1, BEFORE any host output
#   * the host's own output, unharmed
#   * the host's original exit status (42) — i.e. the host really ran
#
# done for BOTH a PIE host (the distro default) and a -no-pie host. This is
# the layer that proves the appender works on a live kernel, not in emulation.
set -uo pipefail
cd "$(dirname "$0")/.."

FAIL=0
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

check() {  # check <label> <expected> <actual>
  if [[ "$2" == "$3" ]]; then
    echo "  ok  $1"
  else
    echo "  FAIL $1"
    echo "       expected: $2"
    echo "       actual:   $3"
    FAIL=1
  fi
}

build_host() {  # build_host <name> <extra gcc flags...>
  local name="$1"; shift
  cat > "$tmp/$name.c" <<'EOF'
#include <unistd.h>
int main(void) {
  const char m[] = "host alive\n";
  (void)!write(1, m, sizeof m - 1);
  return 42;
}
EOF
  gcc -O2 "$@" -o "$tmp/$name" "$tmp/$name.c"
}

BEACON="sleepmask: coupled | linux x86-64 | host continues"
EXPECT="$BEACON
host alive"

for kind in pie no-pie; do
  flags=()
  if [[ $kind == no-pie ]]; then flags=(-no-pie -static); fi
  build_host "host_$kind" "${flags[@]}"

  if ! micromamba run -n mdev python tools/append_elf.py \
      "$tmp/host_$kind" build/beacon_linux.bin "$tmp/host_$kind.coupled" >/dev/null; then
    echo "  FAIL append_elf.py rejected host_$kind"; FAIL=1; continue
  fi

  out=$("$tmp/host_$kind.coupled"; echo "rc=$?")
  body=${out%$'\n'*}         # everything before the last line
  rc=${out##*$'\n'}          # the rc=NN line
  rc=${rc#rc=}

  # host bytes before the beacon must be untouched
  check "$kind: beacon + host output, byte-exact" "$EXPECT" "$body"
  check "$kind: host exit status preserved (42)"  "42" "$rc"

  # the host must still work standalone (we built a copy, but prove it)
  "$tmp/host_$kind" >/dev/null
  check "$kind: pristine host still rc=42" 42 "$?"
done

# structural: the coupled PIE must show one extra PT_LOAD and a new entry
if readelf -hW "$tmp/host_pie.coupled" 2>/dev/null | \
     grep -q 'Entry point address'; then
  entry=$(readelf -hW "$tmp/host_pie.coupled" | awk '/Entry point/{print $4}')
  loads=$(readelf -lW "$tmp/host_pie.coupled" | grep -c 'LOAD')
  orig_loads=$(readelf -lW "$tmp/host_pie" | grep -c 'LOAD')
  check "coupled: PT_LOAD count +1" $((orig_loads + 1)) "$loads"
  echo "  info coupled entry: $entry"
else
  echo "  FAIL readelf missing"; FAIL=1
fi

if [[ $FAIL == 0 ]]; then
  echo "PASS (linux host coupling: beacon fired, host ran, exit code preserved, PIE + no-pie)"
  exit 0
fi
echo "FAIL"
exit 1
