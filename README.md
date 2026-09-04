# sleepmask — a cross-platform malware family

One position-independent shellcode base, three deployable artifacts, and
three appenders that graft the beacon onto a live host binary — all
self-contained (no imports, no IAT, no CRT — every kernel entry is a direct
`syscall`, every API address resolved at runtime from the process's own
loader structures). Build it, ship it, run it — or graft it into a process
that wasn't asking for it.

## The family

| artifact | format | size | what it does when you run it |
|---|---|---|---|
| `malware/sleepmask-loader/build/sleepmask.exe` | PE32+ x64, no imports | 2048 B | walks the PEB (`gs:[0x60]`) → `Ldr` → in-load-order list → `ntdll.dll`; parses the export dir; reads the syscall numbers for `NtDelayExecution`, `NtProtectVirtualMemory`, `KeQuerySystemTime` straight out of the export stub prologues (`B8 nn 00 00 00 0F 05`); marks the `NtDelayExecution` text RWX and overwrites it with a 12-byte mask (`mov rax,<stub>; jmp rax`) so every sleep the process takes routes through a stub that polls `KeQuerySystemTime` and restores the original bytes on return; re-protects, sets its done flag, and returns into the loader trampoline (which idles in a `pause` loop with the mask live in-process). |
| `malware/sleepmask-loader/build/sleepmask_linux` | static ELF x86-64 (`gcc -static`) | ~785 KB (CRT + 81 B payload) | stage-0 dropper: `mmap` a fresh RWX page, `memcpy` the 81-byte PIC payload in, jump to it. The payload emits the beacon `sleepmask: armed \| linux x86-64 \| self-injected` on fd 1 and `exit(0)`. Ground truth: **executed for real, stdout byte-checked.** |
| `malware/sleepmask-loader/build/sleepmask_macho` | Mach-O `MH_EXECUTE` x86_64 | 4177 B | same 81-byte PIC payload (XNU syscalls: `write` = `0x2000000`, `exit` = `0x2000001`), embedded in a two-load-command executable (`LC_SEGMENT_64` `__TEXT` + `LC_MAIN`). Beacon: `sleepmask: armed \| macos x86-64 \| self-injected`. |

Everything is **position-independent**: the payloads reference only
RIP-relative / `call/pop`-resolved addresses, so they run at any base — the
stage-0 stub maps them at its own discretion, and the macOS test re-runs the
image at a `+0x1000` slide to prove it.

## Deploying

All three are single files with zero runtime dependencies:

```
# linux amd64 — static, runs anywhere with a kernel
scp build/sleepmask_linux  host: && ssh host ./sleepmask_linux

# windows x64 — PE32+, no imports; the PEB walk finds ntdll in any process
#               context it lands in
sleepmask.exe

# macos x86_64 — Intel Macs natively; Apple Silicon under Rosetta
scp build/sleepmask_macho mac: && ssh mac 'chmod +x ./sleepmask_macho && ./sleepmask_macho'
```

To couple the payload into a *host* process instead of shipping a wrapper, the
appenders do the graft per format. Each appends the beacon as a new RWX
section, re-points the host entry to a 10-byte trampoline
(`call <beacon>; jmp <old entry>`), and leaves the host's original bytes
byte-identical. The beacon saves all 15 GPRs, fires its `write`, and `ret`s —
so the host continues as if it had never been preceded:

```
tools/append_elf.py   <host.elf>   <beacon.bin> <out.elf>   relocates phdr, re-points PT_PHDR
tools/append_pe.py    <host.exe>   <beacon.bin> <out.exe>   adds a .bcon RWX section, re-points entry
tools/append_macho.py <host.macho> <beacon.bin> <out.macho> adds a __bcon segment, re-points LC_MAIN
```

`tools/bin2c.py build/payload_linux.bin payload.h` + `stage0/stage0.c` remain
the manual path (emit a C header, mmap RWX → memcpy → call) for hosts you'd
rather graft by hand.

## Build + verify

```
bash malware/sleepmask-loader/test_all.sh
```

Eight layers, all green:

```
  PASS  build (nasm -f bin)
  PASS  linux (real ELF, executed)
  PASS  linux-coupled (append_elf, PIE + no-pie, on metal)
  PASS  windows (PE32+ + unicorn entry)
  PASS  windows-coupled (append_pe + unicorn, real + decoy nr)
  PASS  macos (Mach-O + unicorn xnu)
  PASS  macos-coupled (append_macho + unicorn, base + slide)
  PASS  harness (raw blob, PEB walk)
------------------------------------------------------------------
ALL 8 LAYERS GREEN
```

- **build** — `nasm -g -f bin` every `.asm` in the loader dir.
- **linux** — the ground truth: `gcc -static` builds the real ELF, executes it,
  byte-checks stdout and the exit code.
- **linux-coupled** — the host-coupling ground truth: `tools/append_elf.py`
  grafts the beacon onto a *real* gcc host (PIE and `-no-pie`), and the result
  is executed on real metal — beacon line first, host line byte-exact, host
  exit status (42) preserved, `PT_LOAD` count +1.
- **windows** — `tools/mk_pe.py` writes the PE32+; the test validates header
  fields, cross-checks with the independent stdlib-only PE reader in
  `research/pe/`, then loads the *whole image* in Unicorn and runs it from the
  real entry point (trampoline → blob → `ret` landing in the spin loop),
  asserting the syscall trace (`0x2B 0x2B`: two `NtProtectVirtualMemory`
  calls), the done flag, and the 26 `KeQuerySystemTime` polls.
- **windows-coupled** — `tools/append_pe.py` appends a `.bcon` RWX section and
  re-points the entry; the coupled image is run in Unicorn from its real entry
  against a fake PEB/ntdll, twice — real syscall numbers and decoy numbers —
  proving the nr is read from the export prologue. Asserts beacon-first write,
  host write, exit 42, and the R15 sentinel intact.
- **macos** — `tools/mk_macho.py` writes the Mach-O; the test walks the load
  commands with an independent generic walker, then runs it in Unicorn with an
  XNU syscall class emulator (`0x2000000 | nr`) — `write` captured, `exit`
  clean — at the nominal base *and* slid `+0x1000` (PIC check).
- **macos-coupled** — `tools/append_macho.py` appends a `__bcon` segment and
  re-points `LC_MAIN`; the coupled image is run in Unicorn XNU at the nominal
  base *and* slid `+0x1000`, asserting beacon-first write, host write, exit
  42, and the RBX/R15 sentinels intact.
- **harness** — the raw 1267-byte Windows blob against a hand-built fake
  PEB/ntdll: PEB walk → export parse → syscall-number extraction →
  `NtProtectVirtualMemory(RWX)` → mask install → byte restore. The masked
  `NtDelayExecution` comes back byte-identical to
  `b8 3d 00 00 00 0f 05 c3 00 00 00 00` (original nr `0x3d` preserved).

Requires the `mdev` micromamba env (python 3.12 + capstone + keystone +
unicorn) for the emulated layers; the linux layer is pure gcc.

## Layout

```
malware/sleepmask-loader/
  sleepmask.asm        windows PIC shellcode (1267 B): PEB walk + sleep mask
  payload_linux.asm    linux PIC payload (81 B): beacon + exit
  payload_macos.asm    macos PIC payload (81 B): XNU beacon + exit
  beacon_linux.asm     host-coupling beacon (linux): save 15 GPRs, write, ret
  beacon_windows.asm   host-coupling beacon (win): PEB-walk ntdll, write, ret
  beacon_macos.asm     host-coupling beacon (macos): XNU write, ret
  host_win.asm         the "victim" host the windows test couples onto
  host_macos.asm       the "victim" host the macos test couples onto
  stage0/stage0.c      the manual coupler: mmap RWX → memcpy → call (unix)
  tools/bin2c.py       blob → C header (embed the payload anywhere)
  tools/append_elf.py  graft the beacon into a host ELF (relocate phdr)
  tools/append_pe.py   graft the beacon into a host PE (new .bcon section)
  tools/append_macho.py graft the beacon into a host Mach-O (new __bcon seg)
  tools/mk_pe.py       PE32+ writer (the .exe)
  tools/mk_macho.py    Mach-O writer (the macos executable)
  build.sh             nasm every .asm → build/*.bin
  test_all.sh          the 8-layer matrix, one command
  test/                deployables + host-coupling (linux/win/macos) + harness
blogs/<slug>/          the field notes, one dir per post, real captured output
research/pe/           stdlib-only PE reader + offline syscall-stub toolchain
```

## Status, stated plainly

- **Linux deployable: proven on hardware** — real process, real `write`, real
  exit, byte-checked.
- **Windows / macOS deployables: proven to the CPU boundary** — the full image
  runs from its real entry point in Unicorn with only the kernel interface
  emulated (PEB/ntdll layout for Windows, XNU syscall class for macOS), and
  every wrapper is double-parsed by an independent reader. What this does not
  yet include: a run on actual Windows/macOS metal. The shellcode makes no
  assumptions the harness hasn't already exercised — PEB offsets, LDR entry
  layout, export-dir fields, stub prologue format — so the remaining risk is
  in the kernel contract, not the code.
- **Host coupling: proven on hardware (Linux) and to the CPU boundary
  (Windows/macOS)** — the appenders graft the beacon onto a real host binary
  and re-point its entry to a 10-byte `call <beacon>; jmp <old entry>`
  trampoline, leaving the host's own bytes untouched. The Linux graft is
  executed on real metal (PIE and no-pie: host stdout byte-exact, exit status
  preserved, one extra `PT_LOAD`). The Windows/macOS grafts run the coupled
  image from its real entry in Unicorn — beacon fires before the host, the
  host's own write and exit code follow, and GPR sentinels parked in
  callee-saved registers survive the whole run.
- Blog posts documenting each mechanism ship in `blogs/` (flagship:
  `sleep-masking-direct-syscalls`).
