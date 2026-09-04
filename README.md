# sleepmask — a cross-platform malware family

One position-independent shellcode base, three deployable artifacts, all
self-contained (no imports, no IAT, no CRT — every kernel entry is a direct
`syscall`, every API address resolved at runtime from the process's own
loader structures). Build it, ship it, run it.

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

To couple the payload into a *host* process instead of shipping a wrapper:
`tools/bin2c.py build/payload_linux.bin payload.h` emits the C header,
`stage0/stage0.c` is the reference dropper (mmap RWX → memcpy → call). Drop
that two-function pattern into any C/Go/Rust host and the 81-byte blob is
yours. On Windows the equivalent is already the exe: its entry is a 9-byte
trampoline (`call` the shellcode, spin on `pause` after it returns) around the
1267-byte blob.

## Build + verify

```
bash malware/sleepmask-loader/test_all.sh
```

Five layers, all green:

```
  PASS  build (nasm -f bin)
  PASS  linux (real ELF, executed)
  PASS  windows (PE32+ + unicorn entry)
  PASS  macos (Mach-O + unicorn xnu)
  PASS  harness (raw blob, PEB walk)
------------------------------------------------------------------
ALL 5 LAYERS GREEN
```

- **build** — `nasm -g -f bin` every `.asm` in the loader dir.
- **linux** — the ground truth: `gcc -static` builds the real ELF, executes it,
  byte-checks stdout and the exit code.
- **windows** — `tools/mk_pe.py` writes the PE32+; the test validates header
  fields, cross-checks with the independent stdlib-only PE reader in
  `research/pe/`, then loads the *whole image* in Unicorn and runs it from the
  real entry point (trampoline → blob → `ret` landing in the spin loop),
  asserting the syscall trace (`0x2B 0x2B`: two `NtProtectVirtualMemory`
  calls), the done flag, and the 26 `KeQuerySystemTime` polls.
- **macos** — `tools/mk_macho.py` writes the Mach-O; the test walks the load
  commands with an independent generic walker, then runs it in Unicorn with an
  XNU syscall class emulator (`0x2000000 | nr`) — `write` captured, `exit`
  clean — at the nominal base *and* slid `+0x1000` (PIC check).
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
  stage0/stage0.c      the coupler: mmap RWX → memcpy → call (unix droppers)
  tools/bin2c.py       blob → C header (embed the payload anywhere)
  tools/mk_pe.py       PE32+ writer (the .exe)
  tools/mk_macho.py    Mach-O writer (the macos executable)
  build.sh             nasm every .asm → build/*.bin
  test_all.sh          the 5-layer matrix, one command
  test/                linux ground-truth, windows PE, macos Mach-O, raw harness
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
- Blog posts documenting each mechanism ship in `blogs/` (flagship:
  `sleep-masking-direct-syscalls`).
