# stage0.c — the Linux self-injecting loader

The one artifact in this family that is **proven on real metal**, not just
emulated. Where the Windows and macOS layers run their code from *their own*
image's entry point (into the PEB walk / XNU syscall), the Linux artifact
*decouples*: its real entry does the stage-0-to-shellcode handoff the other
layers never have to do on Unix.

## What it does

The executable's real entry (`main`) does **not** run the payload from this
binary's own `.text`. It:

1. `mmap` an anonymous, private, RWX page (`PROT_READ | PROT_WRITE | PROT_EXEC`,
   `MAP_ANONYMOUS`), sized exactly to the embedded payload.
2. `memcpy` the position-independent payload blob into that page.
3. cast the page to a function pointer and jump to it.

The payload therefore executes from **self-chosen RWX memory**, decoupled from
this binary's `.text` — the classic stage-0 → shellcode handoff. On Linux this
matters because a static ELF carries a huge CRT footprint (`~785 KB` total:
`gcc -static` pulls in the C runtime + the `81 B` PIC payload), so the payload
can hide inside a plausible-looking binary and still be the tiny thing that
actually fires.

## How the blob gets in

The 81-byte PIC payload is injected at **build time**. `tools/bin2c.py` emits
`payload.h` defining `payload` (a byte array) and `payload_len`; this file
`#include`s that header. Nothing is linked in — the payload is *data*, not a
symbol, so it leaves no import/no-entry signature in the ELF.

## The beacon

When the payload runs on fd 1 it emits:

```
sleepmask: armed | linux x86-64 | self-injected
```

and exits `0`. That line is the **one native, byte-checked proof** in the whole
family — stdout and exit code are verified against a real `ld.so` map and run.

## Why it is the one layer that ran on metal

The Windows/MacOS layers are "emulated up to the kernel boundary" — they run in
Unicorn from the real entry point, but the kernel they talk to is hand-built.
The Linux artifact is a static ELF that a real loader maps and executes. That
is the load-bearing difference the whole validation model rests on, and it is
why this loader gets its own section.

## Portable scope

The same `mmap`-RWX-copy-jump handoff is portable across Unix targets (Linux,
macOS); on macOS the payload runs the XNU class-tagged `write`/`exit` directly.
On Windows the PE wrapper's entry skips the stage-0 handoff and points straight
at the PEB-resolving shellcode instead — Windows is the one place the loader
*doesn't* do the Unix decoupling.
