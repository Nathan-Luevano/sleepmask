; host_macos.asm — the "victim": an x86-64 Mach-O host main, PIC asm.
;
;   A real program that does its own job: writes "host alive\n" to fd 1, then
;   dies with exit(42) — a non-zero status the test asserts survives the
;   coupling. Like the beacon it uses direct XNU syscalls (class-tagged
;   rax = 0x02000000 | nr; SYS_write = 0, SYS_exit = 1), so there is no
;   libSystem, no dyld, nothing to resolve at runtime.
;
;   Entered the way the kernel enters an image (LC_MAIN entryoff), and never
;   returns: it terminates. It deliberately never touches r15, so the test
;   parks a sentinel there to prove the beacon preserved it end-to-end.
;
;   assemble: nasm -g -f bin -o build/host_macos.bin host_macos.asm

bits 64

start:
    ; ---- 1. write(1, msg, msglen) -----------------------------------------
    mov  rax, 0x2000000    ; (0x02000000 | SYS_write)
    mov  rdi, 1            ; fd = stdout
    lea  rsi, [rel msg]    ; explicit RIP-relative -> PIC from any base
    mov  rdx, msglen
    syscall

    ; ---- 2. exit(42) ------------------------------------------------------
    mov  rax, 0x2000001    ; (0x02000000 | SYS_exit)
    mov  edi, 42           ; non-zero status the test must observe
    syscall

msg:    db  "host alive", 0x0a
msglen  equ $ - msg
