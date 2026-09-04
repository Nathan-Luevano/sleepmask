; payload_macos.asm — x86-64 Mach (XNU) PIC payload (no imports, no libSystem).
;
;   The malware body for macOS. Position-independent (RIP-relative `lea` only),
;   so the stage-0 stub can map it at any base. Behaviour: emit a beacon token
;   on fd 1, then exit(0).
;
;   XNU x86-64 syscalls carry a class tag: eax = (0x2000000 | nr) for the
;   inherited-Unix (BSD) class. SYS_write = 0, SYS_exit = 1.
;
;   assemble: nasm -g -f bin -o build/payload_macos.bin payload_macos.asm

bits 64

    ; ---- write(1, msg, msglen) -----------------------------------------
    mov  rax, 0x2000000    ; (0x2000000 | SYS_write)
    mov  rdi, 1            ; fd = stdout
    lea  rsi, [rel msg]    ; explicit RIP-relative -> PIC from any base
    mov  rdx, msglen
    syscall

    ; ---- exit(0) --------------------------------------------------------
    mov  rax, 0x2000001    ; (0x2000000 | SYS_exit)
    xor  edi, edi          ; status = 0
    syscall

msg:    db  "sleepmask: armed | macos x86-64 | self-injected", 0x0a
msglen  equ $ - msg
