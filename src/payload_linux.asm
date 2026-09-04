; payload_linux.asm — x86-64 SysV PIC payload (no imports, no libc).
;
;   The Linux payload body. Position-independent: the only memory
;   reference is a RIP-relative `lea`, so it runs correctly no matter what
;   base the stage-0 stub maps it at. Behaviour: emit a beacon token on fd 1,
;   then exit(0). All kernel entry is via direct `syscall` — nothing resolved
;   through a CRT or import table.
;
;   assemble: nasm -g -f bin -o build/payload_linux.bin payload_linux.asm

bits 64

    ; ---- write(1, msg, msglen) -----------------------------------------
    mov  rax, 1            ; SYS_write
    mov  rdi, 1            ; fd = stdout
    lea  rsi, [rel msg]    ; explicit RIP-relative -> PIC from any base
    mov  rdx, msglen
    syscall

    ; ---- exit(0) --------------------------------------------------------
    mov  rax, 60           ; SYS_exit
    xor  edi, edi          ; status = 0
    syscall

msg:    db  "sleepmask: armed | linux x86-64 | self-injected", 0x0a
msglen  equ $ - msg
