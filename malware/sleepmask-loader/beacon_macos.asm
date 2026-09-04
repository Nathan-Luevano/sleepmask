; beacon_macos.asm — PIC x86-64 *stealth* beacon for the macOS (Mach-O) host.
;
;   The host-coupling variant of the macOS payload. Entered as a function
;   call from the appender's trampoline (see tools/append_macho.py), it saves
;   every general register, emits a beacon token on fd 1 with a direct XNU
;   syscall (class-tagged: rax = 0x02000000 | SYS_write, SYS_write = 0 — no
;   libSystem, no dyld, nothing to resolve), restores everything, and `ret`s
;   so the host binary continues as if nothing happened.
;
;   PIC: the message is located with one RIP-relative `lea`, so the beacon
;   runs at any slide the kernel chooses.
;
;   It deliberately never touches r15, so the test parks a sentinel there to
;   prove the beacon preserved it end-to-end.
;
;   assemble: nasm -g -f bin -o build/beacon_macos.bin beacon_macos.asm

bits 64

start:
    ; save every GPR first: the host (and its loader) may be holding state in
    ; any of them, and the stealth contract is to hand back all of it
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

    ; ---- write(1, msg, msglen) ------------------------------------------
    mov  rax, 0x2000000    ; (0x02000000 | SYS_write)
    mov  rdi, 1            ; fd = stdout
    lea  rsi, [rel msg]    ; explicit RIP-relative -> PIC from any base
    mov  rdx, msglen
    syscall

    ; ---- hand everything back --------------------------------------------
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rbx
    pop rdx
    pop rcx
    pop rax
    ret

msg:    db  "sleepmask: coupled | macos x86-64 | host continues", 0x0a
msglen  equ $ - msg
