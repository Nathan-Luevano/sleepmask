; sleepmask.asm — PIC x64 shellcode: PEB-resolved direct syscalls + sleep masking
;
; assemble: nasm -g -f bin -o build/sleepmask.bin sleepmask.asm
;
; What it does (build+test only, never deployed):
;   1. PEB (gs:0x60) -> PEB_Ldr (PEB+0x18) -> InLoadOrder list -> ntdll.dll
;   2. Parse PE exports (DataDirectory[0]) -> EAT / ENT / ORD
;   3. Resolve NtDelayExecution, NtProtectVirtualMemory
;   4. Read each syscall nr from its export prologue (forward-scan for the
;      nr mov: `B8 <nr:4>` or `48 C7 C0 <nr:4>`)
;   5. NtProtectVirtualMemory(RWX) over the NtDelayExecution text
;   6. Patch NtDelayExecution: `mov rax,<stub>; jmp rax` (12 bytes)
;   7. call [NtDelayExecution] -> stub: poll the KUSER_SHARED_DATA clock
;      ([0x7FFE0014] = SystemTime), restore bytes, ret
;   8. NtProtectVirtualMemory(restore); done_flag=1; ret
;
; PIC: base (r12) resolved at entry via call/pop; every data ref is
;   [r12 + (label - sym_base)]  which nasm folds to a constant displacement.

bits 64
org 0

; ---------------------------------------------------------------------------
; entry
; ---------------------------------------------------------------------------
start:
    ; save the caller's callee-saved regs FIRST (r12 will hold the base, so it
    ; must be parked on the stack before the call/pop below clobbers it)
    push rbx
    push rsi
    push rdi
    push rbp
    push r12
    push r13
    push r14
    push r15
    ; resolve the base: call pushes the return addr (= sym_base), pop into r12
    call sym_base
sym_base:
    pop r12
    ; 0x30 scratch: headroom below the 8 saved registers (they sit at
    ; [rsp+0x30..+0x70] after this sub). Each syscall site aligns RSP down from
    ; here and reserves its frame in/just below this gap, so it must stay clear
    ; of the registers above.
    sub rsp, 0x30

    ; ---- 1. PEB -> Ldr -> walk InLoadOrder for ntdll.dll -----------------
    xor rax, rax
    mov [r12 + (ntdll_base - sym_base)], rax
    mov rax, [gs:0x60]
    mov rax, [rax + 0x18]
    lea r14, [rax + 0x10]
    mov r13, [r14]
.peb_walk:
    mov rsi, [r13 + 0x60]
    movzx rdx, word [r13 + 0x58]
    shr rdx, 1
    lea r8, [r12 + (s_ntdll_u16 - sym_base)]
    mov r9, 9
    call cmp_u16_ci
    test rax, rax
    jz .peb_next
    mov rax, [r13 + 0x30]
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
    xor eax, eax
    mov [r12 + (done_flag - sym_base)], rax
    jmp .exit

.have_ntdll:
    ; ---- 2. parse PE exports -------------------------------------------
    mov r11, [r12 + (ntdll_base - sym_base)]
    mov r10d, [r11 + 0x3C]
    lea r10, [r11 + r10]
    lea r10, [r10 + 0x18]
    mov r11d, [r10 + 0x70]
    add r11, [r12 + (ntdll_base - sym_base)]
    mov [r12 + (exp_dir - sym_base)], r11
    mov r10d, [r11 + 0x18]
    mov [r12 + (num_names - sym_base)], r10
    mov r9d, [r11 + 0x1C]
    mov r10, [r12 + (ntdll_base - sym_base)]
    add r10, r9
    mov [r12 + (eat_base - sym_base)], r10
    mov r9d, [r11 + 0x20]
    mov r10, [r12 + (ntdll_base - sym_base)]
    add r10, r9
    mov [r12 + (ent_base - sym_base)], r10
    mov r9d, [r11 + 0x24]
    mov r10, [r12 + (ntdll_base - sym_base)]
    add r10, r9
    mov [r12 + (ord_base - sym_base)], r10

    ; ---- 3. resolve the two functions ------------------------------------
    lea rsi, [r12 + (s_ntdelay - sym_base)]
    mov rdx, 16
    call find_export
    mov [r12 + (saved_ntdelay - sym_base)], rax
    lea rsi, [r12 + (s_ntprotect - sym_base)]
    mov rdx, 22
    call find_export
    mov [r12 + (saved_ntprotect - sym_base)], rax

    ; ---- 4. read syscall numbers from export prologues ------------------
    mov rsi, [r12 + (saved_ntdelay - sym_base)]
    call sysnr_from
    mov [r12 + (data_nr_delay - sym_base)], rax
    mov rsi, [r12 + (saved_ntprotect - sym_base)]
    call sysnr_from
    mov [r12 + (data_nr_protect - sym_base)], rax

    ; ---- 5. NtProtectVirtualMemory(RWX) over the target ------------------
    ;   NtProtectVirtualMemory(NULL, &prot_base, &prot_size, 0x40, &saved_old_prot)
    ;   Windows x64 syscall ABI (direct `syscall`, not a `call`):
    ;     arg0 = RCX mirrored into R10, arg1 = RDX, arg2 = R8, arg3 = R9,
    ;     arg4 = [RSP+0x28]; RSP must be 16-byte aligned at the `syscall`.
    mov r10, [r12 + (saved_ntdelay - sym_base)]
    mov [r12 + (prot_base - sym_base)], r10
    mov dword [r12 + (prot_size - sym_base)], 12
    ; entry-independent 16-align for the `syscall`: park S0=rsp in r13, round
    ; RSP down to 16 (works for ANY entry alignment, not just RSP%16==8), and
    ; reserve the frame so arg4 lands at [rsp+0x28]. r13 is callee-saved and
    ; preserved across the syscall, so it holds the restore point.
    mov r13, rsp                     ; r13 = S0 (restore point)
    and rsp, -16                     ; RSP = S0 & ~0xF (16-aligned, <= S0)
    lea r10, [r12 + (saved_old_prot - sym_base)]
    mov [rsp + 0x28], r10            ; arg4 = &saved_old_prot (OldProtect, out)
    lea rdx, [r12 + (prot_base - sym_base)]   ; arg1 = BaseAddress*
    lea r8,  [r12 + (prot_size - sym_base)]   ; arg2 = RegionSize*
    mov r9d, 0x40                    ; arg3 = PAGE_EXECUTE_READWRITE
    xor rcx, rcx                     ; arg0 = NULL (current process)
    mov r10, rcx                     ; arg0 -> R10 (the kernel reads arg0 from R10)
    mov eax, [r12 + (data_nr_protect - sym_base)]
    syscall
    mov rsp, r13                     ; restore RSP = S0
    test eax, eax                    ; NTSTATUS: bit31 set = error/fatal
    jns .s6_patch                    ; success/warning -> go patch + mask
    ; NtProtect failed: the text isn't RWX, so we can't safely patch it in
    ; place. Fall back to a real (unmasked) NtDelayExecution so the wait still
    ; happens -- "runs no matter what."
    lea rdx, [r12 + (timeout_val - sym_base)]   ; arg1 = &Duration (250 ms, 100ns)
    xor rcx, rcx                     ; arg0 = InState (0 = relative)
    mov rax, [r12 + (saved_ntdelay - sym_base)]
    call rax
    mov qword [r12 + (done_flag - sym_base)], 1
    jmp .exit
.s6_patch:

    ; ---- 6. save + patch NtDelayExecution (12 bytes) --------------------
    mov r10, [r12 + (saved_ntdelay - sym_base)]
    mov rax, [r10]
    mov [r12 + (saved_bytes - sym_base)], rax
    mov eax, [r10 + 8]
    mov [r12 + (saved_bytes - sym_base) + 8], eax
    ; patch: 48 B8 <8-byte stub addr> FF E0
    mov r9, [r12 + (saved_ntdelay - sym_base)]
    mov byte [r9], 0x48
    mov byte [r9 + 1], 0xB8
    lea rax, [r12 + (.stub - sym_base)]
    mov [r9 + 2], rax
    mov byte [r9 + 10], 0xFF
    mov byte [r9 + 11], 0xE0

    ; ---- 7. invoke the masked sleep -------------------------------------
    mov rax, [r12 + (saved_ntdelay - sym_base)]
    call rax

    ; ---- 8. restore protection (to the saved OldProtect), flag done ------
    ;   Same ABI as step 5; arg3 = the original protection the kernel returned
    ;   into saved_old_prot, so we restore exactly what was there.
    mov r13, rsp                     ; r13 = S0 (restore point)
    and rsp, -16                     ; RSP = S0 & ~0xF (16-aligned, entry-independent)
    lea r10, [r12 + (saved_old_prot - sym_base)]
    mov [rsp + 0x28], r10            ; arg4 = &saved_old_prot
    lea rdx, [r12 + (prot_base - sym_base)]   ; arg1 = BaseAddress* (pointer, like step 5)
    lea r8,  [r12 + (prot_size - sym_base)]   ; arg2 = RegionSize*
    mov r9d, [r12 + (saved_old_prot - sym_base)]  ; arg3 = restore ORIGINAL prot
    xor rcx, rcx                     ; arg0 = NULL
    mov r10, rcx                     ; arg0 -> R10
    mov eax, [r12 + (data_nr_protect - sym_base)]
    syscall
    mov rsp, r13                     ; restore RSP = S0

    mov qword [r12 + (done_flag - sym_base)], 1

.exit:
    add rsp, 0x30
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rdi
    pop rsi
    pop rbx
    ret

; ---------------------------------------------------------------------------
; the mask stub — entered via the patched `jmp rax`, r12 still = base
; ---------------------------------------------------------------------------
; KUSER_SHARED_DATA is mapped at 0x7FFE0000 on every x64 Windows;
; SystemTime (100ns since 1601) is at +0x14. No exports, no calls.
.stub:
    ; Self-contained: recompute the blob base. This stub is reached via the
    ; patched `jmp rax` from ANY thread that calls NtDelayExecution during the
    ; mask window, so r12 (the shellcode's base) is caller-dependent and may be
    ; stale here. Recompute it with a call/pop so the stub is correct no matter
    ; who entered it.
    call stub_base_pop
stub_base_pop:
    pop r12
    sub r12, (stub_base_pop - sym_base)      ; r12 = sym_base (the blob base)
    ; absolute clock load idiom: `mov eax,imm32` zero-extends into rax, then [rax].
    ; NOT `mov rax,[0x7FFE0014]` — nasm encodes that as 48 8B 04 25 ... (a redundant
    ; SIB form) which real Intel/AMD HW mis-decodes as `mov rax,[rsp]` + `sub eax,..`.
    mov eax, 0x7FFE0014
    mov rax, [rax]
    mov [r12 + (data_t0 - sym_base)], rax
.st_wait:
    mov eax, 0x7FFE0014
    mov rax, [rax]
    sub rax, [r12 + (data_t0 - sym_base)]
    cmp rax, [r12 + (timeout_val - sym_base)]
    jae .st_done
    jmp .st_wait
.st_done:
    mov r8, [r12 + (saved_bytes - sym_base)]
    mov r9, [r12 + (saved_ntdelay - sym_base)]
    mov [r9], r8
    mov eax, [r12 + (saved_bytes - sym_base) + 8]
    mov [r9 + 8], eax
    ret

; ---------------------------------------------------------------------------
; helpers
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
;   forward-scans offsets 0..23 for the first nr mov:
;     `B8 <nr:4>`        (mov eax,nr)   — legacy + modern ntdll thunks
;     `48 C7 C0 <nr:4>`  (mov rax,nr)   — alternate encoder
;   the modern x64 thunk is `4C 8B D1 B8 <nr:4> F6 ... 0F 05`, so the B8
;   sits at offset 3 behind the `mov r10,rcx` preamble; first match wins.
;   clobbers rax, r10, r11
sysnr_from:
    xor r10, r10
.snr_scan:
    cmp byte [rsi + r10], 0x48
    je .snr_rax
    cmp byte [rsi + r10], 0xB8
    je .snr_eax
.snr_adv:
    inc r10
    cmp r10, 24
    jb .snr_scan
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
saved_bytes:    resq 2                 ; 12 bytes (+4 pad) of NtDelayExecution
saved_ntdelay:  resq 1
saved_ntprotect:resq 1
saved_old_prot: resq 1
prot_base:      resq 1
prot_size:      resq 1
eat_base:       resq 1
ent_base:       resq 1
ord_base:       resq 1
num_names:      resq 1
exp_dir:        resq 1
ntdll_base:     resq 1
timeout_val:    dq 2500000
data_nr_delay:  resq 1
data_nr_protect:resq 1
data_t0:        resq 1
done_flag:      resq 1
s_ntdelay:      db "NtDelayExecution", 0
s_ntprotect:    db "NtProtectVirtualMemory", 0
s_ntdll_u16:    dw 'n','t','d','l','l','.','d','l','l'
