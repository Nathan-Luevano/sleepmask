; probe_windows.asm — PEB-walk probe, Windows x64, PIC, no imports.
;
;   Full chain, everything resolved at runtime from the PEB
;   (no IAT, no relocations, no hard-coded syscall numbers):
;     1. PEB (gs:0x60) -> PEB_Ldr (+0x18) -> InLoadOrderModuleList (+0x10)
;     2. Walk LDR_DATA_TABLE_ENTRY list for "ntdll.dll"
;        (DllBase +0x30, BaseDllName.Length +0x58, .Buffer +0x60)
;     3. Parse ntdll's PE export directory
;        (NumberOfNames +0x18, EAT +0x1C, ENT +0x20, ORD +0x24)
;     4. Read syscall numbers from export prologues:
;        NtTerminateCurrentProcessEx, NtWriteFile, NtCreateFile, NtClose
;     5. Create sleepmask_probe.txt in the CWD (best effort)
;     6. Write the report to stdout AND the file, one line at a time
;     7. Close the file, NtTerminateCurrentProcessEx(0)
;
;   Success = console shows the report, exit code 0, probe file exists.
;   Failure = ud2 crash dialog; the console shows how far the chain got.
;
;   assemble: nasm -g -f bin -o build/probe_windows.bin probe_windows.asm

bits 64
org 0

start:
    ; self-normalizing prologue: force RSP to 8 (mod 16) regardless of whether
    ; the loader called (RSP would be 0) or jumped (RSP would be 8) to entry.
    ; 'and' rounds down to a 16-byte boundary, 'add 8' lands us at +8.
    and rsp, -16
    add rsp, 8
    push rax
    push rcx
    push rdx
    push rbx
    push rsi
    push rdi
    push rbp
    push r12
    push r13
    push r14
    push r15

    ; resolve blob base: call pushes the address of sym_base
    call sym_base
sym_base:
    pop r12

    ; ---- 1. PEB -> Ldr -> InLoadOrder, find ntdll.dll -----------------------
    mov rax, [gs:0x60]
    mov rax, [rax + 0x18]
    lea r14, [rax + 0x10]
    mov r13, [r14]

.peb_walk:
    ; r13 = LDR_DATA_TABLE_ENTRY (InLoadOrderLinks at +0x00)
    movzx edx, word [r13 + 0x58]
    mov rsi, [r13 + 0x60]
    shr edx, 1
    lea r8, [r12 + (s_ntdll_u16 - sym_base)]
    mov r9d, 9
    call cmp_u16_ci
    test rax, rax
    jnz .found_ntdll
    mov r13, [r13]
    cmp r13, r14
    jne .peb_walk
    ud2

.found_ntdll:
    mov rax, [r13 + 0x30]
    mov [r12 + (ntdll_base - sym_base)], rax

    ; ---- 2. PE export directory ---------------------------------------------
    ;     ntdll+0x3C = e_lfanew; e_lfanew+0x18 = optional header;
    ;     opt+0x70 = DataDirectory[0].VirtualAddress (exports RVA)
    mov r11, [r12 + (ntdll_base - sym_base)]
    mov r10d, [r11 + 0x3C]
    lea r10, [r11 + r10]
    lea r10, [r10 + 0x18]
    mov r11d, [r10 + 0x70]
    add r11, [r12 + (ntdll_base - sym_base)]

    ; IMAGE_DIRECTORY_ENTRY_EXPORT:
    ;   +0x18 NumberOfNames, +0x1C EAT, +0x20 ENT, +0x24 ORD
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

    ; ---- 3. Resolve the four syscalls ---------------------------------------
    lea rsi, [r12 + (s_ntterm - sym_base)]
    mov rdx, 27
    call resolve
    test rax, rax
    jz .die
    mov [r12 + (nr_term - sym_base)], rax

    lea rsi, [r12 + (s_ntwrite - sym_base)]
    mov rdx, 11
    call resolve
    test rax, rax
    jz .die
    mov [r12 + (nr_write - sym_base)], rax

    lea rsi, [r12 + (s_ntcreate - sym_base)]
    mov rdx, 12
    call resolve
    test rax, rax
    jz .die
    mov [r12 + (nr_create - sym_base)], rax

    lea rsi, [r12 + (s_ntclose - sym_base)]
    mov rdx, 7
    call resolve
    test rax, rax
    jz .die
    mov [r12 + (nr_close - sym_base)], rax

    ; ---- 4. File creation structures -----------------------------------------
    ;     file_us: UNICODE_STRING { Length=38, MaxLength=38, Buffer }
    ;     oa: OBJECT_ATTRIBUTES { Length=0x30, ObjectName=&file_us,
    ;             Attributes=OBJ_CASE_INSENSITIVE }
    mov word [r12 + (file_us - sym_base)], 38
    mov word [r12 + (file_us - sym_base) + 2], 38
    lea r10, [r12 + (filename_u16 - sym_base)]
    mov [r12 + (file_us - sym_base) + 8], r10
    mov dword [r12 + (oa - sym_base)], 0x30
    lea r10, [r12 + (file_us - sym_base)]
    mov [r12 + (oa - sym_base) + 0x10], r10
    mov dword [r12 + (oa - sym_base) + 0x18], 0x40

    ; ---- 5. Create the report file (best effort) ------------------------------
    call create_file
    mov [r12 + (create_status - sym_base)], rax

    ; ---- 6. Report: stdout AND the file, line by line -------------------------
    lea rsi, [r12 + (s_l_hello - sym_base)]
    call line_add_str
    call line_write

    lea rsi, [r12 + (s_l_ntdll - sym_base)]
    call line_add_str
    mov rax, [r12 + (ntdll_base - sym_base)]
    mov rcx, rax
    call line_add_hex
    call line_write

    lea rsi, [r12 + (s_l_ntterm - sym_base)]
    call line_add_str
    mov rcx, [r12 + (nr_term - sym_base)]
    call line_add_hex
    call line_write

    lea rsi, [r12 + (s_l_ntwrite - sym_base)]
    call line_add_str
    mov rcx, [r12 + (nr_write - sym_base)]
    call line_add_hex
    call line_write

    lea rsi, [r12 + (s_l_ntcreate - sym_base)]
    call line_add_str
    mov rcx, [r12 + (nr_create - sym_base)]
    call line_add_hex
    call line_write

    lea rsi, [r12 + (s_l_ntclose - sym_base)]
    call line_add_str
    mov rcx, [r12 + (nr_close - sym_base)]
    call line_add_hex
    call line_write

    lea rsi, [r12 + (s_l_file - sym_base)]
    call line_add_str
    mov rcx, [r12 + (create_status - sym_base)]
    call line_add_hex
    call line_write

    lea rsi, [r12 + (s_l_done - sym_base)]
    call line_add_str
    call line_write

    ; ---- 7. Close, exit --------------------------------------------------------
    mov rax, [r12 + (fh_out - sym_base)]
    test rax, rax
    jz .no_file
    mov rcx, rax
    call close_fh
.no_file:
    xor ecx, ecx
    call term_proc
    ud2

.die:
    ud2

; ---------------------------------------------------------------------------
; resolve + syscall wrappers
; ---------------------------------------------------------------------------

; resolve: rsi=name(ascii), rdx=len -> rax=sysnr (0 if missing)
resolve:
    call find_export
    test rax, rax
    jz .res_zero
    mov rsi, rax
    call sysnr_from
    test eax, eax
    jz .res_zero
    ret
.res_zero:
    xor eax, eax
    ret

; write_to: rcx=handle, rsi=buf, rdx=len -> rax=STATUS
;   NtWriteFile(handle, 0, 0, 0, &iosb, buf, len, 0, 0)
write_to:
    sub rsp, 0x60
    lea r10, [r12 + (iosb - sym_base)]
    mov [rsp + 0x28], r10
    mov [rsp + 0x30], rsi
    mov [rsp + 0x38], rdx
    mov qword [rsp + 0x40], 0
    mov qword [rsp + 0x48], 0
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    mov r10, rcx
    mov eax, [r12 + (nr_write - sym_base)]
    syscall
    add rsp, 0x60
    ret

; create_file: -> rax=STATUS ; handle lands in fh_out
;   NtCreateFile(&fh_out, 0x12019F, &oa, &iosb, 0, 0x80, 7, 2, 0x42, 0, 0)
create_file:
    sub rsp, 0x60
    lea r10, [r12 + (fh_out - sym_base)]
    mov rcx, r10
    mov edx, 0x12019F
    lea r8, [r12 + (oa - sym_base)]
    lea r9, [r12 + (iosb - sym_base)]
    mov qword [rsp + 0x28], 0
    mov qword [rsp + 0x30], 0x80
    mov qword [rsp + 0x38], 7
    mov qword [rsp + 0x40], 2
    mov qword [rsp + 0x48], 0x42
    mov qword [rsp + 0x50], 0
    mov qword [rsp + 0x58], 0
    mov eax, [r12 + (nr_create - sym_base)]
    syscall
    add rsp, 0x60
    ret

; close_fh: rcx=handle -> rax=STATUS
close_fh:
    sub rsp, 0x30
    mov r10, rcx
    mov eax, [r12 + (nr_close - sym_base)]
    syscall
    add rsp, 0x30
    ret

; term_proc: rcx=exit status
term_proc:
    sub rsp, 0x30
    mov r10, rcx
    mov eax, [r12 + (nr_term - sym_base)]
    syscall
    ud2

; ---------------------------------------------------------------------------
; line buffer (linebuf + line_len), flushed to stdout and fh_out
; ---------------------------------------------------------------------------

; line_add_str: rsi=ptr to nul-terminated ascii
line_add_str:
    xor r10, r10
.las_loop:
    movzx r11, byte [rsi + r10]
    test r11, r11
    jz .las_done
    mov byte [r12 + (linebuf - sym_base) + r10], r11b
    inc r10
    jmp .las_loop
.las_done:
    add [r12 + (line_len - sym_base)], r10
    ret

; line_add_hex: rcx=value -> appends 16 hex digits
line_add_hex:
    lea r10, [r12 + (linebuf - sym_base)]
    add r10, [r12 + (line_len - sym_base)]
    mov rsi, r10
    call fmt_hex64
    add qword [r12 + (line_len - sym_base)], 16
    ret

; fmt_hex64: rcx=value, rsi=out[16] -> 16 hex digits, MSB first
fmt_hex64:
    mov r8, rcx
    mov cl, 60
    xor r10, r10
.fh_loop:
    mov r9, r8
    shr r9, cl
    and r9, 0xF
    movzx eax, byte [r12 + (hex_tab - sym_base) + r9]
    mov [rsi + r10], al
    inc r10
    sub cl, 4
    cmp r10, 16
    jb .fh_loop
    ret

; line_write: flush linebuf + CRLF to stdout (1) and fh_out, then reset
line_write:
    mov r10, [r12 + (line_len - sym_base)]
    lea r11, [r12 + (linebuf - sym_base)]
    mov byte [r11 + r10], 0x0D
    inc r10
    mov byte [r11 + r10], 0x0A
    inc r10
    mov r13, r10
    xor eax, eax
    mov [r12 + (line_len - sym_base)], rax
    mov rsi, r11
    mov rdx, r10
    mov ecx, 1
    sub rsp, 8
    call write_to
    add rsp, 8
    mov rax, [r12 + (fh_out - sym_base)]
    test rax, rax
    jz .lw_done
    mov rcx, rax
    lea rsi, [r12 + (linebuf - sym_base)]
    mov rdx, r13
    sub rsp, 8
    call write_to
    add rsp, 8
.lw_done:
    ret

; ---------------------------------------------------------------------------
; name matching + export lookup (unchanged from the minimal probe)
; ---------------------------------------------------------------------------

; cmp_u16_ci: rsi=p1, rdx=len1(u16 count), r8=p2, r9=len2 -> rax=1/0
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

; sysnr_from: rsi=fn -> rax=nr (64-bit, 0 if not found)
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

; cmp_ascii_ci: rsi=p1, rdx=len1, r8=p2, r9=len2 -> rax=1/0
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

; ---------------------------------------------------------------------------
; data
; ---------------------------------------------------------------------------
ntdll_base:    resq 1
eat_base:      resq 1
ent_base:      resq 1
ord_base:      resq 1
num_names:     resq 1
nr_term:       resq 1
nr_write:      resq 1
nr_create:     resq 1
nr_close:      resq 1
fh_out:        resq 1
create_status: resq 1
iosb:          resq 2
file_us:       resq 2
oa:            resq 6
linebuf:       resb 96
line_len:      resq 1
hex_tab:       db "0123456789abcdef"
filename_u16:  dw 's','l','e','e','p','m','a','s','k','_','p','r','o','b','e','.','t','x','t'
s_ntdll_u16:   dw 'n','t','d','l','l','.','d','l','l'
s_ntterm:      db "NtTerminateCurrentProcessEx", 0
s_ntwrite:     db "NtWriteFile", 0
s_ntcreate:    db "NtCreateFile", 0
s_ntclose:     db "NtClose", 0
s_l_hello:     db "sleepmask probe - windows x64 (pic, no imports)", 0
s_l_ntdll:     db "ntdll base: 0x", 0
s_l_ntterm:    db "NtTerminateCurrentProcessEx: 0x", 0
s_l_ntwrite:   db "NtWriteFile: 0x", 0
s_l_ntcreate:  db "NtCreateFile: 0x", 0
s_l_ntclose:   db "NtClose: 0x", 0
s_l_file:      db "created sleepmask_probe.txt: 0x", 0
s_l_done:      db "done - exit 0", 0
