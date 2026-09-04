from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RIP, UC_X86_REG_GS_BASE, UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_INS_SYSCALL
import struct

PEB_PTR = 0x7FF6F0001000
uc = Uc(UC_ARCH_X86, UC_MODE_64)
uc.mem_map(0x0, 0x1000)
uc.mem_write(0x60, struct.pack('<Q', PEB_PTR))
uc.mem_map(0x1000, 0x2000)

code = (b'\x48\x8B\x44\x26\x60'        # mov rax, [gs:0x60]
        b'\x48\x89\xC3'                # mov rbx, rax
        b'\xB8\x3D\x00\x00\x00'        # mov eax, 0x3D
        b'\x0F\x05'                    # syscall
        b'\x90'*16)
uc.mem_write(0x1000, code)
uc.reg_write(UC_X86_REG_RIP, 0x1000)
uc.reg_write(UC_X86_REG_GS_BASE, 0)

def on_code(uc_, code_id, size, ud):
    if code_id == UC_X86_INS_SYSCALL:
        nr = uc_.reg_read(UC_X86_REG_RAX)
        print(f"  [hook] syscall nr={nr:#x} -> emulating (sentinel 0x5A5A)")
        uc_.reg_write(UC_X86_REG_RAX, 0x5A5A)
        uc_.reg_write(UC_X86_REG_RIP, uc_.reg_read(UC_X86_REG_RIP) + 2)
        uc_.emu_stop()

uc.hook_add(UC_HOOK_CODE, on_code)
uc.emu_start(0x1000, 0x1000 + len(code))
print("rax=%#x (expect 0x%x)" % (uc.reg_read(UC_X86_REG_RAX), PEB_PTR))
print("rbx=%#x (expect 0x%x)" % (uc.reg_read(UC_X86_REG_RBX), PEB_PTR))
print("PROBE OK" if uc.reg_read(UC_X86_REG_RAX) == PEB_PTR and uc.reg_read(UC_X86_REG_RBX) == PEB_PTR else "PROBE FAIL")
