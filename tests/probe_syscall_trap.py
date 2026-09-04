"""Verify: CODE hook can intercept `syscall` (0F 05), emulate, and resume at rip+2."""
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RIP, UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX

uc = Uc(UC_ARCH_X86, UC_MODE_64)
uc.mem_map(0x1000, 0x2000)
code = (b'\xB8\x3D\x00\x00\x00'   # mov eax, 0x3D  (NtDelayExecution nr)
        b'\x0F\x05'               # syscall
        b'\x90'*16)
uc.mem_write(0x1000, code)
uc.reg_write(UC_X86_REG_RIP, 0x1000)
uc.reg_write(UC_X86_REG_RCX, 0x1111)
uc.reg_write(UC_X86_REG_RDX, 0x2222)

events = []
def on_code(uc_, rip, size, ud):
    insn = uc_.mem_read(rip, 2)
    if insn == b'\x0f\x05':
        nr = uc_.reg_read(UC_X86_REG_RAX)
        events.append(('syscall', nr))
        uc_.reg_write(UC_X86_REG_RAX, 0x00000000C0000001)  # STATUS_PENDING-ish sentinel
        uc_.reg_write(UC_X86_REG_RIP, rip + 2)
        uc_.emu_stop()

uc.hook_add(UC_HOOK_CODE, on_code)
uc.emu_start(0x1000, 0x1000 + len(code))
print("events:", events)
ok = events == [('syscall', 0x3D)] and uc.reg_read(UC_X86_REG_RAX) == 0x00000000C0000001
print("rax after:", hex(uc.reg_read(UC_X86_REG_RAX)))
print("rcx (should be untouched 0x1111):", hex(uc.reg_read(UC_X86_REG_RCX)))
print("PROBE:", "PASS" if ok else "FAIL")
