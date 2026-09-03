from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_MEM_READ, UC_HOOK_MEM_READ_UNMAPPED
from unicorn.x86_const import *

uc = Uc(UC_ARCH_X86, UC_MODE_64)
uc.mem_map(0x0, 0x1000)
uc.mem_write(0x60, b'PEBPTRTEST')
uc.mem_map(0x1000, 0x1000)
uc.mem_write(0x1000, b'\x48\x8B\x44\x26\x60')
uc.reg_write(UC_X86_REG_RIP, 0x1000)

def rd(uc_, *a):
    print("  MEM_READ args:", [hex(x) if isinstance(x,int) else x for x in a])
def rdu(uc_, *a):
    print("  MEM_READ_UNMAPPED args:", [hex(x) if isinstance(x,int) else x for x in a])
    return False

uc.hook_add(UC_HOOK_MEM_READ, rd)
uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, rdu)
uc.reg_write(UC_X86_REG_GS_BASE, 0)
print("GS_BASE readback:", hex(uc.reg_read(UC_X86_REG_GS_BASE)))
try:
    uc.emu_start(0x1000, 0x1006)
    print("OK rax=%#x" % uc.reg_read(UC_X86_REG_RAX))
except Exception as e:
    print("FAILED:", e)
