from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import *
import struct

uc = Uc(UC_ARCH_X86, UC_MODE_64)
uc.mem_map(0x1000, 0x2000)
code = (b'\xB8\x3D\x00\x00\x00'        # mov eax, 0x3D
        b'\x0F\x05'                    # syscall
        b'\x90'*16)
uc.mem_write(0x1000, code)
uc.reg_write(UC_X86_REG_RIP, 0x1000)

count = {'n': 0}
def on_code(uc_, *a):
    count['n'] += 1
    if count['n'] <= 8:
        print("  [code-hook] args:", [hex(x) if isinstance(x,int) else x for x in a])

uc.hook_add(UC_HOOK_CODE, on_code)
try:
    uc.emu_start(0x1000, 0x1000 + len(code))
    print("emu finished normally, rax=%#x" % uc.reg_read(UC_X86_REG_RAX))
except Exception as e:
    print("emu error:", e)
