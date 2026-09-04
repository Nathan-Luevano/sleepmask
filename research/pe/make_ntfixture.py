#!/usr/bin/env python3
"""Build a minimal x64 PE DLL with three named exports (ntdll-style fixture).

Two exports are syscall thunks (`mov eax, <imm32>; <0F 05>; ret`); the third
(KeQuerySystemTime) is NOT a syscall thunk. The export names and the thunk
bytes match the runtime test harness byte-for-byte.

Run:  python make_ntfixture.py     -> writes ntdll.dll next to this file
"""

import os

EXPORTS = [
    ("NtDelayExecution", bytes.fromhex("B83D0000000F05C3")),
    ("NtProtectVirtualMemory", bytes.fromhex("B82B0000000F05C3")),
    ("KeQuerySystemTime", bytes.fromhex("4881C0A0860100C3")),
]

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ntdll.dll")
