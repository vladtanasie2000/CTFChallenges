from pwn import *
from capstone import *
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_MODE_LITTLE_ENDIAN
from unicorn.arm_const import UC_ARM_REG_R0

context.arch = "arm"
context.endian = "little"
p = remote("154.57.164.82", 30107)
for i in range(50):
    info("Iteration %d/50", i + 1)
    p.recvuntil(b"/50: ")
    instr = b""
    raw = p.recvuntil(b"\n")
    raw = raw[:-1]
    instr = raw

    instr = bytes.fromhex(raw.decode())
    # print(instr)
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    # for i in md.disasm(instr, 0):
    #    print(f"{i.address:04x}: {i.mnemonic} {i.op_str}")

    emu = Uc(UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_LITTLE_ENDIAN)
    BASE = 0x10000
    emu.mem_map(BASE, 0x1000)
    emu.mem_write(BASE, instr)
    emu.emu_start(BASE, BASE + len(instr))

    # get final r0
    r0 = emu.reg_read(UC_ARM_REG_R0)
    info("R0 = 0x%x", r0)
    r0 = f"0x{r0:08x}".encode()

    payload = r0
    p.sendlineafter(b"Register r0", payload)
flag = p.recvline()
info("Flag %s", flag)
