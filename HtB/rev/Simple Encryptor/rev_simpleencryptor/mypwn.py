from ctypes import CDLL
from ctypes.util import find_library

libc = CDLL(find_library("c"))
with open("flag.enc", mode='rb') as file: # b is important -> binary
    result=""
    fileContent = file.read()
    random_seed=fileContent[:4]
    random_seed=int.from_bytes(random_seed,byteorder="little",signed=False)
    print(hex(random_seed))
    fileContent = fileContent[4:]
    libc.srand(random_seed)
    for i in range(len(fileContent)):
    	random1=libc.rand()
    	random2=libc.rand()
    	random2=random2 & 0xFF & 0x7
    	dec_byte=((fileContent[i] >> random2) | (fileContent[i] << (8-random2))) & 0xFF
    	xor1=random1 & 0xFF
    	dec_byte=xor1^dec_byte
    	result+=chr(dec_byte)
    print(result)


	
