# Solution
In this challange we have two writes, one in a possition given by the program and another directly on the stack. The one on the stack is relativly small (only 64 bytes out of which 40 are needed to get to `RIP` meaning 24 usable bytes or 3 gadgets) the other is a 256 byte write. Looking at the gadgets available for this challange we can see we have

`POP RAX`
`XCHG RAX,RSP` -- changes the `RSP` with `RAX`
`MOV RAX,qword ptr [RAX]` -- stores into `RAX` to value of at the address of `RAX`

Using these gadgets, we can perform a `stack pivot` meaning that we can change the `stack` to point to another zone in memory. This will be done via the `XCHG` instruction and the new stack will be possition where we have the bigger write.

Analyzing `libpivot.so` we see that we have a function call `ret2win` meaning that all we have to do is call it. However it is not that simple, as `ret2win` is in another library. If we want to call `ret2win` we need to resolve the address of it. 

TO do that, we can see that we have the function `foothold_function` which is in our program and the `libpivot.so` . To be able to read it it needs to be resolved by the `PLT` and to do that, it needs to be called at least once in the program.

After the function has been called, we can use a read gadget such as `puts(foothold_function)` (which we can call by passing to RDI to `GOT` entry of `foothold_function` and calling `puts`) and we got the address of `foothold_function`in the library `libpivot.so` relative to our program.

However, we can only get this address *AFTER* we have send the `stack pivot payload`, so we cannot directly send it in the payload. To mediate this, we will use a `write gadget` based on `write(0,bss()+100,<garbage from rdx>)` to chain a write *AFTER* we have gotten our address. This will be place in the `bss+100` location. 

After that address is placed, all we have to do is call it using `call RAX` instruction and get the flag