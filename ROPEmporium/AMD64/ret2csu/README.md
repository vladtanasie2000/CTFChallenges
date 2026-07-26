# Solution

Looking at the binary, we see that we have to call `ret2win(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)` but we also see that we do not have the necessary gadgets to do so.

However we can make use of the universal gadget, or sometimes called `ret2csu`

Examining the `_libc_init_csu` we can see the following important gadgets:

```
		MOV        RDX,R15
		MOV        RSI,R14
		MOV        EDI,R13D
		CALL       qword ptr [R12 + RBX*0x8]

```
and 

``` 
		POP        RBX
		POP        RBP
		POP        R12
		POP        R13
		POP        R14
		POP        R15
		RET

```

As we can see, the second gadgets sets the `RDX,RSI,EDI` register based on values from `R15,R14,R13D` which we can controll using the second gadget. The call for `qword ptr [R12 + RBX*0x8]` can be circumventented controlling both `R12` and `RBX`. We can make the zone in memory call a `_DYNAMIC` section, specifically `0x600e48` which points to a section of `_fini` with this code
```
   0x00000000004006b4 <+0>:     sub    rsp,0x8
   0x00000000004006b8 <+4>:     add    rsp,0x8
   0x00000000004006bc <+8>:     ret

```
after the call is made, we return to 
```
		ADD        RBX,0x1
		CMP        RBP,RBX
		JNZ        LAB_00400680
		LAB_00400696                                 
		ADD        RSP,0x8
		POP        RBX
		POP        RBP
		POP        R12
		POP        R13
		POP        R14
		POP        R15
		RET
```
By having `RBP` and `RBX` equal after the `ADD RBX,0x1` instruction, we pop the values again, but now with `RDX` and `RSI` set. All we need to do now is add to the stack the needed values for the correct ammount of pop(which is 6 from the POP and +1 from the `ADD RSP,0x8`), return to a `POP RDI` gadget and then call `ret2win`