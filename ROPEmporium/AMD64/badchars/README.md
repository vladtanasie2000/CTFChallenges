# Solution
In this problem, we still need to insert the `flag.txt` text into memory, however we cannot insert the `a`,`g`,`.`,`x` chars. So to solution is to encode them. We can do this using a `XOR` decoder, based on the insturction found in the `usefullGadgets` section,
`xor byte ptr [r15], r14b` . As we can see, we can use `LSB` of the `R14` register to decode the chars found at the address stored in the `R15` register. Seeing as the operation is on `byte ptr`, we need to do this for each byte. For 8 bytes in `flag.txt` we need at least 8 calls to the `XOR Decoder` plus another 7 to move the `R15` register one possition forwards. 

Examining the binary we can see a few interesting instructions which we can use such as:
`mov qword ptr [r13], r12` : one instruction to send the whole 8 byte `encoded flag.txt`
`pop r12; pop r13; pop r14; pop r15; ret; 8 ` : one instruction which sets both `R13` and `R12`

Using these instructions and a few more, the flow becomes:
* encode the flag.txt
* send it using the `mov` instruction into `bss`
* decode each byte of the encoded `flag.txt`
* call `print_file`