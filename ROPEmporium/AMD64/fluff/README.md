# Solution
We are again given the task of writting `flag.txt` to the `BSS` however with another twist, we have no `move [reg],reg` instructions. This forces us to be creative in how we use the gadgets availabe

Looking into the list, we see a few interesting gadgets
`XLAT`: takes the input from \[RBX+AL\] and puts it into AL
`BEXTR`: instruction that when given a start possition and a lenght puts the bits from the `SRC` into `DEST`
	   : for our application the paremeters are : RBX destionation, RCX source, RDX possition and lenght
`STOSB`: instruction which stores into \[RDI\] the AL value (RDI also autoincrements)
`POP RDX,POP RCX,ADD RCX,3ef2`:pops that also modify the RCX

As we can see, we do not have a direct `move [reg],reg` , however the binary is full of `ascii` letters. We can use those to create the `flag.txt` one letter and one byte at a time using the following steps

* setup `RDI` for the write to point towards the `BSS` (as said, `RDI` autoincrements with `STOSB` so no need to change it each time)
* calculate the address of the letter we want to send using the formula `letterAddress+oppositeNumber-currentAL`
* * `oppositeNumber` is the opposite number of 3ef2 written twos complement (`opposite_number=0xFFFFFFFFFFFFFFFF-0x3ef1`)
* * `currentAL` starts at the beginning of the program as `0xb` changing to our letter after each XLAT
* using the address pop the registers and call `BEXTR`
* call `XLAT` to put into `AL` the letter
* call `STOSB` to store it into `RDI`
* this needs to be done for each letter, after this is done we can call print_file