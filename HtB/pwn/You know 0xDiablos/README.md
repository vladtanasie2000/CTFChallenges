# Desc

I missed my flag

# Executable Description

The binary asks for our input, displaying it afterwards and exiting the program

# Solution

Looking at the binary with `Ghidra` we can see two interesting things

* a `gets` function that puts our input into a 180 char array
* a function called `flag` which opens a `FILE` and reads the `flag.txt` contents

Also looking at the binary and how it was compiled we can see

* a `x86` binary, meaning `parameters` are passed via the stack
* no canary

Meaning that this challenge is a `ret2win` challenge in which we need to call the `flag` function.
The binary is `Possition Independent Code` , meaning that the register `EBX` is used for `relative` accessing of the variables.
The `EBP` register is `callee saved` register, and we can see it being saved here

```

        08049272 55              PUSH       EBP
        08049273 89 e5           MOV        EBP,ESP
        08049275 53              PUSH       EBX
```

along with the `EBP`, meaning that for our overflow the reach `EIP` we need to overflow

* 180 bytes for the array
* 4 bytes for the `EBX`
* 4 bytes for the `EBP`

with a total of `188 bytes`. Also we now need to pass the arguments
The arguments needed are `0xdeadbeef` for the first one and `0xc0ded00d` for the second one.
The way functions are usually called is with the following values being send on the stack
`EIP for return -> param1 -> param2 -> param3 -> ... -> paramN`
So, if we want to call the `flag` function we need to send

* something for the `EIP` (I choose main but 0x0 could also work if we don't care about the state of the program)
* `0xdeadbeef` for the first param
* `0xc0ded00d` for the second param
