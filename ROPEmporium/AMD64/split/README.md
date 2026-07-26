# Solution

In this challenge we need to discuss how parameters are passed to functions. This behavior changes from architecture to architecture (i386 uses the stack, amd64 registers, arm a different set of registers).

For AMD64/x86-64 for Linux LibC the ABI denotes that parameters are passed via registers for the first 6 parameters. Afterwards they can use the stack.This is called the `calling convection`

The order in which these parameters and registers are set is:

```
RDI
RSI
RDX
RCX
R8
R9
```
So we can call any functions with any parameters as long as we have an address to that function and we can manage the registers. We can manage the registers via the `pop reg; ret`gadget. This gadget takes a value from the stack and puts it in the registers of our choice. Afterwards we can pass the function and the parameters we want to call and send them. For our case, we wanted to call `system` with `/bin/cat flag.txt`. We found it in the program using pwntools, and we also found a `system` call by examining the binary. Afterwards all I needed to do was set the `RDI` to `/bin/cat flag.txt` and call `system` keeping in mind address alignment