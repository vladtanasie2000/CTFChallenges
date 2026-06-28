# Desc:
Nate

I created a pirate story simulator

# Executable description:
The executable when ran offers us 4 options, with each option we are tasked with providing a name. At the end of execution a phrase along with our name is printed

# Solution:
Analyzing the program using Ghidra we can see the issue is in the choice selection part of the program.
The errors stems from the condition 3 in the selection process. In all other cases the name buffer is being send first and then the function that needs to be called. However for the choiceSel==3 the program first sends the eatCoconut address and then the name buffer. 
```    
if (choiceSel == 3) {
      handlePirate(eatCoconut,localBuffer);
      goto code_r0x0010158d;
    }
```
This causes the program to treat the eatCoconut function address as the name string and the localBuffer address as the callback/function pointer. As a result, when handlePirate calls the function pointer, execution jumps to our input buffer.

This is possible due to NX (non executable) being **disabled** thus allowing us to run code from our stack

The next problem is the alphaNum check. It checks if the name contains only numbers or letters.This check is based on two parameters, the buffer where the value is being stored and the size of the buffer (obtained via `strlen`)

The issue with this check is IF the buffer size is returned as 0, then the `is_alphanum_string` function returns 1, meaning that all characters are alphanumeric. 

We can achieve this by sending a char sequence beginning with `0x00`. In C, strings are null terminated, meaning that C considers the ending of a string to be at `0x00 `byte. However, if we send a char sequence beginning with `0x00` of any size, `strlen` returns 0, thus bypassing the is_alphanum_string function. 

We can send null bytes because the program uses `read` which only stops when the specified size is reached or when encountering `EOF`

The last issue is that having a `0x00` at the beginning of the shellcode will break the it. To prevent this , I opted to use `\x00\xc0` at the beginning , which is the opcode for `ADD AL,AL`. While this does change the AL and in consequence the RAX register, the shellcode we provide immediatly sets `mov rax, 0x732f2f2f6e69622f` which overwrites the AL as well.
