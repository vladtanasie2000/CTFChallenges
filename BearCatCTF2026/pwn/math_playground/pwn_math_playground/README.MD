# Desc:

Sean

My python calculator was a total disaster, so I decided to write one in c since c is known for being a secure programming language right?

Be aware: the layout of the program on remote may be slightly different than the containerized version.

# Executable descripion:

The program is an arithemtic calculator, being able to do adition, substraction, multiplication and division. We can select the operation we want to do, after that sending two integers that we want to participate in that opertion, with the result being returned to us. 

The operations array is used to point to the function responsible for the mathematical operations.

# Solution:

Looking at the code, we can see a few interesting things. 
Examining the binary we can see no PIE (Possition Independed Executable) and partial RELRO running on i386 architecture. No PIE and Partial RELRO (Relocation Read-Only) are vital for this exploit as they will be used throughout the exercise.

Examining the .C file provided, we can see a few interesting things.
1. operations is a global array
2. operations is an array of pointers to functions that get called with two parameters
3. there is no input validation for accessing members of that array

Using these three factors, we can start developing a rough exploit. By inputting values that correspond to offsets of functions from the "operation" array point of view, we can run functions that we weren't meant to. With the ability to also send parameters via the two integers, we can run functions with either 0,1 or 2 parameters. 

This gives us a constrained arbitrary function call primitive. With writable GOT entries and libc leaks, we can turn it into code execution.

While this is indeed powerful, the first problem arises. The function ends immediately after returning the result. To circumvent that, we will use the first "operation" exploit to overwrite the printf GOT value to point instead to the main function of the program (specifically right after the second to last printf). We do this by using the scanf function, which takes a format string and one or more destination pointers.

Looking into the code, we can see we can use the `"%d"` restriction already defined in the program, and seeing as the program is partial RELRO we can overwrite the GOT of printf. 

By analyzing the code, we can see that from the operations perspective, a pointer to scanf is 12 bytes behind it (0804c02c - 0804c020 = 12). Now seeing as we are working with addresses in i386, address values are only 4 bytes in length.This means that from the operations perspective scanf is behind it by 3 units. We can also see that 1 is subtracted from the introduced value to make it 1 indexed instead of 0. So the actual value we need to send is -2

With all of these, we can send our input.
We will send 
* -2 to point to a scanf pointer
* a pointer to the single `"%d"` symbol
* the address of GOT printf

After we send these inputs, we can send the address of the main function where we want execution to run every time afterwards.

**NOTE** the addresses need to be send as integers as that's what `"%d"` expects

Now that we have a way of running the program indefinitely. We leak the contents of GOT entries, such as puts@got and setvbuf@got, to recover their actual libc runtime addresses. We would only need one theoretically to defeat ASLR, but seeing as we don't know the exact libC version that the application is running, we need a few (in the script, I leak puts and setvbuf addresses).

Using these addresses, we can determine the exact libC version using sites like https://libc.rip/

For leaking I am using the puts function, seeing as it accepts one parameter. I will use the trick above where 
* -4 is used to point to puts
* the function which address we want leaked is used
* zero as the second parameters doesn't matter

The leaked addresses in my case were :
`puts:0xf7dd1e80`
`setvbuf:0xf7dd2560`

Using these addresses the first thing we do is set the libc.address in our python script.

On i386 with ASLR enabled, libc addresses often appear in the high 32-bit address range, for example around `0xf7xxxxxx`. Since we are using `"%d"` to send data to the application, `scanf` will parse our input as a signed 32-bit integer. This means that values above `0xf7xxxxxx`, such as `0xf7d4a8d0`, cannot be sent as positive integers.
To preserve the same 32-bit bit pattern, we need to send these addresses as their signed two's-complement equivalent. In practice, if an address is larger than `0xf7xxxxxx`, we subtract `0x100000000` from it before sending it. The function we use, `str(value).encode()`, will then send the negative decimal representation, and `scanf("%d")` will store the correct 4-byte value in memory.

Afterwards we need to look at libc.rip, to see which libC versions our applications could be using. After a few round of testing I found that it uses **"libc6-i386_2.36-9+deb12u13_amd64.so"**
After also getting the libC version, the rest of the exploit is simple. Firstly we write `"/bin/sh\0"` at the BSS+100 using the same steps that we used to write the printf GOT. To do that we will do it in two passes (as it's a 8 byte value and `"%d"` accepts only 4 bytes).


After the string has been writen, the final steps are to set the setvbuf GOT to system and then call "setvbuf" (the GOT entry for it) using the same trick with the values
* -3 setvbuf possition from operations standpoint
* bss+100 to point towards the zone where the "/bin/sh\0" has been written
* 0 as the last parameter doesn't matter

Doing all of this and executing setvbuf we get a shell.










