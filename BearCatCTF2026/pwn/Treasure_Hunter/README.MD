# Desc:

Nate

The captain of the crew needs help finding the secret treasure

# Executable Description:

The program ask for out name as a pirate returning "Hello" and our name. Afterwards it asks for where we think the treasure is located and then it reads our input again, returning afterwards

# Solution

Analyzing the program with Ghidra, we can see that we have a function called win. This function reads a file called "flag.txt" and prints the content. However it is protected using a password which expects us to call it using either a first parameter of `\x06` or with a second parameter of `\x07`

Analyzing the `find_treasure` function, we can see that have a format string vulnerability along with a buffer overflow. However we also have a canary that gets checked. 

The solution is to first leak the canary using the printf function and then overwrite the stack with both the canary and the win address so we return to win instead of main. When calling the win function we also send it it's parameters . This type of attack is called ret2win.

To leak the canary, we can use either a cyclonic pattern or just examine multiple stack positions. After analyzing using GDB I found that at the 13 position using the `lx` format we can find the canary.

To call win using a parameter we can use a ROP gadget. We will set the first parameter to `\x06` so we need a `pop rdi; ret;` gadget to read from the stack our inserted value and put it into the `RDI` register.
