
# Description

The famous hacker Script K. Iddie has finally been caught after many years of cybercrime. Before he was caught, he released a server sending mysterious data, and promised his 0-days to anyone who could solve his multi-level hacking challenge. Now everyone is in an ARMs race to get his exploits. Can you be the one to solve Iddie's puzzle?

# Executable Description

We are given a series of bytes, and we are asked to give the `r0 state`

# Solution

Looking at the description we can assume that the problem is an `arms v5 problem` (especially given that the register `r0` is being asked for). We can then assume that what we are being given are `arm instructions`

The time being given to emulate or run the instructions is small, with it changing subtlety each run and we have around `50 levels`, so we need to automate this somehow. For this I have used two libraries:

* pwntools to connect to the endpoint , parse the instructions and send the response
* unicorn to emulate the `ARMv5` instruction set

Using this two tools, I can receive the instructions, decode them, run them using `unicorn`, get the `r0` state after the program ends execution and then finally send the `r0` state
