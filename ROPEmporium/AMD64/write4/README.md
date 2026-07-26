# Solution
In this executable we have a function called `print_file` which reads the contents of a file and prints the output to `stdout`. However we have one problem, there is no `flag.txt` string in the binary. We can remedy this however by inserting our own.

Using the `usefulGadgets MOV qword ptr [R14],R15` instruction found at the `usefulGadgets` symbol, we can move the contents of the `R15` register into the address located in the `R14` register. This is how we make our `flag.txt` available for the program.

We need tot `POP R14,POP R15` to set them to `R14` to `BSS` (a writable zone in memory where we have mostly 0s) and `R15` to `flag.txt`. Because the `BSS` is mostly `0` it also null-terminates our `flag.txt` string.

After that we `POP RDI` the `BSS` and call `print_file`