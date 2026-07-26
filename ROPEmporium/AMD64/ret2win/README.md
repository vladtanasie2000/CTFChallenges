# Solution 

Examening the binary, we can see we have a function called `ret2win`. To call it, we need to overwrite the stack until we reach the RIP 

The stack is formatted in this way
`32 bytes -- RBP -- RIP`
The 32 bytes is where the user input is supposed to go. However thanks to using the `read` function with an input bigger than the size we can overwrite those addresses.

We need to overwrite until we reach the `RIP` so we need to send at least 40 bytes. `RBP` should also probably be a writable location so I have chosen `BSS`. 

We still have one more problem, alligment. Functions or more specifically `system` expects the `return address` to be 16 bytes alligned. We can achive this by using another `ret`, which `pop` some values and makes it `16 bytes alligned`