# Desc:
Sean

A sea monster appears and offers you an impossible game. Do you bet your life for the chance to get a flag?

# Executable description:
The program presents us with two chances of inputting the correct number. If the number we input is correct, then we get the flag.

# Solution:
Looking into the get_guess function, we can see that unless we send the value of 0 , we have a format string vulnerability using printf
```
    guess = strtoul(input, NULL, 0);
    if (!guess){
        printf("Guess not allowed %s\n", input);
        return 0;
    }
    printf(input);

```
We can use this to get the stack value of the guessed number using an information leak to read from the stack.

Using either guesses or a cyclonic pattern (based on the reading the guess from the stack using a debugger), we get that at the 14th position from the printf perspective we have the number.

Using the first try we determine the number we have to guess and in the second attempt we send it.
