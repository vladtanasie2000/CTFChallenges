# Description 
On our regular checkups of our secret flag storage server we found out that we were hit by ransomware! The original flag data is nowhere to be found, but luckily we not only have the encrypted file but also the encryption program itself.

# Executable Description 
The program seems to be a simple encryptor, reading the contents of `flag` file outputting the `flag.enc` file

# Solution 

Examining the contents of the binary using `Ghidra` we can see 
* The program reads the contents of `flag` 
* The program gets the current time via `time` and converts it to an `unsigned integer` and sets the seed for `random` using `srand`

```
```
```

  timeFunctionRes = time((time_t *)0x0);
  intTimeResult = (uint)timeFunctionRes;
  srand(intTimeResult);

```

* For each byte of the `flag` the program `XORs` it with a `random` value, then gets another `random` value and `Rotates Left` the result based on the second `random` value

```
    random = rand();
    *(byte *)((long)fileInput + index) = *(byte *)((long)fileInput + index) ^ (byte)random;
    secondRandom = rand();
    secondRandom = secondRandom & 7;
    *(byte *)((long)fileInput + index) =
         *(byte *)((long)fileInput + index) << (sbyte)secondRandom |
         *(byte *)((long)fileInput + index) >> 8 - (sbyte)secondRandom;
```

* At the end, the program writes into `flag.enc` the `intTimeResult` and the `encrypted flag`

And so, to reverse the `encryption` process we need to:
* get the `intTimeResult` and use it as the `seed`
* after that, for every byte we need to `Rotate Right` based on the number of bits given by the `secondRandom` and `XOR` the result with the value of the `firstRandom`
