# Desc

Get a shell!

# Executable Description

We are able to send strings, with the string being send back at us

# Solution

Examining the binary, we can see that it's an `ARM 32 bit` binary. This changes a few things, most importantly being

* the registers are different, with `r0-r3` being the arguments passed to functions
* `pc` being the `program counter` register
* `bx` being `branch exchange` changing from `normal` to `thumb` mode
* instructions are either `4 bytes` or `2 bytes` (depending on the mode)

And much more, but these will be important for us

Looking at the code using `Ghidra` we can see the function responsible for the storing and displaying of strings. It's appropriately called `string_storer` and it these are the important parts of it

```
  int iVar1;
  char local_34 [32];
  int local_14;
  
  local_14 = __stack_chk_guard;
  while( true ) {
    __isoc99_scanf("%m[^\n]%n",&tmp,&n);
    getchar();
    memcpy(local_34,tmp,n);
    free(tmp);
    iVar1 = memcmp(local_34,&exit,4);
    if (iVar1 == 0) break;
    puts(local_34);
  }
  if (local_14 != __stack_chk_guard) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail(0);
  }
```

as we can see, the program uses `scanf("%m[^\n]%n",%tmp,&n)` to read user input. What this basically does is

* read input until you encounter `\n`
* store the number of bytes into `n`
* allocate that many bytes into `tmp`
* store the result into `tmp`

This is fine, however the next instruction `memcpy(local_34,tmp,n)` stores what is in `tmp` into `local_34` with `local_34` being only `32 bytes` big.

So we have a classic `stack overflow`, this time in ARM!

There are a few issues, one of them being the presence of a stack canary as seen by

```
  if (local_14 != __stack_chk_guard) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail(0);
```

Also the binary is `PIE` meaning, we don't know the address of any functions. And also (`spoilers`), the gadgets we have at our disposition aren't enough to get ourselves a shell.

So the exploit is going to work in 4 parts

1. Get the `canary`
2. Get a `PIE Adress`
3. Get a `LibC Leak`
4. Get a `Shell`

The first part isn't that complicated. The code runs in a loop, with our input being directly shown via the `puts` call. The stack canary is directly after the buffer for the user input. We also know that `ARM` is `little endian` and that `canaries` always end with `00`. We also know that `puts` reads until it reaches a `00`.

So the first step is writing `33 bytes`, `32 bytes` for the buffer, and `1 byte` to overwrite to `00` from the canary. This allows us to read the other `3 significant bytes` of the canary and display them via `puts`. This way, after we get the `significant bytes` we can simply append a `00` in front of it and get the `4 byte canary`

The next step is getting a `PIE Leak`. Looking at the code, we can see `stmdb sp!,{r4,r11,lr}` which is the `ARM` equivalent of  the `push instruction` for `x86` machines. However, we can see that we have `3 pushes`. As each instruction is `4 bytes` in `normal mode`, and the canary is already at offset `32`, the `LR` (which is the `link register`, responsible for setting the `program counter`) we have :

    32 bytes (buffer) + 4 bytes (canary) + 4 bytes(r4)+4 bytes (r11) = `44 bytes` needed before we reach the `LR`

Using a similar trick to the one above, if we overwrite `44 bytes` we can read from the stack the `return address of main+108`. We know the address ends with `0x48` so we can search for that value.

After that, we can calculate the `elf base address` and we can get `PIE Adress`

Now that we have the `PIE Addres` and the `canary` , we can start chaining `gadgets`. We want a `LibC leak` for 3 reasons

* access to the `system` function to get a `shell`
* access to a `/bin/sh` string that we don't have to insert ourselves
* access to more powerful gadgets

To get this leak, we will call `puts@plt` with `r0` being set to `puts@got`. To do this, I have used to following gadgets

```
    pop {r4, r5, r6, r7, r8, sb, sl, pc}
    pop r3,pc
    mov r0, r7; add r4, r4, #1; blx r3; cmp r6, r4; bne #0x9cc; pop {r4, r5, r6, r7, r8, sb, sl, pc};
```

As we can see, I use second gadget to set `r3` to `puts@plt` so that it can be called by the third gadget (`blx r3`) . The first gadget sets `r7` to `puts@got` for the third gadget to set `r0=puts@got`. It also sets `r4` and `r6` to `0` and `1` so that they are equal, so that we jump over `branch not equal (bne)` and go into the `pop`

After this is done, we simply read the result, get the `puts` address, subtract this from the base `libc.sym.puts` address and get the `libc leak`

The final step is getting a shell. For this, the following gadget has been used

```
    pop {r0,r4,pc}
```

With a `/bin/sh` string being found in the `libc`.

Now the chain becomes:

1. set `r0` to `/bin/sh`
2. put into `pc` to `system`

After this, we get a `shell`
