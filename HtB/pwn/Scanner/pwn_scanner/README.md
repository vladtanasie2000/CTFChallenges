# Description

In the spirit of optimisation, I wanted a fast memory searching algorithm, and thanks to this program I think I've finally found one. Not only is it fast, it's also completely secure.

# Executable Description

We are offered a few options

1. Updating a buffer in which data is searched
2. Running either a memory scan using `memmem`, `naive1` or `naive2`
3. Running a benchmark

# Solution

## Part 1. Leaking Data

Looking thorough the code, especially through `scanner_naive1` we can see

```
  index = 0;
  do {
    if (0xfff < index) {
      return -1;
    }
    if (*(char *)(param_1 + index) == *param_3) {
      found = true;
      for (loopIndex = 1; (ulong)(long)loopIndex < param_4; loopIndex = loopIndex + 1) {
        if (*(char *)(param_1 + (loopIndex + index)) != param_3[loopIndex]) {
          found = false;
          break;
        }
      }
      if (found) {
        return index;
      }
    }
    index = index + 1;
  } while( true );
}
```

This code searches throughout the `buffer memory zone`, incrementing two indexes, `loopIndex` and `index`, in a `sliding window` style. However we can also see that while `index` searches up until it reaches `0xfff`, `loopIndex+index` doesn't have this check. Meaning that `loopIndex+index` can be used to search after the array and leak addresses nearby.

Looking at the memory we have at that location, we can see the following qwords

```
0x7fffffffdc10: 0x000055555555d2a0      0x0000000000000002
0x7fffffffdc20: 0x0000000000000000      0x00007ffff7df7083
0x7fffffffdc30: 0x0000000200000061      0x00007fffffffdd18
```

With each of them meaning the following:
    `0x000055555555d2a0` -- this is the `heap pointer`
    `0x0000000000000002` -- `window size`
    `0x0000000000000000` -- empty
    `0x00007ffff7df7083` -- `__libc_start_main+243` pointer
    `0x0000000200000061` -- not important
    `0x00007fffffffdd18` -- `stack leak`

We can leak these values `one byte at a time`. By setting the memory where the search is happening to some known values, we can search for a byte outside of the memory zone. I did this by setting the `buffer` to `b'A'*4095` which also added a `null terminator` (important later).

For the search the algorithm is

1. set the `winodow size` to 2 (one for the `null terminator` and another for the byte we are trying to find)
2. try all 256 bytes
3. when a byte is found, increment the window size, append the byte we found, and try with another byte

This works because `loopIndex+index` can search further than `0xFFF`, as that value is never checked

However we need to be careful, as the `heap pointer` and the `window size` will change. The `window size` is an `unsigned size`, meaning for `amd64` machines it's an `unsigned long` (this is because of `malloc` promotes it to unsigned long). After we found the `heap pointer` we can simply insert the `window size` and continue searching.

The `heap pointer` also changes. The `heap pointer` is controlled by the `window size` with `malloc` using the `window size` as it's `size field`. We are using small values for the search, with the `chunks` going to `tcachebin`. `Tcachebin chunks` increase in order of `0x10` bytes, changing from the `0x20` to `0x30` and so on until `tcache_max_bytes` has been reached. This also changes the pointer values, in our case it changes the `0xa0` to a `0xc0` and finally to a `0xf0`. This change happens at indexes of 16 and 32, meaning `0x10` and `0x20`.

## Part 2 Getting a shell

After getting our leaks, we need to prepare the data a bit.

We of course first set the `libc base address` and the `heap address` but we also need to work with the `stack address`. The `stack leak` we get is consistently

1. `0x1108` bytes in front where our `buffer starts`
2. `0xF8` bytes in front of the `RBP`

The second one is very important, as our attacks targets the `RBP`. Looking at the `read_parameters` code, we can see this `scanf`

```
    undefined1 local_18 [16];
    iVar1 = __isoc99_scanf("%16s %u",local_18,param_3);
```

This `scanf` is crucial, as even though it's `length checked` it has a massive issue. It adds a `null terminator`. Because of the `%s` being used and with `strings` in C being `null terminated`, after it ends reading the 16 bytes it appends a `\x00`. However, our field is also `16 bytes` and sits just behind the `saved RBP`, meaning that it overwrites the `LSB` of the `RBP` with `\x00`.

This corruption is later propagated throughout the program because of `leave` instruction, making the corrupt `RBP` available for `main` and later `fgets` as well

This changes where the `variables` and more importantly the `return addresses` are being loaded for. For example, when `no ASLR` is used on my machine I get the following addresses

```
    [*] Stack Leak 0x7fffffffdd18
    [*] Buffer start 0x7fffffffcc10
    [*] Original RBP 0x7fffffffdc20
    [*] New RBP at 0x7fffffffdc00
```

It is important to note there are two occasions where the original `RBP` determines if the script is going to work or not

1. it already ends with `0x00` meaning no overwrite is happening
2. it ends with `0x10`, which messes up with the value for the menu check and crashes the program

We can use this, but we have some problems first. After setting the new `RBP` in `read_parameters` the code will go through `get_scanner_index` and finally through `run_scanner`. However, `run_scanner` will fail with `Invalid Scanner`, `Invalid data buffers`

```
  if (((int)param_1 < 0) || (2 < param_1)) {
    puts("Invalid scanner!");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
```

```
  if ((param_2 != 0) && (param_4 != 0)) {return}
  puts("Invalid data buffers!");
  exit(1);
```

or after the `run_scanner` exits the `free` in the

```
  read_parameters(&local_c,&local_18,&local_10);
  uVar2 = run_scanner(local_c,local_1018,0x1000,local_18,local_10);
  print_scanner_output(uVar2);
  free(local_18);
  local_18 = (void *)0x0;
```

will return `invalid pointer`.

To fix this, we need to setup the buffer before hand. Since we know where our `buffer` starts and where the `new RBP` is set, we can calculate an `offset`, subtract from it `16 bytes` and fill the rest of the data with a pointer to the `heap chunk` and a `scanner`. This is because after we exit `read_parameters` and return to `main` but before `run_scanner` is executed, the `new RBP` is still set, with the memory looking like so.

```
   0x5555555558ea <main+288>               mov    eax, dword ptr [rbp - 8]        EAX, [0x7fffffffdbf8] => 0
   0x5555555558ed <main+291>               mov    ecx, eax                        ECX => 0
 ► 0x5555555558ef <main+293>               mov    rdx, qword ptr [rbp - 0x10]     RDX, [0x7fffffffdbf0] => 0x55555555d2a0 ◂— 
```

This passes both the `scanner check` and the `free check`.

After this is done, we have `RBP` in a state where we can directly insert data into it. This is also called a `stack pivot`. The final step is doing a `ret2libc` attack. We can do this by using the `fgets` inside the `main function`, and `set` it's `RIP` using the `RBP`.

However we have a small issue, using constant offsets breaks as sometimes the `original RBP` is set with `0xa0` or `0x20` or other values. To fix this, I build a `nop;ret` sled of `508` times to be sure. Afterwards, I lunched the attack and got a `shell`
