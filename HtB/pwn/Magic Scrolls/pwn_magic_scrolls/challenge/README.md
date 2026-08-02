# Description

Legends say that if magical numbers align in the right sequence, magic will happen.

# Executable Description

When first entering the application, the process request a `magic charm`

Afterwards several operations are available:

* we can insert new magic numbers (between 1 and 4)
* we can create new spells (between 0 and 15)
* we can remove spells
* we can set a favorite spell (only one favorite per process)
* we can view that favorite spell
* we can exit our process

# Solution

The program comes with `ld-2.37.so` and `libc.so.6` files, which will be used later.

First of all, `create_spell` functions creates `spells` on the `heap` and it stores their `spell_len` and `spells` pointer. It also has a variable called `spell_count` which gets increased every time a new spell is created but cannot be decremented

`set_favorite_spell` function gets one spell from the `spells` list and sets it as the `super_spel`, setting `super_spel_set` to `True` (cannot be reset to `False`) and `super_spel_len` to the length

`read_spell` reads the `super_spell` and returns it to us

`remove_spel` frees the `spell`, removes the `heap pointer` from the `spells` and sets the `spell_len` to 0

Analyzing the binary we can see a few interesting things

* `power` is set to `4` if the `magic charm` *DIFFERS* from `Alohomora`
* `power` is used by the `update_magic_numbers`  function

Looking into how `update_magic_numbers` works, we can see

```
    if (power != 0) {
      if ((magic_numbers == 0) && (DAT_00105070 == 0)) {
        memset(&magic_numbers + power,0,1);
      }
      else {
        (&magic_numbers)[power] = magic_numbers & DAT_00105070;
      }
      if ((DAT_00105068 == 0) && (DAT_00105078 == 0)) {
        memset(&magic_numbers + (power + 1),0,1);
      }
      else {
        (&magic_numbers)[power + 1] = DAT_00105068 & DAT_00105078;
      }
    }
```

For simplicity sake, we will use

* `magic_numbers` as `index 1`
* `DAT_00105070` as `index 3`
* `DAT_00105068` as `index 2`
* `DAT_00105078` as `index 4`

If `index 1` and `index 3` are both `0` then it goes into `magic_numbers+power` and clears the `LSB`
If not, then it sets `magic_numbers+power` as `index 1 & index 3`
If `index 2` and `index 4` are both `0` then it goes into `magic_numbers + (power+1)` and clears the `LSB`
If not, then it sets `magic_numbers+(power+1)` as `index 2 & index 4`

This is extremely important, as right next to `magic_numbers` is `spells`, which is our array of `heap pointers`

```
0x555555559060 <magic_numbers>: 0x0000000000000000      0x0000000000000000
0x555555559070 <magic_numbers+16>:      0x0000000000000000      0x0000000000000000
0x555555559080 <spells>:        0x0000000000000000      0x0000000000000000
0x555555559090 <spells+16>:     0x0000000000000000      0x0000000000000000

```

Using the fact that `power=4`, we can perform `arbitray writes` into the `spells` array, with an even `partial overwrite`

For this, we will first need to allocate two chunks

* chunk 0 : 0x7 `spell_len`
* chunk 1 : 0xff `spell_len`

The logic being the following

* chunk 0 is going to be freed
* chunk 0 is going to go into the `tcachebin`
* chunk 0 is closer to the beginning of the `heap`
* chunk 1 will be used to read `0xFF` bytes from the overwritten zone and get a `heap leak`

Assuming that our allocate second chunk is at `0x000055555555d2a0` , we can see that after our corruption using

* `index 1` and `index 3` as `0x1111`
* `index 2` and `index 4` as `0`
we have

```
0x555555559060 <magic_numbers>: 0x0000000000001111      0x0000000000000000
0x555555559070 <magic_numbers+16>:      0x0000000000001111      0x0000000000000000
0x555555559080 <spells>:        0x0000000000001111      0x000055555555d200

```

With a chunk layout of

```
x55555555d0a0  0x0000000000000000      0x0000000000000000      ................
        ... ↓      30 repeated lines skipped
0x55555555d290  0x0000000000000000      0x0000000000000021      ........!.......
0x55555555d2a0  0x000000055555555d      0x57feeefdab530b53      ]UUU....S.S....W         <-- tcachebins[0x20][0/1]
0x55555555d2b0  0x0000000000000000      0x0000000000000111      ................
0x55555555d2c0  0x4242424242424242      0x4242424242424242      BBBBBBBBBBBBBBBB

```

since we start reading from `0x000055555555d200` `0x100` bytes, we can read from `0x000055555555d200` till `0x000055555555d300`, covering our `tcachebin` and getting an `FD` which by shifting it to the left 12 positions we get `0x000055555555d000` which corresponds to our `heap`

With a `heap leak`, the next step is a `libC leak`. This can be achieved using an `unsortedbin attack`. For that however, we need to fill the `tcachebins`.

Using `gdb`, we can see that `tcache_count = 7`, meaning that for each `tcachebin` of one size it can only hold `7 chunks`

So for this the next step was creating `8 chunks` of `0x88` size and freeing them in `reverse order` to prevent consolidation.

Using the discovered `heap leak` and looking in `gdb`, we can calculate exactly at what offset the `favorite spell` pointer needs to be for us to read the `FD` of the `unsortedBin`. The `FD` points towards the `main arena`, a zone in the `LibC` found at a specific offset

After getting the `main arena` using the `unsortedbin attack`, we can get the `libC base address`.

The final leak I got is a `stack leak`. Using the `_environ` variable in the `LibC` that holds `arguments` and the `LibC address`, we can get a `stack leak`

Once all of these values have been leaked, it's time to construct a `write primitive`. We will use for this a chunk holding two `fake chunks` of size `0x31`. The idea being that we can pass the `favorite_spell` pointer to these `fake_chunks`, free them and get them into the `tchachebin 0x30`. After the `chunks` have been placed in the `bins`, we can free the `original chunk`

This gives us the opportunity to overwrite the `chunk data` of a `freed chunk`, thus allowing us to modify the `FD` of the `freed tcachebin` and making it point wherever we want.

We need however to be careful as `tcachebins` need to be `16-byte alligned` and their `FD` is `encrypted` using the formula
`16-byte alligned destination ^ (chunk_addr >> 12)`

But seeing as we have a `heap leak` this can be achieved.

The location chosen for the overwrite is the `RIP` address on the stack for the `create_spell` function.

This will be overwritten with a `onegadget` that will get us a shell.

A script will be provided that will execute all of these commands.
