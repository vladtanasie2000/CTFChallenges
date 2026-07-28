# Description

VAULTRIX runs the quiet backend for people who need something to vanish — blackmail files, insider ledgers, kill lists rebranded as "enterprise notes." Tonight one of those notes goes to auction, and your handler wants it gone before the bidding closes. Their pitch deck brags — "We rewrote our entire backend in Zig. No garbage collector. No hidden allocations. No glibc heap exploits from 2015. Memory safety isn't a feature — it's the foundation." — but you've got a leaked socket, a countdown, and a hunch that "memory safe" doesn't mean "exploit safe."

# Executable Description

The program is a locally ran executable, allowing us to insert `keys` of varying sizes (from 1 to 1024). We can view the `keys`, delete them and modify them based on an index given.

# Solution

Looking at the binary using `checksec`, we can see that `Position Independent Executable` is enabled

```
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        PIE enabled

```

Examining the binary the relevant options for my exploit are:

* PUT -- puts data with a key and a length
* PATCH -- gets a pointer to the chunk and overwrites up to 48 bytes from that chunk
* RENDER -- calls a callback function the display the value

When a new value is first inserted, a new anonymous zone in memory is created where `chunks` are stored. There seems to be two ways in which `chunks` are allocated:

For values smaller or equal than 16 or bigger than 32, they seem to be placed in a higher zone in memory with a pointer towards that zone

For example, allocating via `PUT 1 10 AAAAAAAAAA` we get
at the beginning of the anonymous memory zone
`0x7ffff7ee0000`

```
0x7ffff7ee0000: 0x00007ffff7f00000      0x000000000000000a
0x7ffff7ee0010: 0x00007ffff7f96f30      0x0000000000000000

```

and the actual values here

```
0x7ffff7f00000: 0x4141414141414141      0x0000000000004141
0x7ffff7f00010: 0x0000000000000000      0x0000000000000000

```

as we can see, the format seems to be

* userdata pointer
* size
* pointer to `callback` function used for `RENDER`
* padding

However there seems to be an issues, as with `chunks` that are bigger than 16 byte but smaller than 33 bytes the alocator stores data in-line and puts the `userdata` right behind to the `metadata`.

An example can be seen here

```
0x7ffff7ee0020: 0x4242424242424242      0x4242424242424242
0x7ffff7ee0030: 0x4242424242424242      0x4242424242424242
0x7ffff7ee0040: 0x00007ffff7ee0020      0x0000000000000020
0x7ffff7ee0050: 0x00007ffff7f96f30      0x0000000000000000

```

This can have disastrous effects because `PATCH` allows to patch up to 48 bytes regardless of the size of the `chunk`. If the `userdata` is stored `in-line`, then `PATCH` can modify the `chunks` metadata and overwrite the `callback` address, executing whatever we want.

For this exercise, the function we want is found at `0016b820` from `Ghidras` prospective. This function call for us `/bin/sh` getting us a shell.

However there is a problem and that is that `PIE` is enabled. For this, we need to leak an address, so why not the original `callback` function address?

We can do this using this sequence of of chunks

* First chunk is a normal 10 byte chunk
* Second chunk is a corrupt chunk of 24 bytes

The first chunk will be placed at `0000` offset, while the corrupt `chunk` will be at offset `0020`. By patching the second chunk we can make it point at the first chunk. This is done by overwriting the `0x00007ffff7ee0020` to `0x00007ffff7ee0000` by overwriting the `least-significant byte`. When `RENDER 2`is called, we will be able to print all of the first chunk, including metadata and the `callback` function address. This is because `RENDER` is going to use the `chunks` size field, which still corresponds to the `second's chunk` bigger size field of `24`

Using this trick we have achieved two things

* First we got a `PIE` leak, which we can use to calculate the executable address and see where our function is
* The second thing is by overwriting that pointer with the first chunk, we can now directly write into the `first chunk`.

Seeing as the first chunk is a composed of `32` bytes, we can use `PATCH 2 32` and simply write all 32 bytes with addresses to the `/bin/sh function`. The next time `RENDER 1`gets called, a `shell` should lunch.
