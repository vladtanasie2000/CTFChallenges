# Desc

A task management service with a worker thread and a plugin system. Can you find the thread?

# Executable description

The program offers us a couple of choices:

- Initialize chunks of 256 bytes
- Modify/Delete/View them
- Run in a separate thread the process and read plugin state

# Solution

Looking at the securities offered by the application, we see we have :

```
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    FORTIFY:    Enabled
    SHSTK:      Enabled
    IBT:        Enabled
```

With probably the most important being `PIE enabled`

The first thing that is important about this binary and this challenge is the `ld-linux-x86-64.so.2` file. This is the loader, and will be used to load the `threadweaver` binary. The application is then loaded as `./ld-linux-x86-64.so.2 --library-path . ./threadweaver`. This can be observed from the `heap leaks` on remote, as most `heap leaks` start from `0x5555xxxxxxxx` meaning that the first `memory page` being loaded into the program is the `heap`

This has the following effects on the memory of the application

```
        0x555555555000     0x555555576000 rw-p    21000       0 [heap]
        0x7ffff0000000     0x7ffff0021000 rw-p    21000       0 [anon_7ffff0000]
        0x7ffff0021000     0x7ffff4000000 ---p  3fdf000       0 [anon_7ffff0021]
        0x7ffff73ff000     0x7ffff7400000 ---p     1000       0 [anon_7ffff73ff]
        0x7ffff7400000     0x7ffff7c00000 rw-p   800000       0 [anon_7ffff7400]
        0x7ffff7c00000     0x7ffff7c28000 r--p    28000       0 libc.so.6
        0x7ffff7c28000     0x7ffff7db0000 r-xp   188000   28000 libc.so.6
        0x7ffff7db0000     0x7ffff7dff000 r--p    4f000  1b0000 libc.so.6
        0x7ffff7dff000     0x7ffff7e03000 r--p     4000  1fe000 libc.so.6
        0x7ffff7e03000     0x7ffff7e05000 rw-p     2000  202000 libc.so.6
        0x7ffff7e05000     0x7ffff7e12000 rw-p     d000       0 [anon_7ffff7e05]
        0x7ffff7fae000     0x7ffff7faf000 r--p     1000       0 libplugin.so
        0x7ffff7faf000     0x7ffff7fb0000 r-xp     1000    1000 libplugin.so
        0x7ffff7fb0000     0x7ffff7fb1000 r--p     1000    2000 libplugin.so
        0x7ffff7fb1000     0x7ffff7fb2000 r--p     1000    2000 libplugin.so
        0x7ffff7fb2000     0x7ffff7fb3000 rw-p     1000    3000 libplugin.so
        0x7ffff7fb3000     0x7ffff7fb8000 rw-p     5000       0 [anon_7ffff7fb3]
        0x7ffff7fb8000     0x7ffff7fb9000 r--p     1000       0 threadweaver
        0x7ffff7fb9000     0x7ffff7fba000 r-xp     1000    1000 threadweaver
        0x7ffff7fba000     0x7ffff7fbb000 r--p     1000    2000 threadweaver
        0x7ffff7fbb000     0x7ffff7fbc000 r--p     1000    2000 threadweaver
        0x7ffff7fbc000     0x7ffff7fbd000 rw-p     1000    3000 threadweaver
```

As we can see, the first of memory is the `heap`, with `libc` and `threadweaver` zones sharing the same `cluster` in memory. This will be important much later.

Looking at the program, we can see that chunks that are allocated are stored in the `bss` in the following format:

- heap pointer - 8 bytes -- the pointer to the `user data` in the `heap`
- size - 8 bytes -- size of the chunk
- ref - 4 bytes -- reference used for operations
- wasUsed - 4 bytes -- marking the availability of the chunk

```
        0x7ffff7fbc140: 0x0000555555556330      0x0000000000000100
        0x7ffff7fbc150: 0x0000000100000001
```

With a hard limit of `5 chunks` being allowed

Along with the `heap pointers` and their metadata, `stdin,out,err` pointers are also stored in the `bss`

Looking at the `delete chunk` function in the `main thread` section, we can see the following code

```
        index = readChoice("Index: ");
        if (index < 5) {
          dlopen_pointer = (long)(int)index;
          if ((&heapExistsAddr)[dlopen_pointer * 6] != 0) {
            refCount = &heapRef + dlopen_pointer * 6;
            if (*refCount < 1) {
              puts("[-] Already deleted.");
            }
            else {
              LOCK();
              freeSlots = *refCount;
              *refCount = *refCount + -1;
              UNLOCK();
              if (freeSlots == 1) {
                free(*(void **)(&heapPointers + dlopen_pointer * 0x18));
              }
              __printf_chk(2,"[+] Task %d refcount: %d -> %d.\n",index,freeSlots,freeSlots + -1);
            }
            goto LAB_0010146d;
          }
```

which calls `free` on the pointer and sets `refCount` to `refCount-1`. This is fine, however the `edit` and `view` functions check only if the pointer exists, not if `refCount<=0`

`if ((&heapExistsAddr)[dlopen_pointer * 6] != 0)`

This oversight allows us to `modify and view deleted chunks`. We cannot delete them again using the `main thread` however, as that part of the function does check the `refCount`

```
          if ((&heapExistsAddr)[dlopen_pointer * 6] != 0) {
            refCount = &heapRef + dlopen_pointer * 6;
            if (*refCount < 1) {
              puts("[-] Already deleted.");
            }
```

This restriction is only available for the `main thread` however, as the application also spawns a `worker thread` which communicates and executes the `plugin functions`.
The `process task` leaf in the `switch(index)` tree allows any chunk to be `processed` as long as the chunk pointer exists in the `bss`

```
         index = readChoice("Index: ");
        if ((index < 5) && ((&heapExistsAddr)[(long)(int)index * 6] != 0)) {
          refCount = &heapRef + (long)(int)index * 6;
          LOCK();
          *refCount = *refCount + 1;
          UNLOCK();
          pthread_mutex_lock((pthread_mutex_t *)&lock);
          if (condFlag == 0) {
            compFlag = 0;
            condFlag = 1;
            arg = index;
            pthread_cond_signal((pthread_cond_t *)&sharedVar);
            pthread_mutex_unlock((pthread_mutex_t *)&lock);
            __printf_chk(2,"[+] Task %d queued for processing.\n",index);
          }
          else {
            pthread_mutex_unlock((pthread_mutex_t *)&lock);
            puts("[-] Worker busy.");
            LOCK();
            *refCount = *refCount + -1;
            UNLOCK();
          }
```

This is important as at the end of the `plugin task` function, a `free` is called on the `heap chunk pointer` as long as the `refCount` is `0` when the chunk first enters the `plugin process` path.

```

        if (*(long *)(&heapPointers + index * 0x18) != 0) {
          (*pcVar4)(*(long *)(&heapPointers + index * 0x18),(&heapSize)[index * 3]);
        }
        refCount = &heapRef + index * 6;
        LOCK();
        *refCount = *refCount + -1;
        UNLOCK();
        if (*refCount == 0) {
          free(*(void **)(&heapPointers + index * 0x18));
        }

```

This allows us to `double free` and get `tcache poisening`

With all of these elements, we can start to formulate an `exploit chain`

1. Get a `heap leak` via a `tcachebin encrypted fd`
2. Get a `libc leak` via an `unsortedbin`
3. Overwrite the `stdout` using a `House of Apple 2` style of attack

The first step is pretty simple, as all we have to do is allocate one chunk, delete it, and view it. Seeing as the first `tcachebin chunk` is always encrypted as `(chunkAddr>>12)`, from the result we can get the `chunkAddr<<12`, see where our chunk lands using `gdb` and add the offset. We then also get the `heap base`

The next part is a bit more involved. First thing first is that `tcachebins` are `per thread`, meaning that `main thread` and `worker thread` both have their own `tcachebins`. However a few aspects are important

- the chunk size is 0x100, bigger than a `fastbin`
- the `tcachebin 0x100` can hold at most `7 chunks`
- once more than `7 chunks` have been `freed`, an `unsortedbin chunk` is created
- an `unsortedbin chunk` holds in it's `FD` a pointer towards the `LibC`
- `unsortedbin` are `per process` meaning we should view it in `every thread`

The idea is to `free` enough of the `same chunk` to trigger an `unsorted chunk` to be created on the `worker thread` which is also visible in the `main thread`

Mitigations have been created for `free`. Once a chunk has been `freed`, it's `BK` is populated with a value for `integrity checking`. If it corresponds, then `malloc` fails calls `abort` and `exits`

This can be easily avoided in our case, as we can edit the `value` to `0000000000000000` and allow freeing again and again.

Using these steps, we can get a `libc leak`

The final step is overwriting the `stdout` . To do so, we can use a `tcachebin dup`, setting the `FD` to our desired place. One important thing to mention however, is that the application clears the zone in memory before `malloc` is called via the `STOSQ.REP` instruction. Meaning we have to be careful where we place it as it can (and has) crash the application. The best place is in `bss` towards our `heap pointers`. If we manage to change those pointers, we can then `view and modify stdout`

Allocating the chunk directly in `stdout` crashes (due to the `STOPSQ.REP` instr creating an invalid `stdout`) the application. The same thing happens if we directly allocate the chunk to the `heapPointers` location, so we need to put `bss+120(stdout location)-0xa0` to overlap the pointers.

After that is done, we edit the `stdout` pointer with a `House of Apple 2 payload` and get a shell.

The `House of Apple2` attack works by creating a `fake FILE struct` that replaces the `stdout`. This `fake FILE struct` has some important fields set such as

- `flag` being set to `/bin/sh`
- `_IO_wfile_jumps` used for a custom `vtable` which points to `system`
- `mode` set to `wide_data`

This payload can be easily created using the library `pwncli` from `RoderickChan` and the code

```

file = io_file.IO_FILE_plus_struct()
payload = file.house_of_apple2_execmd_when_do_IO_operation(
    libc.sym["_IO_2_1_stdout_"], libc.sym["_IO_wfile_jumps"], libc.sym["system"]
)

```

which simplifies the creation of such a payload

Now one question should pop into everyone mind

`If the binary has PIE enabled, then how can we know the BSS address?`

The answer is via `libc+0x214000`. This is a bit strange and I am not entirely sure why it happens. The application is ran via `/home/ctf/ld-linux-x86-64.so.2 --library-path /home/ctf /home/ctf/threadweaver` in the `remote instance`, meaning that `ld is being ran first`. This messes up with the `usual memory mappings`, making the `heap` memory being the first loaded at `0x555..` with the `libc and application` being loaded in the same `cluster`. Due to the anonymous zones created also by the `so` for the `plugin process`, I believe the space between `libplugin->anon->libc->threadweaver` is constant meaning that offsets between these `SHOULD` be consistent on remote.

Bellow are two separate instances of `threadweaver` ran, and their `/proc/$pid/maps` on remote

First Run

```

        f7b8cd44000-7f7b8cd45000 r--p 00000000 00:bc 269942809                  /home/ctf/libplugin.so
        7f7b8cd45000-7f7b8cd46000 r-xp 00001000 00:bc 269942809                  /home/ctf/libplugin.so
        7f7b8cd46000-7f7b8cd47000 r--p 00002000 00:bc 269942809                  /home/ctf/libplugin.so
        7f7b8cd47000-7f7b8cd48000 r--p 00002000 00:bc 269942809                  /home/ctf/libplugin.so
        7f7b8cd48000-7f7b8cd49000 rw-p 00003000 00:bc 269942809                  /home/ctf/libplugin.so
        7f7b8cd49000-7f7b8cd4c000 rw-p 00000000 00:00 0 
        7f7b8cd4c000-7f7b8cd74000 r--p 00000000 00:bc 269942808                  /home/ctf/libc.so.6
        7f7b8cd74000-7f7b8cefc000 r-xp 00028000 00:bc 269942808                  /home/ctf/libc.so.6
        7f7b8cefc000-7f7b8cf4b000 r--p 001b0000 00:bc 269942808                  /home/ctf/libc.so.6
        7f7b8cf4b000-7f7b8cf4f000 r--p 001fe000 00:bc 269942808                  /home/ctf/libc.so.6
        7f7b8cf4f000-7f7b8cf51000 rw-p 00202000 00:bc 269942808                  /home/ctf/libc.so.6
        7f7b8cf51000-7f7b8cf60000 rw-p 00000000 00:00 0 
        7f7b8cf60000-7f7b8cf61000 r--p 00000000 00:bc 269942810                  /home/ctf/threadweaver
        7f7b8cf61000-7f7b8cf62000 r-xp 00001000 00:bc 269942810                  /home/ctf/threadweaver
        7f7b8cf62000-7f7b8cf63000 r--p 00002000 00:bc 269942810                  /home/ctf/threadweaver
        7f7b8cf63000-7f7b8cf64000 r--p 00002000 00:bc 269942810                  /home/ctf/threadweaver
        7f7b8cf64000-7f7b8cf65000 rw-p 00003000 00:bc 269942810                  /home/ctf/threadweaver

```

Second Run

```

        7fc6a465c000-7fc6a465d000 r--p 00000000 00:bc 269942809                  /home/ctf/libplugin.so
        7fc6a465d000-7fc6a465e000 r-xp 00001000 00:bc 269942809                  /home/ctf/libplugin.so
        7fc6a465e000-7fc6a465f000 r--p 00002000 00:bc 269942809                  /home/ctf/libplugin.so
        7fc6a465f000-7fc6a4660000 r--p 00002000 00:bc 269942809                  /home/ctf/libplugin.so
        7fc6a4660000-7fc6a4661000 rw-p 00003000 00:bc 269942809                  /home/ctf/libplugin.so
        7fc6a4661000-7fc6a4664000 rw-p 00000000 00:00 0 
        7fc6a4664000-7fc6a468c000 r--p 00000000 00:bc 269942808                  /home/ctf/libc.so.6
        7fc6a468c000-7fc6a4814000 r-xp 00028000 00:bc 269942808                  /home/ctf/libc.so.6
        7fc6a4814000-7fc6a4863000 r--p 001b0000 00:bc 269942808                  /home/ctf/libc.so.6
        7fc6a4863000-7fc6a4867000 r--p 001fe000 00:bc 269942808                  /home/ctf/libc.so.6
        7fc6a4867000-7fc6a4869000 rw-p 00202000 00:bc 269942808                  /home/ctf/libc.so.6
        7fc6a4869000-7fc6a4878000 rw-p 00000000 00:00 0 
        7fc6a4878000-7fc6a4879000 r--p 00000000 00:bc 269942810                  /home/ctf/threadweaver
        7fc6a4879000-7fc6a487a000 r-xp 00001000 00:bc 269942810                  /home/ctf/threadweaver
        7fc6a487a000-7fc6a487b000 r--p 00002000 00:bc 269942810                  /home/ctf/threadweaver
        7fc6a487b000-7fc6a487c000 r--p 00002000 00:bc 269942810                  /home/ctf/threadweaver
        7fc6a487c000-7fc6a487d000 rw-p 00003000 00:bc 269942810                  /home/ctf/threadweaver

```

as we can see, `ASLR` works, as instances have `diiferent bases`, however the `anon zone` between `libplugin` and `libc` is always `0x3000` and the `anon zone` between `libc` and `threadweaver` is `0xF000` with the difference between `libc` and `pie` being `0x214000`

Locally this didn't work for me, but I ended up noticing the small differences in addresses between `libc` and `threadweaver` and decided to brute-force attempts on remote. The smallest difference I saw was `0x200000` with the biggest being `0x3f0000` so I decided to try and `brute-force` switching between instances using `page alligned` values (so addresses ending with `0x000`). Imagine my surprise when I noticed that the difference was consistently `0x214000`

One more obstacle is in our way, as the flag is set in an `image` and not as a `text file`. The script handles this by `encoding the file in base64` for transportation and setting a `marker` to denominate the end of the image file, with it also attempting `OCR` via `tesseract` . After this is done we have the flag
