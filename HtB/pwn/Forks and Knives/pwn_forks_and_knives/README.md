# Description

Here at the Forks & Knives restaurant we recently hired a new IT guy to add some features to our ordering and reservation system. Apparently, he isn't very good. We want to hire you to test our system. Can you find any problems?

# Executable Description

The first thing the program asks is our username. Afterwards the user can reserve a table for `x` amount of persons, and can order food, with an option being given to add more. There are also menu options specifically for `managers`

# Solution

Examining the binary, we can see that we are dealing with a `server`, with user being able to connect to the binary using sockets, and new connections being created using `fork`. This will prove useful later

The second thing of note is when the user is asked for it's name. If we look into the program we can see a few things. The first is that the socket reads `0x10` bytes using `read`, however the size of the `name` flag in the `bss` section is `0x0f`

```
  sVar3 = read(socket,&name,0x10);
  (&name)[(int)sVar3] = 0;
```

The second thing worth mentioning is that right after the `name`, we have the `isManager` integer value. This value controls access to a few menu options such as clearing reservations or viewing them.

```

                             name                                             
        00104030                 ??         ??
        00104031                 ??         ??
        00104032                 ??         ??
        00104033                 ??         ??
        00104034                 ??         ??
        00104035                 ??         ??
        00104036                 ??         ??
        00104037                 ??         ??
        00104038                 ??         ??
        00104039                 ??         ??
        0010403a                 ??         ??
        0010403b                 ??         ??
        0010403c                 ??         ??
        0010403d                 ??         ??
        0010403e                 ??         ??
        0010403f                 ??         ??
                             isManager                                       
        00104040                 undefined4 ??
        00104044                 ??         ??
        00104045                 ??         ??
        00104046                 ??         ??
        00104047                 ??         ??
```

The third thing worth mentioning is that after the data has been read, a `0x00` is added to the end of the array.

This is an overflow, by sending `0x10` bytes (in my case, 15 'A' and one '0x0a'), we can overwrite the `isManager` value with `0x00`. Because of `little endian` order, the `least significant byte` is stored first, meaning that we can overwrite `isManager` and make is `0x00`

We are doing this to get ourselves a leak. specifically a `LibC Leak`. In the `ReserveTable` function, we can see the following code

    write(socket,"How many people would you like to reserve the table for?\n=> ",0x3c);
    readBytes = read(socket,&numberOfPeople,4);
    *(undefined1 *)((long)&numberOfPeople + (long)(int)readBytes) = 0;
    snprintf(local_38,0x20,"Table for %s\n",&numberOfPeople);
    iVar1 = openReservationFile(local_38);
There are issues with this code .
First, no check is made that the input given is a number, meaning that user can send any inputs up to `4 bytes`. And second, the string is prepared with `snprintf` with the `%s` format being specified. However when it's saved in the `reservations.txt` file, it uses the `openReservationFile` function, which looks like this

```
{
  FILE *__stream;
  undefined8 uVar1;
  
  __stream = fopen("reservations.txt","a");
  if (__stream == (FILE *)0x0) {
    perror("fopen");
    uVar1 = 0xffffffff;
  }
  else {
    fprintf(__stream,param_1);
    fclose(__stream);
    uVar1 = 0;
  }
  return uVar1;
```

as we can see, no format is given to `fprintf`, meaning that we can send strings like `%2$p` to the reservation function, a string will be prepared for it and then when it comes time to saving that string, it will run the `%2$p` format string and get a stack value. In our case, it's the `lseek64+11` address.

Using this and the fact that managers have access to `ViewReservations` functions, we can see the reservation and get ourselves a `libc leak`

Now that we have a `libc leak`, our next goal is to get a `shell`. To do so, we will use the `PlaceOrder` function. Looking at the function, we can see the following code

```
undefined1 firstOrder [264];
    write(socket,"What would you like to order?\n=> ",0x21);
    sVar2 = read(socket,firstOrder,0x100);
    firstOrderReadBytes = (int)sVar2;
    write(socket,"Would you like to add anything to your order? (y/n)\n=> ",0x37);
    read(socket,orderAgain,2);
    orderAgain[1] = 0;
    iVar1 = strcmp(orderAgain,"y");
    if (iVar1 == 0) {
      write(socket,"What else will you add to your order?\n=> ",0x29);
      read(socket,firstOrder + firstOrderReadBytes,0x100);
    }
    hasOrdered = 1;
    write(socket,"You order has been placed!\n",0x1b);
```

which reads up to `0x100` bytes of user data, stores it into the `firstOrder`, then reads AGAIN up to `0x100` bytes, and stores it at the `firstOrder + firstOrderReadBytes` offset. This is a `stack overflow` as by sending `256 chars` first and then sending some data in the second order phase, we can overwrite the `RIP`.

There is however a canary as seen by this code snippet

```
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
```

Thankfully however this server accepts new connections using `fork`. A quirk of `fork` is that it copies the `stack` of the parent process, meaning that unlike normal applications, this process uses the same `canary` between user connections. We can use this to our advantage and `brute force` the canary one byte at the time, meaning we need at most `256*7` tries before getting the canary instead of `256^7` tries.

After the canary has been `brute forced`, we can now build a `rop chain`. The usual `pop rdi; bin sh; system` will not work however, because we are connected via `sockets` to this application. If we do the normal chain, `system` will run , however we will not get any input or output. To correct this , we need to also run `dup2` for `stdin,stdout,stderr` before. `Dup2` is a `C function` that redirects an old `file Descriptor` to a `new one`. Meaning that we can redirect `stdin,out and err` to `socket file descriptor`, which after looking at the code it's `4`. With this step done, running `pop rdi; bin sh; system` will get us a shell
