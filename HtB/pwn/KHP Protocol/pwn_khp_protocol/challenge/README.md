# Desc

Welcome to Operation Red Roch, Your mission, should you choose to accept it. Find a zero day in this protocol to gain access in the system. Your exploit will be used by our Red Team in their next mission. Good luck.

# Executable Description

The executable start a server, which we can connect using netcat.
In the application we can register new users, load the database (a file called users.keys)
and persist the users in the database. If we have the admin privileges, we can even get a shell!

# Solution

The goal of this challenge is to call GetAShell() function. Inspecting it we can see that it requires the user to be authenticated and an admin.

```
  if (CURRENT_PROFILE == 0) {
    Send("You need to be authenticated. \n");
  }
  else {
    iVar1 = strcmp(CURRENT_ROLE,"admin");
    if (iVar1 == 0) {
```

The program offers us a few interesting options which I will detail a bit later:

* REKE <user>:<role> <credentials> - register a new user
* AUTH <id> - authenticate with user
* SAVE <id> - save a user to the database
* DEKE <id> - delete a register in-memory user
* RLDB - load the database users
* EXEC - the goal of this CTF

We can register new users using the RegisterNewKey() function, using the format `REKE <user>:<role> <key>`. Seeing as
we control the input we could simply write `REKE user:admin 1`. However this doesn't work as an explicit check has been placed
against saving users with `admin` role to `user.keys`.

For `CURRENT_PROFILE` and `CURRENT_ROLE` to be defined we need to call the Auth() function `(AUTH <id>)`. This function reads two locations, the `IN_MEM_KEYS` which is our input stored in the heap and `KEYS_BUF` using the CheckIfKeyExist() function.

```
  else if (*(long *)(IN_MEM_KEYS + (long)idInput * 8) == 0) {
    Send("There is no key with the id -> %d \n",idInput);
  }
  else {
    inDatabase = CheckIfKeyExist(idInput);
    if (inDatabase == 0) {
      Send("Key should be exist in the database to use it for authentication. \n");
    }
```

`KEYS_BUF` is defined by LoadKeysDB(), which loads `user.keys` into the heap. Seeing as `KEYS_BUF` is loaded as a file we don't have access to, and we cannot save a user with `admin` role we need some unconventional methods to achieve this.

Input is being read via sockets, using the Read() function defined in the application. The function
accepts input up to 256 bytes. This is important as this buffer is used for all operations.
That means that for every operation the application calls a new 0x100 sequence is read.
However not all operations support this size, and the most important one is RegisterNewKey().

Looking at the RegisterNewKey function we can see:

```
    strtok(inputReg," ");
    username = strtok((char *)0x0,":");
    role = strtok((char *)0x0," ");
    credentials = strtok((char *)0x0,";");
    id = GetFreeId();
    ...
    heapPointer = malloc(0x54);
    *(void **)(IN_MEM_KEYS + (long)id * 8) = heapPointer;
    malloc_usable_size(*(undefined8 *)(IN_MEM_KEYS + (long)AVAIL_ID * 8));
    sprintf(*(char **)(IN_MEM_KEYS + (long)AVAIL_ID * 8),"%s:%s %s;",username,role,credentials);
```

that it allocates a heap space of 0x54 heap space and then places a username, role and credentials into it.
But these are our controlled values bigger than 0x54 meaning we have a heap overflow!

This will be base of our exploit, utilizing this and Heap feng-shui we can overwrite the heap and give ourselves admin role

The exploit will follow these steps :

* allocate two users, one will be used to authenticate the other will be used for the overwrite
* load the `KEYS_BUF` using `RLDB`
* delete the second user using `DEKE 2`
* register a new user and overwrite the `KEYS_BUF`
* authenticate using the first user

Take note of the order as it's important

The first step is allocating two users. The first user should be of the format `user:admin 1`. While it is true we cannot save users with admin credentials into the `users.keys`, we can save them into the `IN_MEM_KEYS`. This combined with our capability of overwriting the `KEYS_BUF` we can give ourselves a user with admin privileges.

The second doesn't matter, so I have chosen `user:notadmin 1`

After that we load the `KEYS_BUF` using `RLDB`. We do it now because we want our chunks to be ordered. We will use the first user to authenticate and the second user to overwrite the `KEYS_BUF`. If we do it in reverse (so first `RLDB` and then `REKE`) we would only be able to overwrite the other user.

When this is done, we delete the second user using `DEKE 2`. This uses `free` which frees up the ID that was used and more importantly places the second chunk into `tcachebins`. The `malloc` internals aren't important right now, what is important the next time we request a new user it will place it in the same chunk as the second user was.

This gives us the unique position in which we have a controllable chunk of data between two stored chunks.

We will use this chunk the next time we call `REKE` to overwrite the `KEYS_BUF`.

The exact layout can be seen here

```
    After two REKE operations and RLDB:

    [ user 1 chunk ][ user 2 chunk ][ KEYS_BUF chunk ]

    After DEKE 2:

    [ user 1 chunk ][ freed chunk ][ KEYS_BUF chunk ]

    After the overflowing REKE:

    [ user 1 chunk ][ attacker-controlled record ---> overwrites KEYS_BUF ]
```

The exact offsets and payload is stored in the `.py` file.

After this is done, we can use `AUTH 1` to connect and call `EXEC` to get a shell
