# Desc

After 3 weeks of doing menial work as an intern, they finally allowed me to create front-facing programs!! Could you rate my work?

# Executable Description

The program seems to be a `funkynator`, taking the user input of `Anon` and turning it into `aNoN`. The user can create up to 10 of these strings, being able to overwrite them it they don't like it.

# Solution

Looking at the code, we can see that all the `funky` texts goes into the `heap`

```
else if (userChoice == 2) {
      createChunk(&local_70,&local_68);

void createChunk(long* param_1,long *param_2)
  __isoc99_scanf(&%ld,param_1);
  getchar();
  puts("your message:");
  pvVar2 = malloc(*param_1 + 1);
  *param_2 = (long)pvVar2;
  if (*param_2 == 0) {
                    /* WARNING: Subroutine does not return */
    __assert_fail("*message","funkynator.c",0x2d,"read_parameters");
  }
  fgets((char *)*param_2,(int)*param_1 + 1,stdin);
  getchar();
```

This is fine, however the interesting option is found in the `postProcessing` part of the program, specifically here

```
    if (iVar1 == 2) {
      puts("Your message:");
      puts(param_1);
    }
    else if (iVar1 == 3) {
      puts("please give the offset of the byte:");
      __isoc99_scanf(&%lu,&local_18);
      getchar();
      puts("with what value should this position be overwritten with?");
      iVar1 = getchar();
      param_1[local_18] = (char)iVar1;
      getchar();
```

there is no check for the `local_18` parameter, and it's being read as an `unsigned long` meaning two things

* we can overwrite other chunks metadata, getting a `LibC Leak` via an `unsortedbin FD` and a `Heap Leak` via a `tcachebin FD` by modifying the chunk metadata so that there are no `00` (`puts` stops reading at `00`)
* we can modify directly into `LibC` using the `param_1[local_18]=(char)iVar1` , overwriting the `_IO_list_all` pointer to a `fake file` created on the `heap` and achive a `House of Apple 2` type of attack

The `LibC` leak will be first, seeing as we need chunks big enough to into the `unsortedbin` I choose chunks `1047` size. I also put the `LibC` leak first as consolidation for `tcachebins` doesn't happen like with other chunks. And so to keep the `heap` as neat as possible I started with this.

I created three chunks

* first will be used for editing the second chunk
* second will `freed` thus getting a pointer to the `main arena`
* third is to stop `chunk consolidation` with the `top chunk`

After modifying and reading the LibC leak two things happen

* the value is checked to be at least 6 bytes (so that `puts` read the whole leak and didn't stop at a `00`)
* the chunks are restored and `freed` so we get a clean heap

The same principal is happening in the `tcachebins` but now only with two chunks instead of three. One thing to mention is that the `FD` for the `tcachebins` is `encrypted`. For the first `tcachebin` however, the formula is `chunk_addr >>12` which can be reversed into the `base heap address`

After both the `LibC leak` and the `Heap Leak` have been obtained, it's time to create the fake `FILE` with the following data

| Offset | Value | Explanation |
| -------- | ------- | ------------- |
| `0x00` | `b" sh"` | `_flags` – must not have `_IO_NO_WRITES` (0x8) or `_IO_CURRENTLY_PUTTING` (0x4000). The space makes `system(" sh")` execute `sh`. |
| `0x28` | `p64(1)` | `_IO_write_ptr` – set > `_IO_write_base` (0) to trigger `_IO_OVERFLOW` on flush. |
| `0x88` | `p64(fake_file + 0x40)` | `_lock` – points to a writable location inside the same chunk (offset 0x40). |
| `0xA0` | `p64(fake_file + 0xE0)` | `_wide_data` – points to the `_IO_wide_data` structure placed at offset 0xE0. |
| `0xC0` | `p32(1)` | `_mode` – set to 1 (wide‑mode) to use wide‑file functions (`_IO_wfile_overflow`). |
| `0xD8` | `p64(wfile_jumps)` | Main vtable – points to legitimate `_IO_wfile_jumps`, passes `_IO_vtable_check`. |
| `0x100` | `p64(1)` | (Unused) part of the seed; not critical. |
| `0x1C0` | `p64(fake_file + 0x1C8)` | `_wide_data->_wide_vtable` – points to a fake vtable at offset 0x1C8 (unchecked). |
| `0x230` | `p64(system)` | Function pointer at `_wide_vtable + 0x68` – called by `_IO_wdoallocbuf` → `system(fp)`. |

With this `fake FILE` strut created that passes the integrity checks for `glibc 2.41`, we can overwrite `_IO_list_all` using the same trick for the `chunk metadata`

After that all we need is to trigger `exit` and get a `shell`
