
# CTF Challenges — Binary Exploitation & Reverse Engineering

A collection of Capture the Flag solutions, exploit scripts, and technical writeups focused primarily on **binary exploitation**, **glibc heap internals**, **return-oriented programming (ROP)**, and **reverse engineering**.

The goal of this repository is not just to store flags or final payloads. Each challenge is used to document the full exploitation process: identifying a primitive, understanding the relevant mitigations, building leaks or memory corruption primitives, and turning them into reliable code execution.

## Technical Skills Demonstrated

### Exploit Development

- Stack-based buffer overflows and control-flow hijacking
- `ret2win`, `ret2libc`, stack pivoting, and multi-stage ROP chains
- Format-string leaks and information disclosure
- Stack-canary, PIE, ASLR, NX, and RELRO-aware exploitation
- GOT/PLT abuse and writable-GOT overwrites under Partial RELRO
- Shellcode execution and function-pointer corruption
- Cross-architecture exploitation on **AMD64, i386, and ARM32**

### Heap & glibc Internals

- Fastbin duplication / double-free exploitation
- Safe and unsafe unlink techniques
- House of Force and top-chunk corruption
- Unsorted-bin and tcache-based leaks
- Tcache poisoning and safe-linking-aware pointer encoding
- `__malloc_hook` / `__free_hook` attacks in older glibc targets
- `_IO_list_all`, fake `FILE` structures, and FSOP
- House of Orange and House of Apple 2 style exploitation

### Reverse Engineering & Analysis

- Static analysis with **Ghidra**
- Runtime analysis and memory inspection with **GDB**
- Binary protection analysis with `checksec`
- Gadget discovery with **pwntools ROP** and `ropper`
- Reimplementation/reversal of custom encryption logic
- Heap layout analysis and exploit-oriented allocator reasoning

### Tooling

`Python` · `pwntools` · `Ghidra` · `GDB` · `ropper` · `checksec` · `Docker` · `netcat` · `ctypes` · `requests`

---

## Selected Technical Work

These are some  examples to review first.

| Challenge | What it demonstrates |
| --- | --- |
| [HTB — Arms roped](https://github.com/vladtanasie2000/CTFChallenges/tree/main/HtB/pwn/Arms%20roped) | **ARM32 exploitation**: stack-canary leak, PIE leak, libc leak, ARM gadget chaining, and `system("/bin/sh")`. |
| [HTB — funkynator](https://github.com/vladtanasie2000/CTFChallenges/tree/main/HtB/pwn/funkynator) | Heap OOB byte writes, unsorted-bin + tcache leaks, safe-linking reasoning, and **House of Apple 2 / FSOP** using a fake `FILE` structure and `_IO_list_all`. |
| [HTB — Magic Scrolls](https://github.com/vladtanasie2000/CTFChallenges/tree/main/HtB/pwn/Magic%20Scrolls/pwn_magic_scrolls/challenge) | Partial/OOB writes into heap-pointer metadata, heap/libc/stack leaks, tcache poisoning, safe-linking-aware target encoding, and RIP overwrite. |
| [HTB — Last Resort](https://github.com/vladtanasie2000/CTFChallenges/tree/main/HtB/pwn/Last%20Resort) | Exploitation of glibc `qsort` behavior: forcing the `_quicksort` path with `RLIMIT_AS`, abusing insertion-sort behavior for OOB writes, then building PIE/libc primitives toward code execution. |
| [HTB — Scanner](https://github.com/vladtanasie2000/CTFChallenges/tree/main/HtB/pwn/Scanner/pwn_scanner) | Byte-by-byte OOB information disclosure, heap/libc/stack leaks, saved-frame-pointer corruption, stack pivoting, and ret2libc. |
| [Heap — House of Orange](https://github.com/vladtanasie2000/CTFChallenges/tree/main/HeapExploitation/HeapExp/HouseOfOrange) | Top-chunk corruption, unsorted-bin attack, fake `FILE` state, `_IO_list_all`, and vtable-driven execution. |
| [ROP Emporium — pivot](https://github.com/vladtanasie2000/CTFChallenges/tree/main/ROPEmporium/AMD64/pivot) | **Stack pivoting**, GOT/PLT resolution, leaking a shared-library symbol, runtime base calculation, and indirect execution. |
| [ROP Emporium — ret2csu](https://github.com/vladtanasie2000/CTFChallenges/tree/main/ROPEmporium/AMD64/ret2csu) | Use of `__libc_csu_init`-style universal gadgets to control argument registers when straightforward gadgets are unavailable. |
| [BearCat CTF — math playground](https://github.com/vladtanasie2000/CTFChallenges/tree/main/BearCatCTF2026/pwn/math_playground/pwn_math_playground) | i386 OOB function-pointer indexing, constrained arbitrary function calls, Partial RELRO, and GOT overwrite exploitation. |
| [BearCat CTF — Sea Story](https://github.com/vladtanasie2000/CTFChallenges/tree/main/BearCatCTF2026/pwn/Sea_Story) | Function-pointer confusion, stack execution with NX disabled, shellcode, and a null-byte/`strlen` validation bypass. |
| [HTB — Simple Encryptor](https://github.com/vladtanasie2000/CTFChallenges/tree/main/HtB/rev/Simple%20Encryptor/rev_simpleencryptor) | Reversing a PRNG-based byte transformation by reproducing `srand`/`rand`, rotation, and XOR operations. |

---

---

## How I Approach a Challenge

1. **Map the attack surface** — inspect inputs, data flow, architecture, and binary protections.
2. **Identify an exploit primitive** — overflow, leak, OOB access, use-after-free-style condition, arbitrary write, or logic flaw.
3. **Model memory precisely** — stack frames, heap chunks/bins, GOT/PLT state, allocator metadata, or function-pointer layouts.
4. **Defeat mitigations as required** — leak canaries, PIE/libc/heap/stack addresses, account for NX/RELRO, and preserve alignment/calling conventions.
5. **Build a reproducible exploit** — automate the chain in Python and document why each stage works.

## Scope & Responsible Use

All material in this repository comes from **CTF challenges, intentionally vulnerable binaries, or authorized lab environments**. The exploit techniques and payloads are included for education, research, and portfolio demonstration only.

---

I recommend starting with **Arms roped**, **funkynator**, **Magic Scrolls**, **Last Resort**, and the **HeapExploitation** labs; together they show the broadest range of architecture-specific exploitation, mitigation bypasses, allocator internals, and exploit development.
