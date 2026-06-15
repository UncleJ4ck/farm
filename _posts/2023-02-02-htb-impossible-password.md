---
layout: post
title: "Impossible Password (HTB rev)"
subtitle: "first check is a fixed strcmp, second compares against a runtime-random string, so patch the branch"
date: 2023-02-02
tags: [htb, ctf, rev, ghidra, binary-patching]
category: writeups
kind: challenge
tldr: "The binary gates the flag behind two checks. The first compares input to a hardcoded key, the second compares to a 20-byte string generated at runtime that you cannot guess. I patched the conditional jump after the second strcmp to a NOP so the flag routine always runs."
---

## the challenge

Impossible Password is a 64-bit ELF reversing challenge. Run it and it prompts for input, twice. The name is the hint: the second stage is built to be unbeatable by guessing. The goal is to recover the flag the program would print if both checks passed.

## analysis

`strings` on the binary leaked the first-stage key: `SuperSeKretKey`. That gets you past prompt one. In Ghidra the relevant function lined up two comparisons:

```c
local_10 = "SuperSeKretKey";
printf("* ");
__isoc99_scanf(&DAT_00400a82, local_28);
printf("[%s]\n", local_28);
local_14 = strcmp(local_28, local_10);
if (local_14 != 0) {
  exit(1);
}
printf("** ");
__isoc99_scanf(&DAT_00400a82, local_28);
__s2 = (char *)FUN_0040078d(0x14);
iVar1 = strcmp(local_28, __s2);
if (iVar1 == 0) {
  FUN_00400978(&local_48);
}
```

The first `strcmp` is solvable. The second compares my input against `FUN_0040078d(0x14)`, a routine that produces a fresh 20-byte string at runtime. Inside, it seeds with `time(0)` through `srand()` and then makes 20 `rand()` calls to fill the buffer, so the target changes every second. There is no fixed value to type, so stage two cannot be passed by input. The flag-printing routine `FUN_00400978` only runs when that second `strcmp` returns 0.

## the solve

Since the comparison is unbeatable but the success branch is right there, I patched the branch. After the second `strcmp`, the code tests the result and jumps over the flag call when it is non-zero:

```asm
00400966 85 c0           TEST  EAX,EAX
00400968 75 0c           JNZ   LAB_00400976
0040096a 48 8d 45 c0     LEA   RAX=>local_48,[RBP + -0x40]
0040096e 48 89 c7        MOV   RDI,RAX
00400971 e8 02 00 00 00  CALL  FUN_00400978
```

The `JNZ` at `0x00400968` (bytes `75 0c`) skips the flag call whenever the strings differ, which is always. I overwrote it with a two-byte NOP (`66 90`) so execution falls straight into the `LEA`/`MOV`/`CALL` that runs `FUN_00400978`:

```asm
00400966 85 c0           TEST  EAX,EAX
00400968 66 90           NOP
0040096a 48 8d 45 c0     LEA   RAX=>local_48,[RBP + -0x40]
0040096e 48 89 c7        MOV   RDI,RAX
00400971 e8 02 00 00 00  CALL  FUN_00400978
```

## the flag

I saved the patch out of Ghidra and ran the patched binary. With the conditional gone, the second comparison no longer matters and `FUN_00400978` fires unconditionally, printing the flag. It is a short `HTB{...}` hex string.

Patching is not the only way in. The success branch is reached whenever `strcmp` returns 0, so under a debugger you can let the program run to the `TEST EAX,EAX` and just zero `EAX` (or set ZF) before the `JNZ`, with no file edit at all. Either route forces the same `FUN_00400978` call.

## references

- [Impossible Password, Shaswata Das](https://medium.com/@shaswata56/impossible-password-hackthebox-reversing-challenge-8c98b8da6db6)
