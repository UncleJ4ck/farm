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

{% raw %}

## the challenge

Impossible Password is a reversing challenge shipped as a single ELF. Running it prompts for input, prints what I typed, then prompts a second time. The name is the hint: stage two is built so no input can ever match. The goal is the flag the program would print if both checks passed.

```text
impossible_password.bin: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
dynamically linked, ... GNU/Linux 2.6.32, ... stripped
```

It is 64-bit and stripped, so no function names. I worked off addresses and Ghidra's auto-named `FUN_` labels.

## analysis

`strings` on the binary leaked exactly one useful token:

```text
$ strings impossible_password.bin | grep -i super
SuperSeKretKey
```

That is the stage-one key. The main logic function (Ghidra called it `FUN_0040085d`) lines up the whole flow:

```c
local_10 = "SuperSeKretKey";
local_48 = 0x41; local_47 = 0x5d; local_46 = 0x4b; local_45 = 0x72;
local_44 = 0x3d; local_43 = 0x39; local_42 = 0x6b; local_41 = 0x30;
local_40 = 0x3d; local_3f = 0x30; local_3e = 0x6f; local_3d = 0x30;
local_3c = 0x3b; local_3b = 0x6b; local_3a = 0x31; local_39 = 0x3f;
local_38 = 0x6b; local_37 = 0x38; local_36 = 0x31; local_35 = 0x74;

printf("* ");
__isoc99_scanf(&DAT_00400a82,local_28);
printf("[%s]\n",local_28);
local_14 = strcmp(local_28,local_10);
if (local_14 != 0) {
  exit(1);
}
printf("** ");
__isoc99_scanf(&DAT_00400a82,local_28);
__s2 = (char *)FUN_0040078d(0x14);
iVar1 = strcmp(local_28,__s2);
if (iVar1 == 0) {
  FUN_00400978(&local_48);
}
```

The block of `0x41, 0x5d, 0x4b ...` bytes is a 20-byte array built on the stack and handed to the success routine (`&local_48`). It is not the password. It is the flag stored XOR-encoded: `FUN_00400978` walks the 20 bytes and XORs each by `9` before printing, so `0x41 0x5d 0x4b 0x72` decodes to `H T B {` and the full array becomes `HTB{40b949f92b86b18}`. That is why stage two only gates whether the routine runs, never what it prints.

Stage one is trivial: type `SuperSeKretKey` and the first `strcmp` returns 0, so the `exit(1)` is skipped. The disassembly around that first check:

```asm
40090d: call   400630 <strcmp@plt>
400912: mov    DWORD PTR [rbp-0xc],eax
400915: cmp    DWORD PTR [rbp-0xc],0x0
400919: je     400925                 ; equal -> continue
40091b: mov    edi,0x1
400920: call   400680 <exit@plt>      ; not equal -> exit(1)
```

Stage two is the impossible part. My second input is compared against the return of `FUN_0040078d(0x14)`. That function builds a fresh 20-byte (`0x14`) string at runtime. Disassembling it shows why guessing is hopeless:

```asm
40078d <gen>:
 ...
 4007a0: mov    DWORD PTR [rbp-0x14],0x7e     ; upper bound 0x7e ('~')
 4007a7: mov    DWORD PTR [rbp-0x18],0x21     ; lower bound 0x21 ('!')
 4007ae: mov    edi,0x0
 4007b3: call   400650 <time@plt>             ; time(0)
 4007b8: mov    edx,eax
 4007ba: mov    eax,DWORD PTR [rbp-0x24]      ; arg = 0x14
 4007bd: imul   edx,eax                       ; time(0) * 0x14
 ...
 4007d9: call   400620 <srand@plt>            ; srand(time-derived seed)
 4007e1: add    eax,0x1
 4007e9: call   400660 <malloc@plt>           ; malloc(0x14 + 1)
 ...
 ; loop body, 0x14 iterations:
 400802: call   400690 <rand@plt>             ; rand()
 400807: mov    edx,DWORD PTR [rbp-0x14]      ; 0x7e
 40080a: add    edx,0x1                        ; 0x7f
 40080d: mov    ecx,edx
 40080f: sub    ecx,DWORD PTR [rbp-0x18]      ; 0x7f - 0x21 = 0x5e (range span)
 400812: cdq
 400813: idiv   ecx                           ; rand() % 0x5e
 400815: mov    eax,DWORD PTR [rbp-0x18]      ; 0x21
 400818: add    eax,edx                       ; 0x21 + (rand()%0x5e)  -> printable byte
 40081a: mov    DWORD PTR [rbp-0x1c],eax
 ...
 40082d: mov    BYTE PTR [rdx],al             ; store byte into buffer
 ...
 400836: cmp    eax,DWORD PTR [rbp-0x24]      ; i < 0x14 ?
 400839: jl     400802
 400848: mov    BYTE PTR [rax],0x0            ; NUL terminate
```

So the routine seeds `srand` with `time(0) * 0x14` (plus a global counter), then fills 20 bytes, each `0x21 + rand() % 0x5e`, landing in the printable range `0x21`..`0x7e`. The string is reseeded from the clock on every run, so it changes second to second. There is no fixed value to type, which is the "impossible" in the name. The flag routine `FUN_00400978` only runs when that second `strcmp` returns 0.

## the solve

The comparison is unbeatable, but the success branch sits right after it. So instead of matching the random string, I made the program take the success branch unconditionally by killing the conditional jump.

After the second `strcmp`, the code tests the result and jumps over the flag call when the strings differ:

```asm
400966 85 c0           TEST   EAX,EAX
400968 75 0c           JNZ    LAB_00400976   ; skip flag call if not equal
40096a 48 8d 45 c0     LEA    RAX,[RBP-0x40] ; -> &local_48 (the buffer)
40096e 48 89 c7        MOV    RDI,RAX
400971 e8 02 00 00 00  CALL   FUN_00400978   ; the flag routine
400976 c9              LEAVE
400977 c3              RET
```

The `JNZ` at `0x00400968` (bytes `75 0c`) is the gate. Since `strcmp` is essentially always non-zero, that jump always fires and always skips the flag call. I overwrote those two bytes with a two-byte NOP (`66 90`) so execution falls straight through into the `LEA`/`MOV`/`CALL`:

```asm
400966 85 c0           TEST   EAX,EAX
400968 66 90           NOP                  ; was JNZ
40096a 48 8d 45 c0     LEA    RAX,[RBP-0x40]
40096e 48 89 c7        MOV    RDI,RAX
400971 e8 02 00 00 00  CALL   FUN_00400978  ; now always reached
```

I used Ghidra's assembly patcher, picked `66 90` so the patch is exactly two bytes (same width as `75 0c`, no shifting), and exported the patched binary with Export Program. `66 90` is the canonical two-byte NOP (`xchg ax,ax`); `90 90` would work just as well since both bytes are still in the instruction stream.

## the flag

I ran the patched binary, fed `SuperSeKretKey` at the first prompt and any junk at the second, and with the `JNZ` gone the second comparison no longer mattered. `FUN_00400978` fired and printed the flag:

```text
* SuperSeKretKey
[SuperSeKretKey]
** whatever
HTB{40b949f92b86b18}
```

Patching the file is not the only route. The success branch is taken whenever the result is zero, so under a debugger I could break at `0x00400966`, run the program normally to that point, and clear `EAX` (or set the zero flag) right before the `JNZ`. The `test eax,eax` then sets ZF, the `JNZ` does not fire, and the same `FUN_00400978` runs with no file edit at all. Either way the gate disappears.

{% endraw %}
