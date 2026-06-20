---
layout: post
title: "Behind the Scenes (HTB rev)"
subtitle: "SIGILL handlers hide the real password compare from ltrace and strace, so read it statically"
date: 2023-02-02
tags: [htb, ctf, rev, anti-debug, static-analysis]
category: writeups
kind: challenge
tldr: "The binary deliberately executes UD2 to raise SIGILL and runs the real password logic inside the signal handler, so dynamic tracing shows nothing. I skipped the dynamic angle and pulled the flag straight out of the binary with a hex editor."
---
{% raw %}

## the challenge

Behind the Scenes is a 64-bit reversing challenge. One file, an ELF:

```
behindthescenes: ELF 64-bit LSB pie executable, x86-64, dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, not stripped
```

It is a PIE and, helpfully, not stripped, so `main` and the handler keep their symbol names. It wants a password on the command line:

```
$ ./behindthescenes
./challenge <password>
```

The only two strings of interest in the binary are the usage line and the success format:

```
$ strings behindthescenes | grep -iE 'HTB|password'
./challenge <password>
> HTB{%s}
```

So it prints `> HTB{...}` once the password matches. The whole challenge is in how the comparison hides from the obvious tools.

## analysis

My first instinct was to trace the comparison dynamically. Both `ltrace` and `strace` came back with nothing useful: no visible `strcmp`, no readable arguments, no syscall that exposed the check. That is the tell the challenge name points at. The work is happening somewhere the tracer cannot follow.

The reason is in `main`. The function never runs straight through. Every few instructions there is a `ud2`:

```nasm
1261 <main>:
  1261:  endbr64
  ...
  12b3:  call   1130 <sigemptyset@plt>
  12b8:  lea    rax,[rip-0x96]          ; -> 1229 <segill_sigaction>
  12bf:  mov    QWORD PTR [rbp-0xa0],rax
  12c6:  mov    DWORD PTR [rbp-0x18],0x4 ; SIGILL = 4
  ...
  12dc:  mov    edi,0x4                  ; signum = SIGILL
  12e1:  call   10e0 <sigaction@plt>
  12e6:  ud2                            ; <-- illegal instruction
  12e8:  cmp    DWORD PTR [rbp-0xa4],0x2 ; argc == 2 ?
  12ef:  je     130b
  12f1:  ud2
  12f3:  lea    rdi,[rip+0xd0a]          ; "./challenge <password>"
  12fa:  call   10d0 <puts@plt>
  12ff:  ud2
```

`ud2` is the two-byte opcode `0f 0b`. On x86-64 it raises an Invalid Opcode Exception, which the kernel delivers to the process as `SIGILL`. There are fifteen of them scattered through `main`:

```
$ objdump -d behindthescenes | grep -c ud2
15
```

Before the first one runs, `main` registers a handler with `sigaction(SIGILL, ...)`. The handler is `segill_sigaction`, and it is tiny:

```nasm
1229 <segill_sigaction>:
  1229:  endbr64
  122d:  push   rbp
  122e:  mov    rbp,rsp
  1231:  mov    DWORD PTR [rbp-0x14],edi  ; signum
  1234:  mov    QWORD PTR [rbp-0x20],rsi  ; siginfo_t *
  1238:  mov    QWORD PTR [rbp-0x28],rdx  ; void *ucontext
  123c:  mov    rax,QWORD PTR [rbp-0x28]
  1240:  mov    QWORD PTR [rbp-0x8],rax
  1244:  mov    rax,QWORD PTR [rbp-0x8]
  1248:  mov    rax,QWORD PTR [rax+0xa8]  ; ctx->uc_mcontext.gregs[REG_RIP]
  124f:  lea    rdx,[rax+0x2]             ; rip + 2
  1253:  mov    rax,QWORD PTR [rbp-0x8]
  1257:  mov    QWORD PTR [rax+0xa8],rdx  ; write rip back, advanced
  125e:  nop
  125f:  pop    rbp
  1260:  ret
```

The handler reads the third argument, the `ucontext`, fishes the saved instruction pointer out of it at offset `0xa8` (the `REG_RIP` slot inside `uc_mcontext.gregs`), adds 2, and writes it back. Two bytes is exactly the length of `ud2`. So every time execution trips on a `ud2`, the kernel diverts into `segill_sigaction`, which rewinds the saved `rip` past the faulting bytes and returns. Control resumes on the instruction after the `ud2`, as if nothing happened.

That is the entire anti-analysis trick. The program runs correctly because the handler papers over each fault, but the real control flow hops through the signal machinery instead of the normal instruction stream. `ltrace`/`strace` see only the `sigaction` setup and the faults, never the comparison, because the comparison runs between two faults under a handler that the tracer is not stepping into. Naive disassemblers also stop at each `ud2`: tools like Ghidra assume an illegal instruction terminates the path and refuse to disassemble past it, so the body between the `ud2` markers looks like dead bytes.

But objdump linear-sweeps right through it. With the `ud2` noise mentally stripped, `main` is a plain four-stage password check. First it confirms `argc == 2` and that the password is exactly twelve bytes:

```nasm
  130d:  mov    rax,QWORD PTR [rbp-0xb0]
  1314:  add    rax,0x8                  ; argv[1]
  1318:  mov    rax,QWORD PTR [rax]
  131e:  call   10f0 <strlen@plt>
  1323:  cmp    rax,0xc                  ; len == 12 ?
  1327:  jne    1432
```

Then four `strncmp` calls, three bytes each, walking the password in three-character chunks against four rodata constants:

```nasm
  ; chunk 0: argv[1][0..2] vs 0x201b
  133d:  mov    edx,0x3
  1342:  lea    rsi,[rip+0xcd2]          ; 0x201b
  134c:  call   10c0 <strncmp@plt>
  ; chunk 1: argv[1]+3 vs 0x201f
  1369:  add    rax,0x3
  1372:  lea    rsi,[rip+0xca6]          ; 0x201f
  137c:  call   10c0 <strncmp@plt>
  ; chunk 2: argv[1]+6 vs 0x2023
  1399:  add    rax,0x6
  13a2:  lea    rsi,[rip+0xc7a]          ; 0x2023
  13ac:  call   10c0 <strncmp@plt>
  ; chunk 3: argv[1]+9 vs 0x2027
  13c5:  add    rax,0x9
  13ce:  lea    rsi,[rip+0xc52]          ; 0x2027
  13d8:  call   10c0 <strncmp@plt>
  ; all four matched -> printf("> HTB{%s}\n", argv[1])
  13f4:  lea    rdi,[rip+0xc30]          ; "> HTB{%s}\n"
  1400:  call   1110 <printf@plt>
```

If every chunk matches, the password is reflected into `> HTB{%s}`. The flag is therefore the password itself.

## the solve

Satisfying the obfuscated check at runtime is the slow path. The four comparison constants are plain bytes in `.rodata`, and the success string just echoes the password back, so the answer is already in the file. I dumped `.rodata`:

```
$ objdump -s -j .rodata behindthescenes
 2000 01000200 2e2f6368 616c6c65 6e676520  ...../challenge
 2010 3c706173 73776f72 643e0049 747a005f  <password>.Itz._
 2020 306e004c 795f0055 4432003e 20485442  0n.Ly_.UD2.> HTB
 2030 7b25737d 0a00                         {%s}..
```

Lining the four `strncmp` targets up with their addresses:

- `0x201b` -> `Itz` (`49 74 7a`, then `00`)
- `0x201f` -> `_0n` (`5f 30 6e`, then `00`)
- `0x2023` -> `Ly_` (`4c 79 5f`, then `00`)
- `0x2027` -> `UD2` (`55 44 32`, then `00`)

Concatenated in chunk order, the four constants form the twelve-byte password `Itz_0nLy_UD2`, which matches the `len == 12` gate exactly. Feeding it back on the command line clears all four `strncmp` calls, and the binary reflects it into `> HTB{%s}` as the success line:

```text
$ ./behindthescenes Itz_0nLy_UD2
> HTB{Itz_0nLy_UD2}
```

No need to defeat the signal trick at all. A hex editor or `objdump -s` reads the password straight out of the constants the comparison points at. If I had wanted the dynamic route instead, the patch is just as mechanical: replace each `0f 0b` (`ud2`) with `90 90` (two `nop`s) and the binary runs as a normal linear program that `strncmp` traces happily.

## the flag

The flag is the twelve-byte password wrapped in `HTB{...}`: `HTB{Itz_0nLy_UD2}`. Its wording calls out that it was only `UD2` doing the hiding. The takeaway held: when `ltrace` and `strace` go silent because of `SIGILL` and signal-redirected control flow, stop fighting the runtime and read the binary. The data the comparison references, the rodata constants and the format string, gives up the answer with no execution at all.
{% endraw %}
