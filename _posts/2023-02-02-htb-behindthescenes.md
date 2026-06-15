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

Behind the Scenes is a 64-bit ELF reversing challenge. It takes a password on the command line (`./challenge <password>`) and prints `> HTB{%s}` when you get it right. The twist is in how it hides the check.

## analysis

My first instinct was to trace the comparison dynamically. Both `ltrace` and `strace` came back with nothing useful, no visible `strcmp`, no readable arguments. The reason is the anti-debug trick the name points at. The binary scatters `UD2` instructions through its code, fifteen of them, which raise an illegal-instruction fault (SIGILL). It registers a handler with `sigaction` and `sigemptyset`, so each fault hands control to the handler instead of crashing.

The real password logic lives inside that signal flow. Execution hits a `UD2`, the kernel delivers SIGILL, and the handler advances past the faulting bytes and does the work there. Straight-line tracers never see the comparison because the control flow jumps through the signal machinery, not normal calls. The on-disk instruction stream also looks broken at every `UD2`, which throws off naive disassembly.

## the solve

Fighting the anti-debug dynamically is the slow path. The flag is a static string the program eventually prints, so I went after the bytes directly. I opened the binary in a hex editor and read the flag out of it. No need to satisfy the obfuscated comparison at runtime when the answer is sitting in the file.

## the flag

The flag came out of the hex dump intact, an `HTB{...}` string whose wording calls out that it is only UD2 doing the hiding. The lesson held: when dynamic tools go quiet because of SIGILL or signal-based control flow, drop to static analysis and read the binary. A shortcut that also works: search the binary for the program name string passed as `argv[0]`, since the password bytes live near it in the data the program references.
{% endraw %}
