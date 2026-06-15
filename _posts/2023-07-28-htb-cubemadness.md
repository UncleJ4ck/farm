---
layout: post
title: "CubeMadness (HTB rev)"
subtitle: "patch a live Unity IL2CPP game's memory to flip the win check"
date: 2023-07-28
tags: [htb, ctf, rev, unity-il2cpp, memory-patching]
category: writeups
kind: challenge
tldr: "A Unity IL2CPP Windows game holds a win condition compiled into GameAssembly.dll. Rather than beat the game, I wrote a small injector that finds the process, resolves the module base, and patches one byte at base+0xA681FB from 0x7C to 0x7F so the check passes."
---

## the challenge

CubeMadness is a Windows reversing challenge shipped as a Unity game, `HackTheBox CubeMadness1.exe`. Unity built with IL2CPP, which means the C# game logic is ahead-of-time compiled into native code inside `GameAssembly.dll`. The flag drops when the cube counter hits 20, but the level only spawns 6 cubes, so it is impossible to clear by playing. The win check is a comparison in that native module.

## analysis

The interesting code is in `GameAssembly.dll` at offset `0xA681FB` from the module base. The check there reads one byte that I needed to be `0x7F`, but the running value was `0x7C`. Flipping that single byte from `0x7C` to `0x7F` satisfies the condition. Because the game is live, the clean approach is to attach to the process and write the patched byte directly into its memory.

## the solve

I wrote a small C++ injector. It walks the process list with a Toolhelp32 snapshot to find the game PID, opens the process, walks the module list to get the `GameAssembly.dll` base, then uses `WriteProcessMemory` to drop `0x7F` at `base + 0xA681FB`.

```cpp
unsigned long long lv = 0x7F; // 7C --> 7F

DWORD tpid = 0;
HANDLE hw = OpenProcess(PROCESS_ALL_ACCESS, 0,
                        tpid = GetPID("HackTheBox CubeMadness1.exe"));
if (!hw) { printf("not found"); exit(-1); }

uintptr_t base = GetBaseAddr(tpid, "GameAssembly.dll");

if (!WriteProcessMemory(hw, (LPVOID)(base + 0xA681FB), &lv, 1, 0)) {
    CloseHandle(hw);
    exit(-1);
}
```

`GetPID` uses `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` and compares each `PROCESSENTRY32` name with `_stricmp`. `GetBaseAddr` snapshots modules with `TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32` and matches `GameAssembly.dll` to read its `modBaseAddr`. The write touches exactly one byte, so I pass length `1` even though `lv` is wider.

## the flag

With the game still running, I built and ran the injector. The single-byte patch flipped the comparison in place, the win state triggered, and the game presented the flag. It reads as cube madness, unmaddened.

The shorter intended route skips writing code entirely: attach Cheat Engine to the process, scan for the cube counter as a 4-byte int (start at 0, collect one cube, scan for the increased value, repeat to isolate the address), then freeze it at 20. The counter passes the same `0x14` check from the data side instead of patching the comparison from the code side. The injector is the equivalent move done with `WriteProcessMemory` against the instruction rather than the value.

## references

- [CubeMadness1, Rahul R](https://rahulr.in/HackTheBox-GamePWN/)
