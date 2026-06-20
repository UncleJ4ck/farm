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

CubeMadness (the HTB name is CubeMadness1) is a Windows reversing challenge in the game-pwn category. It ships as a folder of Unity files: a couple of EXEs, several DLLs, and the data folders, with the entry point `HackTheBox CubeMadness1.exe`. The game drops you in a field and you collect cubes. The flag spawns in the middle of the field once the collected count reaches 20, but the level only ever spawns 6 cubes. Playing it straight cannot win, so the win condition has to be forced from outside.

The reason you cannot just open the C# in dnSpy is the build mode. Unity built this with IL2CPP, which transpiles the C# game logic to C++ and compiles it ahead of time into native code inside `GameAssembly.dll`. There is no managed IL to decompile cleanly, so the cube-count comparison lives as native instructions in that DLL.

## analysis

The win check is a comparison in `GameAssembly.dll` at offset `0xA681FB` from the module base. It reads one byte that the branch tests, and the value the game needs there is `0x7F` while the value sitting in the instruction stream was `0x7C`. Those two bytes are short-jump conditional opcodes: `0x7C` is `JL` (jump if less) and `0x7F` is `JG` (jump if greater). Flipping the conditional from one to the other inverts which way the count-versus-20 comparison sends control, which is enough to satisfy the win path.

The data-side reading of the same condition is the `0x14` (20) the count is compared against. So there are two ways at the same gate: change the count value to 20, or change the comparison instruction so the current count passes. Because the game is running, the cleanest code-side move is to attach to the process and write the patched byte straight into its memory at runtime.

## the solve

I wrote a small C++ injector. It does three things: find the game's PID, resolve the base address of `GameAssembly.dll` inside that process, then `WriteProcessMemory` a single byte at `base + 0xA681FB`.

### finding the process

`GetPID` walks the process list with a Toolhelp32 snapshot and matches the executable name case-insensitively:

```cpp
DWORD GetPID(const char* pn)
{
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pE;
        pE.dwSize = sizeof(pE);
        if (Process32First(hSnap, &pE))
        {
            if (!pE.th32ProcessID)
                Process32Next(hSnap, &pE);
            do
            {
                if (!_stricmp(pE.szExeFile, pn))
                {
                    procId = pE.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &pE));
        }
    }
    CloseHandle(hSnap);
    return procId;
}
```

### resolving the module base

PIE/ASLR means `GameAssembly.dll` loads at a different base each run, so I cannot hardcode the absolute address. `GetBaseAddr` snapshots the loaded modules of the target PID and reads `modBaseAddr` for the matching module name:

```cpp
uintptr_t GetBaseAddr(DWORD proid, const char* modName)
{
    uintptr_t modBaseAddr = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, proid);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(modEntry);
        if (Module32First(hSnap, &modEntry))
        {
            do
            {
                if (!_stricmp(modEntry.szModule, modName))
                {
                    modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
                    break;
                }
            } while (Module32Next(hSnap, &modEntry));
        }
    }
    CloseHandle(hSnap);
    return modBaseAddr;
}
```

### writing the byte

`wmain` ties it together: open the process with full access, get the DLL base, and write `0x7F` over the one byte at `base + 0xA681FB`. The length passed to `WriteProcessMemory` is `1`, so even though `lv` is a wider integer, only the low byte (`0x7F`) hits the target.

```cpp
unsigned long long lv = 0x7F; // 7C --> 7F

int wmain() {
    DWORD tpid = 0;
    HANDLE hw = OpenProcess(PROCESS_ALL_ACCESS, 0,
                            tpid = GetPID("HackTheBox CubeMadness1.exe"));
    if (!hw) { printf("not found"); exit(-1); }

    uintptr_t base = GetBaseAddr(tpid, "GameAssembly.dll");

    if (!WriteProcessMemory(hw, (LPVOID)(base + 0xA681FB), &lv, 1, 0)) {
        CloseHandle(hw);
        exit(-1);
    }
    return 0;
}
```

`OpenProcess(PROCESS_ALL_ACCESS, ...)` returns a handle with the write rights `WriteProcessMemory` needs. Resolving `base` at runtime and adding the static `0xA681FB` offset gives the absolute address of the patch site regardless of where the DLL loaded that session.

## the flag

I started the game, left it running, then built and ran the injector. The single-byte write flipped the `JL` at the patch site to `JG` in place. With the comparison inverted, the win state triggered without me ever collecting 20 cubes, and the game presented the flag:

```text
HTB{CU83_M4DN355_UNM4DD3N3D}
```

The intended, code-free route hits the same gate from the data side with Cheat Engine. Attach Cheat Engine to `HackTheBox CubeMadness1.exe`, collect one cube, and do a 4-byte integer scan for `1`. That first scan returns hundreds of thousands of candidates, so you collect another cube, next-scan for the new value, and repeat until the list narrows to a handful of addresses. Set the cube-counter address to `20` (and freeze it), and the same `0x14` check passes from the value instead of the instruction. The injector is that move done with `WriteProcessMemory` against the comparison opcode rather than against the counter.
