---
layout: post
title: "SimpleEncryptor (HTB rev)"
subtitle: "the encryptor writes its own srand seed into the file header, so the cipher is reversible"
date: 2023-02-02
tags: [htb, ctf, rev, crypto, prng]
category: writeups
kind: challenge
tldr: "The encryptor seeds rand() with time(NULL) and, fatally, writes that 4-byte seed to the front of the output before the ciphertext. With the seed I replay the same rand() stream and undo each byte's xor-then-rotate in reverse order."
---

## the challenge

SimpleEncryptor ships as a 64-bit ELF `encrypt` and an encrypted `flag.enc`. There are no author notes, so I worked it from the binary's behavior. The job is to recover the plaintext flag from the 32-byte `flag.enc`.

## analysis

The binary is not stripped, so `main` reads cleanly. It opens `flag`, slurps it into a heap buffer, then seeds the PRNG from the clock and transforms the buffer in place:

```c
seed = time(NULL);
srand(seed);
for (i = 0; i < size; i++) {
    buf[i] ^= rand() & 0xff;          // step 1: xor with a random byte
    buf[i]  = rol(buf[i], rand() & 7);  // step 2: rotate left by 0..7
}
```

Two `rand()` calls per byte, in that fixed order: first the xor byte, then the rotate amount. The mistake is what happens after the loop. It writes the output as the 4-byte `seed` first, then the ciphertext:

```c
out = fopen("flag.enc", "wb");
fwrite(&seed, 1, 4, out);   // seed goes in the header
fwrite(buf, 1, size, out);  // then the encrypted bytes
```

Seeding `rand()` from `time(NULL)` would normally force a brute over a time window, but the seed is handed to me in the file. `flag.enc` is 32 bytes: a 4-byte seed header plus 28 bytes of ciphertext. With the seed I reproduce the exact `rand()` sequence and invert each step.

## the solve

Inverting a byte means undoing the operations in reverse: rotate right first, then xor. The catch is order of `rand()` consumption. Encryption pulled the xor byte then the rotate count, so the decryptor has to pull them in the same order, then apply them backward (ror with the second value, xor with the first).

```python
import struct

data = open("flag.enc", "rb").read()
seed = struct.unpack("<I", data[:4])[0]
ct   = data[4:]

# minimal glibc rand() reimplementation, seeded with the file's seed
rng  = GlibcRand(seed)

out = bytearray()
for b in ct:
    x = rng.next() & 0xff   # first rand(): xor byte (consumed first)
    r = rng.next() & 7      # second rand(): rotate amount
    b = ((b >> r) | (b << (8 - r))) & 0xff  # undo rol with ror
    b ^= x                                   # undo xor
    out.append(b)

print(out.decode())
```

The only requirement is a `rand()` that matches glibc's stream for a given seed, since the order of draws has to line up byte for byte.

## the flag

Reading the seed from the header and replaying the stream undid the cipher exactly, and the 28 decrypted bytes spelled the `HTB{...}` flag. Putting the key in the ciphertext is the whole bug: a keyed transform is only as good as the key staying secret. If the seed had not been written to the file, the `time(NULL)` seeding would still have been weak, a brute over a small window of candidate seeds would have recovered it, since each guess either yields printable `HTB{...}` text or garbage.
