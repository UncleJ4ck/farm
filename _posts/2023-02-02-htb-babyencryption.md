---
layout: post
title: "BabyEncryption (HTB crypto)"
subtitle: "an affine byte cipher inverted by brute-forcing the printable range"
date: 2023-02-02
tags: [htb, ctf, crypto, affine]
category: writeups
tldr: "The challenge encrypts each plaintext byte with the affine map (123*p + 18) mod 256 and stores the result as hex. Since the keyspace per byte is tiny, I recovered every byte by brute-forcing the printable ASCII range against the ciphertext."
---

## the challenge

I got the encryptor `chall.py` and the ciphertext `msg.enc`. The encryptor walks the secret message byte by byte and pushes each through one arithmetic step:

```python
def encryption(msg):
    ct = []
    for char in msg:
        ct.append((123 * char + 18) % 256)
    return bytes(ct)
```

The output is written as a hex string to `msg.enc`:

```
6e0a9372ec49a3f6930ed8723f9df6f6720ed8d89dc4937222ec7214d89d1e0e...
```

## the bug

This is a classic affine cipher over `Z_256`: `c = (a*p + b) mod 256` with `a = 123` and `b = 18`. The map is invertible because `123` is odd and so coprime to `256`, which means there is exactly one plaintext byte per ciphertext byte. No padding, no chaining, no key beyond the two fixed constants baked into the source. Each byte is independent, so I never needed the modular inverse at all. The plaintext is printable text, and the printable ASCII range is only about 93 values, so I could just try every candidate byte and keep the one whose forward encryption matched.

## the solve

`decode.py` reads the hex, turns it back into bytes, and for each ciphertext byte loops over printable values `33..125`, re-applying the exact forward formula until it lands on a match:

```python
fd = open('msg.enc','r')
secret = fd.read()
ct = bytes.fromhex(secret)

decrypted_str = ""
for char in ct:
    for brute_val in range(33, 126):
        if ((123 * brute_val + 18) % 256) == char:
            decrypted_str += chr(brute_val)
            break

print(decrypted_str)
```

Running it printed the message straight out:

```
python3 decode.py
```

## the flag

The decrypted string was the flag in `HTB{...}` form. Inverting a per-byte affine map is trivial when the alphabet is this small. Even without computing the inverse of `123 mod 256`, brute-forcing the printable range recovers the whole plaintext in one pass.
