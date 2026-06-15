---
layout: post
title: "RsaCtfTool (HTB crypto)"
subtitle: "an RSA modulus that is a prime cube, so phi comes straight from the single prime"
date: 2023-07-28
tags: [htb, ctf, crypto, rsa, prime-power]
category: writeups
kind: challenge
tldr: "The public modulus n is a prime cube p^3, which breaks the usual two-prime phi formula. With p from factordb I computed phi = p^2*(p-1), recovered d, decrypted the RSA-wrapped AES key, then AES-ECB decrypted flag.txt.aes."
---

## the challenge

I had a public key `pubkey.pem`, an RSA-encrypted symmetric `key`, and `flag.txt.aes`. The key file holds the AES key encrypted under RSA. The flag itself is AES-ECB encrypted with that wrapped key. So the chain was: break RSA, recover the AES key, then decrypt the flag.

Loading the public key gave me `n` and `e`, with `e = 65537` (the usual `0x10001`).

## analysis

The modulus is not the usual product of two distinct primes. It is a prime power, `n = p^3`. Pasting `n` into factordb returned a single base raised to the third power rather than two cofactors, which is what gave the structure away. That changes the totient. For `n = p^k`, `phi(p^k) = p^k - p^(k-1) = p^(k-1) * (p-1)`, so for the cube:

```
phi = p^2 * (p - 1)
```

`p` was already in factordb, so I pulled it from there directly. With a single prime and the right phi, the private exponent is just `d = e^-1 mod phi`. From there `pow(key, d, n)` undoes the RSA wrapping on the AES key.

## the solve

`exp.py` imports the public key, hardcodes `p` from factordb, builds phi for the prime-cube case, inverts `e`, and decrypts the wrapped key. Then it runs AES-ECB on the flag ciphertext:

```python
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES

pub = RSA.importKey(open('pubkey.pem', 'r').read())
n = pub.n
e = pub.e

# p from factordb.com
p = 1128137999850045612492145429133282716267233566834715456536184965477269592934207986950131365518741418540788596074115883774105736493742449131477464976858161587355643311888741515506653603321337485523828144179637379528510277430032789458804637543905426347328041281785616616421292879871785633181756858096548411753919440011378411476275900648915887370219369154688926914542233244450724820670256654513052812215949495598592852131398736567134556141744727764716053145639513031
phi = p * p * (p - 1)
d = pow(e, -1, phi)

key = int(open('key', 'r').read(), 16)
key_decrypted = long_to_bytes(pow(key, d, n))

cipher = AES.new(key_decrypted, AES.MODE_ECB)
ct = open('flag.txt.aes', 'rb').read()
print(cipher.decrypt(ct[:-1]))
```

The RSA decrypt returns a 16-byte value, the AES-128 key. The AES file is 33 bytes, so the script trims the last byte before decrypting (`ct[:-1]`). That last byte is a trailing newline, not padding, and dropping it leaves 32 bytes, two clean 16-byte blocks for ECB.

The challenge is named after `RsaCtfTool`, and the tool would have solved it without writing any of this. Its prime-power attack handles `n = p^k` directly:

```bash
RsaCtfTool.py --publickey pubkey.pem --uncipherfile key
```

## the flag

The AES-ECB decrypt printed the flag in `HTB{...}` form. The whole break hinged on noticing `n` was a prime cube. The standard `(p-1)*(q-1)` would have produced the wrong phi and a useless `d`. Once the totient matched the prime-power structure, the rest was a plain modular inverse and one AES decrypt.

## references

- [7Rocky: RsaCtfTool](https://7rocky.github.io/ctf/htb-challenges/crypto/rsactftool/)
- [forensicskween: HackTheBox RsaCtfTool](https://forensicskween.com/ctf/hack-the-box/htb-rsactftool/)
