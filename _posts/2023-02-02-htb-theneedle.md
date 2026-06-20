---
layout: post
title: "The Needle (HTB hardware)"
subtitle: "carving router firmware to find a hardcoded telnet login"
date: 2023-02-02
tags: [htb, ctf, hardware, firmware, binwalk]
category: writeups
kind: challenge
tldr: "I extracted the router firmware filesystem with binwalk, grepped for login entries, and found telnetd started with Device_Admin and a password stored in a $sign file. Telnetting in with those creds returned the flag."
---

## the challenge

The target was a router firmware image, `firmware.bin`, plus a live service exposed on a host and port. The goal was to dig a hardcoded credential out of the packed filesystem and use it to log in to the running service over the network. This is the standard embedded-device pattern: the firmware on disk and the device on the wire share the same baked-in secret, so reading the image gives you the key to the box.

## analysis

First I fingerprinted the blob. `file firmware.bin` and a quick `binwalk firmware.bin` scan showed it was not a single executable but a packed firmware image: a bootable Linux kernel followed by a compressed root filesystem. The signature scan flagged a kernel image (a `zImage`-style Linux kernel) and a `SquashFS` filesystem, which is the read-only compressed filesystem almost every consumer router ships its root tree in.

`binwalk -e` ran the extraction. It walks the image, finds each known signature, and carves the regions out, decompressing the SquashFS as it goes. Everything landed in `_firmware.bin.extracted/`, and the real root tree sat under `_firmware.bin.extracted/squashfs-root/`, a normal Linux directory layout: `bin`, `etc`, `usr`, `sbin`, and so on. That is the device's actual filesystem, the same files that are mounted when the router boots.

From the root of that tree I grepped recursively across every file for any login reference:

```bash
binwalk -e firmware.bin
cd _firmware.bin.extracted/squashfs-root
grep -rn -e "login" ./
```

That turned up the telnet startup line, inside the device's init script `etc/scripts/telnetd.sh`:

```
telnetd -l "/usr/sbin/login" -u Device_Admin:$sign
```

So the device starts `telnetd` with a fixed user `Device_Admin`, and the password is whatever `$sign` resolves to. The `-l` flag points the daemon at `/usr/sbin/login` as the login program and `-u user:pass` hardcodes the credential pair. `$sign` was not inline; it was a variable the script reads from a config file elsewhere in the tree. A `find` for that file name located it:

```bash
find . -type f -name sign
```

That pointed at `squashfs-root/etc/config/sign`, which held the actual password value:

```
$sign: "qS6-X/n]u>fVfAt!"
```

So the full credential pair baked into the image was `Device_Admin` / `qS6-X/n]u>fVfAt!`. Nothing about it changes per device; anyone holding the firmware holds the login.

## the solve

A quick `nc <host> <port>` confirmed the service on the wire was a real telnet login prompt rather than a raw text banner, so it expected the protocol's option negotiation, not just a typed password into a dumb socket. I switched to a real telnet client so the negotiation was handled and the prompt behaved:

```bash
telnet <host> <port>
```

It asked for a username and password. I gave the pair from the script and the config file, `Device_Admin` and `qS6-X/n]u>fVfAt!`. The login dropped me onto the device, and `flag.txt` was right there in the landing directory.

```bash
cat flag.txt
HTB{4_hug3_blund3r_d289a1_!!}
```

## the flag

The session returned `HTB{4_hug3_blund3r_d289a1_!!}`, the kind of flag that names this for what it is, a huge blunder. A hardcoded telnet credential baked into shipped firmware is a static password anyone with the image can read, and it logs in to every unit of that model on the network. Pulling the filesystem and grepping for login was enough to walk straight in. The name fits: the credential was one config line buried in a full firmware image, a needle in the haystack.
