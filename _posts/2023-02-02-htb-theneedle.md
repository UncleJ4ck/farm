---
layout: post
title: "The Needle (HTB hardware)"
subtitle: "carving router firmware to find a hardcoded telnet login"
date: 2023-02-02
tags: [htb, ctf, hardware, firmware, binwalk]
category: writeups
tldr: "I extracted the router firmware filesystem with binwalk, grepped for login entries, and found telnetd started with Device_Admin and a password stored in a $sign file. Telnetting in with those creds returned the flag."
---

## the challenge

The target was a router firmware image, `firmware.bin`. The goal was to dig a hardcoded credential out of the packed filesystem and use it to log in to the running service over the network.

## analysis

`binwalk -e` unpacked the firmware and dumped its filesystem to disk. From there I grepped recursively across every file for any login reference:

```bash
binwalk -e firmware.bin
grep -rn "./" -e "login"
```

That turned up the telnet startup line:

```
telnetd -l "/usr/sbin/login" -u Device_Admin:$sign
```

So the device starts `telnetd` with a fixed user `Device_Admin`, and the password is whatever `$sign` resolves to. `$sign` was not inline; it pointed at another file in the extracted tree that held the actual password value:

```
$sign: "qS6-X/n]u>fVfAt!"
```

## the solve

With the username from the telnetd line and the password from the `$sign` file, I connected to the host and authenticated as `Device_Admin`:

```bash
nc <host> <port>
```

Logging in as `Device_Admin` with `qS6-X/n]u>fVfAt!` dropped me onto the device and the flag was right there.

## the flag

The session returned the flag in `HTB{...}` form, the kind that names this for what it is, a huge blunder. A hardcoded telnet credential baked into shipped firmware is a static password anyone with the image can read. Pulling the filesystem and grepping for login was enough to walk straight in.
