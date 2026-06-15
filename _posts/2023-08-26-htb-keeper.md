---
layout: post
title: "HTB: Keeper"
subtitle: "Request Tracker default creds to reused SSH password, then a KeePass dump CVE recovers the root PuTTY key"
date: 2023-08-26
tags: [htb, linux, request-tracker, keepass, cve-2023-32784]
category: writeups
kind: machine
tldr: "A ticketing subdomain ran Request Tracker with default root:password. A ticket exposed lnorgaard's password, which was reused for SSH. Her home held a KeePass database and a memory dump, and CVE-2023-32784 recovered the master password from the dump. The database stored root's PuTTY private key, which converted to an OpenSSH key for a root login."
---

## the box

Keeper is an easy Linux box. Ports `22` (OpenSSH 8.9p1) and `80` (nginx 1.18.0) were open. The web root pointed at a ticketing system. Vhost enumeration found one subdomain:

```
gobuster vhost -w subs.txt -u keeper.htb
Found: tickets.keeper.htb (Status: 200) [Size: 4236]
```

## foothold

`tickets.keeper.htb` ran Request Tracker 4.4.4. RT ships with a well-known default administrator account, `root:password`, and it still worked here. That logged me into the RT admin panel.

## user

Inside RT, the user list had two accounts:

```
lnorgaard   Lise Nørgaard   lnorgaard@keeper.htb
root        Enoch Root      root@localhost
```

A ticket noted lnorgaard was set up with a default password, and her RT user profile (the admin user-edit page) carried it in cleartext, `Welcome2023!`. That same password worked for SSH:

```bash
ssh lnorgaard@keeper.htb
```

lnorgaard owned the user flag. Her home directory also held `RT30000.zip`, which unpacked to a KeePass database `passcodes.kdbx` and a memory dump `KeePassDumpFull.dmp`.

## root

A KeePass crash dump plus a `.kdbx` is the signature of CVE-2023-32784, which affects KeePass 2.x before 2.54. KeePass leaves the master password in process memory in a recoverable form, where each typed character can be carved from the dump except the first. I used the [keepass-dump-masterkey](https://github.com/CMEPW/keepass-dump-masterkey) tool against `KeePassDumpFull.dmp`, which recovered the master password:

```
rødgrød med fløde
```

I copied the database off the box and opened it with that master password:

```bash
scp lnorgaard@keeper.htb:/home/lnorgaard/passcodes.kdbx .
```

The database stored root's SSH access as a PuTTY private key (`keeper.txt`). PuTTY keys are not directly usable by OpenSSH, so I converted it:

```bash
puttygen keeper.txt -O private-openssh -o id_rsa
chmod 600 id_rsa
ssh root@keeper.htb -i id_rsa
```

That logged in as root and gave the root flag.

## takeaway

Both ends of this box are credential hygiene failures. A production ticketing system left on its install-time `root:password` is an instant admin login, and reusing that ticketed password for SSH turned a web account into a shell. The root step is more interesting, the KeePass dump CVE is a reminder that secret managers leak through process memory, and that storing a private key inside a vault is only as safe as the vault's master password.

## references

- [0xdf - HTB: Keeper](https://0xdf.gitlab.io/2024/02/10/htb-keeper.html)
