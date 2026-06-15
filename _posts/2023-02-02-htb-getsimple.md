---
layout: post
title: "HTB: GetSimple"
subtitle: "default admin:admin into authenticated theme-edit RCE, then sudo php to root"
date: 2023-02-02
tags: [htb, linux, getsimple-cms, cve-2019-11231, gtfobins]
category: writeups
kind: machine
tldr: "Recon found GetSimple CMS 3.3.15 with the admin SHA-1 hash sitting in a world-readable XML file that cracked to admin. From the dashboard I edited a theme template to drop a reverse shell as www-data. www-data could run /usr/bin/php under sudo NOPASSWD, so a one-liner from GTFOBins gave root."
---

## the box

GetSimple is an easy Linux box. Two ports were open, `22` running OpenSSH 8.2p1 and `80` running Apache 2.4.41. The web root served a GetSimple CMS install, version 3.3.15. SSH had nothing for me, so the whole box lived on port 80.

## recon

`robots.txt` disallowed `/admin/`, which was a good start. Directory brute forcing turned up the usual GetSimple layout: `/admin/`, `/backups/`, `/data/`, `/plugins/`, `/theme/`. The data directory was the interesting one. GetSimple stores users as flat XML, and `/data/users/admin.xml` was readable without auth.

```xml
<item>
  <USR>admin</USR>
  <NAME/>
  <PWD>d033e22ae348aeb5660fc2140aec35850c4da997</PWD>
  <EMAIL>admin@gettingstarted.com</EMAIL>
  <HTMLEDITOR>1</HTMLEDITOR>
  <TIMEZONE/>
  <LANG>en_US</LANG>
</item>
```

That `PWD` value is an unsalted SHA-1. `d033e22ae348aeb5660fc2140aec35850c4da997` is the SHA-1 of the string `admin`. So the credentials were `admin:admin`, and they logged straight into `/admin/`.

## foothold

GetSimple 3.3.x (through 3.3.15) has an authenticated RCE in the theme editor, CVE-2019-11231. `theme-edit.php` does insufficient input sanitization, so an authenticated admin can edit the raw PHP of a template file and the server executes whatever you save. The Cardinal theme was installed, so I edited its `template.php` through the editor at:

```
http://10.129.87.63/admin/theme-edit.php?t=Cardinal&f=template.php
```

I pasted a PHP reverse shell into the template and saved it, then triggered it and caught the connection. The shell landed as `www-data`. There is a Metasploit module for this CVE, but editing the template by hand was simpler. From there I found the user `mrb3n` and read the user flag.

## user

The www-data shell already had read access to the user flag, so user fell out of the foothold step.

## root

First thing on a www-data shell, `sudo -l`:

```
User www-data may run the following commands on gettingstarted:
    (ALL : ALL) NOPASSWD: /usr/bin/php
```

`php` runnable as root with no password is a clean GTFOBins entry. The PHP `system()` call inside a root-run interpreter spawns a root shell.

```bash
sudo php -r "system('/bin/bash');"
```

That returned a root shell and the root flag.

## takeaway

Two avoidable mistakes stacked on top of each other. The user database XML was served by the web server with no access control, and the password was an unsalted SHA-1 of a dictionary word. Either one alone is bad. Together they hand you admin. After that the box is a textbook GTFOBins sudo abuse, `php` should never sit in a NOPASSWD rule.
