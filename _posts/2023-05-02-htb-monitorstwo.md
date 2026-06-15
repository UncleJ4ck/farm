---
layout: post
title: "HTB: MonitorsTwo"
subtitle: "Cacti unauth RCE inside a container, crack marcus, then a Docker overlay2 escape to host root"
date: 2023-05-02
tags: [htb, linux, cacti, rce, docker, container-escape]
category: writeups
tldr: "Cacti is vulnerable to unauthenticated RCE via remote_agent.php (CVE-2022-46169), landing www-data inside a Docker container. The container config.php has database creds, I crack marcus's bcrypt to funkymonkey and SSH in. Host root comes from CVE-2021-41091: lax overlay2 permissions let me run a SUID bash planted from inside the container."
---

## the box

MonitorsTwo is a Linux box fronted by Cacti. nmap:

```
22/tcp open  ssh   OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp open  http  nginx 1.18.0 (Ubuntu)
```

Port 80 is a Cacti login page.

## recon

This version of Cacti is vulnerable to CVE-2022-46169, an unauthenticated command injection in `remote_agent.php`. Public PoCs exist and need only the target URL and a listener.

## foothold

Running the exploit dropped a shell as `www-data`, but inside a Docker container, not on the host. The `/.dockerenv` file and the container-style hostname made that obvious, and linpeas later confirmed the container ID and `docker-default` AppArmor profile.

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## user

Inside the container, `/var/www/html/include/config.php` holds the database connection details pointing at the `db` host:

```php
$database_hostname = 'db';
$database_username = 'root';
$database_port     = '3306';
```

Querying the `user_auth` table dumped the Cacti accounts and their bcrypt hashes:

```
| admin  | $2y$10$IhEA.Og8vrvwueM7VEDkUes3pwc3zaBbQ/iuqMft/llx8utpR1hjC |
| marcus | $2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C |
```

I cracked marcus's hash with hashcat:

```bash
hashcat -a 0 -m 3200 hash /usr/share/seclists/rockyou.txt
```

It fell to `funkymonkey`, and that password is reused for SSH on the actual host:

```bash
ssh marcus@10.129.51.52   # funkymonkey
```

marcus owns the user flag.

## root

marcus on the host is a regular user, and the container shell is root inside the container. A mail to marcus in `/var/mail/marcus` named the exact path forward:

```
CVE-2021-41091: This vulnerability affects Moby ... Attackers could exploit
this by traversing directory contents and executing programs on the data
directory with insufficiently restricted permissions.
```

Docker Engine before 20.10.9 leaves `/var/lib/docker/overlay2` world-traversable. Every running container's live filesystem sits at a `merged` path on the host, and without user-namespace remapping, UID 0 in the container is UID 0 on the host. So a SUID root binary created inside the container is a SUID root binary on the host, reachable by anyone who can `cd` into the overlay path.

I found the right overlay path with `findmnt`:

```
/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
```

Inside the container as root, I set the SUID bit on bash:

```bash
chmod u+s /bin/bash
```

Then back on the host as marcus, that same binary is now SUID root under the merged path, so executing it through the overlay gives a root shell. That is the root flag.

## takeaway

The whole box is layered access: the Cacti RCE only reaches a container, the cracked password only reaches marcus, and neither is root. The escape works because two defaults line up, overlay2 at permissive permissions and no userns remapping, so container root equals host root through a path marcus is allowed to traverse. I wrote the overlay2 escape up in detail as a standalone PoC, see the [CVE-2021-41091 post]({{ '/cve-2021-41091/' | relative_url }}).
