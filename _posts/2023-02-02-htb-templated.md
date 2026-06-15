---
layout: post
title: "Templated (HTB web)"
subtitle: "the url path is rendered as a jinja2 template, so the path is the injection"
date: 2023-02-02
tags: [htb, ctf, web, ssti, jinja2]
category: writeups
tldr: "A Flask app reflected the requested URL path into a Jinja2 template. Visiting /${{1+1}} returned 2, which confirmed server-side template injection. I walked the object globals to import os and ran commands, then read the flag the same way."
---
{% raw %}

## the challenge

The server banner gave it away as Flask on Werkzeug:

```text
Server: Werkzeug/1.0.1 Python/3.9.0
```

Any path I requested came back reflected in the response. That reflection was not plain text, it was rendered through Jinja2.

## the bug

When user input is dropped into a template that the engine then evaluates, the input becomes template code. I tested with an arithmetic probe in the path:

```text
http://TARGET/${{1+1}}
```

It returned `2`. The server evaluated `1+1`, so this is server-side template injection in Jinja2. The path itself is the injection point.

## the solve

From an SSTI primitive to RCE I climbed the Python object model. Jinja2 only renders, it does not give `os` directly, so I reached it through objects the template already exposed. `request.application` is the Flask app, `__globals__` is the global namespace of the function it lives in, and that namespace carries `__builtins__`. From `__builtins__` I called `__import__('os')`, then `popen(...).read()` to run a command and capture its output. I put the whole chain in the URL path:

```text
${{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

The response contained the output of `id`, so I had command execution. The same gadget, pointed at the flag file instead of `id`, returned its contents.

## the flag

I reused the `os.popen(...).read()` gadget in the path to read the flag file on disk, and Jinja2 rendered the contents back into the response. It came out as `HTB{...templates...}`.
{% endraw %}
