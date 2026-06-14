---
layout: post
title: "Odoo snippet filters: a public domain you control, filtered as superuser"
subtitle: "the dynamic product filter on /website/snippet/filters ran the visitor's search_domain against a sudo recordset, turning a marketing widget into a pre-auth boolean oracle over the database"
date: 2026-03-23
tags: [orm-injection, odoo, pre-auth, oracle, bug-bounty]
category: research
tldr: "POST /website/snippet/filters is auth='public'. The website_sale dynamic filter takes a caller-supplied search_domain and hands it to sold_products.filtered_domain(domain) on a recordset that still carries superuser rights. Because the domain is evaluated with full read access, relational traversal reaches fields the public user can never see, and the rendered snippet becomes a true/false oracle you can walk character by character with no login. Odoo fixed it by dropping privileges on that path (sudo(False)) and committed to a CVE. Found with Aymane Mazguiti."
---

## the route nobody thinks of as a query interface

`/website/snippet/filters` exists to render a small marketing block: latest products, best sellers, recently viewed. It is `auth='public'`, because the block shows up on pages anonymous visitors see. The body carries the snippet's parameters, and one of them is `search_domain`, the filter the block applies before it picks what to show.

A "domain" in Odoo is the ORM's query language: a list of leaves like `[('list_price', '>', 100)]`, combined with `&` / `|`, and crucially able to walk relations with dotted paths (`partner_id.email`, `create_uid.login`). It is the same expression the framework turns into SQL. So a public route that accepts a domain and acts on it is, structurally, a public route that accepts queries. The only thing standing between that and a data leak is whose permissions the domain runs under.

## reading the path down to the sink

The render walks `website.snippet.filter._render` -> `_prepare_values`, and for a `website_sale` product filter it lands in `_get_products`, which dispatches by `mode` and ends in `_get_products_latest_sold`. That is where the caller's domain meets the records:

```python
# addons/website_sale/models/website_snippet_filter.py  (pre-fix)
@api.model
def _get_products(self, mode, **kwargs):
    dynamic_filter = self.env.context.get("dynamic_filter")
    handler = getattr(self, "_get_products_%s" % mode, self._get_products_latest_sold)
    ...

def _get_products_latest_sold(self, website, limit, domain, **_kwargs):
    ...
    if sold_products:
        products = sold_products.filtered_domain(domain)[:limit]
    return products.with_context(display_default_code=False)
```

`domain` is the attacker's `search_domain`, pulled from context and passed straight in. `filtered_domain` evaluates that domain in memory against `sold_products`, and every field it touches, including dotted traversal into related records, is read with the rights of `self`. On this render path `self` is the superuser recordset that builds the snippet. So the domain is evaluated with full read access to every field on every reachable model.

That is the whole bug. The visitor does not get to read the fields directly, but they get to *ask questions about them* and watch whether records match. A leaf like `('create_uid.login', '=like', 'a%')` keeps a record in the set only if an admin login starts with `a`. The block renders one product or zero. Repeat over the alphabet and over positions and the rendered count spells out the value, with no session, no cookie, no login.

## why it is a real oracle, not a maybe

The signal is binary and you can turn it off on demand, which is the test that separates a finding from a guess. A domain leaf that can never be true (`('id', '=', 0)`) renders the empty state. A leaf that is always true renders the normal set. Anything in between is the bit you are reading. Same request, two flippable outcomes, controlled entirely by the part of the domain you supply. That is the negative control baked into the primitive itself.

Relational traversal is what makes it dangerous rather than cute. From a published product you can walk to `create_uid`, `write_uid`, and onward into `res.users` and any model joined to the ones the filter can reach. The public user is never granted read on those fields. The superuser evaluation grants it anyway. The domain is the only thing the attacker needs to control, and the route hands it to them.

## the fix, pulled from the commit

Odoo's fix is two characters of intent repeated twice: drop superuser before the domain is evaluated. Commit `c0c93e0110f9`, `[FIX] website_sale: dynamic filters as a visitor` (opw-6041547):

```diff
 @api.model
 def _get_products(self, mode, **kwargs):
     dynamic_filter = self.env.context.get("dynamic_filter")
-    handler = getattr(self, "_get_products_%s" % mode, self._get_products_latest_sold)
+    handler = getattr(self.sudo(False), "_get_products_%s" % mode, self.sudo(False)._get_products_latest_sold)
```

```diff
 def _get_products_latest_sold(self, website, limit, domain, **_kwargs):
     ...
     if sold_products:
-        products = sold_products.filtered_domain(domain)[:limit]
+        products = sold_products.sudo(False).filtered_domain(domain)[:limit]
```

`sudo(False)` runs the call as the actual request user, which on a public route is the website's public user. Now `filtered_domain` evaluates the attacker's domain under that user's access rules. A leaf that traverses into a field the public user cannot read raises an access error instead of silently resolving, and the oracle loses the thing it was reading. The fix being exactly "add sudo(False) on the domain path" is also the cleanest confirmation that the path previously ran elevated. You do not drop a privilege that was not there.

I confirmed the patched shape in current `19.0` source: the product fetch and the `filtered_domain` call both run `sudo(False)`, so the visitor's domain is bound to public permissions.

## severity and status

I rated it High. It is unauthenticated, network-reachable, fully automated, and it reads arbitrary stored fields through relational traversal, which is a confidentiality hit well past what a marketing snippet should ever expose. It is the same class as [CVE-2024-36259](https://nvd.nist.gov/vuln/detail/CVE-2024-36259), the Odoo 17 oracle via crafted RPC search with elevated privileges, except this one needs no authentication and rides a public website route.

Odoo accepted it, shipped the fix across supported branches, and said they will publish a CVE for it. As of writing the CVE is assigned-intent, not yet live, so this stays in research rather than the CVE shelf until the identifier lands. The Odoo 18 report I filed for the same root was archived as a duplicate of the main one. Found with Aymane Mazguiti.

## the lesson that generalizes

A domain is code. Any public endpoint that accepts one and evaluates it is an attacker-controlled query, and the only real boundary is the permission context it runs in. `auth='public'` plus a record set that still carries `sudo` rights is the combination to grep for: the route is open to everyone and the work is done as root. Odoo's other safe filter paths run as the request user; this one forgot, and the fix is simply to make it agree with its siblings.

## references

- [website_snippet_filter on GitHub (19.0)](https://github.com/odoo/odoo/blob/19.0/addons/website_sale/models/website_snippet_filter.py)
- [Fix commit c0c93e0110f9](https://github.com/odoo/odoo/commit/c0c93e0110f9526e81fde4c1fdccb9ced0eefd97)
- [CVE-2024-36259: Odoo oracle via crafted RPC search with elevated privileges](https://nvd.nist.gov/vuln/detail/CVE-2024-36259)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [Odoo ORM domains (search domains)](https://www.odoo.com/documentation/19.0/developer/reference/backend/orm.html#search-domains)
