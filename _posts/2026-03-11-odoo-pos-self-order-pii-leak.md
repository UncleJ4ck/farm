---
layout: post
title: "Odoo POS self-order: the leak they fixed and the one they didn't"
subtitle: "a PII patch that was dead code, then a real patch, and underneath both a write primitive that still rewrites a stranger's bill"
date: 2026-03-11
tags: [info-disclosure, odoo, pos, bug-bounty]
category: research
tldr: "Scan one restaurant QR code and the POS self-order API hands you the floor plan with no token at all. The email and phone leak got two fixes (the first was literally dead code), and the current odoo:19.0 image does strip them. But the order uuids still leak, and the write path that takes them never checks ownership, so on today's image I rewrote another table's order live: redirected their receipt and pushed their bill from 12.5 to 57.51 with nothing but the shared QR token. Found with Ilyase Dehy."
---

## the access model, because it is the whole point

POS self-ordering has no accounts and no login. Every table in the restaurant carries a QR code with two values: one `access_token` for the whole point-of-sale config (it says which restaurant you are ordering from, not who you are) and a per-table `identifier`. Every `/pos-self-order/*` endpoint authorizes a caller with `_verify_pos_config(access_token)` (`orders.py:177-187`), which only checks that the shared config token is valid. Every customer at every table presents the same token. That is by design, nobody wants to make an account to order a burger. It also means the server has to be careful about every field it returns and every write it accepts, because the credential is shared by the whole room.

The exact construction matters for the threat model. The config `access_token` is `uuid.uuid4().hex[:16]`, 16 hex chars, one per restaurant (`pos_config.py:117`), baked into the QR URL `{base}?access_token={access_token}&table_identifier={identifier}` (`pos_config.py:276`). The `table_identifier` is `uuid.uuid4().hex[:8]`, 8 hex chars, one per table (`pos_restaurant.py:22`). So the credential on the QR is restaurant-scoped, not customer-scoped, and the per-table identifier is an addressing label, not a secret: `/pos-self/data` hands the whole floor plan's identifiers to anyone on page load. Everything downstream has to assume the caller already holds all of those.

Found with Ilyase Dehy. I tested everything below on a fresh `odoo:19.0` (image built 2026-04-21), seeded with five tables and six orders.

## the floor plan leaks with no token at all

Before any of the interesting parts, the warm-up. `/pos-self/data/<config_id>` is what the page calls on load. It does not even need the shared token:

```
=== 1. unauthenticated floor plan disclosure ===
  no token sent -- got 5 tables, 1 products
  table 1: identifier=f05c8ddf
  table 2: identifier=771f05df
  table 3: identifier=4ea2facb
  table 4: identifier=81e95ec5
  table 5: identifier=a2b5947e
```

So a completely anonymous request returns every table's `identifier` for the config. The model field is named "Security Token" in the source, and it is handed out to anyone who asks. You now have the keys you need to address every table by id, without walking the room.

## the fix that was dead code

The contact-info leak is the part someone at Odoo noticed and tried to fix. Reading the history is the fun part. The first attempt, commit `f3f653c7cf6`, changed `_generate_return_values`:

```python
def _generate_return_values(self, order, config):
    orders = self.env['pos.order']._load_pos_self_data_read(order, config)   # read #1
    for o in orders:
        del o['email']      # strips read #1
        del o['mobile']     # strips read #1
    # `orders` is clean now, and never used again
    return {
        'pos.order': self.env['pos.order']._load_pos_self_data_read(order, config),  # read #2, UNSANITIZED
        ...
    }
```

Look at what the loop sanitizes and what the return ships. The loop scrubs `orders`. The return statement calls `_load_pos_self_data_read` a second time, a fresh database read with `email` and `mobile` intact, and ships that. The cleaned `orders` variable is garbage collected without ever being sent. The diff looks like a fix, passes review, and changes nothing. The correct change was one word: return `orders`, not a second read.

That dead-code version is the perfect teaching bug. A sanitizer you write but never wire to the output is not a fix, it is a comment that runs.

## the fix that actually shipped, and what it left behind

A later change (PR 259915) did the real thing and stripped `email` and `mobile` properly, and that one is in the image I tested:

```
=== 2. enumerate all tables + harvest PII ===
  5 identifiers from single request
  email/mobile stripped by patch -- 6 order uuids still exposed (needed for step 3)
```

So the contact-info leak is closed on the current image. Good. But notice what the same response still carries: the per-order `uuid` for every order at every table. The developer stripped the two fields that read as PII and left the identifier that the next request needs. That is the hinge.

## the write primitive nobody closed

`/pos-self-order/process-order/mobile/` feeds the submitted order into `sync_from_ui`, which locates the target order by the client-supplied `uuid` and merges your payload into it. There is no check that the `uuid` belongs to you. The only thing the endpoint validates is the shared config token and that your `table_identifier` is a real table, both of which you have. So I sat at table 1, used my own table's identifier to pass validation, and put table 2's order `uuid` (harvested in step 2) in the body:

```
=== 3. order hijack (not fixed by PR 259915) ===
  target: charlie order 3  table 2
  attacker at table 1 -- uses only the shared QR token
  before: email=charlie.secret@company.com  total=12.5
  after:  email=receipts@attacker.com       total=57.51
  [+] HIJACKED -- receipt now goes to attacker, bill inflated
      attacker used only the shared QR token, never needed charlie's access_token
```

![Rewriting another table's POS order on a live odoo:19.0, receipt redirected and bill inflated with only the shared QR token]({{ '/assets/img/posts/odoo-pos-self-order.png' | relative_url }})

That is a live result on the current image. Charlie is at another table. I changed the email on his order to mine, so his receipt and any notification go to me, and I appended three burgers through the line write, so the server recomputed his total from 12.50 to 57.51. He pays 57.51 at the counter, or his confirmation lands in my inbox. All I held was the QR token any customer gets and his order `uuid`, which the API handed me a request earlier. I never needed his per-order `access_token`.

## the deletion, and an honest caveat

The last step cancels an order:

```
=== 4. cross-table order deletion ===
  before: state=draft
  after:  state=cancel
```

Honest note on this one. `remove-order` checks the per-order `access_token` with a constant-time `consteq`, which is correct. On the patched image that token is no longer leaked by `get-user-data`, so the clean "delete with a leaked token" story from my first report no longer holds on its own; my PoC falls back to a token it learned during admin setup to demonstrate the endpoint. The deletion is still reachable through the same uncontrolled write path as step 3 (force the order to a paid or cancelled state by writing it), so the primitive survives, but I am not going to dress up step 4 as the leaked-token version when the leak that fed it is closed. The sharp, self-contained, still-live bug is the uuid hijack in step 3.

## three bugs, and which ones are still open

1. Floor plan and table identifiers handed to anonymous callers. Odoo's position: you could photograph every table's QR anyway, so the identifier is not secret. Accepted risk for 19.0.
2. Contact info (`email`, `mobile`) in `get-user-data`. Fixed, after one dead-code attempt. Closed on the current image.
3. Order `uuid` returned plus `sync_from_ui` taking it with no ownership check. This is the write primitive. Open on the image I tested. This is the one that turns a read leak into editing a stranger's financial record.

## severity and resolution

I submitted it at `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` = 8.2. The C:H is deliberate and worth defending: within the POS self-order component for one config, the attacker obtains 100% of the confidential data it manages, every active customer's email, phone, and per-order token, across every table, with no cap on how many. C:L is "no control over what is obtained, or limited loss"; here the attacker controls the enumeration (`/pos-self/data` hands out all identifiers, `order_access_tokens: []` works) and gets the complete PII set. The data set is narrow but it is the whole set, so C:H fits and C:L does not.

Accepted at Medium. Odoo settled the rating after downgrading attack complexity (you need to be near the restaurant for the token) and arguing email plus name is not highly confidential. The cross-table order visibility was a deliberate 19.0 feature and was changed in 19.2. I think the accepted-risk call is fair for the identifiers and weak for the write path, where the consequence is editing someone else's order and redirecting their receipt, not reading a token they could scan off a table. No CVE was assigned.

The lesson the commit history teaches by accident: read what your fix returns, not what it deletes. And when you strip the fields that look like PII, check whether the identifier you left behind is the key to a write you never locked.

## references

- [pos_self_order controller on GitHub](https://github.com/odoo/odoo/blob/19.0/addons/pos_self_order/controllers/orders.py)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
