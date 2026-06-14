---
layout: post
title: "Odoo POS self-order: a PII fix that fixed nothing"
subtitle: "a developer saw the leak, shipped a patch, and the patch was dead code"
date: 2026-03-11
tags: [info-disclosure, odoo, pos, bug-bounty]
category: research
tldr: "Scan one restaurant QR code and you can pull the email, phone, and per-order token of every other table. A developer noticed the leak and added five lines to strip the PII, then returned a second fresh read of the same data, so the sanitized copy was thrown away. The fix never ran. Found with Aymane Mazguiti. Accepted on Odoo's Intigriti program, no CVE."
---

## the interesting part is the patch

Most info leaks are a check nobody wrote. This one is better: someone at Odoo found the leak, understood it, wrote a fix, and shipped it. The fix is dead code. The leak after the commit is identical to the leak before it.

Found with Aymane Mazguiti.

## the access model

POS self-ordering has no accounts. Every table has a QR code carrying one `access_token` for the whole restaurant (it identifies the POS config, not the customer) and a per-table `identifier`. Every `/pos-self-order/*` endpoint authorizes the caller with `_verify_pos_config(access_token)`, which only confirms the shared config token is valid. Every customer at every table presents the same token. So the code has to be careful about what it returns, because the credential is shared by design.

In table-service mode, `/pos-self-order/get-user-data` returns the draft orders at a table so people sharing a table can see each other's items. The response should carry order lines, not contact details.

## the fix that does not run

`_generate_return_values` in `pos_self_order/controllers/orders.py` after commit `f3f653c7cf6`:

```python
def _generate_return_values(self, order, config):
    orders = self.env['pos.order']._load_pos_self_data_read(order, config)   # read #1

    for o in orders:
        del o['email']      # sanitizes read #1
        del o['mobile']     # sanitizes read #1
    # `orders` is clean now, and never used again

    return {
        'pos.order': self.env['pos.order']._load_pos_self_data_read(order, config),  # read #2, UNSANITIZED
        'res.partner': self.env['res.partner']._load_pos_self_data_read(order.partner_id, config),
        ...
    }
```

The loop strips `email` and `mobile` from `orders`. The return statement calls `_load_pos_self_data_read` a second time, fresh from the database, and that copy still has `email` and `mobile`. The cleaned `orders` variable is garbage collected. The correct fix was one word: return `orders` instead of a second read. As shipped, the sanitization is dead and the PII flows exactly as before. It also only targeted `email` and `mobile`, never the per-order `access_token`.

## three bugs, one chain

1. The double-read above hands back unsanitized records.
2. No per-table authorization: `get-user-data` takes any `table_identifier` and returns that table's draft orders. `order_access_tokens` can be an empty list, so the caller does not even present a token of their own.
3. Every table identifier is shipped to every client. On page load `/pos-self/data/<id>` returns all tables for the config, `identifier` included. The field is literally named "Security Token" in the model, and it is broadcast to everyone.

Chain them: scan your own QR for the shared token, read the whole floor's table identifiers off the page-load payload, then call `get-user-data` once per table.

## proof

Only the shared QR-code token, no admin login:

```
PHASE 1  table enumeration ......... 5 identifiers (4 tables the attacker never sat at)
PHASE 2  same-table PII ............ alice.victim@example.com   +33612345678
PHASE 3  cross-table PII ........... charlie.secret@company.com  +4917612345678
PHASE 4  cross-table delete ........ Charlie's order  draft -> cancel  (leaked token)
PHASE 5  full harvest .............. 4 victim emails from 5 tables
HTTP requests: 11    elapsed: 0.9s
```

![Harvesting every table's email, phone, and order token from one Odoo POS self-order QR code]({{ '/assets/img/posts/odoo-pos-self-order.png' | relative_url }})

The leaked per-order tokens are not cosmetic. `/pos-self-order/remove-order` guards deletion with a constant-time `consteq` on the order token, which is solid, except the previous call already handed that token to the attacker. So you can cancel a stranger's order from another table. Their food never gets made.

A later patched build closed the email and mobile leak but kept the order `uuid` in the response. That `uuid` feeds `sync_from_ui` with no ownership check, so writing another customer's `uuid` into your payload lets the server merge your data into their order: redirect their receipt email, inflate their bill through server-side price recompute, and they pay it at the counter.

## resolution

Odoo shipped `[FIX] pos_self_order: small fix on the data sent to the frontend`, which strips name and email correctly this time. The leaked order token and table identifiers were ruled accepted risk for 19.0: their position is that anyone can physically walk the room and scan every table's QR anyway, so the identifier is not secret. The cross-table order visibility was a deliberate 19.0 feature and was changed in 19.2. Accepted at Medium, no CVE.

I think the accepted-risk call is reasonable for the identifiers and weaker for the `uuid` write path, where the consequence is editing a stranger's financial record rather than reading a token they could scan. Either way, the lesson is the one the commit teaches by accident: a sanitizer you write but never wire to the output is not a fix, it just looks like one in the diff.

## references

- [pos_self_order controller on GitHub](https://github.com/odoo/odoo/blob/19.0/addons/pos_self_order/controllers/orders.py)
- [CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- [consteq, Odoo constant-time compare](https://github.com/odoo/odoo/blob/19.0/odoo/tools/misc.py)
