---
layout: post
title: "Odoo Xendit: the payment endpoint that skipped the token check"
subtitle: "one public route in a payment module forgot the authorization its siblings all enforce"
date: 2026-03-09
tags: [auth-bypass, odoo, payment, bug-bounty]
category: research
tldr: "/payment/xendit/payment is auth='public' and never calls check_access_token. An unauthenticated caller who knows a transaction reference can drive a real Xendit charge on it using the merchant's stored secret key, flip the transaction to done, and kick off order fulfillment. Found with Aymane Mazguiti. Accepted on Odoo's Intigriti program, fixed upstream, no CVE assigned."
---

## the tell was next door

Payment controllers are a good place to read for missing authorization, because every provider implements the same guard and you only need one to forget it. Odoo's pattern is `payment_utils.check_access_token(token, reference, amount)`, an HMAC bound to the transaction so only the checkout session that created it can act on it.

In `payment_xendit/controllers/main.py` the return endpoint has it. So does Authorize.Net, Adyen's main payment route, and every other provider. The Xendit charge endpoint in the same file does not. When one route in a row of near-identical routes is missing the line they all share, that is the finding.

Found with Aymane Mazguiti.

## the endpoint

```python
# addons/payment_xendit/controllers/main.py:23-33
@http.route('/payment/xendit/payment', type='jsonrpc', auth='public')
def xendit_payment(self, reference, token_ref, auth_id=None):
    tx_sudo = request.env['payment.transaction'].sudo().search(
        [('reference', '=', reference)]
    )
    # no check_access_token -> any caller can charge any transaction
    tx_sudo._xendit_create_charge(token_ref, auth_id=auth_id)
```

`auth='public'`, so no session. The transaction is looked up by `reference`, a value the caller controls. Then `_xendit_create_charge` runs under `sudo()` with the merchant's stored Xendit secret key. There is no check that the caller owns the transaction. Compare the protected sibling in the same file:

```python
# xendit_return, same file
if access_token and str2bool(success, default=False):
    if tx_sudo and payment_utils.check_access_token(access_token, tx_ref, tx_sudo.amount):
        tx_sudo._set_pending()
```

The return route binds the caller to the transaction with an HMAC. The charge route binds nothing.

## what it gives an unauthenticated caller

The lookup by `reference` plus the missing check means one POST acts on any transaction you can name. References are not secrets: Odoo builds them from a timestamp (`tx-YYYYMMDDHHMMSS`) or the order name (`S00014`), and the endpoint doubles as an existence oracle (a nonexistent reference errors differently from a real one).

I proved the chain live on Odoo 19 against the Xendit sandbox, no mocking and no server changes.

State corruption with a junk token:

```
POST /payment/xendit/payment   reference=VICTIM-TX  token_ref=fake
state BEFORE: draft
state AFTER:  error   "Token id is invalid"
```

The state moved and the merchant's secret key was spent on a Xendit API call, on an unauthenticated request. Only the fake token stopped the charge.

Full chain to a real charge. The attacker mints a Xendit card token with the merchant's public key (Odoo prints it in the checkout HTML), clears 3DS programmatically, then replays the token against the victim's reference:

```
POST /payment/xendit/payment   reference=VICTIM-1684  token_ref=<attacker>  auth_id=<attacker 3DS>
state BEFORE: draft
state AFTER:  done    provider_ref=69ad9583c06e738456832dca   (real Xendit charge id)
```

Then Odoo's post-processing runs on its own:

```
sale.order  S00014        draft -> sale       (auto-confirmed)
stock.picking WH/OUT/00005  assigned          (delivery created, stock reserved)
```

![Unauthenticated Xendit charge driving a victim Odoo transaction to done plus downstream fulfillment]({{ '/assets/img/posts/odoo-xendit.png' | relative_url }})

## not just Xendit

The same CWE-862 shape sits in other providers that call the charge API under `sudo()` with no token check: `payment_mercado_pago` (`/payment/mercado_pago/payments`, which also takes `transaction_amount` from the body), `payment_paypal` (`/payment/paypal/complete_order`), and `payment_adyen`'s follow-up `/payments/details` route. I reported those in the same thread rather than farming separate submissions. The protected providers all share the one guard the vulnerable ones drop.

## honest severity

I argued High on integrity: an unauthenticated request changes a financial record's state and pulls a sale order through confirmation, delivery, and stock reservation. Odoo pushed back and settled it Medium. Their reasoning: the attacker pays someone else's order with their own card, or makes it fail, which is a bounded consequence rather than total loss of integrity. That is a fair call for the realistic blast radius, and the report was accepted at Medium. The technical bug is the same either way: a public endpoint performs a privileged action on an arbitrary transaction with no authorization.

## the fix

Upstream commit `[FIX] payment_xendit: link access token to the current transaction` adds the guard the siblings already had:

```python
@http.route('/payment/xendit/payment', type='jsonrpc', auth='public')
def xendit_payment(self, reference, token_ref, access_token, auth_id=None):
    tx_sudo = request.env['payment.transaction'].sudo().search([('reference', '=', reference)])
    if not payment_utils.check_access_token(access_token, reference, tx_sudo.amount):
        raise ValidationError("Invalid access token")
    tx_sudo._xendit_create_charge(token_ref, auth_id=auth_id)
```

The client JS passes the token from the checkout's processing values, the same way every protected provider does. No CVE was assigned: Odoo fixed it as a normal commit and its advisories are enterprise-gated.

## references

- [payment_xendit controller on GitHub](https://github.com/odoo/odoo/blob/19.0/addons/payment_xendit/controllers/main.py)
- [CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)
- [Odoo payment access tokens (payment/utils.py)](https://github.com/odoo/odoo/blob/19.0/addons/payment/utils.py)
