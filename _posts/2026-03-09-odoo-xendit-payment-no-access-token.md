---
layout: post
title: "Odoo Xendit: the payment endpoint that skipped the token check"
subtitle: "one public route in a payment module forgot the authorization its siblings all enforce, and I drove it live"
date: 2026-03-09
tags: [auth-bypass, odoo, payment, bug-bounty]
category: research
tldr: "POST /payment/xendit/payment is auth='public' and never calls check_access_token. With no cookie, no session, and no access token, you name a transaction by its reference and Odoo charges it through Xendit using the merchant's stored secret key. I reproduced it on a fresh odoo:19.0: one unauthenticated request flips a victim transaction from draft to error, and a valid card token would flip it to done and pull the order through fulfillment. Found with Ilyase Dehy."
---

## how I found it: read the row, find the odd one out

Payment controllers are the best place in a big app to hunt for missing authorization, because every provider implements the same job and you only need one of them to forget the same line. In Odoo the line is `payment_utils.check_access_token(token, reference, amount)`. It is an HMAC keyed on the server's secret, bound to a specific transaction reference and amount, compared in constant time. It exists so that only the browser session that legitimately started a checkout can later tell the server "charge this one."

I lined up the payment controllers and read the route signatures. Authorize.Net checks the token. Adyen's main payment route checks it. Xendit's own return route, in the very same file, checks it. Then the Xendit charge route, three lines long, does not. When one entry in a column of near-identical entries is missing the field they all share, you stop reading and start testing. Found with Ilyase Dehy.

## the endpoint, copied out of the running container

This is not from a git blame or my memory. I pulled it out of the live `odoo:19.0` image I tested against:

```python
# addons/payment_xendit/controllers/main.py  (odoo:19.0, image built 2026-04-21)
@http.route('/payment/xendit/payment', type='jsonrpc', auth='public')
def xendit_payment(self, reference, token_ref, auth_id=None):
    tx_sudo = request.env['payment.transaction'].sudo().search([('reference', '=', reference)])
    tx_sudo._xendit_create_charge(token_ref, auth_id=auth_id)
```

Three things stacked on top of each other:

- `auth='public'` means no login, no session, the request is served for anyone.
- the transaction is fetched by `reference`, a value the caller puts in the body.
- `_xendit_create_charge` runs on `tx_sudo`, a `sudo()` recordset, so it executes with full rights and uses the merchant's stored Xendit secret key.

There is no line checking that the caller has any right to this transaction. Compare the protected sibling in the same file, which gates the privileged action behind the HMAC:

```python
# xendit_return, same file
if access_token and str2bool(success, default=False):
    if tx_sudo and payment_utils.check_access_token(access_token, tx_ref, tx_sudo.amount):
        tx_sudo._set_pending()
```

The return route binds the caller to the transaction. The charge route binds nothing. That asymmetry is the whole bug.

## proving it, with a negative control first

A finding you cannot turn off on demand is noise, so I started with the control: a reference that does not exist. No authentication on any of these.

```
# attacker: no cookie, no session, no access_token
POST /payment/xendit/payment  reference=DOES-NOT-EXIST-9999  token_ref=probe
  -> ERROR: Expected singleton: payment.transaction()        (negative control)
```

`search([('reference','=','DOES-NOT-EXIST-9999')])` returns an empty recordset, and calling `_xendit_create_charge` on an empty recordset raises `Expected singleton`. That error is the tell. A real reference does not error the same way:

```
POST /payment/xendit/payment  reference=VICTIM-TX-001  token_ref=probe
  -> result=null
```

So the response shape itself is an existence oracle: `Expected singleton` means no such transaction, `null` means it exists and the charge path ran. With no auth, you can sit on this endpoint and sort real references from fake ones.

Then the actual state change, on a transaction I had not touched yet so the before and after are clean:

```
BEFORE  ref=VICTIM-TX-003  state=draft  msg=False
attacker -> POST /payment/xendit/payment  reference=VICTIM-TX-003  token_ref=stolen_attacker_token
server   -> result=null
AFTER   ref=VICTIM-TX-003  state=error  msg=The payment provider rejected the request.
                                            Token id is invalid
```

![One unauthenticated request flips a victim Odoo transaction from draft to error, Xendit reached with the merchant secret]({{ '/assets/img/posts/odoo-xendit.png' | relative_url }})

Read the `state_message`. "The payment provider rejected the request. Token id is invalid" is Xendit talking, not Odoo. It means my unauthenticated POST made Odoo open a connection to Xendit, authenticate with the merchant's stored secret key, and submit a charge for the victim's transaction. The only reason money did not move is that I handed it a junk token, and Xendit refused the junk. The authorization barrier never ran. The token validity is the operational gate, not the security gate.

## what a valid token does

The charge path is deterministic once Xendit accepts the token. `_xendit_create_charge` posts to Xendit, the success response goes through `_handle_notification_data`, that calls `_set_done`, and `_set_done` triggers post-processing: the sale order confirms, a delivery picking is created, stock is reserved. In my submitted report I drove that full chain against the Xendit sandbox: a card token I minted with the merchant's public key (Odoo prints it in the checkout HTML), 3DS cleared, then replayed on the victim's reference. The transaction went `draft -> done` with a real Xendit charge id, sale order `S00014` auto confirmed, picking `WH/OUT/00005` assigned. That last mile depends on the sandbox 3DS flow, which is flaky, so the reliable, repeatable proof is the `draft -> error` above. Both share the one root: a public endpoint performs a privileged action on an arbitrary transaction with no authorization.

## references are guessable, which removes the last excuse

You do not need to leak references. Odoo builds them from a timestamp (`tx-YYYYMMDDHHMMSS`) or straight from the order name (`S00014`, `S00015`, ...). Add the oracle above and you can walk the space. The "attacker must know a reference" precondition is a few minutes of requests, not a secret.

## it is not only Xendit

The same shape, `auth='public'` plus `sudo()` plus no `check_access_token`, sits in other providers that call the charge API with the merchant's credentials: `payment_mercado_pago` (`/payment/mercado_pago/payments`, which also takes `transaction_amount` from the body), `payment_paypal` (`/payment/paypal/complete_order`), and Adyen's follow-up `/payment/adyen/payments/details`. I reported those in the same thread instead of farming separate submissions. The providers that are safe all carry the one guard the vulnerable ones drop.

## severity, honestly

I argued High on integrity. An unauthenticated request changes a financial record and pulls an order through confirmation, delivery, and stock reservation. Odoo pushed back and settled Medium: in their reading the attacker pays someone else's order with their own card or makes it fail, a bounded outcome rather than total loss of integrity. That is a defensible call on the realistic blast radius and the report was accepted at Medium. The bug underneath does not change with the label.

By the numbers I scored it `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L` = 8.6, CWE-862 (Missing Authorization): an unauthenticated request mutates a financial record (I:H) and kicks off fulfillment that reserves stock (A:L). The exact pattern has precedent: [CVE-2025-14461](https://nvd.nist.gov/vuln/detail/CVE-2025-14461) (CVSS 5.3, identical CWE-862 on the Xendit WooCommerce plugin, unauthenticated order completion via a missing authorization check on the callback) and [CVE-2021-23178](https://nvd.nist.gov/vuln/detail/CVE-2021-23178) (CVSS 7.5, Odoo ≤15.0, payment token reuse across users from missing authorization). Same missing line, three products.

## fix status, verified not assumed

The fix exists in Odoo's source tree, commit `[FIX] payment_xendit: link access token to the current transaction`, which adds the missing guard and updates the client JS to send the token like every other provider:

```python
def xendit_payment(self, reference, token_ref, access_token, auth_id=None):
    tx_sudo = request.env['payment.transaction'].sudo().search([('reference', '=', reference)])
    if not payment_utils.check_access_token(access_token, reference, tx_sudo.amount):
        raise ValidationError("Invalid access token")
    tx_sudo._xendit_create_charge(token_ref, auth_id=auth_id)
```

But the controller block I pasted above is the one running in the `odoo:19.0` image built 2026-04-21, and it is still the three-line vulnerable version. So as of that image the patch has not shipped to the stable tag, and the `draft -> error` proof was captured on it. The fix is in the source, the release lags. No CVE was assigned; Odoo handled it as a normal commit and keeps its detailed advisories behind the enterprise portal.

## references

- [payment_xendit controller on GitHub](https://github.com/odoo/odoo/blob/19.0/addons/payment_xendit/controllers/main.py)
- [payment_authorize controller (the guarded sibling)](https://github.com/odoo/odoo/blob/19.0/addons/payment_authorize/controllers/main.py)
- [CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)
- [Odoo payment access tokens (payment/utils.py)](https://github.com/odoo/odoo/blob/19.0/addons/payment/utils.py)
- [CVE-2025-14461 (Xendit WooCommerce, same CWE-862)](https://nvd.nist.gov/vuln/detail/CVE-2025-14461)
- [CVE-2021-23178 (Odoo payment token reuse)](https://nvd.nist.gov/vuln/detail/CVE-2021-23178)
