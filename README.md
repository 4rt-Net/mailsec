# mailsec

A DNS posture check for SPF, DMARC, and known DKIM selectors. Pass the
organizational/author domain you want to assess; the current implementation
checks its direct `_dmarc` record rather than performing DMARC policy tree-walk
discovery for an arbitrary subdomain.

## Setup

Use the same Python interpreter for installation and execution:

```console
python -m pip install -r requirements.txt
python mailsec.py example.com
```

The import name `dns` is supplied by the package named `dnspython`; there is
no PyPI package named `dns`.

DKIM selectors cannot be enumerated through DNS. For a conclusive key lookup,
copy the `s=` value from a real message's `DKIM-Signature` header:

```console
python mailsec.py example.com --selector selector1
```

Repeat `--selector` when a message has multiple signatures. The DNS checks do
not test lookalike/display-name attacks, mailbox compromise, forwarding rules,
OAuth grants, or whether receivers honor a published DMARC policy.
