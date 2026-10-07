# ADR-0003: Do not automate spam bounces for forwarded mailboxes

Status: Accepted

## Context

A real web.de bounce for `fenchel-schnitzel@posteo.de` carried the correct spam verdict (`X-Spam-Flag: YES` in the quoted original), but posteo.de forwards that mailbox to a web.de account, and it was web.de's infrastructure that rejected the message and signed the bounce (`d=web.de`). `isDkimAuthenticated()` requires `d=` to equal the recipient's domain (`posteo.de`) and `isFromTrustedRelay()` fails on web.de's public IP, so the bounce is not authenticated. Mailbox forwarding is common enough that this is a recurring case.

Background (moved from the former CLAUDE.md, wording preserved):

> **A distinct gap surfaced while verifying this fix against the real bounce above, considered and deliberately left unfixed**: neither `isDkimAuthenticated()` nor `isFromTrustedRelay()` actually authenticates *this* bounce, despite `hasQuotedSpamFlag()` now correctly finding `X-Spam-Flag: YES`. The `Final-Recipient` was `fenchel-schnitzel@posteo.de`, but the quoted original's own `Received:` header showed final delivery `for <sherian.y@web.de>` — i.e. posteo.de forwards that mailbox to a web.de account, and it was *web.de's* infrastructure, not posteo.de's, that actually rejected the (forwarded) message and generated the bounce. `isDkimAuthenticated()` requires the DKIM-signing domain to equal `domainOf($envelopeTo)` (`posteo.de`) — but the bounce is legitimately signed `d=web.de`, so it fails; `isFromTrustedRelay()` also fails, since web.de's own IP is a genuine public address. Mailbox forwarding is common enough (most consumer providers offer it) that the bounce-generating domain differing from the original recipient's own domain is a real, recurring case, not an edge case.

## Decision

Leave it unautomated. The bounce is still logged and forwarded to the owners (now showing the correctly extracted `X-Spam-Flag` reason), just without the automatic batch abort.

## Alternatives considered

Accepting a DKIM signature from *any* domain in `BUILTIN_DOMAINS`/`reliable-spam-reporters:` was rejected (see the moved text below). ARC (RFC 8617) is the standards-track way to verify a forwarding chain, but multi-hop ARC verification is far more complex than anything else in `BounceHandler` and not universally deployed — not attempted.

> The obvious fix — accept a DKIM signature from *any* domain in `BUILTIN_DOMAINS`/`reliable-spam-reporters`, not just one matching `domainOf($envelopeTo)` — was considered and rejected: it would reopen exactly the cross-recipient DoS the domain-match requirement exists to prevent. Forwarding is entirely recipient-controlled and unauditable by Listig — nothing distinguishes an operator's own member setting up a benign personal forward from a malicious member deliberately forwarding their own subscription to a domain known to actively reject spam at SMTP time (web.de itself, confirmed live, is exactly such a domain). Since the token is bound only to that member's own row (see "Which recipient" above), they'd get a genuinely DKIM-signed, reliable-domain "spam" bounce addressed to their own valid VERP token, on demand — and `abortBatchForBounce()`'s action reaches every *other* pending recipient of the batch, not just the forwarder. ARC (Authenticated Received Chain, RFC 8617) is the standards-track mechanism actually designed to verify a forwarding chain cryptographically, but verifying a multi-hop ARC signature chain is substantially more complex than anything else in this class and not universally deployed enough to rely on — not attempted here. The accepted trade-off: a `Spam`-cause bounce whose recipient has forwarded their mailbox elsewhere, and where the downstream domain is the one that rejected it, won't trigger the automatic batch-abort — the bounce is still logged and the owner still notified (now with the correctly extracted `X-Spam-Flag` reason visible), just without automation for this one narrow shape.

## Consequences

A `Spam` bounce whose rejecting domain differs from the recipient's own domain triggers no automatic batch abort.
