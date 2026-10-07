# ADR-0001: Identify a bounced recipient by a signed per-recipient envelope address (VERP)

Status: Accepted

## Context

Bounces arrive asynchronously over IMAP, possibly several worker cycles after the original mail was distributed and while `QueueSender` is still working through the rest of the batch. Before this decision a bounce was only logged and forwarded to the owners; its content had no effect on the pending queue rows. RFC 3464 delivery-status notifications are not authenticated: every field in a DSN (`Final-Recipient`, the attached original's `Message-ID`, `Diagnostic-Code`) is plain text that anyone able to deliver mail into the list's inbox controls.

Background (moved from the former CLAUDE.md, wording preserved):

> RFC 3464 delivery-status notifications carry **no cryptographic authentication at all** — every field in a DSN's body (`Final-Recipient`, the attached original message's own `Message-ID`, `Diagnostic-Code`) is plain text anyone able to deliver mail into the list's own inbox fully controls, the same way `IncomingMailFilter::isBounce()`'s own detection (`Auto-Submitted`, `multipart/report`, a `From: MAILER-DAEMON@...`) is itself trivially spoofable content, not a verified signal. Two design iterations were tried and rejected before landing on the current one, each closing one gap while leaving another open — both are documented here because the reasoning explains why the final design needs *all three* of its layers, not because either intermediate approach still exists in the code:
> 
> 1. **Trust the DSN's claimed `Final-Recipient` domain alone.** Rejected immediately: an attacker could claim *any* address on a genuinely reliable domain (e.g. `alice@gmail.com`) bounced, without ever having sent or received anything through that domain's real infrastructure at all.
> 2. **Also require the claimed `Final-Recipient` to be a real recipient of the batch found via the attached message's Message-ID** (a `batchHasRecipient()` binding check that existed briefly during development). This closed gap 1 for a recipient *outside* the batch, but not for a recipient *inside* it: any genuine member of the same batch already knows the real Message-ID (from their own copy's headers) and could forge a "bounce" claiming a *co-recipient's* address, still without needing any relationship to that co-recipient's real mail server.
> 3. **The design actually shipped** closes both: it never trusts *any* DSN-claimed identity at all (not `Final-Recipient`, not the attached Message-ID) — "which recipient/batch" is decided purely from Listig's own per-recipient bounce address, and "is the content trustworthy" is decided by authenticating the bounce's own transport-level origin, not by reading anything self-reported inside it.

## Decision

Each queued recipient is sent with its own envelope sender `{localPart}+bounce+{token}@{domain}`; the token is `TokenService::sign('b', ListFingerprint::of($listCn), $queueRecipientId)` (7 days). A genuine DSN is addressed back to that address, and `BounceHandler::resolveVerifiedRecipient()` decodes it from the raw `To`/`Delivered-To`/`X-Original-To` headers, verifies it, cross-checks the list and looks up the real `queue_recipients` row. *Which recipient and batch* is decided solely from this token — never from anything inside the DSN. `%failed_recipient%` and `%reason%` in the owner notice stay DSN-sourced, for display only. Whether the bounce's *content* may be trusted is a separate question, see [ADR-0002](0002-bounce-origin-authentication.md).

## Alternatives considered

Two earlier designs were tried and rejected (described in the background above): trusting the DSN's claimed `Final-Recipient` domain, and additionally binding it to a recipient of the batch found via the attached message's `Message-ID`.

> **`mail_queue.message_id` and the `batchHasRecipient()`/`findBatchIdsByMessageId()` methods from design iteration 2 above were removed entirely** once this shipped — no longer needed, since the token directly names the exact row, with no DSN-content search step at all.

## Consequences

- A forged bounce can only ever concern the forger's own row: the token for row *N* never leaves recipient *N*'s own envelope, and deriving another without the HMAC key is infeasible.
- `queue_recipients` rows must outlive the send (see [ADR-0004](0004-queue-retention-for-late-bounces.md)); a bounce whose row was purged has nothing left to act on and is only logged and forwarded.
- `mail_queue.message_id` and the `batchHasRecipient()`/`findBatchIdsByMessageId()` lookups were removed.
