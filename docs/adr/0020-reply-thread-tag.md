# ADR-0020: Reply from the archive via a signed `+re-` address tag

Status: Accepted

## Context

The archive viewer should offer a "reply to this mail" button that works in the user's own mail program and puts the answer into the right thread — in the recipients' mail clients and in Listig's own archive. A `mailto:` link can only prefill To, Subject and Body; mail clients do not honour an `in-reply-to`/`references` parameter. The Message-ID of the archived mail does not fit an address (RFC 5321: 64 bytes local part), and a table of its own just for this would be new state to keep consistent.

## Decision

The button's address is `{localPart}+re-{TOKEN}@{domain}`; `TOKEN` is a `TokenService` token (purpose `t`, payload `ListFingerprint` + `archived_mail.id`, max age 180 days) — the existing surrogate key of the archive index, no new table (`ReplyThreadStore`). The tag is deliberately not a prefix of the masked-reply tag `r-`.

- **Receiving:** the tag is read from the raw `To` (fallback `Delivered-To`/`X-Original-To`) like every other tag. `IncomingMailFilter` (step 7b, after the access checks) rejects a token that is invalid, expired, of another list or points to a mail no longer in the index with `reject.reply_thread_unknown` (a hint to write a new mail instead). `MailProcessor` replaces the token address in the visible To/Cc by the list address and, unless the client set its own, adds `In-Reply-To: <parent>` and `References: <thread root> <parent>`. A token that stops resolving between arrival and moderation acceptance is not an error there: the mail is distributed without threading.
- **Own archive:** the mail is archived as received, without the headers `MailProcessor` adds to the copies, so `ArchiveIndexer` resolves the same tag and stores the parent as `in_reply_to`/`thread_root` — otherwise the reply would start a new thread in the archive viewer.
- **Authorisation** is the normal posting rule (`post-access-*`, `restricted-members:`, moderation); the tag only carries a threading hint, so forging it gains nothing — the signature serves consistency with the other tokens and the list scoping (ADR-0016), not secrecy.
- `type: subaddress` lists, where `+tag` has its own meaning, get no tag and no buttons.

The same change lets the reply relay (`+r-`, ADR-0017) work on `reply-to: sender`/`both` lists too (`ReplyToBehavior::relayMode()`), solely for the archive's "reply to the author only" button: a private mail through the author's masked address, so the real address never appears in the viewer.

## Alternatives considered

- **`mailto:?in-reply-to=…` parameter.** Not honoured by mail clients.
- **The Message-ID (or a hash) in the tag.** Too long for the local part; a hash would need a lookup table anyway.
- **A new table mapping short ids to Message-IDs.** `archived_mail.id` already is such a key.
- **Unsigned `archived_mail.id`.** Would work (authorisation does not depend on it) but sequential ids invite guessing and break the pattern of list-scoped signed tags.
- **Silently posting as a new thread when the token is dead.** Hides that the reply lost its context; the sender gets a rejection with a hint instead.

## Consequences

The mailbox must accept `+re-…` addresses like the other tags (see [Mailbox requirements](../architecture/deployment.md#mailbox-requirements)). A reply sent more than 180 days after the page was viewed, or after the archived mail was deleted or pruned, is rejected with a notice (only to authenticated senders, see ADR-0018).
