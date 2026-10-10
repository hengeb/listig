# ADR-0024: `post-access-unauthenticated` — hold or reject posts whose From could not be verified

Status: Accepted.

## Context

Listig sees only mail the upstream MTA already accepted. The From address is checked against `post-access-members`/`senders:`/owners, but the From of an external member (`@gmail.com`, `@outlook.com`, …) can be forged by a third party whenever that domain publishes DMARC `p=none` and the receiving MTA enforces nothing: the forged mail passes the membership check and is distributed to everybody. The existing SPF/DKIM reject ([ADR-0018](0018-sender-notices-only-to-authenticated-senders.md)) only reacts to an explicit `fail`.

## Decision

A per-list key `post-access-unauthenticated: allow | moderate | deny` (default `allow`, so nothing changes unless set; normal override chain and `{}` resolution). It applies to a mail whose From has **no authentication evidence** from the trusted `Authentication-Results` (aligned `dmarc=pass`, `dkim=pass`, `spf=pass`, or `auth=pass`; see [Sender notices](../architecture/mail-processing.md#sender-notices-backscatter-protection)):

- `moderate`: the mail is held for the owners (their notice says the sender could not be verified), regardless of the sender class.
- `deny`: rejected with `reject.unauthenticated` (never notified to the sender — backscatter).
- **Owners and `senders:` are not special.** Their address is just as forgeable; this is a deliberate exception to "owners are never moderated".
- A private `+r-` relay (`masked-sender`, not `masked-both`) cannot be moderated, so with `moderate` it is rejected instead of held.

The check is the step 7c of `IncomingMailFilter`, after the membership checks and before the rate limit.

### Structure for ARC

`SenderAuthenticator::assess()` returns an `AuthAssessment`: a list of `AuthEvidence(method, domain)`, one per positive result. `isAuthenticated()` is "the list is non-empty". Forwarded mail (a member's mail through a forwarding provider) breaks SPF/DKIM; a later ARC extension adds `arc` evidence — `arc=pass` from a *trusted sealer* (e.g. a `trusted-arc-sealers` key) whose chain validates and whose recorded DMARC result was pass — as one more producer, without touching the filter.

## Alternatives considered

- **Reject only** (no `moderate`). Rejected: too many legitimate mails of forwarding/`p=none` senders would be lost; holding is the safe default for operators.
- **Challenge–response to the sender.** Rejected: backscatter.
- **Exempt mail with a known `List-Id`/owner.** Rejected: also forgeable.
- **Treat a reply as verified when the headers show knowledge a forger would lack** (a valid `+r-`/`+re-` token in the recipient address, a known Message-ID in `In-Reply-To`). Rejected: the `+r-` token belongs to the target, not the sender; a `+re-` token and Message-IDs are known to everyone who can see the archive or received the mail; and none of it proves *which* member wrote.
- **Per-recipient identifiers that come back in a reply** (a signed Message-ID per recipient copy, or a per-recipient `Reply-To` tag). Rejected: mail clients echo only `In-Reply-To`/`References` and the reply address, and reply-all or a direct Cc copies them into mail to third parties — who can then replay them to impersonate the member. Direct (Cc) copies carry no identifier, so many legitimate replies would still be unverified; per-recipient Message-IDs also break threading and client-side duplicate detection.

## Consequences

Fail-closed: if `trusted-authserv-id` is wrong or the MTA adds no header, *all* mail counts as unverified. The worker's hourly warning about a missing/mismatching header says so when the key is not `allow`. Mail from a server that authenticates nothing (`p=none` without SPF/DKIM) is held — that is the point.
