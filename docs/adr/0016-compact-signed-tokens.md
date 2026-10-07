# ADR-0016: Compact signed tokens

Status: Accepted

## Context

`bounce`, `accept`, `reject` (and later `reply`) tokens travel inside an email address local-part, which RFC 5321 limits to 64 bytes. The original format (JSON payload + full hex HMAC-SHA256 joined by `.`) exceeded that by a wide margin (over 100 bytes for accept/reject) for all but the shortest list names.

Background (moved from the former CLAUDE.md, wording preserved):

> Confirmed live as a real, not just theoretical, problem: the original design (`json_encode()` the payload, then a full, untruncated hex HMAC-SHA256 digest, joined with a `.`) made `bounce`/`accept`/`reject` tokens — the three embedded directly in an email address local-part (`{list->localPart}+bounce+{TOKEN}@...`, `+accept-{TOKEN}@...`, `+reject-{TOKEN}@...`) — exceed RFC 5321's 64-byte local-part limit for anything but the very shortest list names, sometimes by a wide margin (well over 100 bytes for `accept`/`reject`). Three independent changes fixed this, all applied uniformly to every purpose (not just the three that needed it, for consistency and because shorter tokens are a nice-to-have for the URL-embedded purposes too):

## Decision

Applied uniformly to every purpose: (1) compact tagged binary payload instead of JSON, (2) 96-bit truncated HMAC, (3) payload and signature in one base64 blob without separator, (4) single-character purpose codes, (5) a one-byte `ListFingerprint` instead of the list name for local-part tokens, (6) accept/reject/bounce/reply tokens reference a database row id instead of embedding `imap_uid`/`imap_uidvalidity` or an address. Details: [Token Format](../architecture/security-and-tokens.md#token-format).

## Alternatives considered

Keeping JSON and hex (does not fit); shortening only the three local-part purposes (inconsistent, and shorter URL tokens are a free benefit).

## Consequences

A typical token is about 30–35 characters. The list fingerprint is only a secondary sanity check (256 values, collisions possible by design); the HMAC and the database lookup are the real boundary.
