# ADR-0023: Store a queued mail's body once, its headers per recipient

Status: Accepted

## Context

`mail_queue` kept the complete MIME of every recipient's copy, keyed by its hash. The documentation promised that identical mails are stored once, but every copy carries a `List-Unsubscribe` header with a per-recipient token, so no two copies are identical: a 5 MB mail to 200 members occupied 1 GB, and completed rows stay 30 days (ADR-0004). Bodies, however, are nearly always the same for everybody.

## Decision

A queued mail is split into **headers** (the message headers — the part that differs per recipient) and **body** (the top-level part with its own headers and all the content), both produced by `Email::getPreparedHeaders()`/`getBody()`, whose concatenation is exactly `Email::toString()` (`QueueMime::split()`).

- The body is stored once in `mail_bodies`, content-addressed by `QueueMime::bodyKey()` (SHA-256 of the body with the random multipart boundaries replaced by numbered placeholders, since every part picks new boundaries when serialized and identical mails would otherwise never match).
- `mail_queue` keeps this recipient's `headers` and the `body_id`; `QueueSender` joins them when sending. Rows queued before the migration keep their complete `mime` and are sent as before. The headers are still produced when the row is inserted, as before.
- `QueueSender` reads the body per row, not in the batch query, so a batch does not hold fifty copies of a large body in memory.
- Purge deletes bodies no row references that are older than an hour; `enqueue()` refreshes `created_at` of a body it reuses, so a body cannot be removed while a transaction is about to reference it.

## Alternatives considered

- **Make the copies identical** (the unsubscribe token out of the headers, resolved when sending): would change what a recipient's mail looks like only at send time, but moves per-recipient personalization into the sender and keeps one `mime` text per row.
- **Compress `mime`:** a constant factor, no sharing.
- **Shorter retention for large mails:** loses late-bounce matching for exactly those.

## Consequences

Storage grows with the number of distinct bodies, not recipients (a personalized body — `personalize`, recipient variables in the footer — is still one per recipient, which is unavoidable). Anything reading `mail_queue.mime` must go through `QueueSender::loadMime()`; nothing else does today. Migration 008.
