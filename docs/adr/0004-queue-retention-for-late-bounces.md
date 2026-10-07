# ADR-0004: Keep completed queue entries for 30 days

Status: Accepted

## Context

`QueueSender::cleanupQueueEntry()` used to delete a `mail_queue` row and its `queue_recipients` children as soon as the last recipient was `sent`. A soft bounce can legitimately arrive days later, long after the row it concerns was gone, and `BounceHandler::resolveVerifiedRecipient()` needs that row ([ADR-0001](0001-verp-bounce-address.md)).

## Decision

`cleanupQueueEntry()` was removed. Completed rows stay until `QueueSender::purgeCompletedEntries()` deletes everything not `pending` with `last_attempt_at` older than 30 days (then sweeps childless `mail_queue` rows). Retained rows enable `QueueSender::markBounced()` (retroactively marks a `sent` row `failed` with a `BOUNCE:*` tag) and `QueueSender::countRecentBounces()` (a plain `COUNT(*)` over the retained history). `QueueController::status()` gained `AND qr.status != 'sent'` so the owner-facing queue view is not flooded.

## Alternatives considered

A dedicated `soft_bounce_tracking` table for the mailbox-full counter, and resending the original mail after a deferral (both described below).

> An **earlier design** for the mailbox-full case used a dedicated `soft_bounce_tracking` table instead of extending retention — dropped once it became clear that keeping `queue_recipients` around a while longer already gives the same information for free, plus the ability to correct history, without a second place to keep in sync.

> **"Resend the original mail" was considered and rejected.** Even with extended retention, the original `mail_queue.mime` reflects whatever the mail looked like *at the time it was first sent* — resending it days later would be stale (wrong "now" for time-sensitive content) and semantically odd. Deferring only ever affects **future, independently-triggered distributions** to that recipient (the next time the list sends anything at all) — never a resend of the specific mail that bounced.

## Consequences

- Deliberate storage cost: a sent mail's MIME (and attachments) persists up to 30 days per recipient — the same retention as `bounce_log`, `imap_seen` and `processing_failures`.
- `retry_not_before` is a per-row timestamp computed in PHP per list, because `sendBatch()` serves all lists in one query; hence `bounce-defer-days`/`bounce-escalate-after` are instance-wide root keys.
