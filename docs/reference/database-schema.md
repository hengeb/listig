# Database schema

Tables owned by Listig and the migration mechanism.

## Database Schema

### Database migrations

Schema changes live as plain `.sql` files in `migrations/`, applied automatically — no manual step, ever, on either a fresh install or an upgrade. `Hengeb\Listig\Database\MigrationRunner::run()` (`src/Database/MigrationRunner.php`):

1. Creates `schema_migrations (version VARCHAR(255) PRIMARY KEY, applied_at DATETIME)` if it doesn't exist yet.
2. Lists `migrations/*.sql`, sorted as plain strings (hence the naming convention below), and runs every file whose filename isn't already a `version` row, in order, via `PDO::exec()` — then records it.

Invoked by `bin/migrate.php` (loads `.env`/the container exactly like `bin/worker.php`), which `docker/entrypoint.sh` runs once, before `exec`ing `CMD` — i.e. before supervisord starts nginx/php-fpm/worker at all. This avoids a race: with three processes started concurrently by supervisord, a web request or worker cycle could otherwise hit the database before migrations finish. Gating it in the entrypoint means nothing in the container ever sees a partially-migrated schema. A failure here is fatal — `bin/migrate.php` exits non-zero, `entrypoint.sh` has `set -e`, so the container aborts loudly rather than starting against a broken schema (same fail-fast philosophy as a missing `$VAR` or an invalid `filters:` regex).

**New migration files** must follow `NNN_description.sql` with a zero-padded, incrementing 3-digit prefix (`002_...`, `003_...`, ...) — plain string sort must match numeric order. **Every statement must be idempotent** (`CREATE TABLE IF NOT EXISTS`, guard an `ALTER TABLE` by checking `information_schema` first, etc.): MariaDB commits DDL implicitly, so a crash between running a file's SQL and recording it in `schema_migrations` can't be rolled back — the file simply runs again on the next start, and idempotency is what makes that safe rather than merely convenient.

### `mail_queue`

Primary key: `sha256(list_cn . ':' . mimeString)`. Identical MIME for the same list deduplicates automatically.

`batch_id`: `sha256(list_cn . ':' . rawIncomingMime)`, computed once per incoming mail in `MailProcessor::process()`. Identifies every recipient's queued copy of the *same original incoming mail*, even though personalization (`BodyPersonalizer`) gives each recipient different outgoing MIME — and therefore a different `id` above, which is a hash of that outgoing MIME. Used by `QueueSender`/`SpamRejectionDetector` to discard sibling copies together (see [Sending batch](../architecture/worker-and-queue.md#sending-batch-queuesender)). `NULL` means "no known siblings" — `QueueSender` never groups by `NULL`/empty, so rows without one are never (mis)matched with each other.

```sql
CREATE TABLE mail_queue (
    id          VARCHAR(64) NOT NULL PRIMARY KEY,
    list_cn     VARCHAR(255) NOT NULL,
    batch_id    VARCHAR(64) NULL,
    mime        LONGTEXT NOT NULL,
    created_at  DATETIME NOT NULL
);
```

### `queue_recipients`

```sql
CREATE TABLE queue_recipients (
    id                BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    mail_queue_id     VARCHAR(64) NOT NULL REFERENCES mail_queue(id),
    envelope_to       VARCHAR(255) NOT NULL,
    attempts          TINYINT UNSIGNED NOT NULL DEFAULT 0,
    last_attempt_at   DATETIME NULL,
    status            ENUM('pending','sent','failed') NOT NULL DEFAULT 'pending',
    error             TEXT NULL,
    retry_not_before  DATETIME NULL
);
```

`retry_not_before` (added by `migrations/006_bounce_auto_actions.sql`) — set by `QueueSender::markBounced()` only for a `BounceCause::MailboxFull` bounce, to the point in time before which `sendBatch()` must not attempt this (list, recipient) pair again — see [Automatic bounce actions](../architecture/bounces.md#automatic-bounce-actions) > [Soft bounces: defer, then escalate](../architecture/bounces.md#soft-bounces-defer-then-escalate).

`mail_queue_id`'s `REFERENCES` has no `ON DELETE CASCADE` — MariaDB still enforces it as a real constraint (auto-named `queue_recipients_ibfk_1`), so any code deleting a `mail_queue` row must delete that row's `queue_recipients` children first, or the delete fails with `"Cannot delete or update a parent row: a foreign key constraint fails"`. `QueueSender::purgeCompletedEntries()` (the renamed, broadened `purgeStaleFailedEntries()` — no longer restricted to `status = 'failed'`, see [Automatic bounce actions](../architecture/bounces.md#automatic-bounce-actions) > "Queue retention") does this correctly: its own stale-row delete (`status != 'pending' AND last_attempt_at < NOW() - INTERVAL 30 DAY`), followed by a `NOT EXISTS` sweep for now-childless `mail_queue` rows. `sendOne()` itself no longer deletes anything on completion (the removed `cleanupQueueEntry()`) — a completed row now always waits for this periodic purge instead.

### `moderation_queue`

No `token` column: accept/reject tokens embed `list_cn`/`imap_uid`/`imap_uidvalidity`
and are HMAC-signed (see Token Format), so verifying a reply never needs a DB lookup.
This table only tracks that an item is pending moderation and when it was created/reminded.

`subject`/`sender_name`/`sender_mail`/`mail_date` (added by `migrations/002_moderation_queue_mail_metadata.sql`,
not backfilled — `NULL` for any row queued before this migration ran) mirror `archived_mail`'s
own subject/sender_name/mail_date columns: a snapshot of the moderated mail's own metadata,
populated once by `ModerationMailer::send()` from the already-parsed `IncomingMail` at the point
the item is first queued (and again, unchanged, on every overdue-reminder resend via
`ModerationChecker::checkOverdue()`, which re-fetches the same `IncomingMail` by UID to pass
through) — so both the moderation request mail's body and the manage page's moderation queue
table (`ListController::getModerationItems()`, `templates/list/manage.latte`) can show subject/
sender/timestamp without a live IMAP fetch per item. `sender_mail` is never displayed directly —
`getModerationItems()` formats it into a `sender_display` field ("Name <mail>", or the bare
address if the sender set no display name), matching `ModerationMailer`'s own `%sender%`
formatting for the request mail.

```sql
CREATE TABLE moderation_queue (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    list_cn         VARCHAR(255) NOT NULL,
    imap_uid        BIGINT UNSIGNED NOT NULL,
    imap_uidvalidity BIGINT UNSIGNED NOT NULL,
    created_at      DATETIME NOT NULL,
    reminded_at     DATETIME NULL,
    subject         VARCHAR(500) NULL,
    sender_name     VARCHAR(255) NULL,
    sender_mail     VARCHAR(255) NULL,
    mail_date       DATETIME NULL,
    UNIQUE KEY uq_list_uid (list_cn, imap_uid, imap_uidvalidity)
);
```

### `imap_seen`

Entries older than 31 days deleted each worker cycle. Inbox mails older than 30 days deleted from IMAP.

```sql
CREATE TABLE imap_seen (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    list_cn         VARCHAR(255) NOT NULL,
    imap_uid        BIGINT UNSIGNED NOT NULL,
    imap_uidvalidity BIGINT UNSIGNED NOT NULL,
    seen_at         DATETIME NOT NULL,
    UNIQUE KEY uq_list_uid (list_cn, imap_uid, imap_uidvalidity)
);
```

### `rate_limit`

Login rate limiting uses sentinel values: `list_cn='__login__'`, `sender=$email` (per-address, max 5/hour) or `sender='__global__'` (max 20/hour).

```sql
CREATE TABLE rate_limit (
    id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    list_cn     VARCHAR(255) NOT NULL,
    sender      VARCHAR(255) NOT NULL,
    sent_at     DATETIME NOT NULL,
    INDEX idx_sender (list_cn, sender, sent_at)
);
```

### `bounce_log`

Contains sender addresses and subjects — document in privacy policy / data retention documentation that these are retained for 90 days.

`message_id` (added by `migrations/003_bounce_log_message_id.sql`, not backfilled — `NULL` for
any row logged before this migration ran, or whose bounce mail had no Message-ID at all) —
bare Message-ID of the bounce mail itself (`HeaderFilter::readMessageId()`, same normalization
`ArchiveIndexer` applies), populated once by `BounceHandler::logBounce()`. Lets the manage
page's bounce table offer a click-through preview (`BounceController`, see [Bounce preview](../architecture/bounces.md#bounce-preview))
the same way `archived_mail.message_id` lets the archive viewer re-locate a distributed mail —
without persisting an IMAP UID, which is meaningless once `ImapArchiver::archiveOrDelete()`
moves the bounce into the archive folder (or deletes it outright, if `archive: off`) right
after this row is written.

```sql
CREATE TABLE bounce_log (
    id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    list_cn     VARCHAR(255) NOT NULL,
    sender      VARCHAR(255) NOT NULL,
    subject     VARCHAR(500) NULL,
    message_id  VARCHAR(255) NULL,
    bounced_at  DATETIME NOT NULL,
    INDEX idx_list_time (list_cn, bounced_at)
);
```

Entries older than 90 days deleted each worker cycle.

### `processing_failures`

Added by `migrations/004_processing_failures.sql`. Tracks how many times `bin/worker.php` has
retried a specific incoming mail after an exception anywhere in its per-mail processing pipeline
— see [Processing-failure retry limit](../architecture/worker-and-queue.md#processing-failure-retry-limit-processingfailuretracker-processingfailurenotifier). Keyed the same way as `imap_seen`/`moderation_queue`,
since it identifies the same kind of thing: one specific message on one specific list's IMAP
mailbox, not-yet-resolved-either-way.

```sql
CREATE TABLE processing_failures (
    id                BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    list_cn           VARCHAR(255) NOT NULL,
    imap_uid          BIGINT UNSIGNED NOT NULL,
    imap_uidvalidity  BIGINT UNSIGNED NOT NULL,
    attempts          TINYINT UNSIGNED NOT NULL DEFAULT 0,
    last_error        TEXT NULL,
    first_attempt_at  DATETIME NOT NULL,
    last_attempt_at   DATETIME NOT NULL,
    UNIQUE KEY uq_list_uid (list_cn, imap_uid, imap_uidvalidity)
);
```

Normally short-lived — a row is deleted (`ProcessingFailureTracker::clear()`) the same cycle the
mail either succeeds or hits `ProcessingFailureTracker::MAX_ATTEMPTS` and is given up on. Rows
older than 31 days are swept as a safety net each worker cycle (same retention as `imap_seen`),
in case the give-up sequence itself kept failing and left a row stuck.

### `bounce_suppressed_members`

Added by `migrations/006_bounce_auto_actions.sql`. Backs the `restrict` automatic bounce action
(see [Automatic bounce actions](../architecture/bounces.md#automatic-bounce-actions)) — written/read exclusively via `BounceSuppressionList`
(`src/Mail/BounceSuppressionList.php`), independent of any list's own `ListProvider`/
`MemberResolver` backend.

```sql
CREATE TABLE bounce_suppressed_members (
    id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    list_cn      VARCHAR(255) NOT NULL,
    envelope_to  VARCHAR(255) NOT NULL,
    reason       VARCHAR(64)  NOT NULL,
    created_at   DATETIME     NOT NULL,
    UNIQUE KEY uq_list_recipient (list_cn, envelope_to)
);
```

No automatic expiry — an address stays suppressed until an owner removes it (there is currently
no UI action for that, only the read-only manage-page listing, see [Automatic bounce actions](../architecture/bounces.md#automatic-bounce-actions))
or an operator deletes the row directly.

---
