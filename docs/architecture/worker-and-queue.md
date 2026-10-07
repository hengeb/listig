# Worker, IMAP and outgoing queue

`bin/worker.php`, IMAP/SMTP connection handling and the outgoing mail queue.

## Core Processing Logic

### Worker loop (`bin/worker.php`)

The worker runs as a single process. If a cycle takes longer than `sleep-seconds`, the next cycle starts immediately after — no overlap protection needed since it is single-threaded.

`sleep-seconds` (step 5, default 60) and `batch-size` (step 3, default 50) are config.yml root keys, like any other setting there — resolved by the `'worker.sleep-seconds'`/`'worker.batch-size'` container entries (`config/container.php`) via `ConfigResolver::getResolvedDefault()`. Neither has an env var of its own; reference `$SOME_VAR` in config.yml (e.g. `sleep-seconds: $WORKER_SLEEP_SECONDS`) if the value should come from the environment instead.

#### Worker loop — config reload

The worker's container (and everything built from it — `ConfigResolver`, every `ListProvider`, all `ListConfig` objects) is built exactly once, before the loop starts, and kept for the entire process lifetime. Every `ListProvider` implementation also memoizes `getLists()`/`getList()` internally the first time it succeeds (`private ?array $lists = null; if ($this->lists !== null) return ...;`) — but unlike a plain in-process cache with no expiry, this is bounded to **one worker cycle**: `ListProvider::reset()` (implemented by every provider — sets `$lists = null`, forcing the next `getLists()`/`getList()` call to re-query its backing store) is called once per iteration, right before the sleep. So an LDAP `description[]` entry, a `config-table` row, or a `type: yaml` provider file's contents are re-read fresh every cycle, without needing a process restart — a change made between two cycles is visible on the very next one, at most `sleep-seconds` later. (The **web/API side has no equivalent concern**: `public/index.php` builds a brand new container, and therefore fresh, unmemoized providers, on every single HTTP request — config changes there are visible on the very next request regardless.)

`ImapMailboxFactory::reset()` used to be called at this same call site, on the same every-cycle schedule — it no longer is (see [IMAP connection reuse across worker cycles](#imap-connection-reuse-across-worker-cycles) below). Directory/config data (`ListProvider::reset()`'s own concern) and IMAP *connections* (`ImapMailboxFactory`'s) turned out to need genuinely different reset policies once looked at closely: a provider's cached directory data has no way to know on its own whether it's gone stale (an LDAP edit or a `config-table` row change is invisible to Listig until it re-queries), so time-bounding it to one cycle is the only option: whereas a cached IMAP *connection*'s liveness is directly, cheaply checkable (see below) — so it no longer needs a blanket, schedule-driven invalidation at all.

What `reset()` does *not* cover: `$this->providerConfig` (a provider's own raw `list-providers.*` entry) and anything the `ConfigResolver` itself resolved from `config.yml`'s structure (named blocks, `use:`, root-level defaults, `filters:`) are parsed once at container build time and never re-parsed mid-process — a provider's `reset()` only re-runs its *query* against that same, still-process-lifetime-fixed provider config. So editing `config.yml` itself — adding/removing a `list-providers` entry, changing a named block, a root default, `filters:` — still requires the full container rebuild a process restart gives you; `reset()` only shortens the previously-unbounded staleness window for the *external data* each provider reads (LDAP directory, DB rows, a YAML file), which is exactly the case that used to be invisible "not just until the next `sleep-seconds` cycle, but indefinitely, until the process actually restarts."

To still catch a `config.yml` structural change without a manual restart, the worker separately watches the file's mtime once per loop iteration and exits cleanly (`exit(0)`) the moment it changes:

```php
clearstatcache(true, $watchedFile);  // filemtime() is cached per-process — without
                                      // this, every check after the first would keep
                                      // returning the original mtime forever
$currentMtime = @filemtime($watchedFile) ?: null;
if ($currentMtime !== $configMtimes[$i]) {
    error_log("Listig: $watchedFile changed on disk — restarting worker to reload configuration.");
    exit(0);
}
```

`docker/supervisord.conf`'s `[program:worker]` already has `autorestart=true`, so supervisord immediately restarts the process — which rebuilds the container from scratch, re-parsing `config.yml`'s structure fresh (unlike a provider's own `reset()`, which re-queries the same, unchanged provider config — see above). A full process restart, rather than trying to invalidate the whole container in place, is deliberate: it's simpler, and guarantees a completely consistent state with no risk of a partially-stale `ConfigResolver`.

This watches every file `ConfigResolver::getIncludedFiles()` returns, not just `config.yml` itself — `config.yml`'s own path is always the first entry (it's `YamlIncludeResolver::parseFile()`'s own top-level call), followed by every file spliced in via `!include`, at any nesting depth. This closes a real, previously-documented gap: a `!include`d fragment of `config.yml` (e.g. `owners: !include config.local.yml`, often used to keep local overrides in a gitignored file) is spliced into the tree once at parse time, before `reset()` has any effect — editing *that* file used to need either a manual restart or a no-op re-save of `config.yml` itself to be picked up at all, silently. `YamlIncludeResolver` is the only place that ever knows which files a given parse actually read (`$lastParsedFiles`, reset at the start of each *top-level* `parseFile()` call — detected via `$visited === []`, which only a genuine top-level call ever passes); `ConfigResolver::__construct()` captures that list into its own instance state immediately after its own top-level call, specifically so a *later*, unrelated `parseFile()` call — `YamlListProvider` parsing its own list file through this same resolver — can never silently clobber it out from under a caller that already read it.

A `type: yaml` provider's own `file:` is deliberately **not** part of this watched set — unlike an `!include`d fragment, its content is already re-read fresh every worker cycle via `reset()` (see above), so watching it for a restart would only cause an unnecessary one: dropping every open IMAP connection and rebuilding the whole container for a change that was already being picked up live, with no restart needed at all.

```
loop forever:
    1. foreach configured list (from all list-providers):
        a. Check LDAP availability; if unreachable: log error, skip IMAP poll for this cycle,
           continue to queue sending (step 3) — SMTP does not require LDAP
        b. ImapPoller::poll():
           - Check UIDVALIDITY via statusMailbox()->uidvalidity; if changed: clear imap_seen, log warning
           - For each unseen UID: fetch raw MIME (getRawMail) + parsed IncomingMail (getMail)
           - Return array of {uid, uidvalidity, mime, mail: IncomingMail}
        c. foreach mail:
            - authResults = HeaderFilter::readAuthResults($mail->headersRaw)
            - result = IncomingMailFilter::filter($mail, $list, $rawMime, $authResults) -> FilterResult
            - FilterResult::Discard: skip silently, mark seen (a `filters:` discard and an auto-reply additionally delete the mail outright)
            - FilterResult::Bounce: log bounce_log, forward to owner, mark seen, ImapArchiver::archiveOrDelete()
            - FilterResult::Reject(reason): notify sender, mark seen, ImapArchiver::archiveOrDelete() (deleted instead for a `filters:` match or a mail to a `+r-` reply address)
            - FilterResult::Moderation: ModerationMailer::send(), insert moderation_queue + imap_seen
            - FilterResult::Distribute:
                - MailProcessor::process($mail, $rawMime, $list):
                    - Build outgoing Email from IncomingMail (body, attachments, threading headers)
                    - Set outgoing headers (From, Sender, Reply-To, List-*, Precedence, X-Loop, etc.)
                    - Apply subject label via VariableResolver with [safeListContext, mailContext]
                    - For each recipient:
                        - Build full recipientContext (firstname, lastname, username, mail — unfiltered)
                        - BodyPersonalizer::personalize($email, [$safeListContext, $mailContext, $recipientContext], $personalizeKeys)
                        - FooterAppender::append($email, $list, [$safeListContext, $mailContext, $recipientContext]) — no whitelist, operator content
                        - Serialize to MIME string via symfony/mime
                        - hash = sha256(list_name . ':' . mimeString)
                        - INSERT INTO mail_queue ... ON DUPLICATE KEY UPDATE id=id
                        - INSERT INTO queue_recipients (mail_queue_id=hash, envelope_to=...)
                - Mark imap_uid + uidvalidity in imap_seen
                - ImapArchiver::archiveOrDelete() per list config, then ArchiveIndexer::index() — a private `masked-sender` reply is deleted instead and never indexed
        d. ImapArchiver::deleteOldMails() -> delete inbox mails older than 30 days
    2. ModerationChecker::checkOverdue() -> remind owners of items pending > 7 days
    3. QueueSender::sendBatch(batch-size, see 'worker.batch-size' above)
    4. Cleanup:
        - DELETE FROM imap_seen WHERE seen_at < NOW() - INTERVAL 31 DAY
        - DELETE FROM rate_limit WHERE sent_at < NOW() - INTERVAL 1 HOUR
        - DELETE FROM bounce_log WHERE bounced_at < NOW() - INTERVAL 90 DAY
        - DELETE FROM processing_failures WHERE last_attempt_at < NOW() - INTERVAL 31 DAY (safety net, see below)
        - QueueSender::purgeCompletedEntries() — finished queue entries older than 30 days
        - ReplyTargetStore::purgeUnused() — reply_targets unused for 180 days
    5. sleep(sleep-seconds, see 'worker.sleep-seconds' above)
```

### IMAP connection reuse across worker cycles

`ImapMailboxFactory` caches one `PhpImap\Mailbox` per list's `imap-*` fingerprint (host/port/user/secure — see its own `fingerprint()`), and that cache now survives across worker cycles, not just within one. Before this, `bin/worker.php` called `ImapMailboxFactory::reset()` at the same call site as `ListProvider::reset()` (end of every cycle, right before the sleep) — dropping every cached `Mailbox` unconditionally meant every list paid for a full LOGIN/TLS handshake again on the very next cycle, even though the existing connection was, in the overwhelming majority of cycles, still perfectly healthy. `reset()` is no longer called there (see [Worker loop — config reload](#worker-loop--config-reload) above for why it and `ListProvider::reset()` turned out to need different policies).

**Liveness check, not a blanket schedule.** `ImapMailboxFactory::getMailbox()` now checks a cached `Mailbox` before handing it out: `Mailbox::hasImapStream()` — a thin, side-effect-free wrapper around `imap_ping()` on the connection's own already-open stream (`is_resource($this->imapStream) && imap_ping($this->imapStream)`, per php-imap's own source). This was chosen over the alternatives available in the library:
- `Mailbox::getImapStream()` (the default, `$forceConnection = true` variant) already transparently pings-and-reconnects internally on every real IMAP call (every one of `Mailbox`'s own methods — `searchMailbox()`, `getMail()`, `statusMailbox()`, ... — calls it first) — but as a side effect of *any* such call, and it repairs the *same* PHP object's stream in place rather than letting `getMailbox()` hand out a fresh one. That distinction matters here specifically because of the folder-selection issue below.
- A genuine no-op IMAP round trip (e.g. re-running `statusMailbox()` just to see if it succeeds) would be real protocol work, not just "is the socket still open" — exactly the SELECT/SEARCH-weight check a liveness probe should avoid paying for on every single `getMailbox()` call.

A dead connection is discarded from the cache and rebuilt via the existing `createMailbox()` (a fresh `Mailbox`, not a repaired one) — deliberately, not just repaired in place, for a second reason beyond the connection itself: `PhpImap\Mailbox` tracks which folder is currently selected as mutable state on the object (`switchMailbox()` rewrites `$imapPath` in place, see [Archive folder path](archive.md#archive-folder-path)), and `ImapArchiver::pruneArchive()` switches the shared cached `Mailbox` to the list's archive folder and never switches it back. Under the old reset()-every-cycle design this never mattered, because every cycle started with a brand-new `Mailbox` freshly constructed pointing at INBOX. Now that the same object can persist across cycles, `ImapPoller::poll()` — always the first IMAP-touching call for a list in every cycle (see the loop pseudocode above) — explicitly re-selects INBOX at its own start (`$mailbox->switchMailbox('INBOX')`) rather than assuming a possibly-reused `Mailbox` is already positioned there; `archiveOrDelete()`/`deleteOldMails()`, which run later in the same cycle and rely on the same "currently on INBOX" assumption without ever selecting it themselves, are correct again as soon as `poll()` has. A freshly reconnected `Mailbox` (the liveness-check-failed path) is unaffected by this either way, since `createMailbox()` always starts a new one at INBOX by construction.

Recovery from a server-side idle timeout is automatic: the liveness check fails on the closed connection, the stale entry is discarded and `createMailbox()` builds a fresh one — see [ADR-0011](../adr/0011-imap-connection-reuse-with-liveness-check.md).

**Error handling is unchanged.** If the reconnect attempt itself fails (server unreachable, credentials no longer valid, ...), it surfaces as an exception from whatever `Mailbox` method needed the stream — the same `try`/`catch` `bin/worker.php` already has around `$imapPoller->poll($list)` catches it and logs "IMAP poll failed for list ...", exactly as it would have for any other IMAP failure. No new exception type or handling path was introduced; the liveness check's only job is making sure a *known-dead* cached connection is never silently handed to `ImapPoller`/`ImapArchiver` in the first place, rather than one of their own calls failing with whatever cryptic error a half-dead stream happens to produce.

### Processing-failure retry limit (`ProcessingFailureTracker`, `ProcessingFailureNotifier`)

Every branch of step 1c above (`ModerationResponseHandler::handle()`, `IncomingMailFilter::filter()`, `BounceHandler::handle()`, `RejectionNotifier::notify()`, `ModerationMailer::send()`, `MailProcessor::process()`, and the `markSeen()`/`archiveOrDelete()`/`ArchiveIndexer::index()` calls around them) runs inside one `try` per mail in `bin/worker.php`. Originally, an uncaught exception anywhere in there was just `error_log()`'d and the loop moved on to the next mail — but since none of `markSeen()`/`archiveOrDelete()` had run yet, the mail stayed unseen and was re-fetched and re-crashed on *every single subsequent cycle*, forever, with the only trace being that repeating log line. Confirmed live: a non-conformant Content-ID (see [Non-conformant Content-IDs](mail-processing.md#attachments--preserving-embedded-cid-images) above, now separately fixed) retried every ~20s for several minutes straight with zero owner-facing signal.

`ProcessingFailureTracker` (`src/Mail/ProcessingFailureTracker.php`) bounds this: a new `processing_failures` table (`migrations/004_processing_failures.sql`), keyed like `imap_seen`/`moderation_queue` by `(list_cn, imap_uid, imap_uidvalidity)`, tracks an `attempts` counter per mail — persisted in the DB, not an in-memory counter, so it survives a worker restart between cycles the same way `imap_seen` does. `bin/worker.php`'s per-mail `catch` now calls `recordFailure()` (upsert + return the new count) instead of just logging; while `attempts < ProcessingFailureTracker::MAX_ATTEMPTS` (3, matching `queue_recipients`' own give-up threshold — see "queue.failure_notice" — same "3 tries, then stop and tell someone" philosophy applied to incoming-mail processing instead of outgoing queue sending), it still just retries next cycle as before. Once the limit is reached, the mail is given up on: `ProcessingFailureNotifier::notify()` emails the list owners (translation key `processing_failure.owner_notice`, original mail attached as `message/rfc822`, same pattern as `BounceHandler`/`ModerationMailer`) with the mail's subject/sender, the attempt count, and the exception message, then `markSeen()` + `archiveOrDelete()` run so the mail finally leaves the retry loop (archived or deleted per the list's own `archive:` setting, same as any other terminal outcome), and the `processing_failures` row is cleared. A failure during this give-up sequence itself (owner notify, mark seen, archive) is caught separately and logged rather than crashing the whole worker cycle — the row is deliberately left in place so the mail is retried (and give-up re-attempted) next cycle instead of silently falling out of tracking.

On the success path, `bin/worker.php`'s per-mail processing was refactored from a `continue`-heavy inline block into a closure (`$processIncomingMail`, still holding the exact same branch logic — every `continue;` became a `return;`) specifically so there is exactly one call site, right after it returns without throwing, to call `ProcessingFailureTracker::clear()` — regardless of which of the branches inside actually handled the mail. Without a single success point, clearing the tracker correctly would have needed a matching `clear()` call added at every one of the six `continue`/end-of-function exits inside the old inline block, an easy place to miss one and leave a stale row (or worse, an under-counted retry limit) behind.

A `processing_failures` row is normally short-lived — cleared within the same cycle it either succeeds or hits the give-up path — so the cleanup-step `DELETE ... WHERE last_attempt_at < NOW() - INTERVAL 31 DAY` (same retention as `imap_seen`) is a safety net for the one case that doesn't self-resolve: the give-up sequence itself repeatedly failing (e.g. sending the owner notification keeps erroring), which would otherwise leave the row behind indefinitely.

### Sending batch (`QueueSender`)

- Fetch up to `batch-size` (see [Worker loop](#worker-loop-binworkerphp) above) `queue_recipients` with `status=pending`, ordered by `last_attempt_at ASC`
- Per recipient: call `SmtpConnectionFactory::getTransport($listConfig)` — reuses open connection if SMTP fingerprint unchanged, otherwise closes and opens a new one
- Send via `symfony/mailer` with explicit `Envelope`
- On success: mark `sent`. The row (and its `mail_queue` MIME) is **kept** until `QueueSender::purgeCompletedEntries()` removes it after 30 days — see [Queue retention: keeping completed entries around](bounces.md#queue-retention-keeping-completed-entries-around)
- On failure: check `SpamRejectionDetector::isSpamRejection()` first (see below); otherwise increment `attempts`, and if `attempts >= 3`: mark `failed`, notify list owner

### Spam rejection at delivery time (`SpamRejectionDetector`)

symfony/mailer's equivalent of checking PHPMailer's `->ErrorInfo` after `send() === false`: a failed `$mailer->send()` throws `Symfony\Component\Mailer\Exception\TransportExceptionInterface`, which carries the receiving mail server's own response via `getMessage()`/`getDebug()`.

- `SpamRejectionDetector::isSpamRejection(\Throwable $e, string $envelopeTo): bool` fires only if **both** hold:
  1. `$e instanceof TransportExceptionInterface` (an actual SMTP-level rejection, not e.g. a connection error or a `RuntimeException` from a missing list)
  2. the recipient's domain (`$envelopeTo`) is in the effective trusted-domain set — `SpamRejectionDetector::BUILTIN_DOMAINS` (gmail.com, gmx.de/net, web.de, outlook.com/hotmail.com/live.com, icloud.com/me.com/mac.com, yahoo.com, aol.com, t-online.de, …) merged with the optional root-level `reliable-spam-reporters:` config.yml key (a plain array of domain strings, instance-wide — no per-list/per-provider concept, unlike the [Global / provider / list levels](config.md#global--provider--list-levels-members-owners-member-resolver-owner-resolver-senders-restricted-members) six keys). This stays a trust boundary for treating another party's SMTP response as authoritative — `reliable-spam-reporters:` can only **add** domains an operator has deliberately chosen to extend that trust to, never replace or narrow `BUILTIN_DOMAINS`, which is always part of the merged set regardless of config. Without either layer, a malicious or misconfigured SMTP server could forge a "spam" response to make Listig discard mail for recipients it has nothing to do with — extending the list is therefore a real trust decision an operator makes deliberately, not a casual setting.
  3. `strtolower($e->getMessage() . ' ' . $e->getDebug())` contains `'spam'`

**`reliable-spam-reporters:` reads from every source, root-direct and `use:`-referenced blocks alike, always concatenated** (`ConfigResolver::getReliableSpamReporters()`) — the root's own direct value plus each root-level `use:`-referenced named block's own value (including one loaded via `!include`), in `use:` order, via the same `collectGlobalSources()` helper the six scoped keys' global level uses (see [Global / provider / list levels](config.md#global--provider--list-levels-members-owners-member-resolver-owner-resolver-senders-restricted-members)), just without any provider/list level of its own. This was a real, confirmed gap when the key was first introduced, worse than the analogous `owners:`/`lists:` gaps fixed earlier: `reliable-spam-reporters:` wasn't just invisible when set inside a `use:`-block — a plain **root-direct** `reliable-spam-reporters: [...]` didn't work *at all*, in any position. The root-key loop in `processConfig()` only special-cases a fixed set of keys (`list-providers`/`filters`/`lists`/the six scoped keys) before falling through to "any other array value becomes a named block, inert unless referenced via `use:`" — `reliable-spam-reporters` wasn't in that fixed set, so it silently became exactly such an inert block itself, and `SpamRejectionDetector` always fell back to just `BUILTIN_DOMAINS`, no error. Confirmed live before the fix: `getResolvedDefault()['reliable-spam-reporters']` was undefined even with the key set directly at config.yml's own root.
- On a match, `QueueSender::discardBatchAsSpam()` aborts immediately (no 3-attempt wait) and marks the current recipient **and every other still-`pending` `queue_recipients` row sharing the same `mail_queue.batch_id`** as `failed` — i.e. every remaining copy of the same original mail, across every list it was addressed to, personalized or not (see `mail_queue.batch_id` in [Database Schema](../reference/database-schema.md#database-schema) for why a shared `batch_id`, not a shared `mail_queue_id`, is required to find them). Rows already `sent` are untouched.
- Discarded copies are marked `failed`, not deleted outright — same as any other delivery failure, they stay visible/retryable/deletable via the manage page's queue status (`QueueController`) until `purgeCompletedEntries()` purges them after 30 days.
- The list owner is notified once per discarded batch (translation key `queue.spam_rejected`), not once per discarded recipient.

### Envelope separation

```php
$mailer->send(
    new RawMessage($mimeString),
    new Envelope(
        new Address("{$list->localPart}+bounce+{$token}@{$list->domain}"),  // Envelope-From: per-recipient VERP, signed token
        [new Address($recipient->envelopeTo)]                      // Envelope-To
    )
);
```

`Sender` header in MIME: `{$list->localPart}+bounce@{$list->domain}` — the base of the per-recipient Envelope-From above (see below), built from `ListConfig::$localPart` (the local part of the list's own `mail` address, e.g. `it` for `it@example.org`), **not** `$list->name`/`{list-cn}` — those commonly differ (a list named `it-team` may have `mail: it@example.org`), and a bounce address built from the internal list name has no reason to be a real, deliverable mailbox at all. The *header* is the same for every recipient, but the *envelope* sender is per-recipient (VERP): `QueueSender::sendOne()` signs `{$list->localPart}+bounce+{$token}@{$list->domain}` with a token naming the exact `queue_recipients` row (`TokenService::sign('b', ListFingerprint::of($listCn), $recipientId)`), so an asynchronous bounce can be attributed without trusting anything inside the DSN — see [Automatic bounce actions](bounces.md#automatic-bounce-actions).
Visible `To`/`Cc` header: the original mail's own `To`/`Cc` addresses, copied verbatim by `MailProcessor::buildOutgoingEmail()` — never the expanded member list, and never the actual per-recipient envelope target (that's the `Envelope` above). This was documented but not actually implemented for a while: `new Email()` starts with no address header at all, and unlike `Message::ensureValidity()` (which requires at least one of To/Cc/Bcc), `Message::toString()` — what `QueueWriter::enqueue()` actually calls to serialize into `mail_queue.mime` — never checks for one, so the omission produced valid-looking, silently header-less mail rather than an error.

---

## SmtpConnectionFactory

Caches open `symfony/mailer` transport instances per SMTP configuration fingerprint (hash of `smtp-host`, `smtp-port`, `smtp-user`, `smtp-secure`). `QueueSender` calls `getTransport($listConfig)` per recipient; the factory reuses the connection if the fingerprint matches, or closes and reopens it if it changes. Takes `PasswordCrypto` in its constructor and calls `decryptIfEncrypted($list->smtpPassword)` when building the DSN — this is the only point where the SMTP password is decrypted.

`ImapMailboxFactory` mirrors this: takes `PasswordCrypto` and calls `decryptIfEncrypted($list->imapPassword)` when constructing `PhpImap\Mailbox` — the only point where the IMAP password is decrypted. Neither `ListConfig` nor any provider ever sees the plaintext password; `imapPassword`/`smtpPassword` getters return the raw stored value (encrypted or plaintext) unchanged, decryption happens exactly where the credential is consumed.
