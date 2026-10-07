# ADR-0008: Cache archived mail as an APCu snapshot

Status: Accepted

## Context

Opening one archived mail in the web viewer is several HTTP requests (`show()`, `frame()`, one `attachment()` per attachment), each building a fresh container with no IMAP connection reuse. `ArchiveMailLocator::find()` (connect + `SEARCH ALL`/`FETCH OVERVIEW` + `getMail()`) cost about 550 ms per call against a 20-message folder, paid by every request.

Background (moved from the former CLAUDE.md, wording preserved):

> Why a *snapshot* (`CachedArchivedMail`/`CachedAttachment`) rather than caching the `PhpImap\IncomingMail` object itself: `IncomingMailAttachment`'s lazy `getContents()` works by holding a `DataPartInfo` that in turn holds a live reference to the `PhpImap\Mailbox`/IMAP connection that produced it — a fetch happens *on the connection* the moment `getContents()` is called, not before. That connection is a PHP resource; it cannot survive `apcu_store()`'s internal serialization, and even if it silently didn't error, it would already be closed (the request that opened it has long since finished) by the time a *different* request tried to read from a cached attachment. `CachedAttachment` sidesteps this by resolving `$contents` to a plain string once, at cache-population time, while the connection is still open — everything downstream (`ArchiveHtmlSanitizer`, `show.latte`) reads plain data with no IMAP dependency left at all. `CachedAttachment` deliberately mirrors `IncomingMailAttachment`'s public property names (`name`/`mimeType`/`sizeInBytes`/`disposition`/`contentId`) so neither `ArchiveHtmlSanitizer` (duck-types `->disposition`/`->contentId`) nor `show.latte` (`->name`, `->sizeInBytes|formatBytes`) needed any change — only `ArchiveController`'s own two remaining property-vs-method differences (`->contents` instead of `->getContents()`, and a plain array instead of `->getAttachments()`) do.

## Decision

`ArchiveMailCache` stores a fully resolved snapshot (`CachedArchivedMail` with `CachedAttachment[]`, contents fetched eagerly) in APCu, keyed by SHA-256 of list + Message-ID, TTL 300 s. A cache hit measured under 5 ms. It degrades to "always miss, never store" if APCu is unavailable. `docker/php.ini` enables `apc.enable_cli` and raises `apc.shm_size` to hold attachment bytes.

## Alternatives considered

Caching the `IncomingMail` object itself (its attachments hold a live IMAP connection that cannot be serialized); a `$_SESSION`-based cache (see below).

> An earlier version of this cache used `$_SESSION` (keyed the same way, but storing only the resolved IMAP UID as a fast-path hint, not the full content) — replaced with APCu specifically because a session-file cache (a) only benefits the one browser session that populated it, not every other viewer of the same mail, (b) writes to disk by default (PHP's file-based session handler), which this codebase otherwise deliberately avoids doing with mail content, and (c) needs its own cleanup story, whereas APCu's per-entry TTL expires it automatically with nothing to ever clean up. `ArchiveMailCache` degrades to "always miss, never store" — never a fatal error — if the `apcu` extension isn't loaded or isn't enabled for the current SAPI (`apcu_enabled()`; disabled for CLI unless `apc.enable_cli=1`, set in `docker/php.ini` alongside a `shm_size` raised from the 32M default to comfortably hold eagerly-cached attachment bytes, not just HTML).

## Consequences

APCu is shared memory across all php-fpm workers, so any user's request warms the cache for all; entries expire on their own with nothing to clean up. A deleted archived mail is evicted explicitly (`ArchiveMailCache::delete()`); a pruned one is not — the 300 s TTL self-heals.
