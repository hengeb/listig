# ADR-0011: Reuse IMAP connections across worker cycles, guarded by a liveness check

Status: Accepted

## Context

`bin/worker.php` used to call `ImapMailboxFactory::reset()` at the end of every cycle, so every list paid for a full LOGIN/TLS handshake again each cycle although the connection was almost always still healthy.

## Decision

The factory keeps its `PhpImap\Mailbox` instances across cycles. `getMailbox()` checks a cached instance with `Mailbox::hasImapStream()` (an `imap_ping()` on the already-open stream); a dead one is discarded and rebuilt with `createMailbox()` — a fresh object, not a repaired one. `ImapPoller::poll()` explicitly calls `switchMailbox('INBOX')` first, because `ImapArchiver::pruneArchive()` leaves the shared object on the archive folder. `ListProvider::reset()` stays per-cycle (cached directory data cannot tell whether it is stale; a connection can).

## Alternatives considered

- Relying on `Mailbox::getImapStream()`'s internal ping-and-reconnect: works, but repairs the same object in place and as a side effect of any call.
- A real no-op IMAP command as probe: protocol-weight work on every `getMailbox()`.
- Keeping the unconditional per-cycle reset.

## Consequences

Folder selection is mutable state on a long-lived object; every code path must not assume INBOX unless `poll()` ran first. Error handling is unchanged: a failed reconnect surfaces from the next `Mailbox` call and is caught by the existing per-list `try`/`catch`.

> **Does this correctly recover from a server-side idle timeout?** Yes — worked through explicitly, since this is the main real-world scenario the whole change is about: many IMAP servers close a connection that's been idle for some period (commonly around 30 minutes). The next time that list is due to be polled (up to `sleep-seconds` later), `getMailbox()` runs `hasImapStream()` against the now-closed connection. `imap_ping()` on a closed stream returns `false` (or the resource/`IMAP\Connection` check itself already fails, depending on exactly how the server closed it — either way `hasImapStream()` returns `false`), so the stale entry is discarded and `createMailbox()` builds a fresh one — the *same* fresh-LOGIN path that ran unconditionally every cycle before this change, just now only paid for when actually needed. `ImapPoller::poll()`'s own explicit `switchMailbox('INBOX')` immediately after `getMailbox()` then re-selects INBOX on this brand-new connection too (a harmless no-op there, since a freshly constructed `Mailbox` is already on INBOX — but keeping it unconditional avoids a special case for "was this cached or fresh").
