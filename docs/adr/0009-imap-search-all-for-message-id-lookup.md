# ADR-0009: Find archived mail with SEARCH ALL + FETCH OVERVIEW, not SEARCH HEADER

Status: Accepted

## Context

A message in the IMAP archive folder has to be re-located by Message-ID (UIDs change when mail is moved).

Background (moved from the former CLAUDE.md, wording preserved):

> **Finding a message by Message-ID (`ArchiveMailLocator::findUidByMessageId()`)** — deliberately `SEARCH ALL` + `FETCH OVERVIEW` (`Mailbox::getMailsInfo()`, whose `message_id` field is exactly the header value, brackets included) rather than IMAP `SEARCH HEADER Message-ID "<...>"`, which was the first approach tried and reliably fails against at least one real deployment (`mail.hengeb.de`) with `"Unknown search criterion: HEADER"` — confirmed by connecting to the actual server: `SEARCH ALL` and `FETCH OVERVIEW` both work fine there, only the `HEADER` search key is unimplemented, even though it's part of the base IMAP4rev1 spec (RFC 3501). `SEARCH`/`FETCH OVERVIEW` calls pass `$disableServerEncoding = true` throughout, to also avoid a *second*, independent failure mode seen along the way: `Mailbox::searchMailbox()` otherwise sends a CHARSET argument (the server's own encoding) to `imap_search()`, which some servers reject outright regardless of the search criteria used. The linear scan over every message's overview is only ever triggered by a single-message lookup (opening one archived mail in the web viewer), not a bulk operation, so its cost is acceptable for a single call — see [Archive mail cache — performance](../architecture/archive.md#archive-viewer) below for why it's now rarely called more than once per mail at all, regardless of how many separate HTTP requests one page view fires.

## Decision

Linear scan: `SEARCH ALL` + `FETCH OVERVIEW` (`Mailbox::getMailsInfo()`, whose `message_id` is the header value including brackets), with `$disableServerEncoding = true` on all calls.

## Alternatives considered

IMAP `SEARCH HEADER Message-ID "<...>"` was tried first and fails reliably against at least one real deployment (`mail.hengeb.de`) with "Unknown search criterion: HEADER", although it is part of RFC 3501. Sending a CHARSET argument (the default behaviour of `Mailbox::searchMailbox()`) is a second, independent failure on some servers.

## Consequences

The cost is linear in folder size, acceptable because it only runs for a single-message lookup — and rarely twice for the same mail thanks to [ADR-0008](0008-apcu-snapshot-cache-for-archive.md).
