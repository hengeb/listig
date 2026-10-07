# ADR-0010: Reconcile the archive index in one direction only

Status: Accepted

## Context

`ArchiveSynchronizer::sync()` reconciles `archived_mail` with the IMAP archive folder when the archive index is opened.

Background (moved from the former CLAUDE.md, wording preserved):

> An earlier version also auto-indexed that second case (one `getMail()` fetch + `ArchiveIndexer::index()`, "just like a normal distribute") — that was a real bug, confirmed live: `bin/worker.php` moves a bounced *or rejected* mail's raw MIME into the exact same archive folder as a distributed one (`ImapArchiver::archiveOrDelete()` runs for all three outcomes — see [IncomingMailFilter — check order](../architecture/mail-processing.md#incomingmailfilter--check-order)), but only ever calls `ArchiveIndexer::index()` for an actual distribute, precisely so bounce/reject mail stays off the member-facing archive (see `ArchiveIndexer`'s own docblock). Nothing on the raw IMAP message distinguishes "a distribute Listig just hasn't indexed yet" from "a reject/bounce Listig never intended to index" — so add-missing necessarily mis-indexed every rejected mail as soon as anyone opened the archive after it landed on IMAP. Remove-missing has no equivalent ambiguity: an indexed Message-ID that's gone from IMAP should always be removed, whatever the reason.

## Decision

Only remove index rows whose Message-ID is no longer on IMAP. A Message-ID on IMAP but missing from `archived_mail` is left alone.

## Alternatives considered

An earlier version also indexed such messages (see below) — a confirmed bug.

## Consequences

Bounced and rejected mail stays out of the member-facing archive; a distribute that was never indexed (e.g. an indexing failure) is not repaired automatically.
