# Moderation

Moderation flow, UI and previews.

## Moderation

### Flow

1. Incoming mail from a sender whose `post-access-members`/`post-access-public` (whichever applies) is `PostAccess::Moderate` — see `IncomingMailFilter::requiresModeration()`; size check passes first
2. `ModerationMailer::send(ListConfig $list, IncomingMail $mail, int $imapUid, int $uidValidity, string $rawMime)` sends to all owners:
   - `From`: list address; `Reply-To`: the accept address itself — so an owner can just hit "Reply" in their mail client to approve, without needing to compose a new message or click the `mailto:` link. Rejecting still requires acting on the `Reject:` line explicitly (there's only one Reply-To slot, and accept is the more common action).
   - `Content-Type: multipart/mixed`:
     - **Part 1** (`text/plain`): the moderated mail's own subject/sender/date, then metadata + mailto links as plain text (**no HTML part** — prevents token leakage in replies):
       ```
       Subject: {subject}
       From: {sender-name} <{sender-mail}>
       Date: {date}

       Accept: mailto:{local-part}+accept-{TOKEN}@example.org?subject=accept
       Reject: mailto:{local-part}+reject-{TOKEN}@example.org?subject=reject
       ```
       `{local-part}` is `ListConfig::$localPart` (the local part of the list's own `mail` address), **not** `$list->name`/`{list-cn}` — same reasoning as the bounce address (see [Envelope separation](worker-and-queue.md#envelope-separation)): they commonly differ, and only the real mailbox's local part is guaranteed deliverable back into the list's own IMAP inbox where `ModerationResponseHandler` can find it. `{TOKEN}` is the normal base64 token (see [Token Format](security-and-tokens.md#token-format)) — recovering it intact from a reply's raw `To` header, rather than the lowercased `$mail->to`, is what makes mail-reply accept/reject actually work; see [Token Format](security-and-tokens.md#token-format) for why.
       `?subject=accept`/`?subject=reject` is a `mailto:` query parameter — mail clients pre-fill the compose window's Subject with it, but it plays no role in `ModerationResponseHandler::detectAction()` (which only ever looks at the `To` address) and is stripped from the actual outgoing `To:` header, so it can't interfere with token detection. Added purely because a mail with a genuinely empty Subject made some mail clients warn the owner before sending; not applied to `$acceptAddress`/`$rejectAddress` themselves, which are also used bare for the `Reply-To` header below and must stay valid, query-free addresses there.
       Sourced directly from the already-parsed `IncomingMail` passed in (`$mail->subject`/`$mail->fromName`/`$mail->fromAddress`/`$mail->date`), not re-read from `$rawMime` — same fields, and same `"{$senderName} <{$senderMail}>"` formatting, persisted to `moderation_queue`'s `subject`/`sender_name`/`sender_mail`/`mail_date` columns (see [Database Schema](../reference/database-schema.md#database-schema)) so the manage page's moderation queue table can show the same information without a live IMAP fetch.
     - **Part 2** (`message/rfc822`): complete original mail
   - The sender also gets a notice (`NotificationMailer`, translation key `moderation.pending_notice`) that their mail is awaiting approval — without this, a moderated mail looked identical, from the sender's side, to one that silently vanished; there's no equivalent of `reject.notice`/`bounce.owner_notice` for "still pending." Sent only when `ModerationMailer::send()`'s own `INSERT ... ON DUPLICATE KEY UPDATE id = id` actually inserted a new row (`$insertStmt->rowCount() === 1`) — `ModerationChecker::checkOverdue()`'s reminder resend calls this same `send()` method (see below) and must not re-notify the sender on every 7-day reminder, only the owners.
3. `imap_uid` + `uidvalidity` (and the mail metadata above) stored in `moderation_queue` + `imap_seen` (the token itself is not persisted — it is self-describing, see Token Format). `ModerationChecker::checkOverdue()`'s reminder resend re-fetches the same `IncomingMail` by UID (`ImapPoller::fetchMailByUid()`) to pass through the same `send()` call — the stored columns are written once at initial queueing and never updated by a reminder.
4. Owner sends to accept/reject address (by replying, or via the `mailto:` link)
5. Worker detects `+accept-` or `+reject-` in `To` (`ModerationResponseHandler::detectAction()`, matched against `$list->localPart`, mirroring how `ModerationMailer` built the address):
   - Validate HMAC + expiry
   - Validate sender is list owner (LDAP)
   - **Both must pass**
6. Accept: fetch from IMAP by UID; if not found → send error to owner, delete from `moderation_queue`; if found → process and enqueue normally, archive/delete
7. Reject: archive/delete, notify original sender (translation key `reject.moderation_declined`)
8. Delete from `moderation_queue`

**Reject via the manage-page button** (`ModerationController::reject()`, `POST /_/api/moderation/{id}/reject` — see [Moderation via UI](#moderation-via-ui)) follows the exact same reject contract as step 7 above: fetch the `IncomingMail` by UID, `RejectionNotifier::notify(..., 'reject.moderation_declined')`, `markSeen()`, `archiveOrDelete()`, then delete the `moderation_queue` row. It did not originally — it only deleted the row, leaving the sender un-notified and the mail stuck in the inbox forever (never marked seen, never archived/deleted) — a UI reject and a mail-reply reject must have identical end states, not two different ones depending on which path an owner happens to use.

`allow-leave: moderated`: when a member requests unsubscription, send a plain notification mail to all owners: "User {firstname} {lastname} ({mail}) has requested removal from list {display-name}." Owner must remove manually in LDAP.

### Overdue reminder

Find rows where `created_at < NOW() - 7 days` and (`reminded_at IS NULL` or `reminded_at < NOW() - 7 days`). Resend moderation mail, update `reminded_at`.

### Moderation via UI

- `POST /_/api/moderation/{id}/accept`
- `POST /_/api/moderation/{id}/reject`

Require valid session (owner of that list) + `X-CSRF-Token`.

The manage page's moderation queue table (`ListController::getModerationItems()`,
`templates/list/manage.latte`) shows Subject/Sender/Received columns alongside Accept/Reject,
reading `moderation_queue`'s `subject`/`sender_display` (see [Database Schema](../reference/database-schema.md#database-schema))/`mail_date`
columns directly — no live IMAP fetch. `mail_date` falls back to `created_at` for a row queued
before the metadata columns existed (the migration doesn't backfill). Each row is itself
clickable (`class="clickable-row"`, whole-row `onclick` plus a real `<a>` on the Subject cell
for no-JS/keyboard/open-in-new-tab access) and opens a full preview of the still-pending mail
— see [Preview: pending mail](#preview-pending-mail) below. The Accept/Reject buttons call `event.stopPropagation()`
first so clicking one doesn't also navigate the row away.

**Latte quoting in `onclick` attributes:** build the whole attribute value as a single `{...}` print expression — see [Latte pitfalls](../library-notes.md#latte-onclick-attributes-are-a-js-string-context).

### Preview: pending mail

Clicking a moderation queue row (see above) opens a read-only preview of the still-pending
mail at `GET /{listname}/moderation/{id}` (`{id}` is `moderation_queue.id`) —
`ModerationController::show()`/`frame()`, reusing the archive viewer's own
`templates/archive/show.latte`/`frame.latte` rather than duplicating them, since the two views
are otherwise identical (metadata table, attachment list/thumbnail gallery, sandboxed HTML
frame, HTML/plain-text toggle, external-image gating). The mail itself comes straight from IMAP
by UID (`ImapPoller::fetchMailByUid()`, the same call `ModerationController::accept()` already
makes) — not `archived_mail`/`ArchiveMailLocator`, since a pending item was never archived and
still lives in the inbox, not the archive folder; there is deliberately no caching layer
equivalent to `ArchiveMailCache` here, since a moderation preview is opened rarely compared to
the archive and a plain per-request IMAP fetch is cheap enough on its own.

**Templates were parametrized, not duplicated**, to support both call sites:
`show.latte`/`frame.latte` take `$baseUrl` (the `.../{id}` prefix every attachment/frame link is
built from — `/{listname}/archive/{id}` for `ArchiveController`, `/{listname}/moderation/{id}`
here), `$backUrl`/`$backLabel` (the "← back" link target/label — the archive index vs. the
list's own manage page), and `$allowDelete` (renamed from the template's old `$isOwner` — gates
the delete button, which only makes sense for an actually-archived mail; `ModerationController`
always passes `false`, since there is no `archived_mail` row here for it to act on).

**Owner-only, always a real session** — unlike the archive viewer's own routes (whose access
depends on the specific list's `archive` mode and so sit behind `OptionalAuthMiddleware`, see
[Archive viewer](archive.md#archive-viewer)), `show()`/`frame()` are plain `AuthMiddleware`-protected routes (same group as
`/{listname}` itself) — a pending mail has no `Public`/`Members` visibility concept, only the
list's owners may ever see it. `attachment()` is the **one exception**: `GET
/{listname}/moderation/{id}/attachment/{index}` sits in the *archive* viewer's own
`OptionalAuthMiddleware` group instead, for the identical reason `ArchiveController::attachment()`
does — the `<img>` tags `frame()`'s sandboxed iframe fetches for `cid:`-rewritten images carry
no session cookie at all (opaque origin, no `allow-same-origin`), so `AuthMiddleware` would
redirect that cookie-less request to `/_/login` before the controller ever got a chance to fall
back to its signed-token grant. That token uses its own dedicated purpose,
`moderation-attachment` (not `archive-attachment`), purely so the two grants can never be
replayed against each other — same `TokenService` purpose-isolation principle as `login` vs.
`unsubscribe` vs. `accept`/`reject`.

**`AttachmentSafety` (`src/Archive/AttachmentSafety.php`)** — `isSafeInlineContent()`
(magic-byte/`getimagesizefromstring()` re-verification of a claimed MIME type before ever
serving an attachment `Content-Disposition: inline`) and `sanitizeFilename()` were extracted out
of `ArchiveController` into their own small class specifically so `ModerationController` could
reuse them rather than maintaining a second copy of security-relevant logic that could drift out
of sync with the original. `ArchiveController` itself was updated to call the shared class too,
so there is exactly one implementation, not two kept in parallel by convention.
