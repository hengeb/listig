# Mail processing

How an incoming mail is filtered and turned into outgoing mail.

## IncomingMailFilter — check order

1. **X-Loop** present (any value) → discard silently
2. **Spam filter**: any rule in `filters:` (config.yml, global, see [Spam filtering](#spam-filtering-filters)) matches → `action: reject` (default): reject, **no notice** (backscatter, see [Sender notices](#sender-notices-backscatter-protection)); `action: discard`: silently dropped, no notice. Either way the mail is *deleted* outright, never archived — regardless of the list's own `archive:` setting (unlike every other reject reason below, which still go through the normal `archiveOrDelete()`).
3. **Bounce** (any match below) → log to `bounce_log`, forward to owner as `multipart/mixed` (Part 1: `text/plain` with metadata — see [Bounce notice details](bounces.md#bounce-notice-details) below; Part 2: `message/rfc822` with full original bounce mail):
   - `Auto-Submitted` present and ≠ `no`
   - `X-Auto-Response-Suppress` present
   - `Content-Type: multipart/report; report-type=delivery-status`
   - `From` contains `MAILER-DAEMON` or `postmaster` (case-insensitive)
   - Subject matches `/^(delivery status|mail delivery failed|undelivered mail)/i`
   - `Auto-Submitted: auto-replied` alone (RFC 3834 auto-responder), `X-Auto-Response-Suppress` alone and `Precedence: auto_reply` are **not** bounces — see step 3b.
3b. **Auto-reply** (out-of-office etc.; only reached if step 3 didn't match, i.e. no DSN/`MAILER-DAEMON`/`auto-generated`) → `FilterResult::discard(forceDelete: true)`: silently dropped and deleted, no `bounce_log` row, no owner notice. Forwarding these was pure noise and could trip `BounceHandler`'s circuit breaker, suppressing real bounces. Implemented by `IncomingMailFilter::isAutoReply()`.
4. **Subaddress validation** (`type: subaddress` lists only, see [type: subaddress — subaddress forwarding](providers-and-members.md#type-subaddress--subaddress-forwarding)): reserved subaddress (`bounce`, `accept-*`, `reject-*`, or list-configured `reserved-subaddresses`) → reject, notify sender; no subaddress at all while at least one member template requires one → reject, notify sender
5. **Authentication-Results**: SPF or DKIM = `fail` in the selected header (see [Header filter](#header-filter)) → reject (`reject.auth_failed`), **never** notify the sender (the From is probably forged)
6. **Size**: raw MIME size > `max-size` → reject, notify sender
7. **Post-access** (`IncomingMailFilter::checkPostAccess()`; for a mail to a `+r-` masked-reply address `checkMaskedReply()` instead — see [Masked reply addresses](masked-replies.md#masked-reply-addresses)): a `restricted-members:` hit → reject (`reject.sender_restricted`), notify sender — checked *first*, overriding even owner status (see [Sender restrictions](providers-and-members.md#sender-restrictions-restricted-members)). Owners and `senders:` addresses (see [Additional senders](providers-and-members.md#additional-senders-senders)) then always pass; a member or public sender whose respective `post-access-members`/`post-access-public` is `deny` → reject (`reject.members_denied`/`reject.public_denied`), notify sender. `allow` and `moderate` both pass here — deciding between them happens later, at step 9, after rate limiting.
7b. **Reply thread tag**: a mail to a `+re-{TOKEN}` address (the archive viewer's "reply to this mail" button, [ADR-0020](../adr/0020-reply-thread-tag.md)) whose token is invalid, expired, of another list or points to a mail no longer in `archived_mail` → reject (`reject.reply_thread_unknown`, a hint to write a new mail), notify sender. A valid one is a normal post; `MailProcessor` then threads it (below).
7c. **Unverified From** (`post-access-unauthenticated`, [ADR-0024](../adr/0024-post-access-unauthenticated.md)): if not `allow` and `SenderAuthenticator::assess()` yields no evidence → `moderate` holds the mail (the owners' notice carries an "unverified sender" hint), `deny` rejects with `reject.unauthenticated` (never notified). Applies to owners and `senders:` too. A private `+r-` relay cannot be held and is rejected.
8. **Rate limit**: exceeded → reject, notify sender
9. **Moderation with no owners** (`IncomingMailFilter::requiresModeration()` — owners never moderated; only reached when the sender's `post-access-members`/`post-access-public` is `moderate`): list has zero owners → reject (`reject.no_owners`), notify sender — a moderation item nobody can ever accept/reject would otherwise vanish silently instead of being distributed or bounced back with feedback

**The spam filter runs *before* bounce detection** (the opposite of every other check below it), so an operator can drop particular unwanted bounces with `action: discard`; the price is that a broad `filters:` rule can also swallow real bounces. Rationale and live confirmation: [ADR-0006](../adr/0006-spam-filter-before-bounce-detection.md).

Bounces are still checked before Authentication-Results and Subaddress validation, for the reasons those two sections already had: `MAILER-DAEMON` mails may legitimately lack valid SPF/DKIM, and address-routing validity is a separate concern from content-based filtering. Note `bin/worker.php` already routes `+accept-*`/`+reject-*` mail through `ModerationResponseHandler` before `IncomingMailFilter::filter()` is ever reached, so the `accept-`/`reject-` check here is defense-in-depth; the `bounce` check is load-bearing, since bounce detection above is content-based and a non-standard bounce sent to `+bounce` would otherwise fall through. The no-owners check is last since it's only relevant once a mail has already cleared every other gate and would otherwise be headed for moderation; `ModerationMailer::send()` still independently checks (and logs, then no-ops) for empty owners too, as a defense-in-depth backstop against a list losing its last owner *after* an item is already in `moderation_queue`.

`PhpImap\Mailbox::getMailHeaderFieldValue()` (populates `IncomingMail::$autoSubmitted`, among others) is typed to always return `string`, using `''` for "header absent" — **never** `null`, despite `IncomingMailHeader`'s own `@var string|null` docblock claiming otherwise. `IncomingMailFilter::isBounce()`'s `Auto-Submitted` check must test `!== null && !== ''`, not just `!== null` — the latter is true for every mail lacking the header (i.e. essentially all normal mail), misclassifying it as a bounce.

## Reply thread tag (`+re-`)

`ReplyThreadStore` (`src/Mail/ReplyThreadStore.php`) issues and resolves `{localPart}+re-{TOKEN}@{domain}`; the token is signed over `ListFingerprint` + `archived_mail.id`, so no table of its own ([ADR-0020](../adr/0020-reply-thread-tag.md), [Archive viewer](archive.md#archive-viewer)). In `MailProcessor::process()` a mail carrying the tag (read from the raw `To`/`Delivered-To`/`X-Original-To`, never `$mail->to`, which PhpImap lowercases):
- has the token address replaced by the list address in the visible To/Cc (`replaceTaggedAddressInRecipients()`, shared with the `+r-` relay) — recipients never see it, and a reply-all goes to the group;
- gets `In-Reply-To: <parent Message-ID>` and `References: <thread root> <parent>` (only the parent if it is the root), unless the client set its own `In-Reply-To`;
- is not an error if the token no longer resolves by now (accepted from moderation much later) — distributed unthreaded.
`ArchiveIndexer::index()` resolves the same tag when the archived original has no `In-Reply-To`, so Listig's own archive threads the reply identically (the original is archived as received, without the headers added to the copies).

## Spam filtering (`filters:`)

Third top-level key in `config.yml`, alongside the root config and `list-providers`. Globally *configured* — one `filters:` list applies to every list — but each mail is checked against it together with the specific list it was sent to, since a rule's pattern may reference that list's own `{}` variables (see below). Checked by `IncomingMailFilter` for every incoming mail on every list (see [IncomingMailFilter — check order](#incomingmailfilter--check-order)). Implemented by `Hengeb\Listig\Mail\SpamFilter`, constructed from `ConfigResolver::getFilters()`.

```yaml
filters-default-action: discard   # optional root key — the action a rule falls back to when it
                                   # sets no action: of its own (default: reject if this key is
                                   # absent too — the original, pre-existing behavior)

filters:
  - subject: abc                  # str_contains(strtolower($subject), 'abc') — case-insensitive
  - subject: def
  - body: xyz                     # checked against textPlain + textHtml combined
  - from: bla                     # checked against fromName + fromAddress combined
  - to: johnny                    # checked against the raw To header (names and addresses)
  - subject: /ab+$/               # /delimited/ value → preg_match instead of str_contains, case-sensitive
  - body: /a\s*b\s*c\*s/
  - to: foo                       # a multi-key entry ANDs its conditions — this rule only
    subject: bar                  # matches a mail whose To *and* Subject both match
  - subject: spam                 # action: discard — mail is silently dropped (marked seen, no
    from: johnny                  # notice to the sender). Either action deletes the mail
    action: discard               # outright, never archives it.
  - from: "MAILER-DAEMON@{domain}" # {} variables resolve against the specific list a mail
    to: "{list-mail}"              # was sent to — see "Variable resolution in filter patterns" (docs/architecture/mail-processing.md)
```

- Each entry is a map with one or more of `subject`, `body`, `from`, `to` as keys, plus an optional `action` key (any other key is a hard error at startup, fail fast, same philosophy as missing `$VAR`s). A single field key is just the common case; when an entry has more than one field key, **all** of that entry's conditions must match (AND) for the entry itself to match — different top-level entries are still ORed against each other (see below). `SpamFilter::normalizeRule()` turns each raw entry into `{conditions, action}`; `match()` returns the first fully-matching entry's action, or `null` if none matched.
- `action` is `reject` or `discard` — defaulting to whichever `filters-default-action` resolves to (`'app.filters-default-action'` in `config/container.php`, read the same `getResolvedDefault()`-backed way as `language`/`log-level`; unlike `filters:` itself, a plain scalar key needs no special-casing in `ConfigResolver::processConfig()` at all — only *array*-shaped root keys like `filters:`/`lists:` do), itself defaulting to `reject` (the original, pre-existing behavior) if the key is absent too. Validated in `SpamFilter`'s own constructor (not just at the `config/container.php` wiring call site) against the same `SpamFilter::ACTIONS` list a per-rule `action:` is checked against, so a typo'd `filters-default-action` fails the same way an invalid per-rule value already does. `action` is **not** a match condition itself — it's read and stripped from the entry before the field keys above are validated/compiled, so it can appear alongside any number of them without affecting what the rule matches on. An entry with only an `action` key and no field key at all (nothing to actually match on) is a hard startup error, same as an entry with zero keys.
  - `reject`: same reject pipeline as every other reason, but `SenderNoticePolicy` never lets a `reject.spam` notice out (it would redistribute the spam to a possibly forged address), so it differs from `discard` only in the reason; the mail is marked seen.
  - `discard`: `FilterResult::discard(forceDelete: true)` — no notice to the sender at all (unlike `reject`), but still marked seen. Distinct from a bare `FilterResult::discard()` (the X-Loop case, `IncomingMailFilter` check 1), which deliberately leaves the mail sitting in the inbox for manual inspection rather than deleting it — named `discard`, not `delete`, for that broader "mail-handling outcome" sense (matching the internal `FilterResult` type), not because of what specifically happens to the IMAP message.
- **Either action deletes the mail outright** (`ImapArchiver::delete()`) rather than going through `ImapArchiver::archiveOrDelete()` — unlike every other reject reason (auth failure, size, rate limit, ...), a spam-filter match is never worth archiving, regardless of what the list's own `archive:` setting says for everything else; `reject`/`discard` set `FilterResult::$forceDelete = true` specifically for this. Confirmed live: a mail matching a `filters:` rule on a list with `archive: members` was deleted from the inbox outright, not moved into the archive folder the way a `reject.size_exceeded` mail on the same list still is.
- The value is matched literally (`str_contains(strtolower($value), strtolower($pattern))` — case-insensitive) **unless** it looks like a delimited PCRE pattern — starts with one of `/ # ~ % !`, and the same character reappears later followed by nothing but valid regex flags (`a-zA-Z`) to the end of the string. In that case it is passed as-is to `preg_match()` (case-sensitive unless the pattern's own flags say otherwise, e.g. `/ab+$/i`). An invalid regex in that form is also a hard startup error.
- Like every other config value, `filters:` supports `!include` (see [File includes](config.md#file-includes-include)), so rules can be outsourced to their own file: `filters: !include filters.yml`.
- A matching rule is traced at `log-level: debug` (see [Debug logging](logging.md#debug-logging)) — which rule (1-based position), its action, and the resolved condition(s) it matched on.

### Variable resolution in filter patterns

A pattern may contain `{}` variables, e.g. `from: "MAILER-DAEMON@{domain}"` to match against a specific list's own bounce-generating domain rather than a hardcoded one. Unlike almost every other `{}` site in this codebase, these are **not** resolved once at startup — `filters:` itself has no list in scope at all (it's parsed once, globally, by `ConfigResolver::processConfig()`, alongside `list-providers:`, before any specific list exists), so there is nothing to resolve `{domain}`/`{list-mail}`/etc. against yet at that point. This was confirmed live as a real, silent bug: a rule referencing `{domain}`/`{list-mail}` matched literally against those unresolved placeholder strings, which no real mail ever contains — the rule simply never fired, with no error or warning to say so.

Fixed by deferring resolution: `SpamFilter::normalizeRule()` keeps a condition's raw pattern text as-is (including any `{}`), and `SpamFilter::match(IncomingMail $mail, ListConfig $list)` — now takes the list being checked, not just the mail — resolves each condition's pattern against `$list->createContext()` fresh, inside `allConditionsMatch()`, only when the raw pattern actually contains a `{` (a plain `str_contains()` check, cheap, and skips building a context array at all for the common case of a rule with no variables). Resolution uses `VariableResolver::resolve()` under `ResolutionPurpose::Disclosed`, same as everywhere else — a pattern that references a blocked key (`{imap-password}`, ...) resolves to the classified placeholder rather than leaking it, safe by construction, not because filters: happens to be a special case.

One consequence of deferring resolution to match time: case-folding a literal (non-regex) pattern also has to happen then, not at `normalizeRule()` time as before, since the pattern isn't fully known until it's resolved against a specific list. Regex-ness (`isRegex()`) and startup-time regex-validity checking are unaffected and still happen once, on the raw pattern, at construction — a `{}` placeholder is always inert, valid PCRE syntax on its own (a `{` that doesn't form a numeric quantifier like `{2,4}` is just a literal character), so validating before resolution doesn't risk a false positive.

No escaping is applied to a resolved value used inside a regex pattern — if a list's own `{list-name}`/`{domain}`/etc. happens to contain a regex metacharacter, it's substituted verbatim and takes on its regex meaning, same as any other `{}` substitution elsewhere in this codebase (e.g. a footer or subject-label template). This is a known, accepted tradeoff, not a bug: operators writing `{}` inside a `/regex/` pattern are expected to understand what they're embedding it into.

## Header filter

`HeaderFilter::parseAuthResults(string $headersRaw, string[] $trustedAuthservIds = []): ?AuthResultsHeader` is the **one place** that selects the `Authentication-Results` (RFC 8601; comments and quoted strings handled, only the top-level header block is read) the receiving MTA's verdict is taken from, or returns `null`:
- `trusted-authserv-id` unset (`$trustedAuthservIds` empty): the **topmost** header. The own MTA prepends its header to every mail it accepts; a sender-supplied header can only sit below it.
- set: only headers whose authserv-id matches (exact, case-insensitive, version ignored) count, whatever their position; all others are treated as absent. The matching ones are merged, topmost first (`AuthResultsHeader::merge()`), so SPF and DKIM written into separate headers both count ([ADR-0019](../adr/0019-optional-trusted-authserv-id.md)).

`AuthResultsHeader` exposes all results per method (`first()`/`all()`, props such as `header.d`, `smtp.mailfrom`, `header.from`). `HeaderFilter::readAuthservIds()` lists the ids found (for the log hint).

`HeaderFilter::readAuthResults(string $headersRaw, string[] $trustedAuthservIds = []): array{spf, dkim, dkimDomain}` is the compact view on that header (first result per method; `dkimDomain` = lowercased `header.d=` of a passing DKIM result, null otherwise), used for the SPF/DKIM reject (step 5) and `BounceHandler::isDkimAuthenticated()` — see [Automatic bounce actions](bounces.md#automatic-bounce-actions). All consumers (worker, `SenderAuthenticator` via `SenderNoticePolicy`, `BounceHandler`) pass `$list->trustedAuthservIds`.

Without the key this requires the operator's MTA to add `Authentication-Results` to every mail — see [Sender authentication](security-and-tokens.md#sender-authentication).

`MailProcessor` builds the outgoing `Email` from scratch via `IncomingMail` fields, so there is no explicit header blocklist. Infrastructure headers (`DKIM-Signature`, `Received`, `Authentication-Results`, `ARC-*`, `Return-Path`) are simply never copied to the fresh outgoing `Email`. Threading headers (`Message-ID`, `In-Reply-To`, `References`, `Date`) are preserved — but not all via the same `Headers` method: symfony/mime's `Headers::HEADER_CLASS_MAP` enforces a specific value class for some header names, rejecting `addTextHeader()`'s always-`UnstructuredHeader` result outright (`LogicException: The "..." header must be an instance of "..." (got "UnstructuredHeader")`). `Message-ID` must be `addIdHeader()` (an `IdentificationHeader`, constructed from the bare id — the raw value's `<>` are stripped first, `IdentificationHeader::getBodyAsString()` re-adds them) and `Date` must be `addDateHeader()` (a `DateHeader`, constructed from a parsed `\DateTimeImmutable`, not the raw string). `In-Reply-To`/`References` are the exception: their `HEADER_CLASS_MAP` entry allows `UnstructuredHeader` *or* `IdentificationHeader` (deliberately lenient, "to allow users entering the original email's Message-ID, even if that is no valid msg-id" — the library's own comment), so `addTextHeader()` continues to work for those two. Each header is preserved best-effort in its own `try`/`catch` — a malformed value from the sending MTA (unparseable `Date`, a `Message-ID` that fails `Address`'s RFC validation) is logged and skipped rather than blocking distribution of an otherwise-fine mail.

## Attachments — preserving embedded (`cid:`) images

`buildOutgoingEmail()` copies `$mail->textHtml`/`$mail->textPlain` into the outgoing body verbatim — any `cid:` references an incoming HTML body contains (e.g. `<img src="cid:part1.ACmwPHTY.OIw3acmz@hengeb.de">`) are never rewritten, so whichever attachment part they point at must survive distribution with the *same* Content-ID and an `inline` disposition, or the reference resolves to nothing in the recipient's mail client. `Email::attach()` cannot do this: it always builds a plain `DataPart` with `Content-Disposition: attachment` and no `Content-ID` at all, regardless of what the original attachment looked like — silently breaking every embedded image on every distributed mail (confirmed live: an incoming mail with one `cid:`-embedded image and one ordinary attached image produced identical `attachment`-disposition parts for both, and Thunderbird rendered a broken-image icon where the embed should have been). `Email::embed()` isn't a fix either — it calls `(new DataPart(...))->asInline()`, but has no parameter for pinning a *specific* pre-existing Content-ID; without one it lazily generates its own via `getContentId()`'s `generateContentId()` fallback, which would never match the id already baked into the copied HTML body.

The fix: for each `IncomingMailAttachment` where `$attachment->disposition === 'inline'` and `$attachment->contentId` is non-empty, build the part manually — `(new DataPart($attachment->getContents(), $attachment->name, $contentType))->asInline()->setContentId($attachment->contentId)`, added via `$email->addPart()` — preserving the exact original id (`IncomingMailAttachment::$contentId` is already bare, without angle brackets, matching both `DataPart::setContentId()`'s expected format and the bare `cid:...` reference already in the HTML). Every other attachment (no Content-ID, or `disposition === 'attachment'`) continues through the plain `$email->attach(...)` path unchanged.

**Non-conformant Content-IDs** — `DataPart::setContentId()` requires an "@" (RFC 2045-style msg-id syntax: `local-part@domain`) and throws `InvalidArgumentException` otherwise; the same requirement is enforced a second time, independently, wherever `getPreparedHeaders()` actually serializes the id (`Headers::setHeaderBody('Id', 'Content-ID', ...)` → `IdentificationHeader::setIds()` → `new Address($id)`, which runs the same "does it look like `local-part@domain`" validation) — so there is no way to bypass the first check (e.g. writing `$this->cid` directly) and still emit a genuinely non-conformant `Content-ID` header via symfony/mime's normal API. Confirmed live from a real sender (an Authentik-generated notification via Amazon SES): `Content-ID: <logo>` — no `@` at all — which, uncaught, crashed `MailProcessor::process()` entirely before any recipient was enqueued; `bin/worker.php`'s outer per-mail `catch` then logged the error and `continue`d, leaving the mail unseen and unarchived, so it was refetched and re-crashed on *every single worker cycle* indefinitely (see [Processing-failure retry limit](worker-and-queue.md#processing-failure-retry-limit-processingfailuretracker-processingfailurenotifier) below for why that no longer happens either way).

Falling back to a plain (non-inline) attachment for such a part would "fix" the crash but silently break the embed for every recipient, even though the original, non-conformant mail displayed it just fine in the sender's own client — not an acceptable trade-off. The actual fix: `buildOutgoingEmail()` first scans every inline attachment's Content-ID; any that doesn't contain `@` gets a synthesized replacement (`$cid . '@listig.invalid'` — the same `.invalid` (RFC 2606) placeholder-domain convention already used for `ReplyToBehavior::Nobody`'s `noreply@{domain}.invalid`, i.e. syntactically valid and deliberately never meant to be dereferenced) recorded in a `$cidRewrites` map. Every `cid:$oldId` occurrence in `$mail->textHtml` is then rewritten to `cid:$newId` **before** the body is set on the outgoing `Email` — the reference and the embed must always agree on the same id, or it resolves to nothing either way, so the body has to be fixed up first. The attachment loop then calls `setContentId($cidRewrites[$cid] ?? $cid)`, and only if *that* still throws (some other, still-unfixable malformation) does it fall back to the old safety net: `try`/`catch (\Throwable)`, plain `$email->attach(...)`, logged via `error_log()` — matching the same "malformed value from the sending MTA, skip and move on" philosophy as the header-preservation loop below, just as a last resort rather than the first response to a merely-missing `@`.

## Headers to set on outgoing mail

| Header | Value |
|---|---|
| `From` | `smtp-from-name <list-mail>` — `smtp-from-name` may contain mail-context variables |
| `Sender` | `{list->localPart}+bounce@{list->domain}` — local part of the list's own mail address, not `{list-cn}` (see [Envelope separation](worker-and-queue.md#envelope-separation)) |
| `Reply-To` | List address (`List`), original sender (`Sender`), both (`Both`), a translated "please do not reply" display name on `noreply@{list->domain}.invalid` (`Nobody`), or a signed `{list->localPart}+r-{TOKEN}@{list->domain}` address that hides the sender (`MaskedSender`/`MaskedBoth`) — see `ReplyToBehavior` and [Masked reply addresses](masked-replies.md#masked-reply-addresses) |
| `X-Original-Sender-Address` | The original sender's address — only when `sender-address-header` is `always`, or `external` and the sender is not a member (default `never`); see [Masked reply addresses](masked-replies.md#masked-reply-addresses) |
| `X-Original-Sender` | Sender's CN — only when the sender's own address is in Reply-To (`Sender`/`Both`; CN not email — privacy) |
| `List-Id` | `<{name}.{domain}>` — uses `name` (stable identifier, not `display-name` which may change) |
| `List-Post` | `<mailto:{mail}>`, or `NO` if both `post-access-members` and `post-access-public` are `deny` (owners-only — see [`post-access-members`/`post-access-public`](../reference/list-config-keys.md)) |
| `List-Help` | `<mailto:{owner-mail}>` — added whenever the list has at least one owner (not conditional on post-access) |
| `List-Unsubscribe` | `<https://{hostname}/{list-name}/unsubscribe?token={TOKEN}>` |
| `List-Unsubscribe-Post` | `List-Unsubscribe=One-Click` |
| `Precedence` | `list` |
| `X-Loop` | List mail address |
| `X-Original-To` | Original `To` header value |

`List-Id` uses `name` rather than `display-name` because it is a stable machine-readable identifier that should not change when the human-readable name is updated.

**No `X-Forwarded-From`.** An earlier version of `MailProcessor::setOutgoingHeaders()` unconditionally added `X-Forwarded-From: {sender's raw address}` to every distributed mail — a real privacy leak, inconsistent with `X-Original-Sender`'s own deliberate choice to expose only the sender's CN, never the address, and directly contradicting the very claim made below ("the sender's real address is never otherwise visible to recipients") one paragraph over in the same file. Confirmed live (before removal): every recipient of a distributed mail could read the original sender's exact address via "view all headers," regardless of the list's `reply-to`/`archive` settings or the sender's own privacy expectations. Removed outright rather than switched to a CN-based value — no known use case in this codebase needed it, so the smallest fix was to simply stop sending it.

**`reply-to: both` and list-member senders** — `MailProcessor::setOutgoingHeaders()` computes `$exposesSenderAddress` once, before building `Reply-To`, and reuses it for the `X-Original-Sender` decision below: `true` for `Sender` always, for `Both` only when `!$list->isMember($senderEmail)`, `false` for `List`/`Nobody`. The reasoning is a duplicate-delivery problem, not a privacy one (the sender's real address is never otherwise visible to recipients — the distributed mail's own `From` is always the *list's* address, per the `From` row above, so `Reply-To` is the only place it can leak at all, now that `X-Forwarded-From` is gone): list distribution already reaches every member, sender included, so if a member's own mail also carries their personal address in `Reply-To`, a mail client that sends a reply to *every* `Reply-To` address (e.g. "Reply All") delivers one copy straight to that address and a second copy via the list redistribution — the same reply, twice, in the same inbox. A non-member sender has no such second path (they're not on the list, so redistribution never reaches them), so for them `both` keeps behaving as its name says.

## Subject label

If `list-label` configured (and not empty string):
- `str_contains($subject, $label)` case-insensitive — skip if already present
- Otherwise: `$subject = "$listLabel $subject"` (label used as-is, no brackets added by Listig)

## Body/subject personalization (`BodyPersonalizer`)

All MIME manipulation uses symfony/mime on decoded content — never raw string replacement.

Subject: RFC 2047 decode → whitelist-gated substitution → RFC 2047 re-encode. The decode step is guarded by `str_contains($value, '=?')` — in practice the subject reaching here is *already* plain, decoded UTF-8 (php-imap decodes `$mail->subject` on parse, well before `MailProcessor::buildOutgoingEmail()`/`applySubjectLabel()` ever touch it), so this is normally a no-op; without the guard, calling `iconv_mime_decode()` on a plain string that merely contains literal non-ASCII bytes (no actual `=?...?=` encoded-word) silently **strips every umlaut** — confirmed live, `iconv_mime_decode()` treats its input as a raw MIME header (7-bit clean outside encoded-words) and `ICONV_MIME_DECODE_CONTINUE_ON_ERROR` drops whatever it can't map under that assumption instead of erroring. This is exactly why every distributed mail's subject lost its umlauts before the guard existed.
Body parts: rebuilt immutably via `new TextPart(…)` + `Email::setBody()`.

`BodyPersonalizer::personalize(Email $email, array $contexts, array $personalizeKeys): void`

**Top-level gate** (`personalizeKeys`): only `{key}` placeholders whose key is listed in `personalizeKeys` are substituted at the top level. Everything else is left literal.

**Recursive resolution**: when a whitelisted key resolves to a value that itself contains `{vars}` (e.g. `vorname: "{firstname}"`), those inner variables are resolved through the full safe context without restriction — they are NOT required to be in `personalizeKeys`.

**Sensitive key blocking**: `BodyPersonalizer` resolves under `ResolutionPurpose::Disclosed` — `VariableResolver::BLOCKED_KEYS` is therefore blocked (substituted with `VariableResolver::CLASSIFIED_PLACEHOLDER`, logged) even via recursive resolution, regardless of what `$contexts` actually contains (see [ResolutionPurpose](variables.md#resolutionpurpose)).

**`personalizeKeys`** (`ListConfig::$personalizeKeys`):
- Always includes `list-url`
- `personalize: off`, empty, or absent → only `list-url`
- `personalize: firstname, list-name` → `['list-url', 'firstname', 'list-name']`

**`FooterAppender`** has no `personalizeKeys` restriction — the footer is operator-authored content and may use all variables in the safe context.

## Footer (`FooterAppender`)

- If `footer` is `null` (not configured): skip
- If `footer` is `''` (explicitly empty): skip (allows overriding a default footer)
- Otherwise: always append — do not check for existing footer content
- Generate plaintext: `<a href="url">Label</a>` → `Label (url)`, block tags → newlines, rest via `strip_tags`
- Append HTML to HTML part, plaintext to text part
- Footer is appended after personalization; footer content may itself contain list-context variables (resolved at append time)

## Shared mail bodies (MIME deduplication)

`QueueWriter::enqueue()` stores a mail as **headers per recipient + one shared body** ([ADR-0023](../adr/0023-shared-mail-bodies-in-the-queue.md)). `Queue\QueueMime::split($email)` returns the message headers (`Email::getPreparedHeaders()`, which differ per recipient — the `List-Unsubscribe` token is one of them) and the body (`Email::getBody()->toString()`: the top-level part's own headers plus all the content); together they are exactly `Email::toString()`. The body goes into `mail_bodies` under `QueueMime::bodyKey()` — a SHA-256 over the body with the random multipart boundaries replaced by numbered placeholders, since every part picks new boundaries when serialized — and is stored once however many recipients get it. `mail_queue` keeps the recipient's `headers` and the `body_id`; `mail_queue.id` is `sha256(list_cn : headers : body_id)`, so recipients with identical headers still share a row. A body is only shared among recipients who get the same content: with `personalize` keys or recipient variables in the footer it is one per recipient. `QueueSender` assembles `headers . body` when sending; rows from before migration 008 carry their whole `mime` and are sent unchanged.

## Recipient filtering

Expand member list. Exclude addresses in original `To` or `Cc`. Normalize to lowercase.

---

## Sender notices (backscatter protection)

Listig only sees mail the upstream MTA has already accepted, so notices to the sender are backscatter whenever the From is forged ([ADR-0018](../adr/0018-sender-notices-only-to-authenticated-senders.md)). `SenderNoticePolicy::decide(ListConfig, IncomingMail, ?string $reasonKey)` is the single place that decides, for `RejectionNotifier::notify()` (all `reject.*` incl. `reject.moderation_declined`) and `ModerationMailer`'s `pending_notice` (`$reasonKey = null`). Order:

1. no From, or `sender-notices: never` → no notice
2. `reject.auth_failed` / `reject.spam` / `reject.unauthenticated` → never, even with `always`
3. `SenderAuthenticator::isAuthenticated()` (DMARC-aligned `dmarc=pass`, aligned DKIM pass, aligned SPF pass, or `auth=pass` — the sender logged in at the receiving server itself, which is all that server writes for mail submitted through it — with an aligned `smtp.mailfrom`; relaxed alignment via `OrganizationalDomain`, a table-based heuristic instead of the Public Suffix List) — `authenticated` (default) requires it, `always` does not
4. throttle: one notice per address per `sender-notice-interval` across all lists (`RateLimiter::isNoticeThrottled()`); only reached after the checks above, so suppressed notices cost nothing
5. send; the original is attached only if authenticated and the reason is not `reject.size_exceeded`; otherwise the notice names subject and date only

Each suppression is logged (`Listig: sender notice suppressed (<reason>) ...`, with the sender's domain only). Config keys: [per-list keys](../reference/list-config-keys.md). Moderation requests to owners are unaffected.

## Making clear which mail a reject/pending notice is about

(Applies to notices that pass `SenderNoticePolicy`; the attachment below is sent only to authenticated senders.)

`RejectionNotifier::notify(ListConfig $list, IncomingMail $mail, ?string $rawMime, string $reasonKey, array $reasonParams = [])`
takes the `IncomingMail` itself (not just the sender's bare address, as before) and the raw
MIME — `reject.notice.body` includes `%subject%`/`%date%` (same fields, same fallback for a
missing/unparseable `Date` header, as `ModerationMailer`'s own metadata — see [Moderation](moderation.md#moderation)),
and the raw MIME is attached as `message/rfc822` (`original.eml`, `8bit` transfer encoding —
per RFC 2046, `message/rfc822` only allows 7bit/8bit/binary, never quoted-printable/base64,
same fix already applied to `ModerationMailer`'s own attachment) so the sender can tell which
of their mails a notice actually refers to, the same way `ModerationMailer`'s request to owners
already could. Without this, a reject notice ("your mail was rejected: spam") gave no way to
identify *which* mail if a sender had sent several around the same time.

All three notification paths that tell a sender their mail didn't go through as expected now
carry this information:
- **Rejected** (`bin/worker.php`'s `isReject` branch, covers every `reject.*` reason —
  spam, auth failure, size, access denied, rate limit, moderation declined, ...) — passes the
  already-parsed `$mail` and `$rawMime` straight through, both already in scope.
- **Moderated** (`ModerationMailer::send()`'s `pending_notice`, see [Moderation](moderation.md#moderation)) — reuses the
  exact same `$mail`/`$rawMime`/`$mailDate` it already computed for the owners' own copy above
  it in the same method, no extra IMAP fetch needed.
- **Moderation declined** (`ModerationResponseHandler::processReject()` and
  `ModerationController::reject()`, both `reject.moderation_declined` via the same
  `RejectionNotifier`) — neither originally fetched the raw MIME (only the parsed
  `IncomingMail`, for the sender's address); both now also call `ImapPoller::fetchByUid()`
  for it, best-effort — a `null` result (mail gone from IMAP between the two fetches) still
  sends the notice, just without the attachment, rather than blocking it entirely.

---
