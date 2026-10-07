# Library notes

Pitfalls of the libraries in use.

## HTML escaping — never use `|escapeHtml`

Latte's `Engine` auto-escapes every `{...}` output expression for its surrounding context (HTML text, an attribute value, `<script>`, ...) by default — no explicit filter is ever needed for correctness, in any context, and none of these templates disable that behavior. `|escapeHtml` (`Latte\Essential\CoreExtension`, backed by `HtmlHelpers::escapeText()`) exists as a built-in filter, but it returns a **plain string**, not a value Latte's compiler recognizes as already-safe — so a value piped through it explicitly gets escaped twice: once by the filter, once again by the engine's own auto-escaping of the print expression. The result is corrupted double-encoded output (`&amp;lt;` instead of `&lt;`, rendering as the literal text `&lt;` in the browser instead of `<`) for any value containing `<`, `>`, `&`, `"`, or `'` — invisible for plain alphanumeric content, which is why ~43 pre-existing `{$value|escapeHtml}` call sites across every `.latte` template went unnoticed until the moderation queue table (see [Moderation via UI](architecture/moderation.md#moderation-via-ui)) started rendering real mail subjects/sender names, which routinely contain `&`.

Fixed by removing `|escapeHtml` everywhere (confirmed via `Latte\Engine::compile()` on all 9 template files, plus targeted `renderToString()` tests with `<`/`>`/`&`-containing values in both text and attribute (`href="..."`) context) — write `{$value}`, not `{$value|escapeHtml}`. If a future template genuinely needs to bypass auto-escaping (rare — inserting pre-sanitized HTML, e.g. the archive viewer's sanitized mail body), that's `|noescape`, the opposite direction, not `|escapeHtml`.

## Latte: `onclick` attributes are a JS-string context

**`onclick` attributes are a JS-string context, not a plain HTML-attribute context** — a
non-obvious Latte behavior that bit the row's `onclick` during development: `{...}` printing
a *plain string* value (not an int) inside an `onclick="..."` attribute gets wrapped in Latte's
own JS-string quoting, on top of whatever quoting the template author already wrote — so
`onclick="location.href='/{$list->name}/...'"` (manual single quotes around the interpolated
`{$list->name}`) rendered as `location.href='/&quot;testliste&quot;/...'`, a second, nested
quoting Latte added because it couldn't tell the manually-quoted JS string apart from a bare
value it needed to quote itself. Confirmed live via `Latte\Engine::renderToString()`: an `int`
value (`{$item['id']}`, as `moderation_queue.id` actually comes back as via `mysqlnd`'s type
handling *despite* the app's `PDO::ATTR_EMULATE_PREPARES` staying at its default `true` — see
[DatabaseConnectionFactory](architecture/providers-and-members.md#databaseconnectionfactory)) rendered correctly bare (`.../moderation/7`), but a `string` value
interpolated the same way did not — and a `{...}` expression is silently left completely
unprocessed, verbatim in the output, if its very first character is a quote (`{'/' . ...}`
never evaluated at all; `{$name . '/' . ...}`, starting with a variable instead, did). The fix,
`onclick="location.href={sprintf('/%s/moderation/%s', $list->name, $item['id'])}"` — the
*entire* attribute value is one `{...}` print expression (no manual quotes at all, and it
doesn't start with a literal), letting Latte supply the one correct layer of JS-string quoting
itself. The pre-existing `onclick="apiPost('/_/api/moderation/{$item['id']}/accept')"` pattern
(Accept/Reject buttons) was never affected by this, precisely because `$item['id']` is an `int`
here, not a `string` — the same pattern with a string interpolated inside manual quotes would
have the identical bug.

## Latte: translated strings inside `<script>` blocks

Inside `<script>` blocks, Latte forbids `{...}` print statements *inside* JS string quotes
(`scriptTagQuotesPass` compile error) — write `alert({$translator->trans('key')})`, not
`alert('{$translator->trans('key')}')`; Latte outputs the JS string literal itself,
correctly escaped for the script context.

## Library API Notes

### php-imap/php-imap (`PhpImap\Mailbox`)

- Default `$imapSearchOption` is `SE_UID`, so `searchMailbox()` returns UIDs (not sequence numbers) and all other methods that take a `$mailId` expect UIDs.
- **UIDVALIDITY**: use `$mailbox->statusMailbox()->uidvalidity` — **not** `getMailboxInfo()`, which returns `imap_mailboxmsginfo()` (no `uidvalidity` property).
- `getRawMail($uid, false)`/`getMail($uid, false)` — pass `false` for the `$markAsSeen` parameter everywhere a mail is *read* without having been fully processed yet (`ImapPoller::poll()`/`fetchByUid()`/`fetchMailByUid()`), so an in-progress or about-to-be-retried mail doesn't look "seen" to an operator's own mail client before Listig has actually finished with it. The dedupe mechanism that decides whether to reprocess a mail next cycle is always the `imap_seen` DB table (`ImapPoller::markSeen()`), never the IMAP `\Seen` flag — but `markSeen()` *also* sets the IMAP `\Seen` flag itself (`Mailbox::markMailAsRead()`), best-effort or only for an operator glancing at the mailbox through a normal mail client; a failure to set it (logged, not thrown) never affects the DB row.
- `getMail($uid, false)` — returns a parsed `PhpImap\IncomingMail` object. Key properties:
  - `$mail->fromAddress`, `$mail->fromName` — sender info
  - `$mail->subject`, `$mail->to`, `$mail->cc` — standard headers
  - `$mail->autoSubmitted` — `Auto-Submitted` header value (for bounce detection)
  - `$mail->headersRaw` — complete raw header block as a string
  - `$mail->textPlain`, `$mail->textHtml` — lazy-loaded decoded body content
  - `$mail->getAttachments()` — returns `IncomingMailAttachment[]`
- **`Email::fromString()` does not exist** in symfony/mime — incoming mails are parsed via `getMail()` and the outgoing `Email` is built from scratch by `MailProcessor`.
- `moveMail()` calls `expungeDeletedMails()` internally; no need to call it again afterwards.
- `deleteMail()` only marks for deletion; a separate `expungeDeletedMails()` call is required to actually remove the message.

### symfony/mime (`TextPart`)

- `TextPart` has no public `getCharset()` method. The charset is a private field exposed only via the prepared `Content-Type` header:
  ```php
  $ct = $part->getPreparedHeaders()->get('Content-Type');
  $charset = $ct instanceof ParameterizedHeader ? ($ct->getParameter('charset') ?: 'utf-8') : 'utf-8';
  ```
- `TextPart::getBody()` always returns `string` (reads resource/File if needed).
- `DataPart` extends `TextPart` — always guard `instanceof TextPart` checks with `&& !($part instanceof DataPart)` to avoid personalizing binary attachments.
- `AlternativePart` and `MixedPart` constructors accept `AbstractPart ...$parts` — rebuild with `new AlternativePart(...$newParts)`.
- `Message::setBody(?AbstractPart $body): static` — use to replace the entire body tree after an immutable rebuild.
- `Headers::addTextHeader($name, $value)` always creates an `UnstructuredHeader`, but `Headers::HEADER_CLASS_MAP` enforces a specific value class for some names and throws `LogicException` otherwise — `Message-ID` needs `addIdHeader()`, `Date`/`From`/`To`/`Cc`/`Bcc`/`Sender`/`Reply-To`/`Return-Path` each need their own dedicated `add*Header()` method too. `In-Reply-To`/`References` are the one deliberate exception (`UnstructuredHeader` *or* `IdentificationHeader` both allowed) — see [Header filter](architecture/mail-processing.md#header-filter) for where this actually bit `MailProcessor`.
- `Email::attach()` always produces `Content-Disposition: attachment` with no `Content-ID`; `Email::embed()` produces `inline` but auto-generates its own Content-ID rather than accepting a specific pre-existing one. To preserve an incoming attachment's *exact* original Content-ID (required for `cid:` references copied verbatim into a forwarded/distributed body to keep resolving), build the `DataPart` manually: `(new DataPart(...))->asInline()->setContentId($id)`, then `$email->addPart($part)` — see [Attachments — preserving embedded (`cid:`) images](architecture/mail-processing.md#attachments--preserving-embedded-cid-images) for where this actually bit `MailProcessor`.

## php-imap: recipient addresses are lowercased

`PhpImap\Mailbox` runs every parsed recipient address through `mb_strtolower()` before `IncomingMail::$to`/`$cc` are populated, which corrupts a case-sensitive base64 token embedded in an address local-part. Read such tokens from the raw header (`HeaderFilter::readHeader($mail->headersRaw, 'To')`, plus `Delivered-To`/`X-Original-To` where relevant) — used by accept/reject, bounce and reply tokens; see [Token format](architecture/security-and-tokens.md#token-format).

## php-imap: absent headers are `''`, not `null`

`Mailbox::getMailHeaderFieldValue()` (which populates e.g. `IncomingMail::$autoSubmitted`) always returns a string, using `''` for "header absent", despite the `@var string|null` docblock. Test `!== null && !== ''`; see [IncomingMailFilter — check order](architecture/mail-processing.md#incomingmailfilter--check-order).

## ext-imap: `disconnect()` twice throws

`verifyPassword()` deliberately never calls `$mailbox->disconnect()` itself — `PhpImap\Mailbox::__destruct()` already does that once the local variable goes out of scope, matching the only other place in this codebase that manages a `Mailbox` lifecycle (`ImapMailboxFactory::reset()`, which just drops cached instances and lets garbage collection trigger the destructor). Confirmed live: calling `disconnect()` explicitly *and* letting the destructor call it again moments later throws `ValueError: IMAP\Connection is already closed` from the second call — a real quirk of `ext-imap`'s PHP 8.1+ object-based connection handle (throws on re-use where the old resource-based API just returned `false`), not something to work around with a guard; simply not calling it twice avoids it entirely.

## jumbojett/openid-connect-php: the session is already closed when the redirect URL is returned

Setting `$_SESSION['oidc_next']` on the initial leg needs an explicit `session_start()`/`session_write_close()` around it, not a bare `$_SESSION[...] = ...`: `jumbojett/openid-connect-php`'s own `requestAuthorization()` calls its `commitSession()` (→ `session_write_close()`) right before redirecting to the IdP, to release the session lock before the browser leaves for what could be a slow round trip — by the time `OpenIdConnectService::authenticate()` returns the redirect URL to `loginOidc()`, the session is already closed. A plain `$_SESSION` write past that point only touches the in-memory superglobal and is silently lost — confirmed live (a deployment with Authelia configured): the session file on disk had `openid_connect_nonce`/`_state`/`_code_verifier` from the library's own commit, but no `oidc_next`, and the callback leg read back nothing. Re-opening (`session_start()`), writing, and closing again (`session_write_close()`) fixes it — the reopen reads the same file the library just wrote, so its keys survive alongside the new one.

## PHPUnit 12: tests that trigger `error_log()` must call `expectErrorLog()`

**A test that deliberately exercises an `error_log()` call must declare `$this->expectErrorLog();`.** PHPUnit 12's `TestCase` redirects the `error_log` ini setting to a private per-test capture file before every test and, in teardown, either asserts that capture is non-empty (if `expectErrorLog()` was called) or — if it wasn't, and something was captured anyway — prints the raw captured text straight to the console, interleaved with the progress dots. A project-wide `<ini name="error_log" value="/dev/null"/>` in `phpunit.xml` does **not** fix this: PHPUnit's own per-test redirect overrides it regardless (confirmed live — `ini_get('error_log')` inside a test returns PHPUnit's own temp path, never the configured one), so the only correct fix is calling `expectErrorLog()` in each test that intentionally triggers logging (`VariableResolverTest`'s not-found/cycle/blocked-key cases, `VariableFilterTest`'s unknown-filter case, ...) — never a leading `@` on the call under test, which suppresses PHP errors/warnings but has no effect on `error_log()` itself. A test whose whole point is proving something *stays silent* (e.g. `quiet: true`) should deliberately omit the call instead — if suppression ever broke, PHPUnit's own unexpected-output print would surface it.
