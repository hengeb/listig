# Security, keys and tokens

Key derivation, password encryption, token format, rate limiting and the full security notes.

## Key Derivation

`APP_SECRET` is the single root secret in `.env`, but it must never be used directly
as a cryptographic key in more than one place. Every consumer (`TokenService`'s HMAC
key, `PasswordCrypto`'s encryption key) gets its own independent
subkey via `Hengeb\Listig\Crypto\KeyDerivation::derive(string $appSecret, string $context): string`
(HKDF-SHA256, `hash_hkdf()`). `$context` is a fixed, purpose-specific string
(e.g. `'listig-token-hmac'`, `'listig-password-encryption'`) — changing it changes the
derived key, so each purpose is cryptographically isolated even though all subkeys
trace back to the same root secret.

This means a weakness discovered in one use (e.g. a padding oracle in password
decryption) cannot be leveraged against another (e.g. forging tokens), and either
subkey's derivation context could be rotated independently without touching the
other. Subkeys are derived once at bootstrap (`config/container.php`) and injected
into services — services never see `APP_SECRET` itself, only their derived subkey.

---

## Password Encryption

`Hengeb\Listig\Crypto\PasswordCrypto` encrypts/decrypts IMAP/SMTP passwords using
AES-256-CBC with the `'listig-password-encryption'` subkey (see Key Derivation above).
Wire format: `base64(iv):base64(ciphertext)` — matches the format already documented
under LDAP `description[]` keys and Security Notes.

- `encrypt(string $plaintext): string` — random IV per call, returns the wire format.
- `decrypt(string $encrypted): string` — throws `\InvalidArgumentException` on a
  malformed value or failed decryption.
- `decryptIfEncrypted(string $value): string` — the method `ImapMailboxFactory` and
  `SmtpConnectionFactory` actually call. Passwords reach `ListConfig` from two kinds
  of sources: LDAP `description[]` values, which are meant to always be encrypted;
  and config.yml values (`$VAR` substitution from `.env`, or a literal), which are
  already plaintext from a trusted source and were never encrypted. Since
  `ListConfig` merges both into the same flat key space with no record of
  provenance, `decryptIfEncrypted()` tells them apart by shape (valid
  `base64:base64` pair whose decoded first half is exactly 16 bytes — the AES-256-CBC
  IV length) and only decrypts values that match it; anything else passes through
  unchanged. A plaintext password coincidentally matching that shape is not
  realistically possible.

### `bin/encrypt-password.php`

CLI tool to produce values in this format for pasting into LDAP `description[]`
(`mail-password:<output>`) or `config.yml`:

```
bin/encrypt-password.php                 # interactive prompt, hidden input (stty -echo)
echo -n 'secret' | bin/encrypt-password.php --stdin
bin/encrypt-password.php --decrypt=<value>   # decrypt an existing value, for verification
```

The password is deliberately never accepted as a plain positional argument — that
would leak it into shell history and `ps` output. Uses the same `.env`-loading and
container-bootstrap pattern as `bin/worker.php`, so it always encrypts with the
same `APP_SECRET`-derived key the running application uses to decrypt.

---

## Token Format

`TokenService` does not hardcode a payload shape — `sign()` takes a purpose plus an
arbitrary, purpose-specific argument list of `string|int|null` values; `verify()` hands
the same list back for the caller to destructure. This keeps the token generic: adding a
new purpose, or new data to an existing one, never requires touching `TokenService`
itself.

`TokenService` is constructed with a subkey already derived via
`KeyDerivation::derive($appSecret, 'listig-token-hmac')` — see Key Derivation above —
not with `APP_SECRET` directly.

```php
// TokenService::sign(string $purpose, mixed ...$payload): string
$data  = encodePayload([$purpose, time(), ...$payload]); // compact binary, not JSON — see below
$hmac  = substr(hash_hmac('sha256', $data, $hmacKey, true), 0, 12); // 96-bit truncated, raw bytes
$token = rtrim(strtr(base64_encode($data . $hmac), '+/', '-_'), '='); // payload + signature, ONE base64 blob, no separator

// TokenService::verify(string $token, string $expectedPurpose, int $maxAge): array
// — returns the payload passed to sign(), in the same order. Throws on invalid
// signature, purpose mismatch, or if the token is older than $maxAge.
```

`$expectedPurpose` is not redundant with the payload: different purposes can (and do,
e.g. `login` and `unsubscribe`) share the same payload shape, so it is the only thing
preventing a token issued for one purpose (and its mail-header/link exposure) from being
replayed for another. `$maxAge` is likewise supplied by the caller, not baked into
`TokenService` — expiry is a policy decision for each call site, not the token itself.

### Compact encoding, truncated signature, no separator

Tokens embedded in an email local-part must fit RFC 5321's 64-byte limit; three uniformly applied changes (compact binary payload, truncated HMAC, no separator) achieve that — background in [ADR-0016](../adr/0016-compact-signed-tokens.md):

1. **Compact binary payload encoding, not JSON.** Each `string|int|null` value gets a 1-byte type tag (`TokenService::TYPE_STRING`/`TYPE_INT`/`TYPE_NULL`) followed — for `string`/`int` — by an unsigned LEB128 varint (`encodeVarint()`/`decodeVarint()` — 7 payload bits per byte, high bit = "more bytes follow") for either the string's byte length or the integer's own value; `null` needs no further bytes at all, just its own type tag. This keeps the same "no payload shape known in advance" property the JSON encoding had (`decodePayload()` reads a stream of tagged values with no schema), while costing far fewer bytes: no quoting/braces/commas, and — the larger win — an integer costs only as many bytes as its actual magnitude needs (e.g. 1-2 bytes for a small ID) instead of up to 10 ASCII digits for a Unix timestamp. `TYPE_NULL` specifically exists because `ListApiController::requestSubscribe()` signs `$body['firstname'] ?? null` (and `lastname`/`username` likewise) — a genuinely absent field, later distinguished from an explicit empty string by `attributesFromBody()`'s own `!== null` filter — which the JSON encoding round-tripped for free but the first version of this binary encoding didn't handle at all (confirmed live: it threw rather than silently mis-encoding, since `encodePayload()` rejects anything that isn't `string`/`int`/`null` outright).
2. **Truncated HMAC, not a full digest.** `TokenService::HMAC_BYTES = 12` (96 bits) — RFC 2104/NIST SP 800-107 both explicitly allow a truncated MAC as long as the remaining length still gives an adequate security margin against forgery; 96 bits is comfortably beyond any realistic brute-force capability even across a token's full multi-day validity window, especially given none of the token-verifying endpoints are individually rate-limited (only *requesting* a login link is).
3. **Payload and signature share one base64 blob, no `.` separator.** Since `HMAC_BYTES` is fixed, `verify()` doesn't need a delimiter to find the boundary — it base64-decodes the whole token once, then slices off the last `HMAC_BYTES` bytes as the signature and treats everything before that as the payload. This also means the two pieces round to base64's 3-byte encoding boundary *together* rather than each separately, which — combined with base64 packing 6 bits/character against hex's 4 (hex was the original encoding for the signature; base64 replaced it as part of this same change) — costs noticeably fewer characters than the two-part `payload.hmac` shape ever could.

Together, these took a typical `bounce`/`accept`/`reject` token from well over 100 characters down to roughly 30-35 (see the short purpose codes below for the remaining piece of that reduction), comfortably inside the local-part budget even with the `+bounce+`/`+accept-`/`+reject-` prefix.

### Short purpose codes

Every purpose is signed as a single-character string, not the readable full word — `'b'` not `'bounce'`, `'a'`/`'r'` not `'accept'`/`'reject'`, and so on for every purpose, including the ones with no local-part length constraint at all (query-parameter purposes benefit too, and consistency avoids a "which purposes are abbreviated" special case). `TokenService` needed no changes for this: `$purpose` is still just an arbitrary `string` as far as it's concerned, compared for equality — the short codes are purely a convention each call site's `sign()`/`verify()` pair agrees on, not a registry `TokenService` itself owns (preserving "adding a new purpose never requires touching `TokenService`").

| Full purpose | Code | Used by |
|---|---|---|
| login | `l` | `AuthController` — payload `listCn, userCn, next` (the validated page to return to, may be null) |
| unsubscribe | `u` | `MailProcessor`, `DashboardController`, `ListController` (sign) / `UnsubscribeController` (verify) |
| accept | `a` | `ModerationMailer` (sign) / `ModerationResponseHandler` (verify) |
| reject | `r` | `ModerationMailer` (sign) / `ModerationResponseHandler` (verify) |
| bounce | `b` | `QueueSender::sendOne()` (sign) / `BounceHandler::resolveVerifiedRecipient()` (verify) |
| subscribe | `s` | `ListApiController` |
| archive-attachment | `v` | `ArchiveController` |
| moderation-attachment | `m` | `ModerationController` |
| bounce-attachment | `n` | `BounceController` |
| reply | `p` | `ReplyTargetStore` — payload `ListFingerprint::of($listCn), $replyTargetId`, no max age (the `reply_targets` row is the boundary; unused `external` rows are purged after 180 days) |
| reply-thread | `t` | `ReplyThreadStore` — payload `ListFingerprint::of($listCn), $archivedMailId`, max age 180 days; address tag `+re-` ([ADR-0020](../adr/0020-reply-thread-tag.md)) |

`accept`/`reject` are the one case where the short code and the *visible* address tag genuinely differ: `ModerationMailer::send()` still builds `{list->localPart}+accept-{TOKEN}@...`/`+reject-{TOKEN}@...` (the full word, unabbreviated — an owner-facing `mailto:` address, not itself byte-constrained the way the token portion is) while signing the token itself with `'a'`/`'r'`. `ModerationResponseHandler::detectAction()` still extracts the full word from that address (`'/' . preg_quote($localPart, '/') . '\+(accept|reject)-(.+?)@/i'`, unchanged) since that's also what drives the accept-vs-reject dispatch and error-log messages elsewhere in `handle()` — only the value actually passed to `TokenService::verify()` needs to match what was signed, so `ModerationResponseHandler::TOKEN_PURPOSE_MAP` (`['accept' => 'a', 'reject' => 'r']`) translates just before that one call, nothing else in the method.

### `ListFingerprint` — bounding the list name's own contribution

Even with both changes above, `bounce`/`accept`/`reject` tokens had one more unbounded cost: `$listCn` itself, embedded raw as a string, has no length an operator is required to respect (a longer list name simply made the token longer, reopening the same 64-byte problem for any list with a long enough name — confirmed by direct calculation, not just for the specific list name that first surfaced the issue). `Hengeb\Listig\Token\ListFingerprint::of(string $listCn): int` (`crc32($listCn) & 0xFF`) replaces the raw string with a single byte for these three purposes specifically — every other purpose (`login`/`unsubscribe`/`subscribe`/the `*-attachment` purposes) is a URL query parameter with no such constraint, and still signs/returns the full, real list name, since those callers (e.g. `AuthController::verifyToken()` setting `$_SESSION['user']['listCn']`) genuinely need it back, not just a match/mismatch verdict.

This is safe specifically *because* the fingerprint is only ever used as the existing defense-in-depth "does this token actually belong to this list" sanity check (same principle as `UnsubscribeController`'s own `{listname}`-vs-token check) — never the token's actual security boundary, which remains the HMAC signature over the whole payload, fingerprint included. A forged fingerprint value is unreachable without first breaking the signature; an accidental collision between two differently-named lists (deliberately possible at only 256 distinct values — collisions are far more likely than with a full hash, by design) only ever weakens that secondary check for an operator with a large number of lists, not the actual security of any individual token, and a Listig instance anywhere near 256 lists is far outside this project's realistic scale.

### `accept`/`reject` — referencing `moderation_queue.id`, like `bounce` already referenced `queue_recipients.id`

The original `accept`/`reject` payload — `$listCn, $imapUid, $imapUidvalidity` — had a second problem beyond the raw list name: `$imapUidvalidity` is commonly itself a full Unix timestamp (many IMAP servers derive it from the mailbox's creation time), costing as much as the token's own timestamp field a second time over. Fixed the same way the `bounce` token already solved an analogous problem for `queue_recipients` (see [Automatic bounce actions](bounces.md#automatic-bounce-actions) → "1. Which recipient"): reference the `moderation_queue` row by its own `id` instead of embedding `imap_uid`/`imap_uidvalidity` directly.

This required reordering `ModerationMailer::send()`: the `INSERT INTO moderation_queue` now runs *before* the accept/reject tokens are signed (previously after), since the tokens need the row's own `id` to exist first. Getting that `id` back correctly on *both* the genuine-new-item and reminder-resend (duplicate-key) paths needed one more fix, confirmed empirically against MariaDB: the previous `ON DUPLICATE KEY UPDATE id = id` (a deliberate no-op, chosen specifically so `ROW_COUNT()` — and therefore `$isNewItem` — stays `0` on a resend) never touches `LAST_INSERT_ID()` at all on the duplicate-key path, so `PDO::lastInsertId()` would return stale or wrong data for a resend. `ON DUPLICATE KEY UPDATE id = LAST_INSERT_ID(id)` fixes this: confirmed live, `LAST_INSERT_ID(id)` evaluates to the *existing* row's own `id` — still a no-op on the column's actual value, so `ROW_COUNT()`/`$isNewItem` are completely unaffected — while also setting the session's `LAST_INSERT_ID()` to that same value as a side effect, so `lastInsertId()` now reliably returns the correct row id either way.

`ModerationResponseHandler::handle()` mirrors this on the verify side: decodes `[ListFingerprint::of($listCn), $itemId]`, checks the fingerprint, then `SELECT id, list_cn, imap_uid, imap_uidvalidity FROM moderation_queue WHERE id = :id` — a single lookup that both resolves the real `imap_uid`/`imap_uidvalidity` (no longer signed into the token at all) and doubles as the exact same idempotency check the old `(list_cn, imap_uid, imap_uidvalidity)`-keyed lookup already provided (a re-sent reminder or a double-click, after the row was already deleted by a prior accept/reject, correctly finds nothing and stops).

Each call site defines its own payload shape and max age, and destructures the same way on both ends — purposes named here by their full, readable word; see the short-code table above for what's actually signed into the token itself:

| Purpose | `sign()` payload | Max age | Used by |
|---|---|---|---|
| `login` | `$listCn, $userCn` | 5 minutes | `AuthController` |
| `unsubscribe` | `$listCn, $userCn` | 7 days | `MailProcessor` (sign) / `UnsubscribeController` (verify) |
| `accept` / `reject` | `ListFingerprint::of($listCn), $moderationQueueId` | 7 days | `ModerationMailer` (sign) / `ModerationResponseHandler` (verify) |
| `bounce` | `ListFingerprint::of($listCn), $recipientId` (`queue_recipients.id`) | 7 days | `QueueSender::sendOne()` (sign) / `BounceHandler::resolveVerifiedRecipient()` (verify) — see [Automatic bounce actions](bounces.md#automatic-bounce-actions) |

URL-safe Base64 (`+`→`-`, `/`→`_`, no padding) — the entire token (payload and truncated signature together, see above), safe in mail `+` addresses.

An `accept`/`reject`/`bounce` token rides in an email address's local-part (`{list->localPart}+accept-{TOKEN}@{list->domain}`, `{list->localPart}+bounce+{TOKEN}@{list->domain}`, see Moderation / [Automatic bounce actions](bounces.md#automatic-bounce-actions)) — `PhpImap\Mailbox` parses every recipient address through `mb_strtolower()` before the app ever sees it (`possiblyGetEmailAndNameFromRecipient()`), which would corrupt a mixed-case base64 token if the token were read from `$mail->to`/`$mail->cc`. Rather than change the token encoding (base64 is kept, unchanged, for all purposes), `ModerationResponseHandler::detectAction()`/`BounceHandler::extractBounceToken()` both read the address straight out of the raw, unparsed header instead (`HeaderFilter::readHeader($mail->headersRaw, 'To')` and, for a bounce, also `Delivered-To`/`X-Original-To` as fallbacks) — case exactly as the sending mail client/server wrote it — and regex-match against that string directly, never touching the lowercased `$mail->to`/`$mail->cc` arrays for this purpose. Confirmed live: a real reply's `$mail->to` key showed an all-lowercase token where the raw header still had the original mixed case, and `TokenService::verify()` only succeeds against the latter.

Tokens are stateless and self-describing: the HMAC signature is the only thing that
needs verifying, so `TokenService::verify()` never touches the database. Purposes that
need to identify a specific database row (`accept`/`reject` → a `moderation_queue`
item, `bounce` → a `queue_recipients` item) embed that row's own primary key in the
payload instead of persisting the token somewhere to look up later — this is why
`moderation_queue` has no `token` column. Resolving the payload's own natural key back
to a real row (`ModerationResponseHandler`'s `SELECT ... WHERE id = :id`,
`BounceHandler`'s `QueueSender::findRecipientById()`) still needs exactly one DB lookup
either way, the same one both purposes already needed for their own idempotency check —
this property is about `TokenService::verify()` itself never touching the database to
authenticate the token, not about the caller never needing the database at all to act
on it.

---

## Rate Limiting

**Mailing:** `(list_cn, sender)` in last 10 min, limit = `max-per-sender` (default 5).

**Login:**
- Per-address: `list_cn='__login__'`, `sender=$email`, max 5/hour
- Global: `list_cn='__login__'`, `sender='__global__'`, max 20/hour
- Always show same response regardless of result — prevents enumeration

**Sender notices:** `list_cn='__notice__'`, `sender=<lowercased From>` — one per `sender-notice-interval` (default 1 hour, max 1 day), see [Sender notices](mail-processing.md#sender-notices-backscatter-protection).

Rows older than 1 day deleted each worker cycle (every user filters by its own window).

**Compose form:** `POST /_/api/compose/{listname}` records `list_cn=<list>`, `sender='__compose__:<user>'` via `RateLimiter::isExceeded()` — max 20 per 10 minutes per user and list (`ComposeController`), since each call may create a `reply_targets` row.

**API token brute force:** `ApiTokenMiddleware` records each invalid Bearer-token
attempt via `RateLimiter::isExceeded($listName, '__api-token__', 20)` (same 10-minute
window) — past 20 failed attempts for a list within 10 minutes, further requests get
`429` instead of `401`. Every invalid attempt is also logged via `error_log()`.

---

## Sender authentication

Which `Authentication-Results` header is believed is decided by `HeaderFilter::parseAuthResults()` ([ADR-0018](../adr/0018-sender-notices-only-to-authenticated-senders.md), [ADR-0019](../adr/0019-optional-trusted-authserv-id.md)):

- **Default (no `trusted-authserv-id`): the topmost header.** The own MTA prepends its header to every mail it accepts, so the topmost one is its verdict while a header forged by the sender can only sit below it. This is a requirement on the operator: the MTA (opendkim, rspamd, ...) must add `Authentication-Results` to **every** mail, including locally submitted ones. If it ever does not, a sender-supplied header becomes the topmost one and is believed. Not guaranteed for a mailbox at a third-party provider — set the key there.
- **`trusted-authserv-id` set:** only headers with that authserv-id are believed, at any position; no match means unauthenticated. The MTA should still remove incoming headers carrying its own id (RFC 8601 §5), otherwise a sender can copy the id.

A mail without a (matching) header counts as unauthenticated: no sender notice in the default mode, no SPF/DKIM reject, no DKIM-authenticated bounce action. The worker logs a warning for it, at most once per hour and list, only to the log (it is a server problem, not the list owners'); with the key set it names the authserv-ids actually found. Lists without the key get a one-time `info` hint at worker start.

---

## Security Notes

- IMAP passwords: AES-256-CBC, `base64(iv):base64(ciphertext)` in LDAP, using a subkey derived from `APP_SECRET` (see Key Derivation) — never `APP_SECRET` itself
- `APP_SECRET`: root secret in `.env` only; never used directly as a cryptographic key — see Key Derivation for how per-purpose subkeys (encryption, HMAC) are derived from it
- `config.yml`: contains LDAP bind password; must be mounted as volume, never baked into image
- Native PHP sessions; session ID = CSRF token (sent as `X-CSRF-Token`)
- Login always returns same response (prevents enumeration)
- Unsubscribe errors do not reveal address existence
- Moderation: HMAC + owner identity both required
- Sensitive config keys (passwords, hostnames) blocked at `{}` resolution time via `ResolutionPurpose::Disclosed` (`VariableResolver::BLOCKED_KEYS`) — never reachable from mail body, footer, or UI, regardless of what a given `$contexts` array actually contains (see [ResolutionPurpose](variables.md#resolutionpurpose))
- `bounce_log` retains sender addresses 90 days — document in privacy/data-retention policy
- Never log MIME content, passwords, or tokens
- `display_errors` must stay `Off` in production (`docker/php.ini`) — the base image's default (`display_errors = STDOUT`) echoes even a vendor-library warning (e.g. `PhpImap\Mailbox` on a transient IMAP outage) directly into the HTTP response body. Beyond the obvious information disclosure (internal file paths, stack traces), this silently breaks intended non-200 status codes: once that warning has been echoed, output has already started, so a controller's later `withStatus(404)` can no longer take effect (`header()` is a no-op after output begins) — the response reaches the client as a broken `200` with error text as its body. Applies to the whole app, not just the archive viewer.
- **Slim's own `$displayErrorDetails` is a separate flag from `display_errors`, and must independently stay `false` in production.** `public/index.php`'s `$app->addErrorMiddleware($displayErrorDetails, $logErrors, $logErrorDetails)` controls whether Slim's *own* exception handler puts the caught exception's type/message/file/line/stack trace into the HTTP *response body* — entirely independent of php.ini, since Slim catches the exception itself before it would ever become a raw PHP error. Confirmed live as a real leak: an automated `GET /.git/HEAD` scan happened to path-match the `{listname}/{mail}` route (registered `PUT`/`DELETE` only, see [Routes](../reference/routes.md#routes) — any two-segment path scanners commonly probe, `/wp-admin/x`, `/.env/y`, etc., matches the same way), producing a `405` whose response body — sent to that anonymous, unauthenticated request — included `/app/vendor/slim/slim/Slim/Middleware/RoutingMiddleware.php` and a full call stack. Fixed by passing `false` for `$displayErrorDetails` while leaving `$logErrors`/`$logErrorDetails` `true` — the exact same "log everything server-side, show the client nothing" split `display_errors=Off`/`log_errors=On` already establishes for PHP-level errors, just Slim's own independent equivalent of it. Confirmed live after the fix: the same request now returns a generic `405 Method Not Allowed` page with no file paths or trace, while `docker logs` still shows the full detail.
- Archive viewer (see [Archive viewer](archive.md#archive-viewer) for the full design): sanitized via `ezyang/htmlpurifier` with a fixed small allowlist, rendered in a scriptless sandboxed `<iframe>` with its own CSP, external images opt-in only, attachments never trusted on their own MIME/disposition claim (magic-byte check before any inline delivery), and no email addresses displayed in the viewer's own UI (metadata only — see [Privacy](archive.md#archive-viewer) there for the body-text scope boundary). `Hidden`/`Off` are indistinguishable 404s, even to the list's own owner.
- **Untrusted input in `{}` templates**: `VariableResolver::resolve()` only recursively re-resolves a value that is a *plain string taken directly from a context array* — i.e. genuinely operator-authored config, like a `vorname: "{firstname}"` alias or `list-mail: "{list-name}@..."`. Two other kinds of value are always treated as terminal, even if they contain `{`, and are never re-parsed as a template:
  - **Callables** — `MailProcessor`'s `sender-name` derives its result from the incoming mail's raw `From:` header, which an external sender controls.
  - **`Literal`-wrapped values** (`Hengeb\Listig\Variable\Literal`) — every value `MailProcessor::buildMailContext()`/`buildRecipientContext()` puts into the sender/recipient context (`Member::$attributes`, `subaddress`, `mail`) is wrapped this way, because it ultimately comes from a directory/database/CSV row or a self-service subscribe request, not list config.

  Both exclusions are necessary and independent: (1) a crafted `From: "{sender-someAttribute}" <x@y>` sent to a list using the documented `smtp-from-name: "{sender-name} (via {display-name})"` example would, without the callable exclusion, get `sender-name`'s raw extracted text re-parsed as a template — leaking whatever `someAttribute` happens to be on the *sender's own* `Member::$attributes`, broadcast to every recipient via the outgoing From header, with **no `personalize:` misconfiguration required**. (2) Separately, a member whose own `firstname` (or any other attribute, however sourced — e.g. self-set via the public subscribe API) is literally the string `"{someOtherAttribute}"` would, without the `Literal` exclusion, have that attribute's value substituted into their personalized mail even when `someOtherAttribute` was **never itself included in `personalize:`** — the whitelist only gates the *top-level* placeholder actually written in the mail, not what a resolved value's own nested `{}` syntax would otherwise trigger during recursive resolution. Any future context-building code that puts sender/recipient/incoming-mail-derived data into a context array must wrap it in `Literal` for this reason — a plain string is fair game for the next `{...}` it contains, so it must always be config, never message/member data.

  This is a related but distinct protection from `ResolutionPurpose` (next bullet): `Literal`/callable exclusion stops *recursion into message/member data* regardless of who wrote the referencing template; `ResolutionPurpose` stops *reaching a specific credential key* regardless of who authored the referencing template (operator config included).
- **`personalize:` is a genuine trust boundary, not just a formatting preference**: since `Member::$attributes` is fully dynamic (see [Member attributes — fully dynamic](providers-and-members.md#member-attributes--fully-dynamic)), whitelisting a key there exposes whatever that resolver's backing store happens to have under that name to every sender who can address the list — including a member writing `{key}` in their own mail's subject/body, which `BodyPersonalizer` will substitute per-recipient. Only whitelist keys that are safe for members to see about *themselves* (firstname, pronoun, ...); never add anything sourced from a column/attribute that isn't meant to be mail-visible. This is still worth getting right even with the `Literal` protection above, since `Literal` only stops a whitelisted key's *value* from being abused to reach a second, non-whitelisted key — the whitelisted key's own value is always shown as-is.
- **`ResolutionPurpose::Disclosed` blocks `VariableResolver::BLOCKED_KEYS` at resolution time, not by pre-filtering the context** (see [ResolutionPurpose](variables.md#resolutionpurpose) above) — this protects every `Disclosed` resolution uniformly, regardless of which code path triggered it. Concretely: `ListConfig::$displayName` is read directly in many places outside the mail-sending pipeline (UI templates, notification mail subjects, the `smtp-from-name` fallback); a list configured with `display-name: "{imap-password}"` must not leak that value just because some *other* code path reads `$list->displayName` directly, whether directly or via another template's recursive resolution. More significantly, `list-mail` (see [`list-mail`](config.md#list-mail) above) is resolved *before* a `ListConfig` even exists — `InlineListProvider`/`YamlListProvider`/`SubaddressListProvider` resolve it against the raw, just-merged provider config, with no `ListConfig` instance to consult. Since the blocking lives in `VariableResolver` itself, `list-mail: "{mail-password}"` is blocked there too, independent of whether any `ListConfig` exists yet.

---
