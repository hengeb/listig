# List Management API

Bearer-token HTTP API for provisioning.

## List Management API

Bearer-token HTTP API for provisioning: subscribe/unsubscribe members and encrypt a
password for a list, without touching LDAP/the DB directly. Intended for a future
"create/configure mailing lists" admin UI and for trusted external integrations
(e.g. a signup form on another website).

### Authentication

Each list carries its own token in the `api-token` config key (same merge chain as
any other list key — LDAP `description[]`, DB `list_config`, inline config).
**Stored as plaintext, not hashed.** This is a deliberate choice: unlike a login
password, the client must already know this value to present it as a Bearer token,
and the intent is that a client can read the same LDAP/DB configuration Listig itself
reads, without maintaining a separate secret store. The server still compares with
`hash_equals()` for timing safety. A list with no `api-token` set has this entire API
disabled (`404`, as if the routes didn't exist).

`ApiTokenMiddleware` resolves the list from the `{listname}` route argument, checks
the `Authorization: Bearer <token>` header, and — on success — attaches the resolved
`ListConfig` as the `list` request attribute so controllers don't re-fetch it.

### Routes (`ListApiController`)

| Method | Path | Auth |
|---|---|---|
| `PUT` | `/{listname}/{mail}` | Bearer, via `ApiTokenMiddleware` |
| `DELETE` | `/{listname}/{mail}` | Bearer, via `ApiTokenMiddleware` |
| `POST` | `/{listname}/subscribe` | Bearer **or** `public-subscribe: on` (own check, not `ApiTokenMiddleware`) |
| `GET` | `/{listname}/subscribe/confirm` | token in link (query param) |
| `POST` | `/{listname}/encrypt-password` | Bearer, via `ApiTokenMiddleware` |

`PUT`/`DELETE` bypass double opt-in entirely (immediate `addMember()`/`removeMember()`)
— appropriate for a caller that has already verified the address itself out of band.
Both are idempotent: re-subscribing an existing member or unsubscribing a non-member
returns `204` either way, matching the existing unsubscribe philosophy of never
erroring on a state that's already reached. `DELETE` returns `409` instead if the
list's member store can't persist a removal at all (`MemberResolver::supportsRemoval()`
false — static inline config.yml members, or none configured) — same
`\RuntimeException`-to-`409` handling as `PUT`'s `addMember()` failures, see
"MemberResolver interface".

### Double opt-in (`POST .../subscribe` → `GET .../subscribe/confirm`)

`requestSubscribe()` is deliberately **not** behind `ApiTokenMiddleware`, because it
must accept two different kinds of caller with different auth:
- a valid `Authorization: Bearer` header — always allowed, any list;
- no `Authorization` header at all — allowed only if the list has `public-subscribe: on`
  (e.g. a plain HTML `<form method="post" action="https://…/x/subscribe">` hosted
  on another website — works with no CORS configuration needed, since it's a normal
  form submission, not a cross-origin fetch/XHR).

An `Authorization` header that IS present but wrong is rejected with `401` outright —
it never silently falls back to the public path, so a caller with a broken token
finds out rather than unknowingly using the weaker, public-gated flow.

On success it sends a confirmation mail (`TokenService` purpose `subscribe`, payload
`$listCn, $mail, $firstname, $lastname, $username`, 48h max age — the payload carries
everything needed to call `addMember()` on confirm, since there is no other pending-
subscription storage). Request bodies (`PUT`, `POST .../subscribe`) accept `firstname`/
`lastname`/`username` — `ListApiController`'s own small, fixed allowlist (`attributesFromBody()`),
mapped into `Member::$attributes` under those same names, matching inline config.yml
members and the `{firstname}`/`{lastname}` mail variables. Deliberately not "pass the
whole request body through as attributes": those keys can end up interpolated as SQL
column names by `DatabaseMemberResolver::addMember()` (safely validated there, but an
unrecognized column still throws), so accepting arbitrary external input would let a
caller trivially trigger errors with a bogus body key. Rate-limited via the existing `RateLimiter::isExceeded()`
(list+mail, 10-minute window) and always returns the same `202` regardless of outcome,
so failures/rate-limiting aren't observable to the caller.

`confirmSubscribe()` is public (the signed token is the only credential), verifies
purpose `subscribe`, and calls `addMember()`. Renders `templates/subscribe-confirm.latte`
(mirrors `unsubscribe.latte`).

### `addMember()` (`MemberResolver`, `ListConfig`)

New interface method alongside `removeMember()`. `LdapMemberResolver` requires an
existing directory entry matching the email (adds its DN to `member`) — **LDAP-backed
lists can only subscribe emails that already have a directory entry**; there is no DN
to add otherwise, and creating directory users is out of scope. `DatabaseMemberResolver`
upserts a row (`is_member = 1`, preserves existing `is_owner`). `InlineMemberResolver`,
`NullMemberResolver`, and `AggregateMemberResolver` throw `\RuntimeException` — static
config and the lookup-only aggregate resolver have no writable store. Callers must
surface this as a clear error (`409`), not swallow it.

### Password verification (`POST .../encrypt-password`)

Before encrypting and persisting a submitted password, `ListApiController::encryptPassword()` verifies it actually logs in via `ImapMailboxFactory::verifyPassword($list, $password)` — a one-off `PhpImap\Mailbox` built from the list's *current* `imap-host`/`imap-user` (unaffected by the password being submitted) plus the *candidate plaintext* password, bypassing both the shared connection cache and `$list->imapPassword` entirely. A typo would otherwise only surface later, as a silent IMAP failure on the next poll cycle (see [Optional IMAP config](#optional-imap-config-listconfigisimapconfigured) below), rather than an immediate, actionable error to whoever is provisioning the list. `verifyPassword()` just calls `getImapStream()` and lets a login/connection failure propagate as `PhpImap\Exceptions\ConnectionException`; the controller catches `\Throwable` broadly and responds `422` without ever calling `PasswordCrypto::encrypt()`/`setListConfigValue()` — the bad password is never persisted.

Verification only runs when `$list->imapHost !== ''` — a list still mid-setup with no host configured at all (e.g. `api-token` set but nothing else yet, see [Optional IMAP config](#optional-imap-config-listconfigisimapconfigured)) has nothing to connect to, so the password is stored unverified in that case, exactly as before this existed.

`verifyPassword()` deliberately never calls `$mailbox->disconnect()` itself (the destructor does; a second call throws) — see [ext-imap](../library-notes.md#ext-imap-disconnect-twice-throws).

### `setListConfigValue()` (`ListProvider`)

New interface method used by `encryptPassword()` to persist the encrypted password
(`PasswordCrypto::encrypt()`, see Password Encryption) as the list's `mail-password`
key. `LdapListProvider` replaces the matching `description[]` entry in place (LDAP's
`description` attribute is multi-valued and holds unrelated keys side by side, so only
the entries with a matching `key:` prefix are removed before adding the new one).
`DatabaseListProvider` upserts into `config-table`. `InlineListProvider`/`YamlListProvider`
throw — config.yml/the YAML file are not rewritten at runtime. Each provider
invalidates its list cache after a write so a subsequent read in the same request
sees the new value.

### Optional IMAP config (`ListConfig::$isImapConfigured`)

A list may exist with no `imap-host`/password yet — e.g. mid-setup via this API,
token configured but password not yet encrypted/set. `ImapPoller::poll()` and
`ImapArchiver::deleteOldMails()` return early (no error, no log spam) when
`!$list->isImapConfigured`. SMTP sending is unaffected by this flag — a list with no
queued mail simply has nothing to send.

---
