# Per-list configuration keys

Keys settable per list (shown as LDAP `description[]` entries; identical in database, inline and YAML providers).

## LDAP description[] keys

Each `description` value is a `key:value` string. These have the highest priority (level 5). The key is everything before the first `:` on the first line; the value may span several lines (e.g. an HTML `footer`). A `description` value without a `key:` prefix is ignored.

| Key | Values | Description |
|---|---|---|
| `password` | encrypted string | IMAP password, AES-256-CBC with an `APP_SECRET`-derived subkey (see Key Derivation) (legacy; prefer `mail-password`) |
| `mail-user` | string | Sets both `imap-user` and `smtp-user` unless those are set individually |
| `mail-password` | encrypted string | Sets both `imap-password` and `smtp-password` unless those are set individually — AES-256-CBC with an `APP_SECRET`-derived subkey (see Key Derivation) |
| `mail-host` | hostname | Sets both `imap-host` and `smtp-host` unless those are set individually |
| `imap-host` | hostname | IMAP server hostname (overrides `mail-host`) |
| `imap-port` | integer | IMAP port (default: 993) |
| `imap-user` | string | IMAP username (overrides `mail-user`) |
| `imap-password` | encrypted string | IMAP password (overrides `mail-password`) |
| `imap-secure` | `ssl` \| `tls` \| `none` | IMAP connection security (default: `ssl` if `imap-port` is 993, else `tls`) |
| `smtp-host` | hostname | SMTP server hostname (overrides `mail-host`) |
| `smtp-port` | integer | SMTP port (default: 587) |
| `smtp-user` | string | SMTP username (overrides `mail-user`) |
| `smtp-password` | encrypted string | SMTP password (overrides `mail-password`) |
| `smtp-secure` | `ssl` \| `tls` \| `none` | SMTP connection security (default: `ssl` if `smtp-port` is 465, else `tls`) |
| `smtp-from-name` | string | Display name in From header; may contain mail-context variables e.g. `{sender-name} (via {display-name})` |
| `display-name` | string | Human-readable list name for UI (falls back to `cn`); used in `List-Id` header |
| `description` | string | Optional list description shown in UI. Renamed to `list-description` on ingest by `ConfigResolver::resolveListConfig()` (applies to every provider, not just LDAP) — see [`description` → `list-description`](../architecture/config.md#description--list-description) |
| `reply-to` | `list` \| `sender` \| `both` \| `nobody` \| `masked-sender` \| `masked-both` | Reply-To behavior (the `+r-` reply relay is active for every value except `list`/`nobody`; on `sender`/`both` it only serves the archive's "reply to the author only" button) — `both` sets both list and sender addresses, *unless* the sender is already a list member, in which case it's just the list address (see [Headers to set on outgoing mail](../architecture/mail-processing.md#headers-to-set-on-outgoing-mail) for why); `masked-sender`/`masked-both` set a signed `{localPart}+r-{TOKEN}@{domain}` address instead of the sender's own — see [Masked reply addresses](../architecture/masked-replies.md#masked-reply-addresses); `nobody` sets a translated "please do not reply" display name on `noreply@{list->domain}.invalid` (replies are guaranteed undeliverable — `.invalid` per RFC 2606 — and the display name is what a mail client actually shows when Reply is clicked) |
| `post-access-members` | `allow` \| `deny` \| `moderate` | Whether list members may post (default: `allow`) |
| `post-access-public` | `allow` \| `deny` \| `moderate` | Whether non-members may post (default: `deny`) |
| `allow-leave` | `direct` \| `moderated` | Unsubscribe behavior |
| `archive` | `members` \| `owners` \| `authenticated` \| `public` \| `hidden` \| `off` | Archive instead of delete after processing, and who may view it in the web archive viewer — see [Archive access levels](../architecture/archive.md#archive-access-levels) (default: `off`) |
| `archive-folder` | string | Name of the IMAP folder archived mail is moved into (default: `Archive`), created as a top-level folder (sibling of INBOX) if it doesn't exist yet — see [Archive folder path](../architecture/archive.md#archive-folder-path) for why this needs its own explanation. Only relevant when `archive` is not `off` |
| `archive-max-age` | relative-time string, e.g. `30 days` | How long archived mail is kept before being deleted from the archive folder (default: unset — unbounded, kept forever, as before this key existed). See [Archive retention (`archive-max-age`)](../architecture/archive.md#archive-retention-archive-max-age) |
| `max-per-sender` | integer | Rate limit: max mails per sender per 10 min (default: 5) |
| `max-size` | size string or integer | Max accepted mail size (default: `5M`). Accepts `5M`, `5MB`, `5MiB`, `5K`, `5KB`, `5KiB`, `5G`, `5GB`, `5GiB`, or plain bytes. Converted to bytes in `ListConfig`. |
| `list-label` | string | Prepended to subject as `$listLabel $subject` if not already present (case-insensitive) |
| `footer` | HTML string | Footer appended to every distributed mail. Empty string disables footer. |
| `personalize` | comma-separated keys, `off`, or empty | Whitelist of recipient-context variables allowed in body/subject |
| `log-level` | `debug` \| `info` \| `warning` \| `error` | Log verbosity for this list (inherits global default) |
| `language` | `de` \| `en` | Locale for this list's outgoing mails and manage page (inherits global default, code-default `en`) — see Internationalization |
| `api-token` | string | Bearer token for the list-management API (plaintext — see [List Management API](../architecture/api.md#list-management-api)). Empty/absent = API disabled for this list |
| `join-policy` | `open` \| `invite` \| `request` | How someone becomes a member (default `invite`). Only `open` does anything: an authenticated user who can see the list gets a "Join" button (dashboard and info page) that adds them immediately — their address is confirmed by the login; offered only if the member store can add members (`MemberResolver::supportsAddition()`: database, CSV, LDAP with an existing directory entry; not static config.yml members). `invite` and `request` are only shown in the list info. The List Management API ignores it. See [Visibility and join policy](../architecture/web-ui.md#visibility-and-join-policy) |
| `visibility` | `public` \| `members` \| `hidden` | Who sees the list in the web UI (default `members`): `public` every authenticated user (dashboard "Other lists" and `/{listname}`), `members` members and owners, `hidden` owners only. Others get a 404 for `/{listname}`; guests see no list at all. Does not change who may read the archive (`archive`) or who receives mail |
| `sender-address-header` | `never` \| `external` \| `always` | Put the original sender's address into an `X-Original-Sender-Address` header (default `never`; `external` = only for non-members) — see [Masked reply addresses](../architecture/masked-replies.md#masked-reply-addresses) |
| `trusted-authserv-id` | string or list | authserv-id(s) of the mail server that checks incoming mail. Unset (default): the topmost `Authentication-Results` header is believed. Set: only headers with one of these ids count (exact, case-insensitive; matching headers are merged), the rest is ignored and no match means unauthenticated — for SPF/DKIM reject, sender notices and DKIM-authenticated bounce actions alike. **Set it** if the mailbox is at a third-party provider, or if you are not sure the MTA adds the header to every mail. **Find the value** in the raw source of a received mail: the first word after `Authentication-Results:` (e.g. `mx.example.org`). Comma-separated string or YAML list; `""` = unset. Override chain, not additive. See [Sender authentication](../architecture/security-and-tokens.md#sender-authentication), [ADR-0019](../adr/0019-optional-trusted-authserv-id.md) |
| `sender-notices` | `authenticated` \| `always` \| `never` | Who gets reject / moderation-pending notices (default `authenticated`: only DMARC-aligned authenticated senders, original attached; `always`: everybody, original only if authenticated; spam and SPF/DKIM-fail rejects never notify) — see [Sender notices](../architecture/mail-processing.md#sender-notices-backscatter-protection) |
| `sender-notice-interval` | seconds or relative time | At most one notice per address in this interval, across all lists (default `1 hour`, max `1 day`, `0` = off). Invalid values fail fast |
| `bounce-action` | `none` \| `mark-invalid` \| `restrict` \| `remove` | Automatic action for a recognized, authenticated permanent bounce (user/mailbox unknown) or an escalated repeated temporary one (mailbox full) — default `none`. See [Automatic bounce actions](../architecture/bounces.md#automatic-bounce-actions) |

**`post-access-members`/`post-access-public` — owners have no key of their own.** List owners can always post, and are never moderated, regardless of what these two keys are set to — there is deliberately no `post-access-owners` (owners posting is not something an operator can restrict). "Owners only may post" is expressed by setting *both* keys to `deny`: `post-access-members: deny`, `post-access-public: deny`. `moderate` queues the mail for owner accept/reject via the normal moderation flow (see [Moderation](../architecture/moderation.md#moderation)) exactly as the old `moderation: on` did, just scoped to whichever sender class (members/public) is actually set to it, instead of applying list-wide to everyone who already cleared the (now-removed) single `post-access` gate. See `IncomingMailFilter::checkPostAccess()`/`requiresModeration()`.
