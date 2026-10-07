# Variables and template resolution

`{}` placeholders, filters, blocked keys and `ResolutionPurpose`.

## Variable substitution

Variables use `{key}` syntax and are resolved **lazily** — at point of use, with the fully merged configuration of the specific list and (where applicable) the current mail being processed.

### Always-available variables (list context)

| Variable | Value |
|---|---|
| `{list-name}` | Internal list identifier, set by the provider (LDAP: `cn`) |
| `{list-mail}` | List email address |
| `{list-domain}` | Domain part of the list email address |
| `{hostname}` | Hostname of the Listig server — the `hostname` config key, or `gethostname()` if unset (see [Docker Setup](deployment.md#docker-setup) — set this explicitly in any real deployment) |
| `{display-name}` | `display-name` config value, falls back to `{list-name}`; alias: `{list-display-name}` |
| `{list-url}` | `https://{hostname}/{list-name}` — link to the list manage page |
| Any other config key | Its resolved value |

### Mail-context variables (available while processing an incoming mail)

These are available in `smtp-from-name` and similar fields that describe the outgoing mail:

| Variable | Value |
|---|---|
| `{sender-name}` | Display name from `From:` header; falls back to `{sender-firstname} {sender-lastname}`; falls back to localpart of sender address |
| `{sender-mail}` | Sender email address |
| `{sender-` + any attribute`}` | Every key in the sender `Member`'s `$attributes`, prefixed `sender-` — e.g. `{sender-firstname}`, `{sender-employeeNumber}` for an LDAP sender. See [Member attributes — fully dynamic](providers-and-members.md#member-attributes--fully-dynamic); nothing beyond `sender-mail` is fixed |
| `{subaddress}` | The `+subaddress` portion of the incoming mail's recipient address relative to `{list-mail}`'s local part and domain, e.g. `alice` for `fwd+alice@example.org`; empty string if the mail had none. Used by `type: subaddress` lists (see [type: subaddress — subaddress forwarding](providers-and-members.md#type-subaddress--subaddress-forwarding)), but computed for every list |

Example use: `smtp-from-name: "{sender-name} (via {display-name})"` — produces e.g. `Alice Müller (via Projektliste)` in the From header.

### Recipient-context variables (available during personalization per recipient)

Only substituted when key is in `personalize` whitelist (plus `{list-url}` which is always available):

| Variable | Value |
|---|---|
| `{mail}` | Recipient's email address |
| Any attribute | Every key in the recipient `Member`'s `$attributes`, under its own name — e.g. `{firstname}`, `{pronoun}`, `{employeeNumber}` for an LDAP recipient. Nothing beyond `mail` is fixed; a key a specific member doesn't have resolves to an empty string rather than leaking `{key}` literally — see [Member attributes — fully dynamic](providers-and-members.md#member-attributes--fully-dynamic) |

### Custom variables

Any key in the config whose value references another variable is a custom alias:
```yaml
vorname: "{firstname}"
```
Makes `{vorname}` available. Resolved recursively with cycle detection (tracked via visited keys; on cycle: log error, leave literal).

### Filters

A variable may be followed by a `|filter:args` pipeline, applied to the resolved value in order: `{key|filter1|filter2:args}`. Implemented by `Hengeb\Listig\Variable\VariableFilter::apply()`, dispatched from `VariableResolver::resolve()` after key lookup and recursive resolution (filters see the final resolved string, not an unresolved template). Filters are not part of key lookup/cycle-detection — those operate on the bare key, and personalization's `personalizeKeys` whitelist check (`BodyPersonalizer`) also checks the bare key via `VariableResolver::baseKey()`, so a filter pipeline cannot be used to reach a non-whitelisted variable.

| Filter | Args | Example |
|---|---|---|
| `match` | comma-separated `pattern=>replacement` pairs | `{pronoun\|match:er=>Lieber,sie=>Liebe}` |
| `default` | a single fallback value | `{pronoun\|default:Hallo}` |
| `lowercase` | — | `{firstname\|lowercase}` |
| `uppercase` | — | `{firstname\|uppercase}` |
| `urlencode` | — | `{mail\|urlencode}` |

- `match` does exact, case-sensitive comparison against the resolved value. No match → empty string (a `match` filter always replaces, it does not pass the original value through) — `match` has no fallback value of its own; chain `|default:...` afterwards for one, e.g. `{pronoun|match:er=>Lieber,sie=>Liebe|default:Hallo}`. (Earlier versions accepted a `default=>...` pair directly inside `match:` for this; that's gone — use the chained `|default:` filter instead, it composes with anything, not just `match`.)
- `default` passes its input through unchanged unless it's empty, in which case its arg is used verbatim — works after any filter (or with none), e.g. `{firstname|default:Listenmitglied}` for a member with no `firstname` at all.
- Commas and `=>` cannot appear literally inside a `match` pattern or replacement — no escaping is implemented; not needed for short salutation-style words.
- An unknown filter name logs an error and passes the value through unfiltered, rather than leaving the whole placeholder literal — this keeps a template typo from leaking raw `{key|filter:...}` syntax into a sent mail.
- `urlencode` uses `rawurlencode()` (RFC 3986 — space becomes `%20`), not `urlencode()` (RFC 1866 — space becomes `+`), since its use cases are URL path/query segments and `mailto:` links, not `application/x-www-form-urlencoded` bodies.
- Nested `{}` inside filter args is supported — e.g. a `{}` variable inside a `match` replacement or a `default` fallback: `{list-mail|default:system@{domain|default:localhost}}`, `{pronoun|match:he=>Lieber {firstname}}`. Placeholder scanning (`VariableResolver::walkPlaceholders()`) is brace-depth aware rather than a plain `[^}]+` regex, so it finds the whole outer placeholder — including any nested one inside a filter arg — instead of stopping at the first `}`. The nested placeholder is resolved (through the same `$contexts`/`ResolutionPurpose`) before the filter that contains it runs, so the filter always sees plain, already-resolved text as its args.
- Filters chain freely, applied left to right, each seeing the previous one's output — not just `match` then `default`; any combination/order works (e.g. `{firstname|lowercase|default:unbekannt}`).
- **A `{` immediately followed by a digit is never treated as a placeholder** — `walkPlaceholders()` passes it through as literal text instead of scanning for a matching `}`. Every variable name in this app is alphabetic/hyphenated (`domain`, `list-name`, `sender-firstname`, a member's own attribute name, ...), never digit-first, so this is an unambiguous way to leave a PCRE quantifier alone. This matters specifically for `filters:` (see [Spam filtering](mail-processing.md#spam-filtering-filters)) — a regex pattern like `subject: /spa{5,}m/i` was, before this, corrupted by `SpamFilter`'s own `{}`-resolution pass (triggered by `str_contains($pattern, '{')`, needed for genuine `{}` variables in a pattern like `from: "MAILER-DAEMON@{domain}"`): `{5,}` was looked up as a variable named `5,`, found nowhere, and silently resolved to `''` per this class's own "key not found → empty string" rule — turning `/spa{5,}m/i` into `/spam/i` without any error. Confirmed live: the same rule matched correctly against a real "SPAAAAAM" (5+ a's) subject after this fix, and still left a genuine `{domain}`/nested-`{}`-in-filter-args placeholder elsewhere in the same string fully resolved, unaffected.

### Blocked variables

Never substituted in any context, even via custom aliases:
`password`, `mail-password`, `imap-password`, `smtp-password`, `ldap-bind-password`, `db-password`, `api-token`, `mail-user`, `imap-user`, `smtp-user`, `mail-host`, `imap-host`, `imap-port`, `imap-secure`, `smtp-host`, `smtp-port`, `smtp-secure`, `db-host`, `db-port`, `db-name`, `db-user`, `ldap-host`, `ldap-base-dn`, `ldap-bind-dn`, `ldap-list-dn`, `oidc-provider-url`, `oidc-client-id`, `oidc-client-secret`, `oidc-public-provider-url`, `oidc-logout-url`

---

## VariableResolver

Static helper class. All resolution goes through `VariableResolver::resolve()`.

```php
// Build context arrays at each processing level
$listContext      = $list->createContext();          // all config keys + list-* computed vars
$mailContext      = [...];                           // sender-* keys (may include callables)
$recipientContext = [...];                           // firstname, lastname, username, mail (unfiltered)
                                                     // top-level gating by personalizeKeys happens in BodyPersonalizer

// Resolve a template with the active stack — ResolutionPurpose::Disclosed since
// this result is going into an outgoing mail (see "ResolutionPurpose" (docs/architecture/variables.md) below)
$result = VariableResolver::resolve('{sender-name} (via {display-name})', [
    $listContext,
    $mailContext,
    $recipientContext,  // only included when personalizing body
], ResolutionPurpose::Disclosed);

// Look up a single key (useful inside callables)
$value = VariableResolver::lookup('sender-firstname', $contexts, $purpose);
```

Context arrays are merged left-to-right via `array_merge` — later entries override earlier ones. Each key should appear in at most one context. Values may be `string|null|callable`; callables receive `array $contexts` and the active `ResolutionPurpose`, and return `string|null`.

The resolver:
- Merges all contexts with `array_merge(...$contexts)` before lookup
- Detects cycles via `$visited` tracking; leaves variable literal on cycle, logs error
- Blocks `VariableResolver::BLOCKED_KEYS` (passwords, hostnames, ...) — see [ResolutionPurpose](#resolutionpurpose) below
- Logs and substitutes an empty string for a key not found in any context — unless called with `quiet: true` (5th param, default `false`), which suppresses just that one log line (cycle detection and blocked-key logging are unaffected) and threads through recursive/filter-arg resolution. Used by `ListConfig::resolveMemberDisplayName()`, where a member/owner with no `firstname`/`lastname` at all (e.g. added via a bare-string `owners:`/`members:` entry, see [Global / provider / list levels](config.md#global--provider--list-levels-members-owners-member-resolver-owner-resolver-senders-restricted-members)) is the routine case, not a misconfiguration worth logging.

`ListConfig::createContext()` produces the list-level context: all merged raw config keys plus computed `list-name`, `list-mail`, `list-domain`, `hostname`, `list-url`, `display-name`/`list-display-name`. It also sets imap/smtp user+password defaults (`imap-user: '{mail-user}'` etc.) so the fallback chain works without special-casing in `ListConfig` properties. It is the **only** context builder — there is no separate "safe" variant; protection against `BLOCKED_KEYS` happens at resolution time instead (next section).

## ResolutionPurpose

`Hengeb\Listig\Variable\ResolutionPurpose` is a plain (non-string-backed) enum with two cases, `Trusted` and `Disclosed`, passed as `VariableResolver::resolve()`/`lookup()`'s third argument and threaded unchanged through recursive resolution (same mechanism as `$visited`). Protection against `VariableResolver::BLOCKED_KEYS` is enforced at this single point of `{}` resolution, not by pre-filtering the context array handed to it — `ListConfig::createContext()` is the **only** context builder, and always returns the full raw config.

- **`Disclosed`** (the default parameter value — least-privilege, secure-by-default) — used for any resolution whose result is user-visible (mail body/subject/headers, the UI, notification mails) or otherwise operator-controlled but not itself a credential lookup. If resolution — at any point in the recursion chain, not just the top-level key — reaches a key in `VariableResolver::BLOCKED_KEYS`, the real value is never returned: `VariableResolver::CLASSIFIED_PLACEHOLDER` (`'*CLASSIFIED*'`) is substituted instead, and the attempt is logged via a direct, unconditional `error_log()` call — this specific log call (a security-relevant event) is deliberately *not* routed through the level-gated `Logger` described under [Debug logging](logging.md#debug-logging), so it can never be silenced by a `log-level` setting, unlike the ordinary tracing added there. The placeholder is never itself re-parsed as a template, same as a `Literal`-wrapped value.
- **`Trusted`** — full, unfiltered access, bypassing the `BLOCKED_KEYS` check entirely. Used *only* by `ListConfig::$imapHost`/`$imapUser`/`$imapPassword`/`$smtpHost`/`$smtpUser`/`$smtpPassword` (see [Which `ListConfig` properties are template-resolved](#which-listconfig-properties-are-template-resolved-and-against-which-context) below) — these are the deliberate case of a credential/connection-string property needing to fall back through another blocked key (`{mail-host}`/`{mail-user}`/`{mail-password}`).

Blocking happens at the single point of `{}` resolution, not by pre-filtering the context array, so it also protects code that resolves before any `ListConfig` exists (`list-mail`) — see [ADR-0014](../adr/0014-block-credentials-at-resolution-time.md).

## Which `ListConfig` properties are template-resolved, and against which context

Every property backed by a raw config value is resolved via `ListConfig`'s private `resolve()` before being cast/validated to its final type (`(int)`, `Enum::from()`, `'on'`/`'off'` comparison, ...) — not just plain string properties. This matters: without it, e.g. `smtp-port: "{port-tls}"` would silently produce `0` (an unresolved `"{port-tls}"` string cast to `int`), and `reply-to: "{my-alias}"` would throw an uncaught `ValueError` from `ReplyToBehavior::from()`.

- **`resolve($raw)`, default `ResolutionPurpose::Disclosed`** — the default for everything: `$displayName`, `$description`, `$replyTo`, `$postAccessMembers`, `$postAccessPublic`, `$allowLeave`, `$archive`, `$archiveFolder`, `$maxPerSender`, `$maxSize`, `$publicSubscribe`, `$logLevel`, `$language`, and — despite being `VariableResolver::BLOCKED_KEYS` themselves — `$imapPort`/`$imapSecure`/`$smtpPort`/`$smtpSecure` too. These four are numeric/enum properties (`(int)` cast, `'ssl'|'tls'|'none'` comparison): resolved under `Trusted`, a value like `smtp-port: "{imap-password}"` could silently become the leading digits of the actual password cast to an int, which could then surface via a connection-failure error message — a *fragment* leak that casting makes easy to miss. Staying on `Disclosed` here means these four properties can no longer reference `{mail-user}`/`{mail-password}`/`{mail-host}` or any other blocked key — a deliberate trade-off in favor of the leak protection, since none of them actually need to (there's no `mail-port`/`mail-secure` fallback level to reach).
- **`resolve($raw, ResolutionPurpose::Trusted)`** — `$imapHost`, `$imapUser`, `$imapPassword`, `$smtpHost`, `$smtpUser`, `$smtpPassword`. These are string-valued connection/credential properties that must be able to fall back through another blocked key one level up — `imap-host`/`smtp-host` through `{mail-host}`, `imap-user`/`smtp-user` through `{mail-user}`, `imap-password`/`smtp-password` through `{mail-password}` (each `mail-*` key sets both `imap-*` and `smtp-*` unless overridden individually — see [config.yml Structure](../reference/config-yml.md#configyml-structure)). Unlike the numeric/enum group above, a resolved host/user/password is used whole (passed straight to the IMAP/SMTP client), not cast or compared — so there's no fragment-leak risk distinct from the whole-value risk `Trusted` already accepts for this deliberately small, documented set of properties.
- **Not template-resolved at all** — `$apiToken`. A Bearer credential the caller must present verbatim; indirection here would only add complexity/attack surface (e.g. accidental sharing via a shared alias) for no real benefit.
- **Not applicable** — `$domain` (derived from `$mail`, not a raw config value), `$personalizeKeys`/`$reservedSubaddresses` (comma-separated *lists of key names*, not content), `$requiresSubaddress`/`$isImapConfigured` (booleans computed from other properties). `$footer`/`$listLabel`/`$smtpFromName` are template-capable but *not* resolved inside `ListConfig` itself — they're read raw and resolved later, downstream, by `FooterAppender`/`MailProcessor` (which already resolve under `ResolutionPurpose::Disclosed`), since they're only ever consumed from the mail-sending pipeline and never read directly elsewhere.

---
