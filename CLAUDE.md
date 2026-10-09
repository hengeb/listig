# Listig – Claude Instructions

## Project Overview

Listig is a self-hosted, Docker-based mailing list manager written in PHP 8.5.
- Polls IMAP mailboxes for incoming mails and distributes them to list members
- Members and list configuration are stored in LDAP, a database, CSV or YAML files
- A queue in MariaDB handles outgoing mails with retry logic
- A web UI (Slim + Latte) allows members to view their subscriptions and owners to manage their lists

## Technology Stack

| Concern | Library / Tool |
|---|---|
| Language | PHP 8.5 (use property hooks introduced in PHP 8.4 where appropriate) |
| IMAP | `php-imap/php-imap` — use `PhpImap\Mailbox` |
| Mail building & parsing | `symfony/mime` |
| SMTP sending | `symfony/mailer` |
| LDAP | `symfony/ldap` |
| OIDC login | `jumbojett/openid-connect-php` — optional, see [Authentication (OIDC)](docs/architecture/web-ui.md#authentication-oidc) |
| Config files | `symfony/yaml` |
| Web framework | `slim/slim` |
| Templates | `latte/latte` |
| HTML sanitization | `ezyang/htmlpurifier` — archive viewer only, see [Archive viewer](docs/architecture/archive.md#archive-viewer) |
| Internationalization | `symfony/translation` (`TranslatorInterface`), YAML catalogs |
| Sessions | Native PHP sessions (no custom session table) |
| Database | MariaDB (separate Docker container) |
| DB access | PDO with prepared statements |
| Coding standard | PSR-1, PSR-2, PSR-4, PSR-12 |

---

## How this documentation is organised

This file is the entry point: project overview, the hard rules that apply to every change, and an index. Everything else lives under [docs/](docs/README.md) and is read **on demand** — before working on an area, read the matching document:

| If you work on… | Read first |
|---|---|
| `config.yml` merging, `use:`, `lists:`, `members:`/`owners:`/`senders:`, `list-mail`, `$VAR`, `!include` | [Configuration semantics](docs/architecture/config.md), [config.yml reference](docs/reference/config-yml.md) |
| `{}` placeholders, filters, `personalize:`, blocked keys, `ResolutionPurpose` | [Variables and template resolution](docs/architecture/variables.md) |
| List providers, `ListConfig`, member resolvers, member attributes, `senders:`, `restricted-members:`, `type: subaddress` | [List providers and members](docs/architecture/providers-and-members.md), [per-list keys](docs/reference/list-config-keys.md), [member/config stores](docs/reference/member-stores.md), [LDAP](docs/reference/ldap.md) |
| `bin/worker.php`, IMAP polling, outgoing queue, SMTP, retries | [Worker, IMAP and outgoing queue](docs/architecture/worker-and-queue.md) |
| Incoming mail filtering, `filters:`, sender notices / backscatter, outgoing headers, attachments, personalization, footer | [Mail processing](docs/architecture/mail-processing.md) |
| Bounce detection, automatic bounce actions, bounce preview | [Bounces](docs/architecture/bounces.md) |
| `reply-to: masked-*`, `+r-` addresses, `reply_targets`, the compose form | [Masked reply addresses](docs/architecture/masked-replies.md) |
| Moderation (accept/reject, previews) | [Moderation](docs/architecture/moderation.md) |
| Archive viewer, archive folder, retention | [Archive](docs/architecture/archive.md) |
| Web UI, Latte templates, login (magic link / OIDC), custom layout | [Web UI](docs/architecture/web-ui.md), [Library notes](docs/library-notes.md) |
| List Management API | [List Management API](docs/architecture/api.md) |
| Tokens, key derivation, password encryption, rate limiting, security review | [Security, keys and tokens](docs/architecture/security-and-tokens.md) |
| Translations | [Internationalization](docs/architecture/i18n.md) |
| Logging | [Logging](docs/architecture/logging.md) |
| Docker, compose, CI, nginx, health check | [Deployment and Docker](docs/architecture/deployment.md), [environment variables](docs/reference/environment.md) |
| Database tables, migrations | [Database schema](docs/reference/database-schema.md) |
| Routes | [Routes](docs/reference/routes.md) |
| Where a file lives | [Project structure](docs/reference/project-structure.md) |
| Tests, live verification on a container | [Testing](docs/architecture/testing.md) |
| A library behaving oddly (php-imap, symfony/mime, Latte, PHPUnit, ext-imap) | [Library notes](docs/library-notes.md) |
| *Why* something is the way it is | [Architecture decision records](docs/adr/README.md) |

### Documenting changes

Every code change that alters behaviour must update the documentation in the same change. Put it where it belongs:

| What | Where |
|---|---|
| A new or changed **rule** that applies broadly (a "never do X", a responsibility boundary) | this file, under *Hard rules* |
| **Detail** about one area (mechanism, classes, flow) | the matching document in `docs/architecture/` |
| A **design decision with rejected alternatives** or a deliberate trade-off | a new ADR in `docs/adr/` (next free number; copy the format of an existing one), plus one sentence and a link where the rule lives |
| A config key, table/column, route, environment variable or directory | `docs/reference/` |
| A pitfall of a third-party library | `docs/library-notes.md` |

Keep it terse, in English, and link instead of repeating. A confirmed live bug that led to a rule becomes one sentence next to the rule, not a story. When you add a document, add it to the index above and to [docs/README.md](docs/README.md).

---

## Deployment in one paragraph

One image (`docker/Dockerfile`): PHP 8.5 php-fpm + nginx + the worker loop (`bin/worker.php`), managed by `supervisord` as three processes; only MariaDB is a separate container. `docker/entrypoint.sh` applies pending database migrations (`bin/migrate.php`) before starting them. `config.yml` and `.env` are mounted/supplied by the operator and never baked into the image. Set `hostname` in `config.yml` explicitly — every generated link depends on it. Details: [Deployment and Docker](docs/architecture/deployment.md).

## Repository layout

```
bin/            worker.php (IMAP polling + queue sending), migrate.php, encrypt-password.php
config/         container.php (DI container); config.yml is operator-supplied and gitignored
deploy/         templates for the published-image deployment (compose, .env, config.yml)
docker/         Dockerfile, entrypoint, nginx/php-fpm/supervisord/php.ini, dev compose
docs/           architecture notes, references, ADRs
migrations/     NNN_description.sql, applied automatically
public/         index.php (Slim front controller), assets/ (served by nginx)
src/
  Archive/      web archive viewer backend
  Config/       ListConfig, ConfigResolver, RestrictionList, YamlIncludeResolver, Enum/
  Crypto/       KeyDerivation, PasswordCrypto
  Database/     DatabaseConnectionFactory, MigrationRunner
  Http/         Controller/, Middleware/
  Imap/         ImapPoller, ImapArchiver, ImapMailboxFactory
  Logging/      Logger, LogLevel
  Mail/         MailProcessor, IncomingMailFilter, BounceHandler, ReplyTargetStore, SpamFilter, ...
  Member/       Member, MemberResolver + implementations
  Moderation/   ModerationMailer, ModerationChecker, ModerationResponseHandler
  OpenIdConnect/
  Provider/     ListProvider + implementations
  Queue/        QueueWriter, QueueSender, SpamRejectionDetector
  RateLimit/    RateLimiter
  Smtp/         SmtpConnectionFactory
  Token/        TokenService, ListFingerprint
  Variable/     VariableResolver, ResolutionPurpose, VariableFilter, Literal
templates/      Latte templates (layout.latte, list/, archive/, ...)
tests/          PHPUnit, mirrors src/ (pure-logic layer only)
translations/   messages.de.yaml, messages.en.yaml
```

The annotated, file-level tree is in [Project structure](docs/reference/project-structure.md).

---

## Hard rules

### Architecture and responsibilities

- **Only LDAP-specific classes may talk to LDAP** (`LdapListProvider`, `LdapMemberResolver`); **only database-specific classes may run provider-specific SQL** (`DatabaseListProvider`, `DatabaseMemberResolver`). Everything else works with `ListConfig` and `Member`. Code that legitimately needs SQL lives in small DB-gated collaborators (`RateLimiter`, `BounceSuppressionList`, `ReplyTargetStore`, ...), never inline in `MailProcessor` and the like. See [List providers and members](docs/architecture/providers-and-members.md).
- **`VariableResolver::resolve()` is the single point of `{}` resolution** — never resolve variables ad hoc. Build contexts from `ListConfig::createContext()`, mail-context callables and the recipient context. Top-level body substitution is gated by `personalizeKeys` in `BodyPersonalizer`, not by pre-filtering the context. See [Variables](docs/architecture/variables.md).
- **Resolve under `ResolutionPurpose::Disclosed` (the default) for anything user-visible**; `Trusted` is reserved for the six IMAP/SMTP host/user/password properties of `ListConfig`. Blocked keys (passwords, hosts, tokens, OIDC secrets) must never be substituted in any `Disclosed` context, at any recursion depth ([ADR-0014](docs/adr/0014-block-credentials-at-resolution-time.md)).
- **Data that comes from a mail or a member is untrusted**: values put into sender/recipient/mail contexts must be wrapped in `Literal` (or be a callable), so a `{` inside them is never re-parsed as a template. `personalize:` is a trust boundary — whitelist only attributes members may see about themselves ([ADR-0015](docs/adr/0015-fully-dynamic-member-attributes.md)).
- **Config keys have three states** — not present (`null`, code default), empty string (explicitly empty, overrides defaults, e.g. disables a footer), non-empty value. Preserve the distinction through the whole merge chain.
- **`members:`, `owners:`, `member-resolver:`, `owner-resolver:`, `senders:`, `restricted-members:` are purely additive across global/provider/list level** — never introduce replacement semantics ([ADR-0013](docs/adr/0013-additive-scoped-config-levels.md)). `filters:` is deliberately not part of this.
- **`Member` has exactly one fixed field (`email`)**; everything else is a dynamic attribute. Never hard-code attribute names outside the documented exceptions.
- **A list name** must match `[A-Za-z0-9_-]` and must not be `_` (reserved for `/_/…` routes); `ListConfig` enforces this fail-fast.
- **Fail fast on configuration errors** (missing `$VAR`, invalid regex, unknown provider type, unparsable `archive-max-age`) — no silent fallbacks. Exceptions for errors; no silent failures.
- **Config changes that alter structure need a restart** (the worker watches `config.yml` and every `!include`d file and restarts itself); external data (LDAP, DB rows) is re-read every cycle via `ListProvider::reset()`. See [Worker, IMAP and outgoing queue](docs/architecture/worker-and-queue.md).

### Mail handling

- **Owners can always post and are never moderated** — there is deliberately no `post-access-owners` key. "Owners only" is `post-access-members: deny` + `post-access-public: deny`.
- **A bounce's content is never trusted.** Which recipient/batch it concerns comes only from the signed per-recipient VERP envelope address; automatic actions require an authenticated origin scaled to their blast radius ([ADR-0001](docs/adr/0001-verp-bounce-address.md), [ADR-0002](docs/adr/0002-bounce-origin-authentication.md), [Bounces](docs/architecture/bounces.md)).
- **System notifications go through `NotificationMailer`** (null sender envelope, `X-Listig-Auto`, `Auto-Submitted`) so they can never start a bounce loop ([ADR-0007](docs/adr/0007-null-sender-envelope-via-reflection.md)).
- **The spam filter (`filters:`) runs before bounce detection**; a `filters:` match deletes the mail outright and never archives it ([ADR-0006](docs/adr/0006-spam-filter-before-bounce-detection.md)). Auto-replies (out-of-office) are discarded silently, never forwarded as bounces. Reject reasons are translation keys, not messages.
- **Notices to a sender are backscatter unless the sender is authenticated.** `SenderNoticePolicy` is the only place that decides whether a reject / moderation-pending notice goes out and whether the original is attached; callers never decide themselves. Default: authenticated (DMARC-aligned) senders only, throttled per address; never for `reject.auth_failed`/`reject.spam`. `Authentication-Results` is selected in one place, `HeaderFilter::parseAuthResults()`: the topmost header (the own MTA's, which must add one to every mail), or with the optional `trusted-authserv-id` only headers of that server ([ADR-0018](docs/adr/0018-sender-notices-only-to-authenticated-senders.md), [ADR-0019](docs/adr/0019-optional-trusted-authserv-id.md), [Sender notices](docs/architecture/mail-processing.md#sender-notices-backscatter-protection)).
- **Never leak a sender's address**: the outgoing `From` is always the list address; the sender's address may appear only through `reply-to: sender`/`both` or the opt-in `sender-address-header`. No `X-Forwarded-From`. `masked-*` replies are relayed, never exposed, and `masked-sender` replies are private — deleted from IMAP and never archived ([Masked reply addresses](docs/architecture/masked-replies.md)).
- **Embedded (`cid:`) attachments keep their exact Content-ID and `inline` disposition**; a non-conformant id gets a synthesized `@listig.invalid` replacement and the HTML body is rewritten to match.
- **A reply from the archive uses a signed `+re-{TOKEN}` address** (token over `archived_mail.id`, no table of its own); `MailProcessor` turns it into `In-Reply-To`/`References` and hides the address, `ArchiveIndexer` threads the archive the same way, a dead token is rejected with a hint ([ADR-0020](docs/adr/0020-reply-thread-tag.md)). The `+r-` relay works for every `reply-to` except `list`/`nobody` (private to the target unless `masked-both`).
- **Tokens embedded in an address local-part are read from the raw header**, never from `$mail->to`/`$mail->cc` (php-imap lowercases those). Tokens are list-specific: look up `(id, list_cn)` of the list the mail arrived on.
- **A mail that keeps failing is bounded** (`ProcessingFailureTracker`, 3 attempts), then the owners are told and the mail leaves the retry loop.

### Security

- `APP_SECRET` is the root secret and is **never used as a key directly** — derive purpose-specific subkeys with `KeyDerivation` ([Security, keys and tokens](docs/architecture/security-and-tokens.md)). IMAP/SMTP passwords are AES-256-CBC encrypted when they come from LDAP; decryption happens only where the credential is consumed.
- `config.yml` and `.env` are mounted, never baked into the image; `.dockerignore`/`.gitignore` exclude them.
- **`display_errors` stays `Off` and Slim's `$displayErrorDetails` stays `false`** — log everything server-side, show the client nothing.
- **Never log MIME content, passwords or tokens.** The blocked-variable log line is deliberately unconditional (not level-gated).
- Native PHP sessions; the session id is the CSRF token (`X-CSRF-Token` on state-changing requests). Login and unsubscribe never reveal whether an address exists; login always returns the same response.
- Moderation requires HMAC **and** owner identity. Deleting an archived mail requires a real session and ownership even for `archive: public` lists.
- Archive viewer: sanitized HTML in a scriptless sandboxed iframe with its own CSP, external images opt-in, attachments never trusted on their claimed MIME type, no full email addresses in the viewer's own UI, `Hidden`/`Off` are indistinguishable 404s.
- The List Management API token is stored in plaintext by design, compared with `hash_equals()`; no token configured means the API is a 404.

### Web UI and i18n

- **Never write `{$value|escapeHtml}` in Latte** — auto-escaping already applies and the filter double-escapes. Use `|noescape` only for already-sanitized HTML. Other Latte pitfalls: [Library notes](docs/library-notes.md).
- Templates call the translator directly (`{$translator->trans('key')}`); strings with interpolated values are resolved in PHP and passed in. List-context mails pass `$list->language` as the locale; list-scoped pages call `setLocale($list->language)` once before rendering. See [Internationalization](docs/architecture/i18n.md).
- **List buttons come from `ListActions` only** (rendered by `templates/list-actions.latte`): every page about a list shows the same set, the current one highlighted; never hand-build them in a template or controller ([Web UI](docs/architecture/web-ui.md#list-action-buttons-listactions)). `ListConfig::canPost()`/`canViewArchive()` are the rules behind them and must stay in line with `IncomingMailFilter::checkPostAccess()` and `ArchiveController::checkAccess()`.
- Every route not scoped to a list lives under `/_/`; list-scoped routes are `/{listname}/…`. Static files are served by nginx from `public/assets/`.

### Database

- Schema changes are plain `migrations/NNN_description.sql` files with a zero-padded incrementing prefix, applied automatically by `bin/migrate.php` before anything else starts. **Every statement must be idempotent** (`CREATE TABLE IF NOT EXISTS`, guarded `ALTER`), because MariaDB commits DDL implicitly. See [Database schema](docs/reference/database-schema.md).
- PDO prepared statements for all queries; dynamic identifiers (attribute names) must be validated and quoted.

## Coding Conventions

- PSR-4 autoloading, namespace root `\Hengeb\Listig\`
- PSR-12 code style
- PHP 8.5 property hooks in value objects and config classes
- String-backed enums for all fixed-value config keys, in `\Hengeb\Listig\Config\Enum\`
- Constructor injection; no static calls except bootstrap
- Only `LdapListProvider` and `LdapMemberResolver` may access LDAP; only `DatabaseListProvider` and `DatabaseMemberResolver` may run provider-specific SQL
- `VariableResolver::resolve(string $template, array $contexts)` is the single point of `{}` variable resolution — never resolve variables ad-hoc elsewhere. Build context arrays from `ListConfig::createContext()`, mail-context callables, and the recipient context. Top-level body substitution is gated by `personalizeKeys` in `BodyPersonalizer`, not by pre-filtering the context.
- `BodyPersonalizer` and `FooterAppender` rebuild `TextPart` immutably via `new TextPart(…)` + `Email::setBody()`. `TextPart` exposes no public `getCharset()` — read the charset from `$part->getPreparedHeaders()->get('Content-Type')?->getParameter('charset')` (returns `''` if unset, fall back to `'utf-8'`). Omit the `$encoding` argument when constructing the new part so symfony/mime auto-detects the correct transfer encoding for the new content.
- No global state
- PDO prepared statements for all DB queries
- Exceptions for errors; no silent failures
- Log to stdout, structured where possible

---

## Testing

`tests/` (PHPUnit 12, `require-dev` only) mirrors `src/` under `Hengeb\Listig\Tests\`. Run `composer test` or `vendor/bin/phpunit [path]`, and `composer stan` (PHPStan level 5, baseline in `phpstan-baseline.neon`), **before every commit** — CI runs both and blocks publishing the image on failure ([Testing](docs/architecture/testing.md#ci)). The suite covers the **pure-logic layer** only; anything needing real IMAP/LDAP/SMTP/DB or a full Slim cycle is verified on a running container (`docker cp`, restart, health check, one-off script — run scripts as `-u www-data`). A test that deliberately triggers `error_log()` must call `$this->expectErrorLog()`. Details and the live-verification procedure: [Testing](docs/architecture/testing.md), [Library notes](docs/library-notes.md).
