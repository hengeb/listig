# Listig – Claude Instructions

## Project Overview

Listig is a self-hosted, Docker-based mailing list manager written in PHP 8.5.
- Polls IMAP mailboxes for incoming mails and distributes them to list members
- Members and list configuration are stored in LDAP, a database, CSV or YAML files
- A queue in MariaDB handles outgoing mails with retry logic
- A web UI (Slim + Latte) allows members to view their subscriptions and owners to manage their lists

---

## Technology Stack

| Concern | Library / Tool |
|---|---|
| Language | PHP 8.5 (use property hooks introduced in PHP 8.4 where appropriate) |
| IMAP | `php-imap/php-imap` — use `PhpImap\Mailbox` |
| Mail building & parsing | `symfony/mime` |
| SMTP sending | `symfony/mailer` |
| LDAP | `symfony/ldap` |
| OIDC login | `jumbojett/openid-connect-php` — optional, see "Authentication (OIDC)" |
| Config files | `symfony/yaml` |
| Web framework | `slim/slim` |
| Templates | `latte/latte` |
| HTML sanitization | `ezyang/htmlpurifier` — archive viewer only, see "Archive viewer" |
| Internationalization | `symfony/translation` (`TranslatorInterface`), YAML catalogs |
| Sessions | Native PHP sessions (no custom session table) |
| Database | MariaDB (separate Docker container) |
| DB access | PDO with prepared statements |
| Coding standard | PSR-1, PSR-2, PSR-4, PSR-12 |

---

## Docker Setup

One image, built from `docker/Dockerfile`: PHP 8.5 (php-fpm) + nginx + the worker loop, all baked into the same container and managed by `supervisord` (`docker/supervisord.conf`) as three processes — nginx (`docker/nginx.conf`, `fastcgi_pass 127.0.0.1:9000` — same container, no network/DNS involved), php-fpm, and `bin/worker.php` (IMAP polling + queue sending loop). Only MariaDB is a separate container. `docker/entrypoint.sh` is the image's `ENTRYPOINT`, running before any of that: it calls `bin/migrate.php` to apply pending database migrations, then `exec`s `CMD` (the `supervisord` invocation) — see "Database migrations" for why this lives here rather than inside the worker loop.

### Simplest deployment (published image, no repo checkout)

`deploy/` holds the three template files needed to run Listig this way — nothing else is needed: MariaDB + the published `ghcr.io/hengeb/listig:latest` image, nothing built locally, no repo clone needed. All three live flat in the operator's own directory (no `config/` subfolder — `compose.yml.example`'s volume mount is `./config.yml:/app/config/config.yml:ro`):

```
mkdir listig && cd listig
curl -O https://raw.githubusercontent.com/hengeb/listig/main/deploy/compose.yml.example
curl -O https://raw.githubusercontent.com/hengeb/listig/main/deploy/.env.example
curl -O https://raw.githubusercontent.com/hengeb/listig/main/deploy/config.yml.example

cp compose.yml.example compose.yml
cp .env.example .env
cp config.yml.example config.yml
# edit .env and config.yml to match your setup

docker compose up -d
```

No manual migration step: the app container's entrypoint applies the schema itself on first start (see "Database migrations"). `compose.yml`/`config.yml` are the operator's real files — gitignored/dockerignored the same as `.env`, never meant to be committed back (see below). Requires the GHCR package to be public (see "CI: build & publish"); if it's private, `docker login ghcr.io` first.

### Building from source (development)

Run via `docker/compose.yaml` (**app** + **db**, builds the image from this checkout instead of pulling it), or directly:
```
docker build -f docker/Dockerfile -t listig .
docker run -d -p 8080:80 --env-file .env -v $(pwd)/config/config.yml:/app/config/config.yml:ro listig
```

Configuration via `config.yml` (structure below) and `.env` for DB credentials and `APP_SECRET`. Neither is committed — `deploy/config.yml.example` and `deploy/.env.example` are the templates (the single source of truth for both this flow and "Simplest deployment" above); copy each into place (`config/config.yml`, `.env`, both at repo root/`config/` per `docker/compose.yaml`'s mounts) and edit before first run. Both `.gitignore` and `.dockerignore` exclude `.env` and `config/config.yml` (the real files, not the `.example` templates), so neither a commit nor a build (e.g. via `COPY . .`) can accidentally bake real secrets in.
`config.yml` may contain secrets via `$VAR` references to environment variables, or directly (e.g. LDAP bind password). Mount as a volume — never bake into the Docker image. `.dockerignore` also excludes `/vendor/`, so a host-side `composer install` (dev dependencies, host-specific builds) can never overwrite the `--no-dev` production `vendor/` that `docker/Dockerfile` installs inside the image.

`docker/php.ini` (`display_errors = Off`, `log_errors = On`, `error_log = /dev/stderr`) overrides the base image's development-oriented defaults (`display_errors = STDOUT`, `log_errors = Off`) — see "Security Notes" for why this is load-bearing, not just tidiness.

**Access logging (`docker logs`)** — nginx's own access log is the canonical one: `docker/nginx.conf` sets `access_log /dev/stdout combined if=$loggable;`, where a `map $request_uri $loggable { ~^/_/health 0; default 1; }` block (same file, http-level, since `docker/nginx.conf` is `include`d from inside the base image's `http {}` block) excludes Docker's own `HEALTHCHECK` (`/_/health`, hit every ~30s — see "Health check" below) from ever reaching it, so `docker logs` isn't dominated by routine, uninteresting `200`s. `docker/php-fpm-pool.conf` (copied to `/usr/local/etc/php-fpm.d/zz-listig.conf` — the `zz-` prefix sorts it after the base image's own `docker.conf`/`zz-docker.conf`, so its directive wins) disables php-fpm's *own* access log entirely (`access.log = /dev/null`, overriding `docker.conf`'s `access.log = /proc/self/fd/2`) so every request is logged exactly once, through nginx, not twice.

This wasn't the first design tried. php-fpm's own access log was briefly the canonical one instead, with `docker/php-fpm-pool.conf` overriding just its `access.format`: the default format's `%r` specifier logs `SCRIPT_NAME`, which is always literally `/index.php` — every request funnels through `docker/nginx.conf`'s `try_files $uri /index.php$is_args$args`, so by the time php-fpm sees it that's genuinely the only script name there is, regardless of what the client actually requested; `%{REQUEST_URI}e` (reading the `REQUEST_URI` FastCGI param, set from nginx's `$request_uri` via `/etc/nginx/fastcgi_params` — unlike `$uri`/`SCRIPT_NAME`, never touched by the internal `try_files` rewrite) fixed that part. Excluding `/_/health` from *that* log was then attempted via php-fpm's own `access.suppress_path[]` pool directive — confirmed to compile and load without error, but empirically unreliable in live testing (suppressed some requests and not others with no consistent relationship to the configured path, including once suppressing a `/_/health` hit that should have matched and *not* suppressing a `/testliste/archive` hit under a config that should have matched everything). Given that, the whole approach was replaced with nginx's `map`/`access_log ... if=`, which is standard, long-established nginx behavvior rather than a php-fpm mechanism with unclear-in-practice matching semantics.

**Set `hostname` explicitly in config.yml.** It's used to build every link Listig generates (login, dashboard, manage page, unsubscribe, moderation) — see `{hostname}` above. Without it, `ListConfig`/`'app.hostname'` (`config/container.php`) fall back to PHP's `gethostname()`, which in a container returns the container's own internal hostname (a random ID or the compose service name) — never the public domain a reverse proxy actually exposes the app under, and there's no way to derive that automatically: the worker has no incoming request to read a `Host` header from at all, and even on the web side, deriving it from the request would make worker-generated links (unsubscribe, moderation) and web-generated links (login) disagree whenever the same instance is reachable under more than one name. `bin/worker.php` logs a warning at startup (`error_log`, not a hard failure) if `hostname` resolves to empty, precisely because this is easy to miss and the resulting links are silently wrong rather than erroring.

`'app.hostname'` is not a raw read of the config key — it goes through `VariableResolver::resolve()` (`'app.hostname.resolved'`, using the merged root default config as its own lookup context, same pattern as a provider's `list-mail` bootstrap resolution), so a root-level alias like `domain: $DOMAINNAME` / `hostname: "lists.{domain}"` actually resolves `{domain}` instead of leaking the literal `{domain}` into every generated URL. `'app.language'`/`'worker.batch-size'`/`'worker.sleep-seconds'` — the other scalar root keys read via `getResolvedDefault()` — go through the same resolution for consistency, even though templating them is a less common case than `hostname`. `db-*` (read directly by `PDO::class`) is the deliberate exception: those are `VariableResolver::BLOCKED_KEYS`, meant to stay pure `$VAR`-substituted literals, never `{}`-templated.

### CI: build & publish (`.github/workflows/docker-publish.yml`)

On every push to `main`, every `v*` tag, and manual dispatch: builds `docker/Dockerfile` and pushes to the GitHub Container Registry as `ghcr.io/<owner>/<repo>` (`${{ github.repository }}` — no hardcoded name, works under any fork/rename). Uses `docker/build-push-action` with the GitHub Actions cache backend (`type=gha`) so unchanged apt/pecl/composer layers aren't rebuilt every run. Tagging (`docker/metadata-action`): the branch name on a branch push, the git tag and derived semver on a version tag, the commit SHA always, and `latest` only on the default branch. Auth is the repo's own `GITHUB_TOKEN` (`permissions: packages: write`) — no PAT or secret to manage. First push creates the package as **private** by default; make it public under the repo's Packages settings if it should be pullable without authentication.

---

## Project Structure

```
/
├── bin/
│   ├── worker.php                    # CLI entry point: IMAP polling + queue sending loop
│   ├── migrate.php                   # CLI entry point: applies pending migrations/*.sql — see MigrationRunner, run by docker/entrypoint.sh
│   └── encrypt-password.php          # CLI tool: encrypt/decrypt a password with PasswordCrypto
├── config/
│   └── container.php                 # DI container (PHP-DI or similar); config.yml itself is gitignored, copied here from deploy/config.yml.example for a repo checkout
├── public/
│   └── index.php                     # Slim HTTP entry point
├── src/
│   ├── Imap/
│   │   ├── ImapPoller.php            # Polls IMAP via PhpImap\Mailbox; checks UIDVALIDITY; returns (uid, uidvalidity, mime, mail: IncomingMail) tuples
│   │   ├── ImapArchiver.php          # Archives or deletes processed mails; deletes inbox mails older than 30 days
│   │   └── ImapMailboxFactory.php    # Builds/caches PhpImap\Mailbox connections per list, keyed by imap-* fingerprint; also computes absolute (top-level) IMAP folder paths — see "Archive folder path"
│   ├── Archive/                      # Web archive viewer backend — see "Archive viewer"
│   │   ├── ArchiveIndexer.php        # Writes archived_mail rows; called alongside (not from) ImapArchiver::archiveOrDelete()
│   │   ├── ArchiveThreader.php       # Pure PHP: annotates a page of rows with depth/thread_size/is_thread_start
│   │   ├── ArchiveMailLocator.php    # Re-locates a message by Message-ID in the list's IMAP archive folder ($archiveFolder), on demand
│   │   ├── ArchiveMailCache.php      # APCu cache of a fully-resolved archived mail, keyed by list+Message-ID — see "Archive mail cache — performance"
│   │   ├── CachedArchivedMail.php    # Serializable snapshot of an IncomingMail — textHtml/textPlain + CachedAttachment[]
│   │   ├── CachedAttachment.php      # Serializable snapshot of an IncomingMailAttachment, contents eagerly resolved
│   │   ├── ArchiveHtmlSanitizer.php  # HTMLPurifier config + cid: rewriting + external-resource gating
│   │   └── ByteFormatter.php         # Shared B/KB/MB/GB/TB formatting — PHP (ArchiveController) and the `formatBytes` Latte filter both use it
│   ├── Mail/
│   │   ├── MailProcessor.php         # Builds outgoing Email from IncomingMail; personalizes per recipient; enqueues
│   │   ├── HeaderFilter.php          # Reads Authentication-Results / arbitrary headers (readHeader) from raw header string
│   │   ├── IncomingMailFilter.php    # Gates incoming mail (takes IncomingMail); returns FilterResult
│   │   ├── FilterResult.php          # final class (not enum — needs per-instance reason string): discard | bounce | reject | moderation | distribute
│   │   ├── SpamFilter.php            # Global content filter from filters: in config.yml; matches subject/body/from/to via str_contains or /regex/
│   │   ├── BodyPersonalizer.php      # Replaces variables in decoded body/subject via VariableResolver
│   │   ├── FooterAppender.php        # Appends footer to symfony/mime object (always if configured)
│   │   └── SubaddressExtractor.php   # Extracts the +subaddress from an incoming mail's To/Cc relative to list->mail; used by IncomingMailFilter and MailProcessor for type: subaddress lists
│   ├── Variable/
│   │   ├── VariableResolver.php      # Static helper; VariableResolver::resolve($template, $contexts, $purpose)
│   │   ├── ResolutionPurpose.php     # Trusted | Disclosed — gates VariableResolver::BLOCKED_KEYS at resolution time; see "ResolutionPurpose"
│   │   ├── VariableFilter.php        # Applies |filter:args pipeline segments (match, lowercase, uppercase) to a resolved variable value
│   │   └── Literal.php               # Marks a context value terminal (never recursively re-resolved) — wraps sender/recipient/Member data; see "Untrusted input in {} templates"
│   ├── Config/
│   │   ├── ListConfig.php            # Typed value object; property hooks; holds MemberResolver; createContext() for resolution
│   │   ├── ConfigResolver.php        # Merges config.yml blocks: use:, priority, $VAR substitution
│   │   ├── YamlIncludeResolver.php   # Resolves !include tags (see "File includes") for config.yml and YamlListProvider files
│   │   └── Enum/
│   │       ├── ReplyToBehavior.php   # 'list' | 'sender'
│   │       ├── PostAccess.php        # 'members' | 'owners' | 'public'
│   │       ├── ModerationMode.php    # 'on' | 'off'
│   │       ├── AllowLeave.php        # 'direct' | 'moderated'
│   │       └── ArchiveMode.php       # 'members' | 'owners' | 'public' | 'hidden' | 'off'
│   ├── Member/
│   │   ├── Member.php                # Value object: email (required) + attributes (everything else, fully dynamic per resolver — see "Member attributes — fully dynamic")
│   │   ├── MemberResolver.php        # Interface: getMembers(), getOwners(), findByEmail(), removeMember()
│   │   ├── NullMemberResolver.php    # No-op implementation
│   │   ├── InlineMemberResolver.php  # Resolves from inline config.yml member lists (plain "mail@x" string or firstname/lastname/mail/username map); removeMember is no-op
│   │   ├── LdapMemberResolver.php    # Resolves via LDAP DNs; removeMember removes DN from member attribute
│   │   ├── DatabaseMemberResolver.php # SELECT * from MariaDB members-table, any non-reserved column becomes an attribute; removeMember sets is_member = 0, then deletes row if no longer member or owner
│   │   ├── CsvMemberResolver.php      # Resolves via a shared flat CSV file (name,mail,is_member,is_owner reserved, any other column an attribute); re-reads per call, flock on write, addMember extends the header on demand
│   │   └── AggregateMemberResolver.php # Searches all providers; used by AuthController
│   ├── Provider/
│   │   ├── ListProvider.php          # Interface: getLists(): ListConfig[], getList(string $name): ?ListConfig
│   │   ├── LdapListProvider.php      # Reads mailGroup objects from LDAP; uses LdapMemberResolver internally
│   │   ├── InlineListProvider.php    # Reads lists from config.yml; inline members or member-resolver; uses DatabaseConnectionFactory for DB member resolvers
│   │   ├── DatabaseListProvider.php  # Reads lists from MariaDB config-table (EAV); uses DatabaseConnectionFactory for context-based DB connection
│   │   ├── YamlListProvider.php      # Reads lists from a separate YAML file; inline members or member-resolver; uses DatabaseConnectionFactory for DB member resolvers
│   │   └── SubaddressListProvider.php # type: subaddress — subaddress forwarding; members: are unresolved templates containing {subaddress}, resolved per incoming mail; owners: resolved normally
│   ├── Database/
│   │   ├── DatabaseConnectionFactory.php # Caches PDO instances by fingerprint of db-* config keys; shared by all DB-backed providers
│   │   └── MigrationRunner.php       # Applies pending migrations/*.sql, tracked in schema_migrations — see "Database migrations"
│   ├── Smtp/
│   │   └── SmtpConnectionFactory.php # Creates/caches symfony/mailer transports per SMTP config fingerprint;
│   │                                 # closes and reopens connection when smtp-host/port/user/secure changes
│   ├── Moderation/
│   │   ├── ModerationMailer.php      # Sends moderation-request mail to owners
│   │   └── ModerationChecker.php     # Checks DB for overdue moderation items, sends reminders
│   ├── Token/
│   │   └── TokenService.php          # Signs and verifies HMAC-SHA256 tokens
│   ├── OpenIdConnect/                # Optional OIDC login — see "Authentication (OIDC)"
│   │   ├── OpenIdConnectService.php  # Thin wrapper around jumbojett/openid-connect-php (Auth Code + PKCE)
│   │   └── OidcRedirectException.php # Turns the library's header()+exit redirect into a catchable PSR-7-friendly exception
│   ├── Crypto/
│   │   ├── KeyDerivation.php          # Static helper: HKDF-SHA256 subkeys from APP_SECRET, one per purpose
│   │   └── PasswordCrypto.php         # AES-256-CBC encrypt/decrypt for IMAP/SMTP passwords
│   ├── Queue/
│   │   ├── QueueWriter.php           # Stores mail + recipients in DB; takes a batch_id (see mail_queue schema)
│   │   ├── QueueSender.php           # Reads queue; uses SmtpConnectionFactory; handles retries; discards spam-rejected batches
│   │   └── SpamRejectionDetector.php # Trusted-provider SMTP "rejected as spam" detection — see "Sending batch"
│   ├── RateLimit/
│   │   └── RateLimiter.php           # Per-sender and global rate limiting (MariaDB-backed)
│   ├── Logging/
│   │   ├── Logger.php                # Level-gated debug() wrapper around error_log() — see "Debug logging"
│   │   └── LogLevel.php              # Debug < Info < Warning < Error enum, backs Logger's threshold comparison
│   └── Http/
│       ├── Controller/
│       │   ├── AuthController.php        # Magic-link login flow, optional OIDC login, logout
│       │   ├── DashboardController.php   # Member view: subscribed lists
│       │   ├── ListController.php        # Owner manage page
│       │   ├── ListApiController.php     # Bearer-token list management API: subscribe/unsubscribe/encrypt-password
│       │   ├── ModerationController.php  # Accept/reject moderation items via API
│       │   ├── QueueController.php       # Queue status API
│       │   ├── UnsubscribeController.php
│       │   └── ArchiveController.php     # Archive viewer: index/show/frame/attachment — see "Archive viewer"
│       └── Middleware/
│           ├── AuthMiddleware.php        # Validates session, injects user identity, redirects to /_/login if absent
│           ├── OptionalAuthMiddleware.php # Like AuthMiddleware but never redirects — see "Archive viewer"
│           ├── CsrfMiddleware.php        # Validates X-CSRF-Token on state-changing requests
│           └── ApiTokenMiddleware.php    # Validates Bearer token against ListConfig::$apiToken
├── templates/
│   ├── layout.latte           # Optionally imports /app/config/custom.latte (operator-mounted, not part of this tree) — see "Custom layout"
│   ├── login.latte
│   ├── dashboard.latte
│   ├── unsubscribe.latte
│   ├── subscribe-confirm.latte
│   ├── list/
│   │   ├── index.latte
│   │   └── manage.latte
│   └── archive/
│       ├── index.latte        # Threaded table view, quick filter, pagination
│       ├── show.latte         # Single message: metadata, attachments, embeds the frame
│       ├── frame.latte        # Standalone doc for the sandboxed iframe — does NOT extend layout.latte
│       └── login_required.latte
├── translations/
│   ├── messages.de.yaml
│   └── messages.en.yaml
├── migrations/
│   └── 001_initial.sql        # includes archived_mail — see "Archive viewer"; applied automatically, see "Database migrations"
├── docker/
│   ├── Dockerfile             # php-fpm + nginx + worker, all in one image
│   ├── entrypoint.sh          # ENTRYPOINT: runs bin/migrate.php, then execs CMD (supervisord)
│   ├── compose.yaml           # Dev/build-from-source compose file
│   ├── nginx.conf             # proxies to 127.0.0.1:9000 (same container)
│   ├── supervisord.conf       # manages php-fpm, nginx, worker as three processes
│   └── php.ini                # display_errors=Off/log_errors=On — see "Security Notes"
├── deploy/                    # Simplest deployment: published image + MariaDB, no repo checkout — see "Docker Setup"
│   ├── compose.yml.example    # Flat layout — config.yml mounted from the same directory, no config/ subfolder
│   ├── .env.example
│   └── config.yml.example     # Single source of truth for the config.yml template — also used by "Building from source"
├── LICENSE
├── README.md
└── composer.json
```

---

## Environment Variables (.env)

Only secrets that must not appear in files committed to version control:

```
# database connection, referenced via 'db-*' keys in config.yml
DB_HOST=db
DB_PORT=3306
DB_NAME=database
DB_USER=user
DB_PASS=secret

# mail server, referenced in config.yml
IMAP_HOST=imap.example.org
SMTP_HOST=smtp.example.org
MAIL_PASSWORD=secret

# 32 random bytes, base64-encoded. Root secret — never used directly as a key;
# per-purpose subkeys (AES-256-CBC, HMAC-SHA256) are derived from it via HKDF,
# see Key Derivation.
APP_SECRET=base64encodedkey32bytes
```

All other configuration lives in `config.yml`. The `db-*` and mail keys are read via `$VAR` substitution in named config blocks and flow into the application through `ConfigResolver`.

---

## config.yml Structure

```yaml
# The root of config.yml is the default configuration, applied to every list. A root
# key is either:
# - 'use:' (see below), 'list-providers:', or 'filters:' — handled specially, always
#   applied, exactly as documented for each elsewhere in this file.
# - a scalar value (string/number/bool) — a direct default key-value, applied to
#   every list unconditionally.
# - a map value — a *named block*, inert unless referenced via 'use:' (here, or in a
#   list-provider's own 'use:'). Named blocks themselves may NOT contain 'use:'
#   (prevents cycles).
# $VAR syntax substitutes environment variables at parse time (before lazy resolution).
# Missing environment variables cause a hard error at startup.
# Direct root key-values take priority over values pulled in via 'use:'.
# Within 'use:', later entries override earlier ones.
# 'use:' also accepts a bare string instead of a YAML list — a single block name
# (use: mail-config), or several separated by commas/whitespace
# (use: mail-config, list-defaults) — normalized into a list the same way
# personalize:/reserved-subaddresses: are (see ConfigResolver::normalizeUse()).
# This applies at both places 'use:' is read: the config.yml root (below) and a
# list-provider's own 'use:' (see "list-providers" below) — not inside a named
# block, which may not contain its own 'use:' at all (prevents cycles).
language: de                        # 'de' | 'en' — global default, code-default is 'en' (see Internationalization)
use:
  - mail-config
  - list-defaults
  - database

# Named block — referenced via 'use:' above
mail-config:
  # mail-host sets both imap-host and smtp-host unless overridden individually —
  # shown here as two separate hosts instead, since IMAP/SMTP are often split
  # across different servers; use mail-host if yours is the same for both.
  imap-host: $IMAP_HOST
  imap-port: 993                      # default: 993
  imap-secure: ssl                    # ssl | tls | none (default: 'ssl' if imap-port is 993, else 'tls')
  smtp-host: $SMTP_HOST
  smtp-port: 587                      # default: 587
  smtp-secure: tls                    # ssl | tls | none (default: 'ssl' if smtp-port is 465, else 'tls')
  # mail-user sets both imap-user and smtp-user unless overridden individually
  # mail-password sets both imap-password and smtp-password unless overridden
  mail-user: "{list-mail}"             # lazily resolved to list mail address per list
  mail-password: $MAIL_PASSWORD       # from environment variable

# Named block — referenced via 'use:' above
list-defaults:
  reply-to: sender
  allow-leave: direct
  list-label: "[{display-name}]"
  footer: "<p>Diese Mail wurde über die Liste {display-name} verschickt. <a href=\"{list-url}\">Zur Liste</a></p>"

# Named block — referenced via 'use:' above. Database connection, used by
# DatabaseConnectionFactory for all DB-backed providers. Keys are db-host, db-port,
# db-name, db-user, db-password (note: db-password, not db-pass).
database:
  db-host: $DB_HOST
  db-port: $DB_PORT
  db-name: $DB_NAME
  db-user: $DB_USER
  db-password: $DB_PASS

list-providers:
  # A map keyed by provider name (not an array) — the name identifies the provider
  # in logs/error messages, and doubles as its 'type' if the provider sets none of
  # its own; see "list-providers — provider name as implicit type" below.
  staff:
    # type: ldap — reads lists from LDAP mailGroup objects; uses LdapMemberResolver internally
    type: ldap
    ldap-host: ldap://ldap.example.org
    ldap-base-dn: dc=example,dc=org
    ldap-bind-dn: cn=admin,dc=example,dc=org
    ldap-bind-password: $LDAP_BIND_PASSWORD
    ldap-list-dn: ou=lists,dc=example,dc=org
    ldap-filter: "(objectClass=mailGroup)"    # default: (objectClass=mailGroup)
    use:
      - my-mail-config
    reply-to: list

  # type: inline — lists defined directly in config.yml
  # members/owners can each independently be inline (overrides member-resolver
  # for that field only) or come from member-resolver; if neither is defined,
  # list has no members (no error)
  # `lists:` is a map keyed by list name (not an array with a `name:` field).
  # `list-mail` is the list's own mail address — see "list-mail" below.
  manual:
    type: inline
    list-mail: "{list-name}@example.org"   # provider-level default; per-list override wins
    member-resolver:
      type: database
      members-table: list_members   # SELECT * FROM {members-table} WHERE name = :name — any non-reserved column becomes an attribute
    lists:
      mylist:
        # list-mail resolves to mylist@example.org via the provider-level default above
        # members AND owners from member-resolver (database)
      otherlist:
        list-mail: other@example.org   # explicit per-list override
        members:                    # inline members override member-resolver for this list.
                                     # each entry is either a plain "mail@example.org" string,
                                     # or a map with mail/firstname/lastname/username.
          - alice@example.org
          - firstname: Bob
            lastname: Miller
            mail: bob@example.org
        owners:
          - mail: carol@example.org
      thirdlist:
        owners:                     # inline owners, but members still come from member-resolver
                                     # (database) since "members" is not set here at all
          - mail: dave@example.org

  # type: database — reads list names and config from MariaDB
  # config-table structure: (name VARCHAR, key VARCHAR, value TEXT)
  # lists-query: SELECT DISTINCT name FROM {config-table}
  # config-query: SELECT key, value FROM {config-table} WHERE name = :name
  db:
    type: database
    config-table: list_config
    member-resolver:
      type: ldap
      ldap-host: ldap://ldap.example.org
      ldap-base-dn: dc=example,dc=org
      ldap-bind-dn: cn=admin,dc=example,dc=org
      ldap-bind-password: $LDAP_BIND_PASSWORD
      ldap-list-dn: ou=lists,dc=example,dc=org

  # type: subaddress — subaddress-based forwarding, see "type: subaddress — subaddress forwarding"
  fwd:
    type: subaddress
    lists:
      fwd:
        list-mail: fwd@example.org
        members:
          - mail: "{subaddress}@intranet.com"   # template, resolved per incoming mail
        owners:
          - mail: admin@example.org
        post-access: owners
        reserved-subaddresses: admin,root       # optional, in addition to built-in bounce/accept-/reject-
```

### list-providers — provider name as implicit type

Every provider is required to resolve to one of the known types (`ldap`, `inline`, `database`, `yaml`, `subaddress`) — but `type:` itself doesn't have to be spelled out on every entry. `type` goes through the normal priority chain (`ConfigResolver::resolveListConfig($providerConfig)` — root `use:`/direct, then the provider's own `use:`/direct, exactly like any other config key), and if that resolves to nothing, the provider's own map key (its name) is used as the type instead. An unresolvable type (name doesn't match a known type, and no `type:` was set anywhere) is a hard error at startup — same fail-fast philosophy as a missing `$VAR` or invalid `filters:` regex.

```yaml
type: ldap   # root-level default type

list-providers:
  provider1:
    ldap-host: ldap://ldap.example.org   # no own 'type' — inherits root default: ldap
    ...
  provider2:
    type: inline                          # explicit — overrides the root default
    ...
```

```yaml
# no root-level default type this time
list-providers:
  ldap:                # no 'type' anywhere → falls back to its own name: type ldap
    ...
  inline:               # same → type inline
    ...
  foo:
    type: database       # explicit → type database
    ...
  bar:                  # no 'type' anywhere, and "bar" isn't a known provider type
    ...                  # → hard error at startup: Unknown list provider type "bar" for provider "bar"
```

### `lists:` format

For `type: inline`, `type: yaml`, and `type: subaddress`, `lists:` is a **map keyed by list name** (not an array of objects with a `name:` field). `type: database` and `type: ldap` have no `lists:` key at all — list names come from the config-table/LDAP directory instead.

### `list-mail`

The list's own mail address — one name, used both as the YAML config key you write and as the `{list-mail}` variable exposed everywhere else (no separate "input key" vs. "output variable" naming). It is a normal config key, merged through the same 5-level priority chain as any other (see "Configuration priority") and lazily resolved via the existing `VariableResolver::resolve()` — no dedicated resolver class; the provider just calls it directly with `{list-name}` (and the rest of the already-merged raw config) as context, since a `ListConfig` doesn't exist yet at this point. This lets `list-mail` be set once at provider level (or in a `use:` block) as a template, e.g. `list-mail: "{list-name}@example.org"`, and every list in that provider gets its own valid address without redefining the key per list; a per-list `list-mail:` still overrides it individually. Only `{list-name}` and other already-merged raw config keys are available while resolving it — not `{list-domain}`/`{list-url}`/`{display-name}`, which are computed *from* the resolved `list-mail` and don't exist yet.

The unresolved raw `list-mail` template is deliberately left in `$raw` as-is, not stripped — `ListConfig::createContext()` already merges its own computed `'list-mail' => $this->mail` last (see its code), so the correctly resolved value always wins over the stale raw entry with no special-casing needed.

The startup error fires only if the **fully resolved** value is empty — not merely if a list omits `list-mail` itself, since it may be inherited from a provider/default-level template. A list with no `list-mail` anywhere in its merge chain throws `\RuntimeException` (fail-fast, same philosophy as missing `$VAR`s or an invalid `filters:` regex).

`type: ldap` reads the list's address from the LDAP `mail` attribute directly (schema-mandated by the `mailGroup` objectClass, not a YAML config key) and `type: database` reads a literal per-list `mail` row from `config-table` — neither goes through this lazy-resolution path, so the templating described here is currently `type: inline`/`type: yaml`/`type: subaddress`-only.

### `description` → `list-description`

Unlike `list-mail`, this one *does* have a different name depending on which side you're looking at — deliberately. You write the short, natural key `description` everywhere a list is configured — LDAP `description[]` (`description:Some text`), the database `list_config` table (a row with `key = 'description'`), and inline/yaml `lists:` entries (`description: "Some text"`). `ConfigResolver::resolveListConfig()` renames it to `list-description` once, for every provider, right before returning the merged config (a plain key rename, not `{}` resolution, so it stays within that method's existing responsibilities). `ListConfig::$description` reads `$this->raw['list-description']`, and `{list-description}` — not `{description}` — is the variable available everywhere else (footer, subject-label, custom aliases, ...).

The rename exists specifically so the list's own description can never collide with a *member's* `description` attribute — a real, commonly-present LDAP person attribute, and just as plausible as a database/CSV column — which, since `Member::$attributes` is fully dynamic (see "Member attributes — fully dynamic"), would otherwise show up as `{description}` in the recipient context too, silently shadowing (or being shadowed by) the list's own. Same reasoning as `list-mail` vs. a member's own `mail`.

Like `$displayName`, `ListConfig::$description` is resolved as a template under `ResolutionPurpose::Disclosed` (see "ResolutionPurpose") — it is read directly in `templates/list/manage.latte`/`list/index.latte`/`dashboard.latte`, so `list-description: "{imap-password}"` must not leak that value there, and `list-description: "Announcements for {list-name}"` works as a template.

A `list-description:` key set directly (bypassing the short form) still works and takes priority if somehow both are present in the same merge. The bare `description` key never survives into the final raw config, so it is never itself resolvable as `{description}`.

### type: subaddress — subaddress forwarding

A `type: subaddress` list forwards mail sent to `{local-part}+{subaddress}@{domain}` (relative to the list's own `mail` address) to a computed target address, without an enumerable member directory. It is an ordinary list in every other respect — same IMAP mailbox, headers, subject-label, footer, moderation eligibility, personalization — only recipient resolution differs.

- No new `recipient`/`target` config key: the destination is expressed by reusing the normal inline `members:` shape (`mail`, and optionally `firstname`/`lastname`/`username`), except each value is a **template** resolved per incoming mail via `VariableResolver`, not static data resolved once at startup. Implemented by `Hengeb\Listig\Provider\SubaddressListProvider` (`ListConfig::$subaddressMemberTemplates`, non-null only for this list type) and `MailProcessor::resolveTemplateMembers()`.
- `owners:` uses the exact same inline mechanism as `type: inline`, so `post-access: owners` works identically. `type: subaddress` lists have no static `members:`, so `getMembers()` is always empty and `post-access: members` is not meaningful for them (rejects everyone).
- `{subaddress}` is a new mail-context variable — the matched extension for the current incoming mail (e.g. `alice` for `fwd+alice@example.org`), computed by `Hengeb\Listig\Mail\SubaddressExtractor` from the mail's `To`/`Cc` addresses relative to `list->mail`'s local part **and** domain (so `fwd+alice@other-domain.com` does not match). Resolves to an empty string when absent, like `{sender-firstname}` etc.
- If no `members[].mail` template references `{subaddress}` at all, the list degrades gracefully into a fixed-target alias — every mail (subaddressed or not) resolves to the same target(s), with no missing-subaddress rejection.
- Reserved subaddresses are rejected (`FilterResult::reject('reject.reserved_subaddress')`), not forwarded: `bounce` (exact — collides with the `{list-name}+bounce@{domain}` Sender header) and the `accept-`/`reject-` prefixes (collide with moderation mailto addresses) are always reserved; a list may reserve more via the comma-separated `reserved-subaddresses` key. A mail with no subaddress at all is rejected with `reject.missing_subaddress`, but only if at least one member template actually requires one (see above).

### Spam filtering (`filters:`)

Third top-level key in `config.yml`, alongside the root config and `list-providers`. Global, list-independent content filter checked by `IncomingMailFilter` for every incoming mail on every list (see "IncomingMailFilter — check order"). Implemented by `Hengeb\Listig\Mail\SpamFilter`, constructed from `ConfigResolver::getFilters()`.

```yaml
filters:
  - subject: abc                  # str_contains(strtolower($subject), 'abc') — case-insensitive
  - subject: def
  - body: xyz                     # checked against textPlain + textHtml combined
  - from: bla                     # checked against fromName + fromAddress combined
  - to: johnny                    # checked against the raw To header (names and addresses)
  - subject: /ab+$/               # /delimited/ value → preg_match instead of str_contains
  - body: /a\s*b\s*c\*s/
```

- Each entry is a single-key map; the key is one of `subject`, `body`, `from`, `to`. More than one key, or a key outside this set, is a hard error at startup (fail fast, same philosophy as missing `$VAR`s).
- The value is matched literally (`str_contains(strtolower($value), strtolower($pattern))` — case-insensitive) **unless** it looks like a delimited PCRE pattern — starts with one of `/ # ~ % !`, and the same character reappears later followed by nothing but valid regex flags (`a-zA-Z`) to the end of the string. In that case it is passed as-is to `preg_match()` (case-sensitive unless the pattern's own flags say otherwise, e.g. `/ab+$/i`). An invalid regex in that form is also a hard startup error.
- A mail matches (is spam) if **any** rule matches. On match, `IncomingMailFilter` returns `FilterResult::reject('reject.spam')` — same reject pipeline as every other reject reason: `RejectionNotifier` notifies the sender (translation key `reject.spam`, e.g. "Spam message rejected" / "Spam-Nachricht abgelehnt"), the mail is marked seen, and `ImapArchiver::archiveOrDelete()` removes it from the inbox (or archives it, unless the list has `archive: off`).
- Like every other config value, `filters:` supports `!include` (see "File includes"), so rules can be outsourced to their own file: `filters: !include filters.yml`.

### App name (`app-name`)

Root-level `config.yml` key, default `'Listig'` — the app's own display name, shown everywhere a page or mail addresses the app itself rather than a specific list (page `<title>`s, the header brand next to the logo mark, the login mail subject, the queue delivery-failure notice). Resolved via `'app.name'` in `config/container.php`, same `VariableResolver::resolve()`-backed pattern as `hostname`/`language` (see the block comment above `'app.hostname.resolved'`) — not blocked, not a credential, just a display string, so `{}` templates referencing other root keys work fine here too.

Every controller that renders a template, plus `QueueSender` (delivery-failure notice), takes `appName`/`$this->appName` accordingly:
- Templates receive it as the `appName` variable — used directly in `layout.latte`'s header/default `<title>` and every page's own `{block title}`, alongside `logo-mark.svg` in the header (see "Static assets" below).
- Translated strings that name the app take `'%app_name%' => $appName` as a `trans()` param — `auth.login_mail.subject`, `queue.failure_notice.body`, and each page-title key (`login.title`, `dashboard.title`, `unsubscribe_page.title`, `subscribe_page.title`).

This is a distinct concept from a *list's* `display-name` (see "`description` → `list-description`" for the analogous list-vs-member key-collision reasoning) — `app-name` names the whole Listig instance, not any one list.

**Static assets**: `public/logo.svg` (full wordmark) and `public/logo-mark.svg` (icon only, no baked-in text — used in the header precisely so it stays correct next to a configurable `appName` instead of always visually saying "Listig") are served directly by nginx via the `location /` fallback's `try_files` (finds the real file before falling through to `index.php`), same as anything under `public/assets/` — no route or controller involved.

### OIDC login (`oidc-*`)

Root-level `config.yml` keys, like `hostname`/`language`/`db-*` — not per-list, since the login flow itself has no list in scope until after a member is found (see `AggregateMemberResolver::findListAndMemberByEmail()`, "Authentication (OIDC)"). Entirely optional: OIDC login is only enabled — `GET /_/login/oidc` registered at all, the "Log in with Single Sign-On" button shown on the login form — when `oidc-provider-url`, `oidc-client-id`, and `oidc-client-secret` are **all** set (`'oidc.enabled'` in `config/container.php`); otherwise the route doesn't exist (`404`), same 404-if-unconfigured philosophy as the List Management API's `api-token` gate.

```yaml
oidc-provider-url: https://sso.example.org   # discovery-capable issuer — /.well-known/openid-configuration is fetched from here
oidc-client-id: listig
oidc-client-secret: $OIDC_CLIENT_SECRET

# Only needed if oidc-provider-url isn't the IdP's own public address — e.g. an
# internal Docker Compose service name/URL — and the IdP (like Authelia) derives
# and validates its issuer strictly from the request's Host header. See
# OpenIdConnectService's docblock for the full mechanism.
oidc-public-provider-url: https://sso.example.org

# Optional: only needed if the IdP has no standard, spec-compliant
# end_session_endpoint in its discovery document (RP-initiated logout is
# discovered automatically otherwise — no config needed). Used verbatim, as the
# full redirect target — Listig appends no query parameters of its own, since a
# non-standard logout endpoint (e.g. Authelia's own) may expect entirely
# different ones than the OIDC-spec id_token_hint/post_logout_redirect_uri.
oidc-logout-url: "https://sso.example.org/logout?rd=https%3A%2F%2Flists.example.org%2F_%2Flogin"
```

- Discovery-only: no separate authorization/token/userinfo endpoint keys — `jumbojett/openid-connect-php` fetches them all from `oidc-provider-url`'s `/.well-known/openid-configuration`.
- Authorization Code flow with PKCE (`S256`), scopes `openid profile email`.
- All five keys are in `VariableResolver::BLOCKED_KEYS` (see "Blocked variables") — same treatment as `ldap-host`/`ldap-bind-dn`/`ldap-bind-password`, resolved under `ResolutionPurpose::Trusted` only at the one point they're actually consumed (`OpenIdConnectService::class` in `config/container.php`).
- `oidc-public-provider-url` is used two ways in `OpenIdConnectService`: its host is spoofed into the `Host`/`X-Forwarded-Proto` headers of every backend→IdP request (so the IdP's discovery document — and the ID token's `iss` claim — reflect the public identity, not the internal address this backend actually connects to), and the token/jwks/userinfo endpoints discovery returns (now necessarily public-host-based too) are rewritten back onto `oidc-provider-url`, since only `authorization_endpoint` is ever browser-facing.
- `oidc-logout-url` — see "Authentication (OIDC)" for the full logout flow (`OpenIdConnectService::getLogoutUrl()`, `AuthController::logout()`).

### Environment variable substitution

`$VAR` in any config value is replaced with the corresponding environment variable at parse time, before lazy variable resolution. This allows secrets to live in `.env` while everything else is in `config.yml`.

- `$VAR` or `${VAR}` syntax supported
- `$VAR`/`${VAR}` may appear anywhere within a string value, not just as the entire value — including nested inside a `{}` template's filter args, e.g. `mail-user: "{list-mail|default:$MAIL_USER}"` or `display-name: "System ({$HOSTNAME})"`. Substitution (`ConfigResolver::substituteEnvVars()`, a brace-aware `preg_replace_callback`) replaces only the `$VAR`/`${VAR}` token itself, leaving the rest of the string — including any surrounding `{...}` — untouched.
- If the environment variable is not set: hard error at startup, do not silently use empty string
- Substitution happens on raw string values only, before `{}` variable resolution
- All config levels support `$VAR` substitution: named blocks, the config.yml root, `list-providers`, and LDAP `description[]` values

### File includes (`!include`)

Any YAML value in `config.yml` (and in `type: yaml` list-provider files, see `YamlListProvider`) can be replaced by the contents of another YAML file, e.g. to move a list's inline members into their own file:

```yaml
list-providers:
  main:
    type: inline
    lists:
      mylist:
        list-mail: mylist@example.org
        members: !include members/mylist.yml
```

- Resolved by `Hengeb\Listig\Config\YamlIncludeResolver` at parse time — before `$VAR` substitution, `use:`/priority merging, and any `{}` variable resolution. The included file's parsed content is spliced into the tree at that node, exactly as if it had been written inline.
- The path is resolved relative to the directory of the file containing the `!include` tag, not always relative to `config.yml` — an included file may itself use `!include`, and paths inside it are relative to its own directory. An absolute path (starting with `/`) is used as-is.
- Circular includes are a hard error at parse time (detected via `realpath`).
- Any other custom YAML tag (e.g. `!foo`) is a hard error — `!include` is the only one supported.
- `YamlListProvider`'s list file goes through the same resolver, so a `type: yaml` provider's `lists:` (or a single list's `members:`/`owners:`) can also be split into separate files.

### Configuration priority (low → high)

0. Code defaults (lowest — ensures keys always have a value; can be overridden at any level)
1. `use:` blocks at the config.yml root (in order; later entries override earlier)
2. Direct key-values at the config.yml root
3. `use:` blocks in `list-provider` (merged; do not override direct root-level values)
4. Direct key-values in `list-provider` (override everything from 1–3)
5. Per-list key-values from the provider (LDAP: `description[]`; database: `config-table` rows; inline: list-level keys) — highest priority

### Key value states

Three distinct states for any key:
- **Not present**: code default is used
- **Empty string** (`key:` with no value, or `key: ""`): explicitly set to empty string — overrides any default including code defaults (e.g. disables footer)
- **Non-empty value**: used as-is

This distinction must be preserved through the entire merge chain. Use `null` internally for "not present" and `''` for "empty string".

### Variable substitution

Variables use `{key}` syntax and are resolved **lazily** — at point of use, with the fully merged configuration of the specific list and (where applicable) the current mail being processed.

#### Always-available variables (list context)

| Variable | Value |
|---|---|
| `{list-name}` | Internal list identifier, set by the provider (LDAP: `cn`) |
| `{list-mail}` | List email address |
| `{list-domain}` | Domain part of the list email address |
| `{hostname}` | Hostname of the Listig server — the `hostname` config key, or `gethostname()` if unset (see "Docker Setup" — set this explicitly in any real deployment) |
| `{display-name}` | `display-name` config value, falls back to `{list-name}`; alias: `{list-display-name}` |
| `{list-url}` | `https://{hostname}/{list-name}` — link to the list manage page |
| Any other config key | Its resolved value |

#### Mail-context variables (available while processing an incoming mail)

These are available in `smtp-from-name` and similar fields that describe the outgoing mail:

| Variable | Value |
|---|---|
| `{sender-name}` | Display name from `From:` header; falls back to `{sender-firstname} {sender-lastname}`; falls back to localpart of sender address |
| `{sender-mail}` | Sender email address |
| `{sender-` + any attribute`}` | Every key in the sender `Member`'s `$attributes`, prefixed `sender-` — e.g. `{sender-firstname}`, `{sender-employeeNumber}` for an LDAP sender. See "Member attributes — fully dynamic"; nothing beyond `sender-mail` is fixed |
| `{subaddress}` | The `+subaddress` portion of the incoming mail's recipient address relative to `{list-mail}`'s local part and domain, e.g. `alice` for `fwd+alice@example.org`; empty string if the mail had none. Used by `type: subaddress` lists (see "type: subaddress — subaddress forwarding"), but computed for every list |

Example use: `smtp-from-name: "{sender-name} (via {display-name})"` — produces e.g. `Alice Müller (via Projektliste)` in the From header.

#### Recipient-context variables (available during personalization per recipient)

Only substituted when key is in `personalize` whitelist (plus `{list-url}` which is always available):

| Variable | Value |
|---|---|
| `{mail}` | Recipient's email address |
| Any attribute | Every key in the recipient `Member`'s `$attributes`, under its own name — e.g. `{firstname}`, `{pronoun}`, `{employeeNumber}` for an LDAP recipient. Nothing beyond `mail` is fixed; a key a specific member doesn't have resolves to an empty string rather than leaking `{key}` literally — see "Member attributes — fully dynamic" |

#### Custom variables

Any key in the config whose value references another variable is a custom alias:
```yaml
vorname: "{firstname}"
```
Makes `{vorname}` available. Resolved recursively with cycle detection (tracked via visited keys; on cycle: log error, leave literal).

#### Filters

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

#### Member attributes — fully dynamic

`Member` has exactly one fixed field: `$email`. Everything else a resolver happens to know about a member — `firstname`, `lastname`, `username`, `pronoun`, an LDAP `employeeNumber`, a custom `title` column/key, anything — lives in `Member::$attributes` (`array<string, string>`), keyed by whatever name the backing store itself uses. **Nothing beyond `email` is hardcoded in `Member` or any resolver** (`is_member`/`is_owner`/`name` are reserved too, but structurally — they scope/filter rows, they never become attributes):

- **`type: database`**: `DatabaseMemberResolver` does `SELECT *` and exposes every column except `name`/`mail`/`is_member`/`is_owner` as an attribute. Add, rename, or remove columns in `list_members` freely — no code change needed. `addMember()` builds its `INSERT`/`ON DUPLICATE KEY UPDATE` column list dynamically from `Member::$attributes`; attribute names are validated as plain SQL identifiers (`^[A-Za-z_][A-Za-z0-9_]*$`) and backtick-quoted before being interpolated — this is what prevents SQL injection via a malicious attribute name, since PDO placeholders only cover values, not column names. An attribute naming a column that doesn't actually exist in the table still fails, just at the database (unknown column).
- **`type: csv`**: `CsvMemberResolver` exposes every CSV column except `name`/`mail`/`is_member`/`is_owner` as an attribute — whatever the file's header row currently has. `addMember()` extends the header with any new attribute key it's asked to write, backfilling `''` for every other row (see "CSV member file format").
- **`type: inline`**: every key in a `members:`/`owners:` entry except `mail` becomes an attribute verbatim (`InlineMemberResolver::toMember()`).
- **`type: ldap`**: `LdapMemberResolver` exposes *every* attribute of the directory entry (`Entry::getAttributes()`, first value of each) except `mail`, under its own LDAP name — `{cn}`, `{givenName}`, `{sn}`, `{employeeNumber}`, `{businessCategory}`, whatever the schema has. There is no translation to `firstname`/`lastname`/`pronoun` — a list defines its own mapping as a normal config key, e.g.:
  ```yaml
  firstname: "{givenName}"
  lastname: "{sn}"
  pronoun: "{businessCategory}"
  ```
  Since these are just config keys, they go through the standard 5-level priority merge (see "Configuration priority") and are resolved lazily like any other `{}` template — settable once at the config.yml root, at list-provider level, or per list, exactly like `list-mail`'s provider-level default. One exception: `LdapMemberResolver` additionally copies `cn` into `attributes['username']` — see "Privacy-preserving `username`" below.

**Resolution** (`MailProcessor::buildRecipientContext()`/`buildMailContext()`): `$recipient->attributes` (or, for the sender, `$senderMember->attributes` prefixed `sender-`) is exposed directly under each key's own name, with the canonical `mail`/`sender-mail` always set last so it can never be shadowed by a same-named attribute. A key a specific member simply doesn't have is absent from that member's context — the merge then falls through to whatever the list config defines for that key (e.g. a `pronoun: "{businessCategory}"` alias), and if nothing resolves it at all, `VariableResolver::resolve()` substitutes an empty string rather than leaking raw `{key}` syntax into a sent mail (see "Variable substitution").

A member with its own explicit attribute value therefore always takes precedence over a list-level alias for that same key — the alias is purely a fallback for providers (chiefly LDAP) that have no dedicated field of their own under that name.

##### Example: pronoun-based salutation

Turn a short code like `he`/`she` into a language-appropriate greeting via the `match` filter, chained with `default` for anyone with no pronoun set (see "Filters"): `personalize: pronoun,firstname` plus body text `{pronoun|match:he=>Lieber,she=>Liebe|default:Hallo} {firstname}`. For `type: database`/`csv`/`inline`, populate a `pronoun` column/key directly. For `type: ldap`, map it from whatever attribute the directory actually has, e.g. `pronoun: "{businessCategory}"`.

##### Privacy-preserving `username`

Two call sites need a non-email identifier for privacy — `MailProcessor` embeds it (instead of the raw address) in unsubscribe tokens and the `X-Original-Sender` header, and `AuthController` in login tokens — via `$member->attributes['username'] ?? $member->email`. For `type: database`/`csv`/`inline`, this is just another attribute like any other (populate a `username` column/key if wanted) — optional, with the same email fallback as any provider that doesn't set it, unchanged from before `Member` was genericized. For `type: ldap`, `LdapMemberResolver` is the **one deliberate exception** to full genericity: it duplicates `cn` into `attributes['username']` in addition to exposing it as `{cn}` under its real name. This exists specifically because `AuthController`'s initial email lookup has no *bounded* list in scope — `AggregateMemberResolver::findListAndMemberByEmail()` searches across every list a user might belong to before any one list is known, so the `username` convention can't rely on a per-list alias the way `pronoun` does — without this one hardcoded convention every LDAP-backed login/unsubscribe/reply would silently embed the plain email address instead. (Once a match is found, `AuthController` does have that one list in scope — it uses it to send the login mail through the list's own SMTP config, see "Authentication (Magic Link)" — the lookup phase itself is what's genuinely list-agnostic.)

**Why LDAP and not the other three:** this isn't arbitrary — `cn` is a schema-guaranteed field (a required attribute on the person object classes Listig expects), so copying it is reliable. Database/CSV/inline schemas are entirely operator-defined; there is no equivalent field to auto-derive a `username` from the way `cn` provides one for LDAP, so requiring one would mean rejecting any member row that doesn't happen to have a `username` column/key populated — a new, stricter requirement those three never had, for no clear benefit. An operator who wants the same privacy protection for a database/CSV/inline-backed list simply populates a `username` column/key themselves.

#### Blocked variables

Never substituted in any context, even via custom aliases:
`password`, `mail-password`, `imap-password`, `smtp-password`, `ldap-bind-password`, `db-password`, `api-token`, `mail-user`, `imap-user`, `smtp-user`, `mail-host`, `imap-host`, `imap-port`, `imap-secure`, `smtp-host`, `smtp-port`, `smtp-secure`, `db-host`, `db-port`, `db-name`, `db-user`, `ldap-host`, `ldap-base-dn`, `ldap-bind-dn`, `ldap-list-dn`, `oidc-provider-url`, `oidc-client-id`, `oidc-client-secret`, `oidc-public-provider-url`, `oidc-logout-url`

---

## LDAP Structure

Lists are stored as `mailGroup` objects. This objectClass provides the `mail` attribute.

```
dn: cn=mylist,ou=lists,dc=example,dc=org
objectClass: mailGroup
cn: mylist
mail: mylist@example.org
member: uid=alice,ou=users,dc=example,dc=org
member: uid=bob,ou=users,dc=example,dc=org
owner: uid=carol,ou=users,dc=example,dc=org
description: reply-to:sender
description: personalize:firstname,username
description: archive:members
```

Member and owner DNs are resolved to email addresses and display names via `LdapService`.
All other components receive a `ListConfig` object — they have no knowledge of LDAP.
IMAP password stored encrypted: `password:base64(iv):base64(ciphertext)`.

Multiple `list-providers` are supported. If the same list `cn` appears in more than one provider, behaviour is undefined.

### LDAP description[] keys

Each `description` value is a `key:value` string. These have the highest priority (level 5).

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
| `description` | string | Optional list description shown in UI. Renamed to `list-description` on ingest by `ConfigResolver::resolveListConfig()` (applies to every provider, not just LDAP) — see "`description` → `list-description`" |
| `reply-to` | `list` \| `sender` | Reply-To behavior |
| `post-access` | `members` \| `owners` \| `public` | Who may post (default: `members`) |
| `moderation` | `on` \| `off` | Whether posts require owner approval |
| `allow-leave` | `direct` \| `moderated` | Unsubscribe behavior |
| `archive` | `members` \| `owners` \| `public` \| `hidden` \| `off` | Archive instead of delete after processing, and who may view it in the web archive viewer — see "Archive access levels" (default: `off`) |
| `archive-folder` | string | Name of the IMAP folder archived mail is moved into (default: `Archive`), created as a top-level folder (sibling of INBOX) if it doesn't exist yet — see "Archive folder path" for why this needs its own explanation. Only relevant when `archive` is not `off` |
| `max-per-sender` | integer | Rate limit: max mails per sender per 10 min (default: 5) |
| `max-size` | size string or integer | Max accepted mail size (default: `5M`). Accepts `5M`, `5MB`, `5MiB`, `5K`, `5KB`, `5KiB`, `5G`, `5GB`, `5GiB`, or plain bytes. Converted to bytes in `ListConfig`. |
| `list-label` | string | Prepended to subject as `$listLabel $subject` if not already present (case-insensitive) |
| `footer` | HTML string | Footer appended to every distributed mail. Empty string disables footer. |
| `personalize` | comma-separated keys, `off`, or empty | Whitelist of recipient-context variables allowed in body/subject |
| `log-level` | `debug` \| `info` \| `warning` \| `error` | Log verbosity for this list (inherits global default) |
| `language` | `de` \| `en` | Locale for this list's outgoing mails and manage page (inherits global default, code-default `en`) — see Internationalization |
| `api-token` | string | Bearer token for the list-management API (plaintext — see "List Management API"). Empty/absent = API disabled for this list |
| `public-subscribe` | `on` \| `off` | Whether `POST /{listname}/subscribe` accepts unauthenticated requests (default: `off`) — see "List Management API" |

### Archive access levels

`archive` (`ArchiveMode` — `src/Config/Enum/ArchiveMode.php`) replaced an earlier plain `on`/`off` boolean. Four of the five values archive the mail identically at the IMAP level — `ImapArchiver::archiveOrDelete()` moves the raw original into the list's archive folder (`$archiveFolder`, see "`archive-folder`" above) on its own IMAP mailbox instead of deleting it — and differ only in who may view it through the web archive viewer (see "Archive viewer" below):

- `members` — visible to list members (and owners)
- `owners` — visible to owners only
- `public` — visible to anyone, no login required
- `hidden` — archived, but exposed to no one via the UI, not even the owner — a retention-only mode (compliance/backup) distinct from `off`, which doesn't keep the mail at all
- `off` (default) — not archived; deleted after processing, as before

### Archive folder path

`ImapArchiver::archiveOrDelete()` creates the archive folder (if it doesn't exist) via `PhpImap\Imap::createmailbox()` directly with a fully-qualified `{host:port/imap/secure}FolderName` path built by `ImapMailboxFactory::getAbsoluteFolderPath()` — deliberately **not** via `PhpImap\Mailbox::createMailbox($name)`. The reason is a real bug this fix replaced: `Mailbox::createMailbox()` resolves `$name` *relative to whichever mailbox is currently selected* on that `Mailbox` instance — and every `Mailbox` this app hands out is always connected with `INBOX` selected (`ImapMailboxFactory::createMailbox()`'s own connection string always ends `.../imap/ssl}INBOX`) — so `createMailbox('Archive')` actually created a folder *nested under INBOX* (`INBOX.Archive` on a `.`-delimited server), not a top-level one. `Mailbox::moveMail($uid, $folder)` (used right after, to actually move the mail there) and `Mailbox::switchMailbox($folder)` (used by `ArchiveMailLocator::find()` to view it, with its own default `$absolute = true`) both target the **top-level** folder name unprefixed — so the folder that got created and the folder those two methods looked for were never the same one, and every single archive attempt failed with `imap_mail_move()`'s `"Could not move messages!"`, even though the (wrong, nested) folder visibly existed on the server. Building the correct absolute path once in `ImapMailboxFactory` (shared with nothing else needing it, currently) and creating it via the low-level `Imap::createmailbox()` call sidesteps `Mailbox`'s relative-path assembly entirely, matching what `moveMail()`/`switchMailbox()` already expected.

### Archive viewer

Routes (`Http/Controller/ArchiveController.php`), all registered outside the blanket-`AuthMiddleware` group (`public/index.php`) under `OptionalAuthMiddleware` (`Http/Middleware/OptionalAuthMiddleware.php` — like `AuthMiddleware` but never redirects; exposes `$_SESSION['user']` or `null` as the `user` request attribute and lets the controller decide). Whether login is required at all depends on the specific list's `archive` value, which isn't known until the controller resolves `{listname}` — a per-list decision `AuthMiddleware`'s blanket redirect can't express at route-group level:

| Method | Path | Access |
|---|---|---|
| GET | `/{listname}/archive` | Threaded table view, quick filter, pagination (1000/page) |
| GET | `/{listname}/archive/{id}` | Single message: metadata, attachment list, embeds the frame |
| GET | `/{listname}/archive/{id}/frame` | Sanitized HTML body, sandboxed — see below |
| GET | `/{listname}/archive/{id}/attachment/{index}` | Attachment download / inline embed |

`{id}` is `archived_mail.id` (surrogate PK), not an IMAP UID. `ArchiveController::checkAccess()` (single method, all 4 actions): `Off`/`Hidden` → 404 for everyone including the owner; `Public` → always allowed; `Members`/`Owners` → requires a session (else a translated "please log in" page, HTTP 401 — no return-URL redirect-back, since the magic-link login flow has no "next" concept to hook into) and `isMember()`/`isOwnedBy()`.

**Index (`archived_mail` table, `migrations/001_initial.sql`)** — populated by `Archive/ArchiveIndexer.php`, called *alongside*, not from within, `ImapArchiver::archiveOrDelete()` — only at the 3 call sites representing a successful distribute (`bin/worker.php`'s `isDistribute` branch, `ModerationController::accept()`, `ModerationResponseHandler::processAccept()`). Deliberately not inside `archiveOrDelete()` itself: that method also runs for bounce/reject outcomes, which were never sent to the list and must not appear in a member-facing archive. Keyed by `message_id` (not `imap_uid`/`imap_uidvalidity` like `moderation_queue`/`imap_seen`) — an IMAP UID is scoped per folder, and archiving moves the mail from INBOX into the archive folder, where it gets a new UID `ImapArchiver` never learns; `Message-ID` is the only stable key. `ArchiveIndexer::normalize()` strips the value's `<>` before storing it, so `archived_mail.message_id` is always the bare id. `Archive/ArchiveMailLocator.php` re-locates the actual body/attachments on demand (`switchMailbox($list->archiveFolder)`, then a linear scan — see below) whenever a single message is opened — the index table only ever serves the list/thread view, never mail content. Both a genuinely missing message and an IMAP-level failure degrade to "mail unavailable" for the current request (rather than a 500), but the two are no longer indistinguishable to the caller: `find()` throws `Archive\ArchiveMailNotFoundException` specifically when a full, successful `SEARCH ALL` scan completed without a match (logged there) — i.e. the mail is confirmed gone from the archive folder, not just unreachable right now — while every other failure (connect/search/fetch exception) still just logs and returns `null`, same as before. `ArchiveController::locateMail()` catches that specific exception and calls `ArchiveIndexer::remove($list->name, $messageId)`, deleting the now-stale `archived_mail` row — so a mail deleted straight from the IMAP archive folder (outside Listig, e.g. by an operator or another mail client) also disappears from the list/thread view, not just the single-message page. This happens lazily, the moment a viewer actually opens that message (`show()`/`frame()`/`attachment()` → `locateMail()`) — there is deliberately no periodic job re-checking every indexed row against IMAP; a mail nobody re-opens keeps its index row until someone does. A transient IMAP outage must never trigger this — that's exactly why the exception is only thrown after a *successful* search that legitimately found nothing, not on a connection/search/fetch failure.

**Finding a message by Message-ID (`ArchiveMailLocator::findUidByMessageId()`)** — deliberately `SEARCH ALL` + `FETCH OVERVIEW` (`Mailbox::getMailsInfo()`, whose `message_id` field is exactly the header value, brackets included) rather than IMAP `SEARCH HEADER Message-ID "<...>"`, which was the first approach tried and reliably fails against at least one real deployment (`mail.hengeb.de`) with `"Unknown search criterion: HEADER"` — confirmed by connecting to the actual server: `SEARCH ALL` and `FETCH OVERVIEW` both work fine there, only the `HEADER` search key is unimplemented, even though it's part of the base IMAP4rev1 spec (RFC 3501). `SEARCH`/`FETCH OVERVIEW` calls pass `$disableServerEncoding = true` throughout, to also avoid a *second*, independent failure mode seen along the way: `Mailbox::searchMailbox()` otherwise sends a CHARSET argument (the server's own encoding) to `imap_search()`, which some servers reject outright regardless of the search criteria used. The linear scan over every message's overview is only ever triggered by a single-message lookup (opening one archived mail in the web viewer), not a bulk operation, so its cost is acceptable for a single call — see "Archive mail cache — performance" below for why it's now rarely called more than once per mail at all, regardless of how many separate HTTP requests one page view fires.

**Archive mail cache — performance (`Archive/ArchiveMailCache.php`, `CachedArchivedMail`, `CachedAttachment`)** — opening one archived mail in the web viewer is not one HTTP request: `show()`, `frame()`, and one `attachment()` request per embedded/downloadable attachment each hit `ArchiveController` independently, and `public/index.php` builds a brand new container (so a brand new `ImapMailboxFactory`, no connection reuse) on every single one of them — see "Worker loop — config reload" for why the web side has no cross-request connection cache the way the worker does. Measured live against a 20-message archive folder: `ArchiveMailLocator::find()` (IMAP connect + `switchMailbox()` + the `SEARCH ALL`/`FETCH OVERVIEW` scan above + `getMail()`) costs ~550ms **per call** — paid again, in full, by every one of those separate requests for the exact same mail.

`ArchiveController::locateMail()` wraps `ArchiveMailLocator::find()` with `ArchiveMailCache`, an APCu-backed cache keyed by list + Message-ID (SHA-256'd into the key, TTL 300s). On a cache miss, it doesn't just cache the outcome of the locate step — it eagerly resolves *everything* `show()`/`frame()`/`attachment()` need while the IMAP connection `find()` just opened is still live: every attachment's `getContents()` is called immediately (not lazily on demand, which is impossible for a cached value anyway — see below) and the result, along with `textHtml`/`textPlain`, is packed into a `CachedArchivedMail` (holding `CachedAttachment[]`, one per attachment) and stored. A subsequent request for the same mail — from any user, not just the one who triggered the cache miss, since APCu is shared memory across every php-fpm worker in the container — reads the cached snapshot and touches IMAP not at all. Measured live: the same 20-message-folder mail dropped from ~550-600ms per request to **under 5ms** on a cache hit.

Why a *snapshot* (`CachedArchivedMail`/`CachedAttachment`) rather than caching the `PhpImap\IncomingMail` object itself: `IncomingMailAttachment`'s lazy `getContents()` works by holding a `DataPartInfo` that in turn holds a live reference to the `PhpImap\Mailbox`/IMAP connection that produced it — a fetch happens *on the connection* the moment `getContents()` is called, not before. That connection is a PHP resource; it cannot survive `apcu_store()`'s internal serialization, and even if it silently didn't error, it would already be closed (the request that opened it has long since finished) by the time a *different* request tried to read from a cached attachment. `CachedAttachment` sidesteps this by resolving `$contents` to a plain string once, at cache-population time, while the connection is still open — everything downstream (`ArchiveHtmlSanitizer`, `show.latte`) reads plain data with no IMAP dependency left at all. `CachedAttachment` deliberately mirrors `IncomingMailAttachment`'s public property names (`name`/`mimeType`/`sizeInBytes`/`disposition`/`contentId`) so neither `ArchiveHtmlSanitizer` (duck-types `->disposition`/`->contentId`) nor `show.latte` (`->name`, `->sizeInBytes|formatBytes`) needed any change — only `ArchiveController`'s own two remaining property-vs-method differences (`->contents` instead of `->getContents()`, and a plain array instead of `->getAttachments()`) do.

An earlier version of this cache used `$_SESSION` (keyed the same way, but storing only the resolved IMAP UID as a fast-path hint, not the full content) — replaced with APCu specifically because a session-file cache (a) only benefits the one browser session that populated it, not every other viewer of the same mail, (b) writes to disk by default (PHP's file-based session handler), which this codebase otherwise deliberately avoids doing with mail content, and (c) needs its own cleanup story, whereas APCu's per-entry TTL expires it automatically with nothing to ever clean up. `ArchiveMailCache` degrades to "always miss, never store" — never a fatal error — if the `apcu` extension isn't loaded or isn't enabled for the current SAPI (`apcu_enabled()`; disabled for CLI unless `apc.enable_cli=1`, set in `docker/php.ini` alongside a `shm_size` raised from the 32M default to comfortably hold eagerly-cached attachment bytes, not just HTML).

`in_reply_to`/`references` are not parsed by php-imap — `HeaderFilter::readHeader()` (generalized from the extraction `MailProcessor` already did for outgoing threading headers) pulls them from `headersRaw` via unfold+regex, same as everywhere else in this codebase. `thread_root` = first Message-ID in `References`, else `in_reply_to`, else the message's own id (see "Archive index" above) — a grouping key, not necessarily an archived row itself.

**Threading (`Archive/ArchiveThreader.php`, pure PHP, no DB access)** — annotates an already-SQL-sorted page with `depth`/`thread_size`/`is_thread_start`. The list query anchors each thread's position by its *most recent* message (`ORDER BY MAX(mail_date) per thread_root DESC, mail_date ASC within`), so a thread with a new reply bubbles toward the top of the newest-first page, and pagination only ever cuts a thread at its edges (never splits it internally within one page's boundary maths). `depth` is resolved by matching `in_reply_to` against `message_id` of other rows **on the same page only** — a row whose parent isn't present there is simply depth 0 (still grouped under the same `thread_root`), not an error. The table/thread-toggle/quick-filter/per-thread-collapse interactions in `templates/archive/index.latte` are all client-side vanilla JS over `data-*` attributes on each `<tr>` — zero network round-trips, consistent with the app's existing minimal-JS house style (`templates/list/manage.latte`). The per-thread expand/collapse control is an inline SVG chevron (`.chevron`), not a swapped-text character (▶/▼) — CSS alone rotates it 90° via `.thread-expand[aria-expanded="true"] .chevron`, so `toggleThread()`/`toggleThreading()` only ever need to flip the `aria-expanded` attribute, not also keep a second, redundant text glyph in sync with it.

**Rendering (`Archive/ArchiveHtmlSanitizer.php`)** — `ezyang/htmlpurifier` (`Cache.DefinitionImpl = null`, no new writable dir beyond the existing `/tmp/latte` precedent) with a fixed small tag/attribute allowlist (`HTML.Allowed`) — `<script>`, `<style>`, `<iframe>`, `<form>`, event handlers, `javascript:` URIs, `srcset`, and `<source>`/`<video>`/`<audio>`/`<picture>` are simply absent from it, so they're stripped outright with no separate blocklist to maintain; `style` is allowed only with a small safe CSS property allowlist (`CSS.AllowedProperties`). `cid:` references are rewritten to the attachment endpoint *before* purification (HTMLPurifier has no built-in "cid" URI scheme, and a pre-processing rewrite is simpler than teaching it one) — always, regardless of the images toggle below, since they're part of the mail's own MIME structure we host, not a third-party fetch. The result is rendered inside `<iframe sandbox>` (bare `sandbox`, no `allow-same-origin`/`allow-scripts`) at the `/frame` route, which also carries its own strict `Content-Security-Policy` header independent of the outer page. Because the sandbox has no `allow-scripts`, "load external images" (off by default — only `img[src]` survives the allowlist to begin with, so nothing else needs gating) cannot be a script-driven DOM mutation: the **outer** (trusted) page's plain button changes the iframe's `src` to add `?loadImages=1`, triggering a full server re-render — no JS ever runs inside the sandboxed content boundary. `frame()`'s CSP `img-src` is *not* a fixed `'self'` — it widens to `'self' https: http:` exactly when `$loadImages` is true, matching what `stripExternalResources()` actually left in the HTML; a fixed `'self'` here silently blocked every off-origin image the "load images" button was supposed to unlock, independent of `stripExternalResources()` correctly leaving them in place.

**Two independent obstacles for `<img>` tags fetched from *inside* the sandboxed frame** (both cid: rewrites and, once `loadImages` is on, external images) — neither is about the image host itself:
1. **Session cookie**: `sandbox` with no `allow-same-origin` gives the iframe's content a unique *opaque* origin, so any request it makes itself — including these `<img src>` loads — carries no cookie at all, regardless of the viewer's own login. For an off-origin image this is irrelevant (no cookie was ever going there), but for a cid:-rewritten same-origin attachment URL it meant `ArchiveController::attachment()`'s own `checkAccess()` always saw a logged-out request and returned `401`, even though the *outer* page's `frame()` request (a normal, non-sandboxed navigation) had already proven access to this exact mail moments earlier. Fixed with a short-lived (`ARCHIVE_ATTACHMENT_TOKEN_MAX_AGE`, 10 min), `archive-attachment`-purpose `TokenService` token scoped to `($list->name, $archivedMailId)`: `frame()` signs one per render and `ArchiveHtmlSanitizer::rewriteCidReferences()` appends it as `?token=...` to every cid: URL it emits; `attachment()` accepts it as a fallback grant only when the normal session-based `checkAccess()` fails, so a plain browser navigation to an attachment link (from `show.latte`, outside the sandbox) still works exactly as before, on the session alone.
2. **Random per-parse attachment ids**: see `ArchiveController::indexAttachmentsByPosition()`'s docblock — `IncomingMailAttachment::$id` (`PhpImap\Mailbox`'s `bin2hex(random_bytes(20))`) is never the same across the separate `getMail()` calls `show()`/`frame()` and `attachment()` each make (via `ArchiveMailLocator`, which caches nothing across requests by design), so using it as the `{index}` URL segment could never resolve — every attachment link or cid: image 404'd unconditionally, regardless of whether the referenced attachment genuinely existed. Fixed by re-keying `getAttachments()` by array position (`array_values()`) instead, which — unlike the random id — is stable: the same raw message always parses its MIME parts in the same order.

**Attachments** — served from `CachedAttachment::$contents`, eagerly fetched once per `ArchiveMailCache` entry rather than live from IMAP on every request (see "Archive mail cache — performance" below; the underlying `IncomingMailAttachment::getContents()` call is still what actually performs each fetch, just moved to cache-population time). `X-Content-Type-Options: nosniff` always, plus `Content-Disposition: inline` whenever `ArchiveController::isSafeInlineContent()` verifies the content — deliberately *regardless* of the mail's own claimed disposition (cid-embedded or a plain attachment are treated the same, see below), on a small whitelist (`INLINE_SAFE_MIME_TYPES`: `png`/`jpeg`/`gif`/`webp`/`pdf` — deliberately not `svg`, which can carry scripts). The claimed MIME type alone is never trusted: images are re-verified via `getimagesizefromstring()` (decodes and reports the real format), PDF via its `%PDF-` magic-bytes header (no lightweight PHP PDF decoder exists, but that prefix is specific enough that an accidental false-positive on a mislabeled non-PDF is implausible). Everything else is forced `attachment` regardless of what the mail claims — and every attachment link in `show.latte` carries `target="_blank" rel="noopener"`, so a safe-inline file opens in a new tab instead of triggering a download prompt, while an unsafe one still downloads (the browser, not this app, decides based on the response headers).

**Attachment list (`show.latte`, above the mail body, not below)** — a single attachment shows its name and size directly; two or more collapse into a `<details>` summary (`archive.show.attachments_summary`, "*N* attachments (*total size*)") that expands to the full per-file list, name and size each. Sizes come from `IncomingMailAttachment::$sizeInBytes` — populated from the MIME `BODYSTRUCTURE`'s own byte count during the normal `getMail()` parse, so listing sizes never needs a separate content fetch. Formatting (`Archive/ByteFormatter.php`, B/KB/MB/GB/TB) is shared between PHP (the collapsed summary's `%size%` param) and Latte (the `formatBytes` filter, registered in `config/container.php`, per-file sizes) — one rule, not two independently-maintained ones.

**Image previews (`show.latte`, below the mail body)** — a second, separate rendering of just the image-typed attachments (`$imageAttachments`, filtered by `str_starts_with($attachment->mimeType, 'image/')` — a UI hint only, not the security-relevant check; that's `isSafeInlineContent()`, applied independently when the browser actually requests the file), each as a bordered thumbnail box (filename + `<img>` pointing at the same `/attachment/{index}` URL) linking to the full attachment. This is intentionally separate from the summary list above — a purely visual complement, not a replacement — and only ever includes non-cid attachments; images already shown inline in the body via a `cid:` rewrite are excluded from both (`ArchiveController::isEmbeddedInline()`), since showing those a second time would be redundant.

**"Load external content" is a real notice, not just a bare button** (`show.latte`'s `.notice` box, modeled on Roundcube's/Thunderbird's own wording) — a warning icon, an explanatory sentence (`archive.show.external_content_notice`), and the action button (`archive.show.load_images`, labelled "Erlauben"/"Allow") together, rather than a button alone with no context for why images are missing. Clicking it removes the notice and reloads the iframe with `?loadImages=1`, same underlying mechanism as before. The notice only renders when `$hasExternalContent` is true (`ArchiveController::show()` computing it via `ArchiveHtmlSanitizer::hasExternalResources()`, gating a `{if}` in `show.latte`) — it previously rendered unconditionally under every mail regardless of whether it actually had any off-origin image to block, which was misleading for a plain-text-only mail or an HTML one with no external images at all (confirmed live against the archived test mails: only the one containing an actual external image showed the notice after the fix, the rest didn't). `hasExternalResources()` runs the same cid:-rewrite + HTMLPurifier pass `render()` does (so a `cid:`-embedded image is never mistaken for external — `isExternal()`'s `^(https?:)?//` pattern doesn't match `cid:` anyway) and then scans for any off-origin `img[src]`/`[srcset]`, sharing the DOM-walk (`findExternalImages()`) with `stripExternalResources()` rather than duplicating it — both operate on the *same already-parsed* `\DOMElement` tree in `stripExternalResources()`'s case (parsing once, finding, then mutating and calling `saveHTML()` on that one tree), since re-parsing a second copy just to search it would return elements belonging to a different tree than the one about to be saved.

**HTML/plain-text toggle** (`show.latte`, only rendered when `$hasPlainAlternative` is true — i.e. the mail actually has *both* parts, computed in `ArchiveController::show()`) — two pill buttons reload the iframe with `?view=html` / `?view=text`; `ArchiveHtmlSanitizer::render()`'s new `$view` parameter forces the plaintext branch even when `$textHtml` is present, the one deliberate override of its normal HTML-if-present default.

**Timestamps are always UTC in the database** (`archived_mail.mail_date`, written via PHP's own default timezone, not the viewer's) — every template that displays one (`archive/index.latte`'s table, `archive/show.latte`'s metadata) renders the raw UTC value as the element's text content (a no-JS fallback) but also sets `data-utc="{iso-8601-with-Z}"` on it; a small unconditional script at the bottom of `layout.latte` finds every `[data-utc]` element on the page and replaces its text with `new Date(...).toLocaleString()` once the DOM is ready, converting to the viewer's own browser locale/timezone with no server-side per-user preference needed.

**Privacy** — table/single-message views show only `sender_name` (display name, `IncomingMail::$fromName`, translated placeholder if empty) — never an email address; From/Reply-To/To/Cc are never rendered anywhere in this feature's own UI. This is scoped to metadata **we** display — an address appearing in a mail's own body text (e.g. a signature) is shown as-is (sanitized for safety, not redacted for privacy).

**Entry points**: linked (not inlined) from `templates/list/manage.latte` (owner view, shown unless `Off`/`Hidden`) and `templates/dashboard.latte` (member view, shown for `Members`/`Public` — the page is already filtered to lists the viewer is a member of). No public cross-list directory for anonymous `Public`-archive discovery — direct URL only, out of scope.

---

## Configuration Architecture

**Only LDAP-specific classes may interact with LDAP. Only database-specific classes may run SQL.**
All other classes work with `ListConfig` and `Member` objects.

### ListProvider interface

```php
interface ListProvider {
    /** @return ListConfig[] */
    public function getLists(): array;
    public function getList(string $name): ?ListConfig;
    public function setListConfigValue(string $listName, string $key, string $value): void;
    public function reset(): void;
}
```

| Implementation | type | Description |
|---|---|---|
| `LdapListProvider` | `ldap` | Reads `mailGroup` objects from LDAP; uses `LdapMemberResolver` internally; `setListConfigValue()` replaces the matching `description[]` entry |
| `InlineListProvider` | `inline` | Reads lists from config.yml; inline members or configured `MemberResolver`; takes optional `DatabaseConnectionFactory`; `setListConfigValue()` throws (static config) |
| `DatabaseListProvider` | `database` | Reads list names + EAV config from MariaDB via `DatabaseConnectionFactory` using context `db-*` keys; `setListConfigValue()` upserts into `config-table` |
| `YamlListProvider` | `yaml` | Reads lists from a separate YAML file; inline members or configured `MemberResolver`; takes optional `DatabaseConnectionFactory`; `setListConfigValue()` throws (file not rewritten at runtime) |
| `SubaddressListProvider` | `subaddress` | Subaddress forwarding — see "type: subaddress — subaddress forwarding"; `members:` are unresolved `{subaddress}` templates, not a `MemberResolver`; `owners:` uses the normal inline mechanism; `setListConfigValue()` throws (static config) |

Every implementation's constructor takes the provider's own name (its key in `list-providers:`, see "list-providers — provider name as implicit type") as its first argument, ahead of `ConfigResolver`/`providerConfig`/etc. — used in log/error messages so a failure (LDAP unreachable, a list missing `list-mail`, a YAML file not found, ...) identifies which provider it came from.

`setListConfigValue()` is used by `ListApiController::encryptPassword()` — see "List Management API". The composite provider in `container.php` delegates to whichever underlying provider actually owns the list; its own `reset()` simply calls `reset()` on every wrapped provider.

**`Provider\AbstractListProvider`** — all five implementations extend this rather than implementing `ListProvider` directly. Before it existed, `getLists()`/`getList()`/`reset()` and the `$lists`/`resolvedProviderConfig()` caching around them were identical, or near-identical, copy-pasted code in every provider; the only thing that ever genuinely differed between them was *how* `$lists` gets populated. `AbstractListProvider` centralizes the shared part and declares that one differing part as `abstract protected function loadLists(): ?array` for each subclass to implement:

- `getLists()`/`getList()`/`reset()` are implemented once, in terms of `loadLists()` and the inherited `protected ?array $lists` cache — `getList()` is `getLists()` then an array lookup, `reset()` sets `$lists = null`. `DatabaseListProvider` is the one subclass that overrides `getList()` — a single targeted row query is cheaper than always loading every list first just to answer one lookup, so the inherited default doesn't fit there.
- `loadLists(): ?array` returns `null`, rather than throwing, for a failure that should be retried on the very next call within the same cycle instead of being cached as "zero lists" — `LdapListProvider` is the one subclass that needs this (an LDAP outage must not look identical to "the directory genuinely has zero lists" for the rest of the worker cycle; see its own `loadLists()`). Every other subclass either succeeds or throws on a hard config/data error (missing YAML file, empty `list-mail`, ...), unchanged from before this class existed.
- `resolvedProviderConfig()` (provider-level `use:`/direct config, no per-list overrides) is also centralized here — cached for the whole process lifetime, *not* reset per cycle like `$lists`, since it's derived purely from `config.yml`'s own structure (only ever changes via a full process restart, see "Worker loop — config reload").

### ConfigResolver

`ConfigResolver` merges config.yml blocks, resolves `use:`, substitutes `$VAR` from environment, and produces a flat merged key-value map for each list. Variable `{}` resolution does **not** happen here — it is deferred to `VariableResolver` at point of use.

- `resolveListConfig(array $providerConfig, array $listOverrides = []): array` — full per-list merge (levels 1–5)
- `getResolvedDefault(): array` — resolves only levels 1+2 (the config.yml root's direct key-values with its `use:` blocks expanded); used to read global settings like `db-*` credentials for the PDO connection

### VariableResolver

Static helper class. All resolution goes through `VariableResolver::resolve()`.

```php
// Build context arrays at each processing level
$listContext      = $list->createContext();          // all config keys + list-* computed vars
$mailContext      = [...];                           // sender-* keys (may include callables)
$recipientContext = [...];                           // firstname, lastname, username, mail (unfiltered)
                                                     // top-level gating by personalizeKeys happens in BodyPersonalizer

// Resolve a template with the active stack — ResolutionPurpose::Disclosed since
// this result is going into an outgoing mail (see "ResolutionPurpose" below)
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
- Blocks `VariableResolver::BLOCKED_KEYS` (passwords, hostnames, ...) — see "ResolutionPurpose" below

`ListConfig::createContext()` produces the list-level context: all merged raw config keys plus computed `list-name`, `list-mail`, `list-domain`, `hostname`, `list-url`, `display-name`/`list-display-name`. It also sets imap/smtp user+password defaults (`imap-user: '{mail-user}'` etc.) so the fallback chain works without special-casing in `ListConfig` properties. It is the **only** context builder — there is no separate "safe" variant; protection against `BLOCKED_KEYS` happens at resolution time instead (next section).

### ResolutionPurpose

`Hengeb\Listig\Variable\ResolutionPurpose` is a plain (non-string-backed) enum with two cases, `Trusted` and `Disclosed`, passed as `VariableResolver::resolve()`/`lookup()`'s third argument and threaded unchanged through recursive resolution (same mechanism as `$visited`). Protection against `VariableResolver::BLOCKED_KEYS` is enforced at this single point of `{}` resolution, not by pre-filtering the context array handed to it — `ListConfig::createContext()` is the **only** context builder, and always returns the full raw config.

- **`Disclosed`** (the default parameter value — least-privilege, secure-by-default) — used for any resolution whose result is user-visible (mail body/subject/headers, the UI, notification mails) or otherwise operator-controlled but not itself a credential lookup. If resolution — at any point in the recursion chain, not just the top-level key — reaches a key in `VariableResolver::BLOCKED_KEYS`, the real value is never returned: `VariableResolver::CLASSIFIED_PLACEHOLDER` (`'*CLASSIFIED*'`) is substituted instead, and the attempt is logged via a direct, unconditional `error_log()` call — this specific log call (a security-relevant event) is deliberately *not* routed through the level-gated `Logger` described under "Debug logging", so it can never be silenced by a `log-level` setting, unlike the ordinary tracing added there. The placeholder is never itself re-parsed as a template, same as a `Literal`-wrapped value.
- **`Trusted`** — full, unfiltered access, bypassing the `BLOCKED_KEYS` check entirely. Used *only* by `ListConfig::$imapHost`/`$imapUser`/`$imapPassword`/`$smtpHost`/`$smtpUser`/`$smtpPassword` (see "Which `ListConfig` properties are template-resolved" below) — these are the deliberate case of a credential/connection-string property needing to fall back through another blocked key (`{mail-host}`/`{mail-user}`/`{mail-password}`).

Enforcing this at the point of `{}` resolution — rather than by filtering the context array before it's built — is what makes the protection apply even when no `ListConfig` exists yet: `InlineListProvider`/`YamlListProvider`/`SubaddressListProvider` all resolve a list's `list-mail` template against the raw, just-merged provider config (see "`list-mail`" above), before any `ListConfig` object is constructed. Passing `ResolutionPurpose::Disclosed` to that `VariableResolver::resolve()` call blocks `list-mail: "{mail-password}"` from resolving to the literal plaintext password, the same way as everywhere else, with no dependency on a `ListConfig` instance.

### DatabaseConnectionFactory

Caches PDO instances per database configuration fingerprint (hash of `db-host`, `db-port`, `db-name`, `db-user`, `db-password`). All DB-backed providers and resolvers call `getConnection(array $config)` with their resolved config — if the fingerprint matches an existing connection, it is reused; otherwise a new PDO is opened and cached.

This means all providers that inherit `db-*` from the same `default` block share one connection. A provider or list that explicitly overrides `db-host` etc. gets its own separate (cached) connection.

`DatabaseListProvider`, `InlineListProvider`, and `YamlListProvider` pass `$configResolver->resolveListConfig($providerConfig)` (provider-level resolved config, no per-list overrides) as the config for their connection. `DatabaseMemberResolver` receives this same config from its parent provider.

### SmtpConnectionFactory

Caches open `symfony/mailer` transport instances per SMTP configuration fingerprint (hash of `smtp-host`, `smtp-port`, `smtp-user`, `smtp-secure`). `QueueSender` calls `getTransport($listConfig)` per recipient; the factory reuses the connection if the fingerprint matches, or closes and reopens it if it changes. Takes `PasswordCrypto` in its constructor and calls `decryptIfEncrypted($list->smtpPassword)` when building the DSN — this is the only point where the SMTP password is decrypted.

`ImapMailboxFactory` mirrors this: takes `PasswordCrypto` and calls `decryptIfEncrypted($list->imapPassword)` when constructing `PhpImap\Mailbox` — the only point where the IMAP password is decrypted. Neither `ListConfig` nor any provider ever sees the plaintext password; `imapPassword`/`smtpPassword` getters return the raw stored value (encrypted or plaintext) unchanged, decryption happens exactly where the credential is consumed.



```php
interface MemberResolver {
    /** @return Member[] */
    public function getMembers(string $name): array;
    /** @return Member[] */
    public function getOwners(string $name): array;
    public function findByEmail(string $email): ?Member;
    public function removeMember(string $listName, string $email): void;
    public function supportsRemoval(): bool;
    public function addMember(string $listName, Member $member): void;
}
```

| Implementation | type | Description |
|---|---|---|
| `LdapMemberResolver` | `ldap` | Resolves member/owner DNs via LDAP; every directory attribute except `mail` becomes a `Member::$attributes` entry under its own name (plus a `username` = `cn` convenience copy — see "Member attributes — fully dynamic"); `removeMember` removes the DN from the `member` attribute; `supportsRemoval` always `true`; `addMember` adds it — but only if a directory entry matching the email already exists, else throws |
| `DatabaseMemberResolver` | `database` | `SELECT *`s `members-table` via `DatabaseConnectionFactory` + context config, exposing every non-reserved column as an attribute; `removeMember` sets `is_member = 0`, then deletes row if `is_member = 0 AND is_owner = 0`; `supportsRemoval` always `true`; `addMember` upserts dynamically from `Member::$attributes` (validated as SQL identifiers), preserving existing `is_owner` |
| `CsvMemberResolver` | `csv` | Reads/writes a flat CSV file (`name,mail,is_member,is_owner` reserved, any other header column exposed as an attribute), shared across lists like `members-table`; re-reads on every call, writes take an exclusive `flock`; `supportsRemoval` always `true`; `addMember` extends the header for new attribute keys — see "CSV member file format" |
| `InlineMemberResolver` | — | Resolves inline config.yml `members`/`owners`; each entry is a plain email string or a map with a required `mail` key plus any other keys, all becoming attributes verbatim. `members` and `owners` are independent — either can be `null` (not configured inline) to defer to a wrapped fallback `MemberResolver` instead. On the static-inline side (`$members !== null`), `removeMember` throws (a request-scoped in-memory removal can never persist — config.yml is never rewritten, and a fresh instance is built from it on every request anyway) and `supportsRemoval` is `false`; on the deferred side, both pass through to the fallback |
| `NullMemberResolver` | — | Returns empty arrays; `removeMember` is a no-op; `supportsRemoval` `false` (no backing store at all); `addMember` throws |
| `AggregateMemberResolver` | — | Searches across all providers; used by `AuthController` to find any list a user belongs to; `supportsRemoval` `false`; `addMember`/mutating calls throw (lookup only) |

`addMember()` is used by `ListApiController` (see "List Management API") for both immediate (`PUT`) and double-opt-in-confirmed subscriptions. Callers must treat the `\RuntimeException` as a real error (e.g. HTTP `409`), not swallow it — an LDAP-backed list silently "succeeding" without actually adding a non-existent-directory-entry member would be worse than an explicit failure.

`supportsRemoval()` — checked via `ListConfig::$supportsUnsubscribe` (a property hook, like every other derived `ListConfig` value — see "ListConfig with property hooks" — not a method, since `MemberResolver::supportsRemoval()` itself is; the interface it belongs to is method-based throughout) — lets a caller find out *before* calling `removeMember()` whether it would actually persist anything, rather than either silently no-op'ing (previously the case for `NullMemberResolver` and static-inline `InlineMemberResolver`, both of which "succeeded" without ever removing anyone) or throwing. `DashboardController` only shows the "Unsubscribe" link when `allowLeave === Direct` *and* `$supportsUnsubscribe`; `UnsubscribeController`'s direct-unsubscribe branch and `ListApiController::unsubscribe()` (`DELETE /{listname}/{mail}`) both check it (or catch the `\RuntimeException`) before claiming success — see "Unsubscribe endpoint".

`member-resolver` can be configured as a sub-object on `type: inline` and `type: database` providers, with `type: database`, `type: ldap`, or `type: csv` (`{type: csv, file: /path/to/members.csv}`). `type: ldap` (the list provider) always uses `LdapMemberResolver` internally, independent of any `member-resolver` sub-object.

For `type: inline` and `type: yaml`: `members` and `owners` can be overridden inline independently — e.g. a list can define inline `owners` while `members` still comes from the configured `member-resolver` (database/ldap/csv), or vice versa. `InlineMemberResolver` is constructed with the configured `member-resolver` as its fallback whenever either key is present, and defers per-field to that fallback for whichever of `members`/`owners` was not given inline. If neither is defined, the list uses the `member-resolver` directly (or has no members if none is configured — no error).

### Database table structures

**config-table** (for `type: database` list provider):
```sql
CREATE TABLE list_config (
    name   VARCHAR(255) NOT NULL,
    key    VARCHAR(255) NOT NULL,
    value  TEXT,
    PRIMARY KEY (name, key)
);
-- SELECT DISTINCT name FROM list_config          -> all list names
-- SELECT key, value FROM list_config WHERE name = :name  -> list config key-values
```

**members-table** (for `type: database` member resolver). Only `name`, `mail`,
`is_member`, `is_owner` are reserved/structural — `DatabaseMemberResolver` does
`SELECT *` and exposes every other column as a `Member::$attributes` entry
under its own name (see "Member attributes — fully dynamic"). The columns
below are a sensible starter set, not a fixed schema — add, rename, or remove
freely without touching any code:
```sql
CREATE TABLE list_members (
    name       VARCHAR(255) NOT NULL,  -- list name
    mail       VARCHAR(255) NOT NULL,
    firstname  VARCHAR(255) NULL,
    lastname   VARCHAR(255) NULL,
    username   VARCHAR(255) NULL,
    pronoun    VARCHAR(255) NULL,
    is_member  TINYINT(1) NOT NULL DEFAULT 1,
    is_owner   TINYINT(1) NOT NULL DEFAULT 0,
    PRIMARY KEY (name, mail)
);
-- SELECT * FROM list_members WHERE name = :name AND is_member = 1  -> members
-- SELECT * FROM list_members WHERE name = :name AND is_owner = 1   -> owners
```

### CSV member file format

For `member-resolver: {type: csv, file: ...}`. Same shape as `members-table` above,
one file shared across all lists using this resolver, scoped by the `name` column.
Only `name`/`mail`/`is_member`/`is_owner` are reserved — every other header
column is exposed as an attribute under its own name, and `addMember()` adds
new columns on demand (backfilling `''` elsewhere) — see "Member attributes —
fully dynamic":

```csv
name,mail,firstname,lastname,username,pronoun,is_member,is_owner
mylist,alice@example.org,Alice,Example,alice,she,1,0
mylist,bob@example.org,,,,,1,0
otherlist,carol@example.org,Carol,Example,carol,,1,1
```

Non-reserved columns may be empty. `is_member`/`is_owner` are `0`/`1`;
missing `is_member` defaults to `1`, missing `is_owner` defaults to `0`. The file is
created on first write if it doesn't exist yet.

### Member value object

```php
class Member {
    public string $email;               // the only fixed field
    /** @var array<string, string> everything else a resolver knows — see "Member attributes — fully dynamic" */
    public array $attributes;
}
```

A key not present in `$attributes` (and not resolvable via any list-level alias
either) resolves to an empty string rather than a literal `{key}` — see
"Variable substitution".

### String-backed Enums

```php
enum ReplyToBehavior: string { case List = 'list'; case Sender = 'sender'; }
enum PostAccess: string { case Members = 'members'; case Owners = 'owners'; case Public = 'public'; }
enum ModerationMode: string { case On = 'on'; case Off = 'off'; }
enum AllowLeave: string { case Direct = 'direct'; case Moderated = 'moderated'; }
enum ArchiveMode: string { case Members = 'members'; case Owners = 'owners'; case Public = 'public'; case Hidden = 'hidden'; case Off = 'off'; }
```

### ListConfig with property hooks

```php
class ListConfig {
    public string $name;  // provider-agnostic identifier (LDAP: cn); constructor throws if this is "_" — reserved for /_/... system routes
    public string $mail;
    private array $raw;              // fully merged key-value map; null = not present, '' = explicitly empty
    private MemberResolver $members; // injected by ListProvider

    public function getMembers(): array { return $this->members->getMembers($this->name); }
    public function getOwners(): array  { return $this->members->getOwners($this->name); }

    /** Returns the context array for this list, ready to pass to VariableResolver::resolve(). */
    public function createContext(): array { /* list-* vars + all raw config keys + imap/smtp defaults */ }

    public string $displayName {
        get => $this->raw['display-name'] ?? $this->name;
    }
    public ReplyToBehavior $replyTo {
        get => ReplyToBehavior::from($this->raw['reply-to'] ?? 'list');
    }
    public ?string $footer {
        get => $this->raw['footer'] ?? null;  // null = not configured, '' = explicitly disabled
    }
    public int $maxSize {
        get => self::parseSize($this->raw['max-size'] ?? '5M');
    }

    /** Returns personalization whitelist. {list-url} always available. */
    public array $personalizeKeys {
        get {
            $raw = $this->raw['personalize'] ?? '';
            if ($raw === 'off' || $raw === '') {
                return ['list-url'];
            }
            return array_merge(['list-url'], array_map('trim', explode(',', $raw)));
        }
    }

    private static function parseSize(string $value): int {
        // M/MB -> *1_000_000, MiB -> *1_048_576, K/KB -> *1_000, KiB -> *1_024,
        // G/GB -> *1_000_000_000, GiB -> *1_073_741_824, plain int -> bytes
    }
}
```

### Which `ListConfig` properties are template-resolved, and against which context

Every property backed by a raw config value is resolved via `ListConfig`'s private `resolve()` before being cast/validated to its final type (`(int)`, `Enum::from()`, `'on'`/`'off'` comparison, ...) — not just plain string properties. This matters: without it, e.g. `smtp-port: "{port-tls}"` would silently produce `0` (an unresolved `"{port-tls}"` string cast to `int`), and `reply-to: "{my-alias}"` would throw an uncaught `ValueError` from `ReplyToBehavior::from()`.

- **`resolve($raw)`, default `ResolutionPurpose::Disclosed`** — the default for everything: `$displayName`, `$description`, `$replyTo`, `$postAccess`, `$moderation`, `$allowLeave`, `$archive`, `$archiveFolder`, `$maxPerSender`, `$maxSize`, `$publicSubscribe`, `$logLevel`, `$language`, and — despite being `VariableResolver::BLOCKED_KEYS` themselves — `$imapPort`/`$imapSecure`/`$smtpPort`/`$smtpSecure` too. These four are numeric/enum properties (`(int)` cast, `'ssl'|'tls'|'none'` comparison): resolved under `Trusted`, a value like `smtp-port: "{imap-password}"` could silently become the leading digits of the actual password cast to an int, which could then surface via a connection-failure error message — a *fragment* leak that casting makes easy to miss. Staying on `Disclosed` here means these four properties can no longer reference `{mail-user}`/`{mail-password}`/`{mail-host}` or any other blocked key — a deliberate trade-off in favor of the leak protection, since none of them actually need to (there's no `mail-port`/`mail-secure` fallback level to reach).
- **`resolve($raw, ResolutionPurpose::Trusted)`** — `$imapHost`, `$imapUser`, `$imapPassword`, `$smtpHost`, `$smtpUser`, `$smtpPassword`. These are string-valued connection/credential properties that must be able to fall back through another blocked key one level up — `imap-host`/`smtp-host` through `{mail-host}`, `imap-user`/`smtp-user` through `{mail-user}`, `imap-password`/`smtp-password` through `{mail-password}` (each `mail-*` key sets both `imap-*` and `smtp-*` unless overridden individually — see "config.yml Structure"). Unlike the numeric/enum group above, a resolved host/user/password is used whole (passed straight to the IMAP/SMTP client), not cast or compared — so there's no fragment-leak risk distinct from the whole-value risk `Trusted` already accepts for this deliberately small, documented set of properties.
- **Not template-resolved at all** — `$apiToken`. A Bearer credential the caller must present verbatim; indirection here would only add complexity/attack surface (e.g. accidental sharing via a shared alias) for no real benefit.
- **Not applicable** — `$domain` (derived from `$mail`, not a raw config value), `$personalizeKeys`/`$reservedSubaddresses` (comma-separated *lists of key names*, not content), `$requiresSubaddress`/`$isImapConfigured` (booleans computed from other properties). `$footer`/`$listLabel`/`$smtpFromName` are template-capable but *not* resolved inside `ListConfig` itself — they're read raw and resolved later, downstream, by `FooterAppender`/`MailProcessor` (which already resolve under `ResolutionPurpose::Disclosed`), since they're only ever consumed from the mail-sending pipeline and never read directly elsewhere.

---

## Database Schema

### Database migrations

Schema changes live as plain `.sql` files in `migrations/`, applied automatically — no manual step, ever, on either a fresh install or an upgrade. `Hengeb\Listig\Database\MigrationRunner::run()` (`src/Database/MigrationRunner.php`):

1. Creates `schema_migrations (version VARCHAR(255) PRIMARY KEY, applied_at DATETIME)` if it doesn't exist yet.
2. Lists `migrations/*.sql`, sorted as plain strings (hence the naming convention below), and runs every file whose filename isn't already a `version` row, in order, via `PDO::exec()` — then records it.

Invoked by `bin/migrate.php` (loads `.env`/the container exactly like `bin/worker.php`), which `docker/entrypoint.sh` runs once, before `exec`ing `CMD` — i.e. before supervisord starts nginx/php-fpm/worker at all. This avoids a race: with three processes started concurrently by supervisord, a web request or worker cycle could otherwise hit the database before migrations finish. Gating it in the entrypoint means nothing in the container ever sees a partially-migrated schema. A failure here is fatal — `bin/migrate.php` exits non-zero, `entrypoint.sh` has `set -e`, so the container aborts loudly rather than starting against a broken schema (same fail-fast philosophy as a missing `$VAR` or an invalid `filters:` regex).

**New migration files** must follow `NNN_description.sql` with a zero-padded, incrementing 3-digit prefix (`002_...`, `003_...`, ...) — plain string sort must match numeric order. **Every statement must be idempotent** (`CREATE TABLE IF NOT EXISTS`, guard an `ALTER TABLE` by checking `information_schema` first, etc.): MariaDB commits DDL implicitly, so a crash between running a file's SQL and recording it in `schema_migrations` can't be rolled back — the file simply runs again on the next start, and idempotency is what makes that safe rather than merely convenient.

### `mail_queue`

Primary key: `sha256(list_cn . ':' . mimeString)`. Identical MIME for the same list deduplicates automatically.

`batch_id`: `sha256(list_cn . ':' . rawIncomingMime)`, computed once per incoming mail in `MailProcessor::process()`. Identifies every recipient's queued copy of the *same original incoming mail*, even though personalization (`BodyPersonalizer`) gives each recipient different outgoing MIME — and therefore a different `id` above, which is a hash of that outgoing MIME. Used by `QueueSender`/`SpamRejectionDetector` to discard sibling copies together (see "Sending batch"). `NULL` means "no known siblings" — `QueueSender` never groups by `NULL`/empty, so rows without one are never (mis)matched with each other.

```sql
CREATE TABLE mail_queue (
    id          VARCHAR(64) NOT NULL PRIMARY KEY,
    list_cn     VARCHAR(255) NOT NULL,
    batch_id    VARCHAR(64) NULL,
    mime        LONGTEXT NOT NULL,
    created_at  DATETIME NOT NULL
);
```

### `queue_recipients`

```sql
CREATE TABLE queue_recipients (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    mail_queue_id   VARCHAR(64) NOT NULL REFERENCES mail_queue(id),
    envelope_to     VARCHAR(255) NOT NULL,
    attempts        TINYINT UNSIGNED NOT NULL DEFAULT 0,
    last_attempt_at DATETIME NULL,
    status          ENUM('pending','sent','failed') NOT NULL DEFAULT 'pending',
    error           TEXT NULL
);
```

`mail_queue_id`'s `REFERENCES` has no `ON DELETE CASCADE` — MariaDB still enforces it as a real constraint (auto-named `queue_recipients_ibfk_1`), so any code deleting a `mail_queue` row must delete that row's `queue_recipients` children first, or the delete fails with `"Cannot delete or update a parent row: a foreign key constraint fails"`. Both cleanup call sites do this correctly: `QueueSender::cleanupQueueEntry()` (once every recipient for a `mail_queue_id` is `'sent'`) and `purgeStaleFailedEntries()` (its own stale-`'failed'`-rows delete, followed by a `NOT EXISTS` sweep for now-childless `mail_queue` rows).

### `moderation_queue`

No `token` column: accept/reject tokens embed `list_cn`/`imap_uid`/`imap_uidvalidity`
and are HMAC-signed (see Token Format), so verifying a reply never needs a DB lookup.
This table only tracks that an item is pending moderation and when it was created/reminded.

```sql
CREATE TABLE moderation_queue (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    list_cn         VARCHAR(255) NOT NULL,
    imap_uid        BIGINT UNSIGNED NOT NULL,
    imap_uidvalidity BIGINT UNSIGNED NOT NULL,
    created_at      DATETIME NOT NULL,
    reminded_at     DATETIME NULL,
    UNIQUE KEY uq_list_uid (list_cn, imap_uid, imap_uidvalidity)
);
```

### `imap_seen`

Entries older than 31 days deleted each worker cycle. Inbox mails older than 30 days deleted from IMAP.

```sql
CREATE TABLE imap_seen (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    list_cn         VARCHAR(255) NOT NULL,
    imap_uid        BIGINT UNSIGNED NOT NULL,
    imap_uidvalidity BIGINT UNSIGNED NOT NULL,
    seen_at         DATETIME NOT NULL,
    UNIQUE KEY uq_list_uid (list_cn, imap_uid, imap_uidvalidity)
);
```

### `rate_limit`

Login rate limiting uses sentinel values: `list_cn='__login__'`, `sender=$email` (per-address, max 5/hour) or `sender='__global__'` (max 20/hour).

```sql
CREATE TABLE rate_limit (
    id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    list_cn     VARCHAR(255) NOT NULL,
    sender      VARCHAR(255) NOT NULL,
    sent_at     DATETIME NOT NULL,
    INDEX idx_sender (list_cn, sender, sent_at)
);
```

### `bounce_log`

Contains sender addresses and subjects — document in privacy policy / data retention documentation that these are retained for 90 days.

```sql
CREATE TABLE bounce_log (
    id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    list_cn     VARCHAR(255) NOT NULL,
    sender      VARCHAR(255) NOT NULL,
    subject     VARCHAR(500) NULL,
    bounced_at  DATETIME NOT NULL,
    INDEX idx_list_time (list_cn, bounced_at)
);
```

Entries older than 90 days deleted each worker cycle.

---

## Core Processing Logic

### Worker loop (`bin/worker.php`)

The worker runs as a single process. If a cycle takes longer than `sleep-seconds`, the next cycle starts immediately after — no overlap protection needed since it is single-threaded.

`sleep-seconds` (step 5, default 60) and `batch-size` (step 3, default 50) are config.yml root keys, like any other setting there — resolved by the `'worker.sleep-seconds'`/`'worker.batch-size'` container entries (`config/container.php`) via `ConfigResolver::getResolvedDefault()`. Neither has an env var of its own; reference `$SOME_VAR` in config.yml (e.g. `sleep-seconds: $WORKER_SLEEP_SECONDS`) if the value should come from the environment instead.

#### Worker loop — config reload

The worker's container (and everything built from it — `ConfigResolver`, every `ListProvider`, all `ListConfig` objects) is built exactly once, before the loop starts, and kept for the entire process lifetime. Every `ListProvider` implementation also memoizes `getLists()`/`getList()` internally the first time it succeeds (`private ?array $lists = null; if ($this->lists !== null) return ...;`) — but unlike a plain in-process cache with no expiry, this is bounded to **one worker cycle**: `ListProvider::reset()` (implemented by every provider — sets `$lists = null`, forcing the next `getLists()`/`getList()` call to re-query its backing store) is called once per iteration, right before the sleep, alongside `ImapMailboxFactory::reset()` (same pattern, same call site — see `bin/worker.php`). So an LDAP `description[]` entry, a `config-table` row, or a `type: yaml` provider file's contents are re-read fresh every cycle, without needing a process restart — a change made between two cycles is visible on the very next one, at most `sleep-seconds` later. (The **web/API side has no equivalent concern**: `public/index.php` builds a brand new container, and therefore fresh, unmemoized providers, on every single HTTP request — config changes there are visible on the very next request regardless.)

What `reset()` does *not* cover: `$this->providerConfig` (a provider's own raw `list-providers.*` entry) and anything the `ConfigResolver` itself resolved from `config.yml`'s structure (named blocks, `use:`, root-level defaults, `filters:`) are parsed once at container build time and never re-parsed mid-process — a provider's `reset()` only re-runs its *query* against that same, still-process-lifetime-fixed provider config. So editing `config.yml` itself — adding/removing a `list-providers` entry, changing a named block, a root default, `filters:` — still requires the full container rebuild a process restart gives you; `reset()` only shortens the previously-unbounded staleness window for the *external data* each provider reads (LDAP directory, DB rows, a YAML file), which is exactly the case that used to be invisible "not just until the next `sleep-seconds` cycle, but indefinitely, until the process actually restarts."

To still catch a `config.yml` structural change without a manual restart, the worker separately watches the file's mtime once per loop iteration and exits cleanly (`exit(0)`) the moment it changes:

```php
clearstatcache(true, $configPath);  // filemtime() is cached per-process — without
                                     // this, every check after the first would keep
                                     // returning the original mtime forever
$currentConfigMtime = @filemtime($configPath) ?: null;
if ($currentConfigMtime !== $configMtime) {
    error_log('Listig: config.yml changed on disk — restarting worker to reload configuration.');
    exit(0);
}
```

`docker/supervisord.conf`'s `[program:worker]` already has `autorestart=true`, so supervisord immediately restarts the process — which rebuilds the container from scratch, re-parsing `config.yml`'s structure fresh (unlike a provider's own `reset()`, which re-queries the same, unchanged provider config — see above). A full process restart, rather than trying to invalidate the whole container in place, is deliberate: it's simpler, and guarantees a completely consistent state with no risk of a partially-stale `ConfigResolver`.

This mtime watch only fires for `config.yml` itself — a change to a file pulled in via `!include`, or to a `type: yaml` provider's own `file:`, is **not** detected this way (no mechanism reports back which included files were actually read) and does *not* trigger a restart. That's fine for a `type: yaml` provider's `file:` specifically, since its content is re-read every cycle via `reset()` regardless (see above) — but an `!include`d fragment of `config.yml` itself is spliced in once at parse time (`YamlIncludeResolver`, before `reset()` has any effect), so editing *that* file still needs either a restart or a no-op re-save of `config.yml` to pick up.

```
loop forever:
    1. foreach configured list (from all list-providers):
        a. Check LDAP availability; if unreachable: log error, skip IMAP poll for this cycle,
           continue to queue sending (step 3) — SMTP does not require LDAP
        b. ImapPoller::poll():
           - Check UIDVALIDITY via statusMailbox()->uidvalidity; if changed: clear imap_seen, log warning
           - For each unseen UID: fetch raw MIME (getRawMail) + parsed IncomingMail (getMail)
           - Return array of {uid, uidvalidity, mime, mail: IncomingMail}
        c. foreach mail:
            - authResults = HeaderFilter::readAuthResults($mail->headersRaw)
            - result = IncomingMailFilter::filter($mail, $list, $rawMime, $authResults) -> FilterResult
            - FilterResult::Discard: skip silently, mark seen
            - FilterResult::Bounce: log bounce_log, forward to owner, mark seen, ImapArchiver::archiveOrDelete()
            - FilterResult::Reject(reason): notify sender, mark seen, ImapArchiver::archiveOrDelete()
            - FilterResult::Moderation: ModerationMailer::send(), insert moderation_queue + imap_seen
            - FilterResult::Distribute:
                - MailProcessor::process($mail, $rawMime, $list):
                    - Build outgoing Email from IncomingMail (body, attachments, threading headers)
                    - Set outgoing headers (From, Sender, Reply-To, List-*, Precedence, X-Loop, etc.)
                    - Apply subject label via VariableResolver with [safeListContext, mailContext]
                    - For each recipient:
                        - Build full recipientContext (firstname, lastname, username, mail — unfiltered)
                        - BodyPersonalizer::personalize($email, [$safeListContext, $mailContext, $recipientContext], $personalizeKeys)
                        - FooterAppender::append($email, $list, [$safeListContext, $mailContext, $recipientContext]) — no whitelist, operator content
                        - Serialize to MIME string via symfony/mime
                        - hash = sha256(list_name . ':' . mimeString)
                        - INSERT INTO mail_queue ... ON DUPLICATE KEY UPDATE id=id
                        - INSERT INTO queue_recipients (mail_queue_id=hash, envelope_to=...)
                - Mark imap_uid + uidvalidity in imap_seen
                - ImapArchiver::archiveOrDelete() per list config
        d. ImapArchiver::deleteOldMails() -> delete inbox mails older than 30 days
    2. ModerationChecker::checkOverdue() -> remind owners of items pending > 7 days
    3. QueueSender::sendBatch(batch-size, see 'worker.batch-size' above)
    4. Cleanup:
        - DELETE FROM imap_seen WHERE seen_at < NOW() - INTERVAL 31 DAY
        - DELETE FROM rate_limit WHERE sent_at < NOW() - INTERVAL 1 HOUR
        - DELETE FROM bounce_log WHERE bounced_at < NOW() - INTERVAL 90 DAY
    5. sleep(sleep-seconds, see 'worker.sleep-seconds' above)
```

### Sending batch (`QueueSender`)

- Fetch up to `batch-size` (see "Worker loop" above) `queue_recipients` with `status=pending`, ordered by `last_attempt_at ASC`
- Per recipient: call `SmtpConnectionFactory::getTransport($listConfig)` — reuses open connection if SMTP fingerprint unchanged, otherwise closes and opens a new one
- Send via `symfony/mailer` with explicit `Envelope`
- On success: mark `sent`; if all recipients for `mail_queue_id` done, delete `mail_queue` row
- On failure: check `SpamRejectionDetector::isSpamRejection()` first (see below); otherwise increment `attempts`, and if `attempts >= 3`: mark `failed`, notify list owner

### Spam rejection at delivery time (`SpamRejectionDetector`)

symfony/mailer's equivalent of checking PHPMailer's `->ErrorInfo` after `send() === false`: a failed `$mailer->send()` throws `Symfony\Component\Mailer\Exception\TransportExceptionInterface`, which carries the receiving mail server's own response via `getMessage()`/`getDebug()`.

- `SpamRejectionDetector::isSpamRejection(\Throwable $e, string $envelopeTo): bool` fires only if **both** hold:
  1. `$e instanceof TransportExceptionInterface` (an actual SMTP-level rejection, not e.g. a connection error or a `RuntimeException` from a missing list)
  2. the recipient's domain (`$envelopeTo`) is in a small hardcoded allowlist of very large providers (gmail.com, gmx.de/net, web.de, outlook.com/hotmail.com/live.com, icloud.com/me.com/mac.com, yahoo.com, aol.com, t-online.de, …) — deliberately **not** configurable via `config.yml`, since this is a trust boundary for treating another party's SMTP response as authoritative, not a per-list setting. Without it, a malicious or misconfigured SMTP server could forge a "spam" response to make Listig discard mail for recipients it has nothing to do with.
  3. `strtolower($e->getMessage() . ' ' . $e->getDebug())` contains `'spam'`
- On a match, `QueueSender::discardBatchAsSpam()` aborts immediately (no 3-attempt wait) and marks the current recipient **and every other still-`pending` `queue_recipients` row sharing the same `mail_queue.batch_id`** as `failed` — i.e. every remaining copy of the same original mail, across every list it was addressed to, personalized or not (see `mail_queue.batch_id` in "Database Schema" for why a shared `batch_id`, not a shared `mail_queue_id`, is required to find them). Rows already `sent` are untouched.
- Discarded copies are marked `failed`, not deleted outright — same as any other delivery failure, they stay visible/retryable/deletable via the manage page's queue status (`QueueController`) until `purgeStaleFailedEntries()` purges them after 30 days.
- The list owner is notified once per discarded batch (translation key `queue.spam_rejected`), not once per discarded recipient.

### Envelope separation

```php
$mailer->send(
    new RawMessage($mimeString),
    new Envelope(
        new Address("{$listCn}+bounce-{$memberCn}@example.org"),  // Envelope-From: VERP
        [new Address($recipient->envelopeTo)]                      // Envelope-To
    )
);
```

`Sender` header in MIME: `{list-cn}+bounce@example.org` (human-visible, no member CN).
Visible `To` header: original recipients only, never expanded member list.

---

## Mail Processing Details

### IncomingMailFilter — check order

1. **X-Loop** present (any value) → discard silently
2. **Bounce** (any match below) → log to `bounce_log`, forward to owner as `multipart/mixed` (Part 1: `text/plain` with metadata — see "Bounce notice details" below; Part 2: `message/rfc822` with full original bounce mail):
   - `Auto-Submitted` present and ≠ `no`
   - `X-Auto-Response-Suppress` present
   - `Content-Type: multipart/report; report-type=delivery-status`
   - `From` contains `MAILER-DAEMON` or `postmaster` (case-insensitive)
   - Subject matches `/^(delivery status|mail delivery failed|undelivered mail)/i`
3. **Subaddress validation** (`type: subaddress` lists only, see "type: subaddress — subaddress forwarding"): reserved subaddress (`bounce`, `accept-*`, `reject-*`, or list-configured `reserved-subaddresses`) → reject, notify sender; no subaddress at all while at least one member template requires one → reject, notify sender
4. **Spam filter**: any rule in `filters:` (config.yml, global, see "Spam filtering") matches → reject, notify sender
5. **Authentication-Results**: SPF or DKIM = `fail` → reject, notify sender
6. **Size**: raw MIME size > `max-size` → reject, notify sender
7. **Post-access**: sender not in allowed group → reject, notify sender
8. **Rate limit**: exceeded → reject, notify sender
9. **Moderation with no owners** (only reached if `moderation: on`): list has zero owners → reject (`reject.no_owners`), notify sender — a moderation item nobody can ever accept/reject would otherwise vanish silently instead of being distributed or bounced back with feedback

Bounces checked before Authentication-Results: MAILER-DAEMON mails may legitimately lack valid SPF/DKIM. Spam filter checked before Authentication-Results too, for the same reason — but after bounce detection, so a MAILER-DAEMON bounce whose body happens to match a filter rule is still handled as a bounce, not a spam reject. Subaddress validation is checked before the spam filter (address-routing validity before content-based filtering) but after bounce detection. Note `bin/worker.php` already routes `+accept-*`/`+reject-*` mail through `ModerationResponseHandler` before `IncomingMailFilter::filter()` is ever reached, so the `accept-`/`reject-` check here is defense-in-depth; the `bounce` check is load-bearing, since bounce detection above is content-based and a non-standard bounce sent to `+bounce` would otherwise fall through. The no-owners check is last since it's only relevant once a mail has already cleared every other gate and would otherwise reach `moderation: on`; `ModerationMailer::send()` still independently checks (and logs, then no-ops) for empty owners too, as a defense-in-depth backstop against a list losing its last owner *after* an item is already in `moderation_queue`.

`PhpImap\Mailbox::getMailHeaderFieldValue()` (populates `IncomingMail::$autoSubmitted`, among others) is typed to always return `string`, using `''` for "header absent" — **never** `null`, despite `IncomingMailHeader`'s own `@var string|null` docblock claiming otherwise. `IncomingMailFilter::isBounce()`'s `Auto-Submitted` check must test `!== null && !== ''`, not just `!== null` — the latter is true for every mail lacking the header (i.e. essentially all normal mail), misclassifying it as a bounce.

#### Bounce notice details

`BounceHandler::forwardToOwners()` extracts a few fields from the raw bounce MIME via `HeaderFilter::readHeader()` (already generic enough to scan any raw text block, not just a header block) and includes them in the Part 1 text/plain body, best-effort — a bounce that isn't a standard RFC 3464 delivery-status notification (or omits these fields) falls back to the `bounce.unknown` translation string per missing field, never a blank or literal placeholder:

- **Ursache/Reason** (`%reason%`) — `Diagnostic-Code` (preferred, human-readable, e.g. `smtp; 550 5.1.1 ...: User unknown`) falling back to the terser `Status` (e.g. `5.1.1`), both RFC 3464 fields living in the bounce's own `message/delivery-status` part.
- **Fehlgeschlagener Empfänger/Failed recipient** (`%failed_recipient%`) — RFC 3464's `Final-Recipient` (falling back to `Original-Recipient`), stripped of its `rfc822;` address-type prefix. This is the specific address delivery failed for — Listig has no per-recipient VERP in its own `Envelope-From` (`{list-cn}+bounce@{domain}` is the same for every recipient, see "Envelope separation"), so this DSN field is the *only* way to learn which member's address actually bounced.
- **Ursprünglicher Absender/Original sender** (`%original_sender%`) — the `From:` header of the *attached original message* (found by searching for `From:` only from the raw MIME's `message/rfc822` marker onward), not the outer bounce's own `From:` (typically `MAILER-DAEMON@...`, already shown separately as `%sender%`).

`readHeader()`'s "first occurrence anywhere in the text" behavior is safe for `Diagnostic-Code`/`Final-Recipient` specifically because a standard DSN's delivery-status part always precedes the attached original message, so there's no risk of accidentally matching something inside the original mail's own headers/body instead.

### Header filter

`HeaderFilter::readAuthResults(string $headersRaw): array{spf, dkim}` — parses the `Authentication-Results` header from the raw header block and returns SPF/DKIM pass/fail strings.

`MailProcessor` builds the outgoing `Email` from scratch via `IncomingMail` fields, so there is no explicit header blocklist. Infrastructure headers (`DKIM-Signature`, `Received`, `Authentication-Results`, `ARC-*`, `Return-Path`) are simply never copied to the fresh outgoing `Email`. Threading headers (`Message-ID`, `In-Reply-To`, `References`, `Date`) are preserved — but not all via the same `Headers` method: symfony/mime's `Headers::HEADER_CLASS_MAP` enforces a specific value class for some header names, rejecting `addTextHeader()`'s always-`UnstructuredHeader` result outright (`LogicException: The "..." header must be an instance of "..." (got "UnstructuredHeader")`). `Message-ID` must be `addIdHeader()` (an `IdentificationHeader`, constructed from the bare id — the raw value's `<>` are stripped first, `IdentificationHeader::getBodyAsString()` re-adds them) and `Date` must be `addDateHeader()` (a `DateHeader`, constructed from a parsed `\DateTimeImmutable`, not the raw string). `In-Reply-To`/`References` are the exception: their `HEADER_CLASS_MAP` entry allows `UnstructuredHeader` *or* `IdentificationHeader` (deliberately lenient, "to allow users entering the original email's Message-ID, even if that is no valid msg-id" — the library's own comment), so `addTextHeader()` continues to work for those two. Each header is preserved best-effort in its own `try`/`catch` — a malformed value from the sending MTA (unparseable `Date`, a `Message-ID` that fails `Address`'s RFC validation) is logged and skipped rather than blocking distribution of an otherwise-fine mail.

### Attachments — preserving embedded (`cid:`) images

`buildOutgoingEmail()` copies `$mail->textHtml`/`$mail->textPlain` into the outgoing body verbatim — any `cid:` references an incoming HTML body contains (e.g. `<img src="cid:part1.ACmwPHTY.OIw3acmz@hengeb.de">`) are never rewritten, so whichever attachment part they point at must survive distribution with the *same* Content-ID and an `inline` disposition, or the reference resolves to nothing in the recipient's mail client. `Email::attach()` cannot do this: it always builds a plain `DataPart` with `Content-Disposition: attachment` and no `Content-ID` at all, regardless of what the original attachment looked like — silently breaking every embedded image on every distributed mail (confirmed live: an incoming mail with one `cid:`-embedded image and one ordinary attached image produced identical `attachment`-disposition parts for both, and Thunderbird rendered a broken-image icon where the embed should have been). `Email::embed()` isn't a fix either — it calls `(new DataPart(...))->asInline()`, but has no parameter for pinning a *specific* pre-existing Content-ID; without one it lazily generates its own via `getContentId()`'s `generateContentId()` fallback, which would never match the id already baked into the copied HTML body.

The fix: for each `IncomingMailAttachment` where `$attachment->disposition === 'inline'` and `$attachment->contentId` is non-empty, build the part manually — `(new DataPart($attachment->getContents(), $attachment->name, $contentType))->asInline()->setContentId($attachment->contentId)`, added via `$email->addPart()` — preserving the exact original id (`IncomingMailAttachment::$contentId` is already bare, without angle brackets, matching both `DataPart::setContentId()`'s expected format and the bare `cid:...` reference already in the HTML). Every other attachment (no Content-ID, or `disposition === 'attachment'`) continues through the plain `$email->attach(...)` path unchanged.

### Headers to set on outgoing mail

| Header | Value |
|---|---|
| `From` | `smtp-from-name <list-mail>` — `smtp-from-name` may contain mail-context variables |
| `Sender` | `{list-cn}+bounce@example.org` |
| `Reply-To` | List address (`ReplyToBehavior::List`) or original sender (`ReplyToBehavior::Sender`) |
| `X-Original-Sender` | Sender's CN — only when `ReplyToBehavior::Sender` (CN not email — privacy) |
| `List-Id` | `<{name}.{domain}>` — uses `name` (stable identifier, not `display-name` which may change) |
| `List-Post` | `<mailto:{mail}>` or `NO` if `PostAccess::Owners` |
| `List-Help` | `<mailto:{owner-mail}>` — added whenever the list has at least one owner (not conditional on `post-access`) |
| `List-Unsubscribe` | `<https://{hostname}/{list-name}/unsubscribe?token={TOKEN}>` |
| `List-Unsubscribe-Post` | `List-Unsubscribe=One-Click` |
| `Precedence` | `list` |
| `X-Loop` | List mail address |
| `X-Original-To` | Original `To` header value |
| `X-Forwarded-From` | Original sender address |

`List-Id` uses `name` rather than `display-name` because it is a stable machine-readable identifier that should not change when the human-readable name is updated.

### Subject label

If `list-label` configured (and not empty string):
- `str_contains($subject, $label)` case-insensitive — skip if already present
- Otherwise: `$subject = "$listLabel $subject"` (label used as-is, no brackets added by Listig)

### Body/subject personalization (`BodyPersonalizer`)

All MIME manipulation uses symfony/mime on decoded content — never raw string replacement.

Subject: RFC 2047 decode → whitelist-gated substitution → RFC 2047 re-encode.
Body parts: rebuilt immutably via `new TextPart(…)` + `Email::setBody()`.

`BodyPersonalizer::personalize(Email $email, array $contexts, array $personalizeKeys): void`

**Top-level gate** (`personalizeKeys`): only `{key}` placeholders whose key is listed in `personalizeKeys` are substituted at the top level. Everything else is left literal.

**Recursive resolution**: when a whitelisted key resolves to a value that itself contains `{vars}` (e.g. `vorname: "{firstname}"`), those inner variables are resolved through the full safe context without restriction — they are NOT required to be in `personalizeKeys`.

**Sensitive key blocking**: `BodyPersonalizer` resolves under `ResolutionPurpose::Disclosed` — `VariableResolver::BLOCKED_KEYS` is therefore blocked (substituted with `VariableResolver::CLASSIFIED_PLACEHOLDER`, logged) even via recursive resolution, regardless of what `$contexts` actually contains (see "ResolutionPurpose").

**`personalizeKeys`** (`ListConfig::$personalizeKeys`):
- Always includes `list-url`
- `personalize: off`, empty, or absent → only `list-url`
- `personalize: firstname, list-name` → `['list-url', 'firstname', 'list-name']`

**`FooterAppender`** has no `personalizeKeys` restriction — the footer is operator-authored content and may use all variables in the safe context.

### Footer (`FooterAppender`)

- If `footer` is `null` (not configured): skip
- If `footer` is `''` (explicitly empty): skip (allows overriding a default footer)
- Otherwise: always append — do not check for existing footer content
- Generate plaintext: `<a href="url">Label</a>` → `Label (url)`, block tags → newlines, rest via `strip_tags`
- Append HTML to HTML part, plaintext to text part
- Footer is appended after personalization; footer content may itself contain list-context variables (resolved at append time)

### MIME deduplication

```php
$mimeString = $email->toString();
$hash = hash('sha256', $listCn . ':' . $mimeString);
$db->execute(
    'INSERT INTO mail_queue (id, list_cn, mime, created_at) VALUES (?, ?, ?, NOW())
     ON DUPLICATE KEY UPDATE id=id',
    [$hash, $listCn, $mimeString]
);
$db->execute(
    'INSERT INTO queue_recipients (mail_queue_id, envelope_to) VALUES (?, ?)',
    [$hash, $envelopeTo]
);
```

### Recipient filtering

Expand member list. Exclude addresses in original `To` or `Cc`. Normalize to lowercase.

---

## Moderation

### Flow

1. Incoming mail for list with `ModerationMode::On`; size check passes first
2. `ModerationMailer` sends to all owners:
   - `From`: list address; `Reply-To`: original sender
   - `Content-Type: multipart/mixed`:
     - **Part 1** (`text/plain`): metadata + mailto links as plain text (**no HTML part** — prevents token leakage in replies):
       ```
       Accept: mailto:{name}+accept-{TOKEN}@example.org
       Reject: mailto:{name}+reject-{TOKEN}@example.org
       ```
     - **Part 2** (`message/rfc822`): complete original mail
3. `imap_uid` + `uidvalidity` stored in `moderation_queue` + `imap_seen` (the token itself is not persisted — it is self-describing, see Token Format)
4. Owner sends to accept/reject address
5. Worker detects `+accept-` or `+reject-` in `To`:
   - Validate HMAC + expiry
   - Validate sender is list owner (LDAP)
   - **Both must pass**
6. Accept: fetch from IMAP by UID; if not found → send error to owner, delete from `moderation_queue`; if found → process and enqueue normally, archive/delete
7. Reject: archive/delete, notify original sender
8. Delete from `moderation_queue`

`allow-leave: moderated`: when a member requests unsubscription, send a plain notification mail to all owners: "User {firstname} {lastname} ({mail}) has requested removal from list {display-name}." Owner must remove manually in LDAP.

### Overdue reminder

Find rows where `created_at < NOW() - 7 days` and (`reminded_at IS NULL` or `reminded_at < NOW() - 7 days`). Resend moderation mail, update `reminded_at`.

### Moderation via UI

- `POST /_/api/moderation/{id}/accept`
- `POST /_/api/moderation/{id}/reject`

Require valid session (owner of that list) + `X-CSRF-Token`.

---

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
arbitrary, purpose-specific argument list; `verify()` hands the same list back for the
caller to destructure. This keeps the token generic: adding a new purpose, or new data
to an existing one, never requires touching `TokenService` itself.

`TokenService` is constructed with a subkey already derived via
`KeyDerivation::derive($appSecret, 'listig-token-hmac')` — see Key Derivation above —
not with `APP_SECRET` directly.

```php
// TokenService::sign(string $purpose, mixed ...$payload): string
$data  = json_encode([$purpose, time(), ...$payload]);
$hmac  = hash_hmac('sha256', $data, $hmacKey); // $hmacKey = derived subkey, not APP_SECRET
$token = rtrim(strtr(base64_encode($data), '+/', '-_'), '=') . '.' . $hmac;

// TokenService::verify(string $token, string $expectedPurpose, int $maxAge): array
// — returns the payload passed to sign(), in the same order. Throws on invalid
// signature, purpose mismatch, or if the token is older than $maxAge.
```

`$expectedPurpose` is not redundant with the payload: different purposes can (and do,
e.g. `login` and `unsubscribe`) share the same payload shape, so it is the only thing
preventing a token issued for one purpose (and its mail-header/link exposure) from being
replayed for another. `$maxAge` is likewise supplied by the caller, not baked into
`TokenService` — expiry is a policy decision for each call site, not the token itself.

Each call site defines its own payload shape and max age, and destructures the same way on both ends:

| Purpose | `sign()` payload | Max age | Used by |
|---|---|---|---|
| `login` | `$listCn, $userCn` | 5 minutes | `AuthController` |
| `unsubscribe` | `$listCn, $userCn` | 7 days | `MailProcessor` (sign) / `UnsubscribeController` (verify) |
| `accept` / `reject` | `$listCn, $imapUid, $imapUidvalidity` | 7 days | `ModerationMailer` (sign) / `ModerationResponseHandler` (verify) |

URL-safe Base64 (`+`→`-`, `/`→`_`, no padding). Safe in mail `+` addresses.

Tokens are stateless and self-describing: the HMAC signature is the only thing that
needs verifying, so `TokenService::verify()` never touches the database. Purposes that
need to identify a specific database row (`accept`/`reject` → a `moderation_queue`
item) embed that row's natural key in the payload instead of persisting the token
somewhere to look up later — this is why `moderation_queue` has no `token` column.

---

## Rate Limiting

**Mailing:** `(list_cn, sender)` in last 10 min, limit = `max-per-sender` (default 5).

**Login:**
- Per-address: `list_cn='__login__'`, `sender=$email`, max 5/hour
- Global: `list_cn='__login__'`, `sender='__global__'`, max 20/hour
- Always show same response regardless of result — prevents enumeration

Rows older than 1 hour deleted each worker cycle.

**API token brute force:** `ApiTokenMiddleware` records each invalid Bearer-token
attempt via `RateLimiter::isExceeded($listName, '__api-token__', 20)` (same 10-minute
window) — past 20 failed attempts for a list within 10 minutes, further requests get
`429` instead of `401`. Every invalid attempt is also logged via `error_log()`.

---

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

## Web UI (Slim + Latte)

### Custom layout

`templates/layout.latte` optionally imports `/app/config/custom.latte` — never baked into the image (no `templates/custom.latte` exists), and mounted as a read-only volume the same way as `config.yml`/`filters.yml` (see `deploy/compose.yml.example`/`docker/compose.yaml`, both commented out by default). Its entire purpose is letting an operator inject their own markup/CSS/navigation into every page without forking `layout.latte` itself or maintaining a patch against it across upgrades.

- Nothing breaks if the file isn't mounted at all: `{if file_exists($customLayoutFile)}{import $customLayoutFile}{/if}` in `layout.latte`'s `<head>` gates the `{import}` — an unconditional `{import}` of a missing file would be a hard Latte error, so the existence check has to happen at the PHP-expression level, not by relying on Latte's own error handling.
- Five block names are recognized, each optional independently — an operator's `custom.latte` may define any subset of them (or none, or all five) using `{define blockname}...{/define}` (not `{block}` — `custom.latte` is only ever consumed via `{import}`, never rendered as a page in its own right, so `{define}`'s "declare, don't auto-render" semantics are the correct ones; a top-level `{block}` in an imported file behaves identically when only ever referenced via `{include #name}`, but `{define}` is the self-documenting choice for a pure block library). Every reference to one of these five is wrapped in `{ifset #name}...{/ifset}` (compiles to `$this->hasBlock('name')`, see `Latte\Runtime\Template::hasBlock()`) precisely so an undefined block silently contributes nothing, rather than `{include #name}` throwing `Latte\RuntimeException: Cannot include undefined block`.

| Block name | Injected... |
|---|---|
| `custom_head` | ...at the end of `<head>` (extra `<style>`/`<link>`/`<meta>`, e.g. a custom stylesheet or favicon override) |
| `custom_body_start` | ...as the very first thing inside `<body>`, before the page header |
| `custom_header` | ...**replacing** the default `<header>` entirely, if defined — a plain `{ifset #custom_header}{include #custom_header}{else}<header>...</header>{/ifset}` around the built-in markup, so an operator can swap in their own branding/navigation instead of only appending to the default one |
| `custom_after_header` | ...immediately after the header (default or custom, whichever rendered) closes, before `<main>` |
| `custom_body_end` | ...after `<main>` closes, right before the closing `</body>` |

Variables already in scope for every page (`$appName`, `$translator`, `$user`, `$language`, ...) are available inside `custom.latte`'s blocks too, since `{import}` renders in the same template's variable scope — an operator's `custom_header` block can reference `{$translator->trans(...)}` or check `{if isset($user)}` exactly like `layout.latte` itself does.

Verified live: with no `custom.latte` mounted, `/_/login` renders byte-identical to before this feature existed (the `file_exists()` check short-circuits to false, nothing else fires). With a `custom.latte` defining only 3 of the 5 blocks, exactly those 3 rendered at their documented positions and the other 2 (including the header) silently fell back to nothing/default. With `custom_header` defined, the built-in `<header>...</header>` markup did not appear in the output at all — confirming the replace-not-append behavior for that one block.

### Authentication (Magic Link)

1. User submits email; `AuthController`/`AggregateMemberResolver::findListAndMemberByEmail()` searches every configured list's members and owners (any provider — LDAP, database, CSV, inline) for a match
2. If not found: rate limit recorded, no mail sent, same response shown always:
   > "Falls wir dich zuordnen konnten, hast du eine Mail mit einem Zugangslink in deinem Postfach."
3. If found: login token generated (embeds the matched list's `name`, not an arbitrary/first list), link sent (valid 5 min) via `AuthController::sendLoginMail()`, which prefers a **root-level default SMTP identity** over the matched list's own — see "Login mail sender" below
4. On verify: native PHP session started, identity stored in session
5. Session ID used as CSRF token: sent as `X-CSRF-Token` header on state-changing requests
6. Logout: `POST /_/api/logout` (`AuthController::logout()`) — behind `AuthMiddleware` + `CsrfMiddleware` like every other `/_/api` route, since it's a state-changing action on an active session, not a public one. Clears `$_SESSION` and calls `session_destroy()`, returns `200` + JSON `{"redirectUrl": "..."}` (usually `/_/login`, but see "Authentication (OIDC)" for when an OIDC session sends the browser to the IdP's own logout page first). Triggered from the "Abmelden"/"Log out" link in `layout.latte`'s nav (shown whenever `$user` is set — every authenticated page passes it), which does the fetch-with-`X-CSRF-Token` dance client-side (same pattern as `list/manage.latte`'s `apiPost`/`apiDelete`) and navigates to the returned `redirectUrl`.

#### Login mail sender

A login mail is a system-level action (proving mailbox ownership to Listig itself), not a per-list distribution — so unlike every other outgoing mail in this codebase (list distribution, moderation requests, bounce/rejection notices, queue failure notices), it should not visibly come from whichever list the matched member happens to belong to. `AuthController::sendLoginMail()` therefore prefers a **root-level default SMTP identity** over the matched list's own, falling back to the list's SMTP config only if no default exists at all:

- `'app.default-smtp-config'` (`config/container.php`) builds a synthetic `ListConfig` from `ConfigResolver::getResolvedDefault()` — i.e. only the config.yml root's own `use:`/direct key-values (priority levels 1–2, see "Configuration priority"), with no list-provider or per-list override applied. Its `name`/`mail` are never displayed or routed (just constructor placeholders for a `ListConfig` that's never looked up by name); `smtpHost`/`smtpUser`/`smtpPassword`/`smtpPort`/`smtpSecure` resolve through `ListConfig`'s existing property hooks exactly as they would for any list that set no `smtp-*`/`mail-*` overrides of its own — including the `mail-*` fallback and `Trusted`-purpose resolution already documented under "Which `ListConfig` properties are template-resolved".
- `sendLoginMail()` checks `$this->defaultSmtpConfig->smtpHost !== ''` — non-empty means the operator has a root-level `smtp-host`/`mail-host` configured (`mail-config`'s `imap-host`/`smtp-host: $MAIL_HOST` in the example config.yml), so that's used: `From` is `$this->defaultSmtpConfig->smtpUser` (e.g. `system@hengeb.de` from `$MAIL_USER`) with display name `$this->appName`, and the transport comes from `$this->smtpConnectionFactory->getTransport($this->defaultSmtpConfig)`.
- If the root resolves no `smtp-host`/`mail-host` at all (truly unconfigured — not just overridden per-list), it falls back to the previous behavior: `From` is the matched list's own `$list->mail`/`$list->displayName`, sent through that list's own resolved SMTP transport.

This matters specifically because `list-mail: "{list-name}@{domain}"`-style `mail-user` templates (common at provider level, so each list sends as its own address) would otherwise make every login mail appear to come from an arbitrary member-matched list address instead of a stable, recognizable system sender — confirmed live: with `mail-user: "{list-mail}"` set at the `inline` provider level (overriding the root's own `mail-user: $MAIL_USER`), a login mail to a member of `testliste` arrived from `testliste@hengeb.de` before this fix, and from `system@hengeb.de` (`$MAIL_USER`) after it.

### Authentication (OIDC)

Optional alternative to the magic-link flow above — only active when `oidc-provider-url`/`oidc-client-id`/`oidc-client-secret` are configured (see "OIDC login (`oidc-*`)"). `OpenIdConnectService` wraps `jumbojett/openid-connect-php`, driving the Authorization Code + PKCE flow via provider discovery — see "OIDC login (`oidc-*`)" for the `oidc-public-provider-url` header-spoofing mechanism some IdPs (e.g. Authelia) need when reached over an internal address.

- **`GET /_/login/oidc`** (`AuthController::loginOidc()`) — a single route serves both legs of the flow, exactly like the reference this was modeled on, distinguished by `OpenIdConnectService::authenticate()` internally (via the underlying library checking for `?code`/`?error`):
  1. **Initial request** (no `?code`/`?error` yet): `authenticate()` returns the IdP's authorization URL; the controller redirects the browser there. This is the URL a login link/button points to directly — a user can link straight to `/_/login/oidc` (e.g. from another site, an email, a bookmark) and never see the magic-link form at all.
  2. **Callback** (the same URL, now with `?code=...&state=...`, since it doubles as the registered `redirect_uri`): `authenticate()` validates the tokens (throws on failure — invalid state, IdP error response, signature/claims failure) and returns `null`.
- On successful validation, the `email` claim (ID token first, `userinfo` endpoint as fallback — `OpenIdConnectService::getUserInfo()`) is looked up via the **exact same** `AggregateMemberResolver::findListAndMemberByEmail()` used by the magic-link flow — OIDC only replaces "prove you own this mailbox by clicking a link" with "prove your identity via your organization's IdP"; list membership is still the actual authorization check, an OIDC login for an email that isn't a member/owner of any list is rejected (`auth.oidc_not_found`) exactly as it would be silently ignored in the magic-link flow (the difference in visibility — an explicit message here vs. always the same generic response there — is *not* an enumeration risk: the magic-link form lets anyone submit *any* email, but only the actual account owner can ever complete their own IdP's login, so revealing "not found" here only ever tells a user something about their own account).
- On success: `session_regenerate_id(true)`, `$_SESSION['user']` set identically to `verifyToken()` (`email` = `$member->attributes['username'] ?? $member->email`, `listCn` = the matched list's `name`). Also stashes the raw ID token in `$_SESSION['oidcIdToken']` — opaque to Listig itself, kept only so `logout()` can hand it back to the IdP as `id_token_hint` (see below).
- No `TokenService`/HMAC token round-trip at all — the IdP's own signed ID token is the credential; Listig only re-derives which *list* the resulting email belongs to.
- `login.latte` renders a "Log in with Single Sign-On" button (linking to `/_/login/oidc`) above the email form when `oidcEnabled` — passed by `showLogin()` — is `true`; entirely absent otherwise.

**Logout** (`AuthController::logout()`, `POST /_/api/logout` — see "Authentication (Magic Link)" step 6 for the route/CSRF wiring, shared with the magic-link flow): destroying `$_SESSION` alone would leave a *local* Listig logout without touching the IdP's own session — the next "Log in with Single Sign-On" click would then silently re-authenticate via the IdP's still-valid cookie, with no login prompt at all. So if the destroyed session had an `oidcIdToken`, `logout()` also attempts **RP-Initiated Logout**:

- `OpenIdConnectService::getLogoutUrl($idToken, $postLogoutRedirectUri)`: if `oidc-logout-url` is configured, returns it verbatim (no params appended — see "OIDC login (`oidc-*`)" for why). Otherwise calls the library's `signOut()`, which discovers `end_session_endpoint` from the provider config and appends `id_token_hint`/`post_logout_redirect_uri` itself (`$postLogoutRedirectUri` = `https://{hostname}/_/login`, so the IdP sends the browser back to Listig's own login page once it's done). Returns `null` — falling back to a purely local logout — if neither is available (no override, and the discovery document has no `end_session_endpoint`; not every IdP implements RP-Initiated Logout) or if anything throws (network error, IdP unreachable, ...) — a failure here must never prevent the local session from being destroyed, which has already happened by this point regardless.
- Because the redirect target sometimes needs to leave Listig entirely (the IdP's own logout page) rather than always being `/_/login`, `logout()` can't just return a plain redirect response the way `verifyToken()`/`sendMagicLink()` do — the client-side `fetch()` in `layout.latte` would follow it as part of the AJAX call itself rather than navigating the browser there. Instead it always returns `200` + JSON `{"redirectUrl": "..."}`, and `listigLogout()` in `layout.latte` sets `location.href` from that.

### Unsubscribe endpoint

`GET /{listname}/unsubscribe?token=...`:
- Invalid signature → error: "Token ungültig"
- `{listname}` doesn't match the `listCn` encoded in the token → same "Token ungültig" error (defense
  in depth against a stale/copy-pasted URL — the token itself is still the sole source of truth for
  which list applies; the URL segment is never trusted on its own)
- Valid but expired → error: "Token abgelaufen"
- `allow-leave: direct` but the list's `MemberResolver` doesn't `supportsRemoval()` (static inline config.yml members, or no member store at all) → error: "Diese Liste unterstützt keine selbstständige Abmeldung..." (`unsubscribe.not_supported`) — a list-wide, non-address-specific fact, safe to reveal (unlike whether a *specific* address is a member), and correct in a way a false "success" isn't: the previous behavior called `removeMember()` unconditionally and always showed success, even when the underlying resolver silently no-op'ed and the member stayed subscribed forever. `removeMember()` is also wrapped in `try`/`catch (\RuntimeException)` as defense-in-depth, converting to the same message rather than an uncaught 500
- Valid, address already removed → success message (idempotent)
- Valid, address present → remove from LDAP (if `allow-leave: direct`) or notify owner (if `allow-leave: moderated`), show success message
- Never reveal whether an address exists

### Routes

Every route not scoped to a specific list lives under the reserved `/_/` prefix. List-scoped routes
are a single bare path segment (`/{listname}`), which can never collide with a `/_/...` route
regardless of registration order, since the latter always has ≥2 segments with a static first
segment — the only requirement is that no list is ever named `_` (enforced fail-fast in
`ListConfig::__construct()`, see "ListConfig with property hooks").

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/_/login` | — | Login form |
| POST | `/_/login` | — | Send magic link (rate-limited) |
| GET | `/_/login/verify` | — | Verify token, create session |
| GET | `/_/login/oidc` | — | OIDC login initiation + callback — only registered when configured, see "Authentication (OIDC)" |
| POST | `/_/api/logout` | user | Destroy session |
| GET | `/` | user | Dashboard: subscribed lists |
| GET | `/{listname}` | user | Manage page (owner) or reduced info page (non-owner) — see "`/{listname}` — owner vs. non-owner view" |
| POST | `/_/api/moderation/{id}/accept` | owner | Accept moderation item |
| POST | `/_/api/moderation/{id}/reject` | owner | Reject moderation item |
| GET | `/_/api/queue/{listname}` | owner | Queue status |
| DELETE | `/_/api/queue/{id}` | owner | Delete failed entry |
| POST | `/_/api/queue/{id}/retry` | owner | Retry failed entry |
| GET | `/{listname}/unsubscribe` | — | Token-based unsubscribe |
| GET | `/{listname}/archive` | per-list `archive` mode | Archive: threaded table view — see "Archive viewer" |
| GET | `/{listname}/archive/{id}` | per-list `archive` mode | Archive: single message |
| GET | `/{listname}/archive/{id}/frame` | per-list `archive` mode | Archive: sandboxed HTML body |
| GET | `/{listname}/archive/{id}/attachment/{index}` | per-list `archive` mode | Archive: attachment download/inline |
| PUT | `/{listname}/{mail}` | Bearer | List Management API: immediate subscribe — see "List Management API" |
| DELETE | `/{listname}/{mail}` | Bearer | List Management API: unsubscribe |
| POST | `/{listname}/subscribe` | Bearer or `public-subscribe: on` | List Management API: request double opt-in |
| GET | `/{listname}/subscribe/confirm` | token in link | List Management API: confirm double opt-in |
| POST | `/{listname}/encrypt-password` | Bearer | List Management API: encrypt + persist a password |
| GET | `/_/health` | — | Health check: DB + LDAP reachability |

Static assets (CSS/images), once added, belong under `public/assets/` as plain files — never routed
through Slim at all. nginx (`docker/nginx.conf`) has an explicit
`location /assets/ { try_files $uri =404; }` block serving these directly, and a fallback
`location / { try_files $uri /index.php$is_args$args; }` that only reaches the Slim front controller
when no real file matches — so `public/assets/...` needs no reserved-name carve-out of its own.
`public/logo.svg`/`public/logo-mark.svg` (see "App name (`app-name`)") predate that convention and sit
directly under `public/` instead — served the same way, via the `location /` fallback's `try_files`
finding the real file before it ever reaches `index.php`, so no nginx change was needed for them either.
Only `index.php` itself is ever passed to php-fpm (`location = /index.php`); any other `.php` request
is rejected with `404` (`location ~ \.php$ { return 404; }`).

### Member dashboard (`/`)

Per subscribed list: mail address, display name (`display-name` || `cn`), description (`text`), "Unsubscribe" button if `AllowLeave::Direct` **and** `ListConfig::$supportsUnsubscribe` — the latter hides the button for a list whose member store can't actually persist a removal (static inline config.yml members, or none configured), instead of showing a button that would previously "succeed" without doing anything.

`DashboardController::index()` includes a list if the viewer is a member **or** an owner of it (`isMember() || isOwnedBy()`) — not just a member. An owner who isn't also a subscribed member (a valid setup — e.g. an LDAP group's `owner:` attribute need not overlap with its `member:` one) previously never appeared here at all, which meant `/{listname}` (the owner manage page) had no discoverable entry point anywhere in the UI for such an owner, not even via this dashboard — see "`/{listname}` — owner vs. non-owner view" below for the matching fix on the other end. Since that route now renders a reduced info page for a non-owner too rather than a 403 (see below), the card's own display name links to `/{listname}` for **every** list shown here (`$listLinks`), member or owner alike — not just owned ones (`$manageLinks`, the owner-only subset), which additionally gets a more prominent "Verwalten"/"Manage" button next to "Unsubscribe" (itself only offered when the viewer is actually a member — an owner-only entry has nothing to unsubscribe from). The archive link (when the list's archive mode makes it reachable at all) lives in the same button row as "Manage"/"Unsubscribe", not as a separate plain inline link.

### `/{listname}` — owner vs. non-owner view

`ListConfig::createContext()`'s `{list-url}` (`https://{hostname}/{list-name}`) is embedded in **every** distributed mail via `list-label`/footer/etc. and reaches every recipient, not just owners — so `ListController::manage()` cannot simply 403 a non-owner the way it used to. It now branches on `isOwnedBy()`:

- **Owner** → the full manage page (`templates/list/manage.latte`, unchanged): list address/display name/description, owners (firstname+lastname only, no email), member count only, moderation queue, queue status, bounce stats.
- **Non-owner** (still requires a session — this route stays behind `AuthMiddleware`, only the ownership check inside it changed) → `renderInfo()` renders `templates/list/index.latte` instead: display name, mail, description, owners, an archive link (only if `archive: public`, or `archive: members` **and** the viewer is actually a member — a non-member must not be handed a link that 401s), and an "Unsubscribe" button (only if the viewer is a member **and** `AllowLeave::Direct` **and** `$supportsUnsubscribe` — the exact same three-part gate `DashboardController` already uses for the same list). No moderation/queue/bounce data is ever computed or passed to this branch at all, not just hidden in the template — `getModerationItems()`/`getQueueStatus()`/`getBounceStats()` are only ever called in the owner branch.

Both views' owner listing renders `trim("$firstname $lastname") ?: ($owner->attributes['username'] ?? '')` per owner, not just `"$firstname $lastname"` — an LDAP-backed list with no `firstname`/`lastname` config alias set up (see "Member attributes — fully dynamic": LDAP has no built-in mapping to those names) would otherwise render nothing but a bare comma per extra owner, since both attributes are simply absent. Falling back to `username` (always populated for LDAP — see "Privacy-preserving `username`" — and commonly populated for other providers too) shows *something* recognizable instead of blank space.

Both branches require `ListController`'s `TokenService`/`'app.hostname'` dependencies now (added for the non-owner branch's unsubscribe-token signing, mirroring `DashboardController`'s own).

### Health check (`/_/health`)

Returns HTTP 200 with JSON `{"db": "ok", "ldap": "ok"}` if both reachable, HTTP 503 (`"error"` for the failing key) otherwise. Used for Docker health checks. DB check is a plain `SELECT 1` against the global PDO connection. LDAP check (`checkLdapReachability()` in `public/index.php`) attempts a bind against every distinct LDAP server referenced anywhere in `config.yml` — both `type: ldap` list-providers and any `member-resolver: {type: ldap}` sub-config nested under `type: inline`/`database`/`yaml` providers; if no LDAP server is configured at all, it reports `ok` trivially (nothing to check).

---

## Security Notes

- IMAP passwords: AES-256-CBC, `base64(iv):base64(ciphertext)` in LDAP, using a subkey derived from `APP_SECRET` (see Key Derivation) — never `APP_SECRET` itself
- `APP_SECRET`: root secret in `.env` only; never used directly as a cryptographic key — see Key Derivation for how per-purpose subkeys (encryption, HMAC) are derived from it
- `config.yml`: contains LDAP bind password; must be mounted as volume, never baked into image
- Native PHP sessions; session ID = CSRF token (sent as `X-CSRF-Token`)
- Login always returns same response (prevents enumeration)
- Unsubscribe errors do not reveal address existence
- Moderation: HMAC + owner identity both required
- Sensitive config keys (passwords, hostnames) blocked at `{}` resolution time via `ResolutionPurpose::Disclosed` (`VariableResolver::BLOCKED_KEYS`) — never reachable from mail body, footer, or UI, regardless of what a given `$contexts` array actually contains (see "ResolutionPurpose")
- `bounce_log` retains sender addresses 90 days — document in privacy/data-retention policy
- Never log MIME content, passwords, or tokens
- `display_errors` must stay `Off` in production (`docker/php.ini`) — the base image's default (`display_errors = STDOUT`) echoes even a vendor-library warning (e.g. `PhpImap\Mailbox` on a transient IMAP outage) directly into the HTTP response body. Beyond the obvious information disclosure (internal file paths, stack traces), this silently breaks intended non-200 status codes: once that warning has been echoed, output has already started, so a controller's later `withStatus(404)` can no longer take effect (`header()` is a no-op after output begins) — the response reaches the client as a broken `200` with error text as its body. Applies to the whole app, not just the archive viewer.
- Archive viewer (see "Archive viewer" for the full design): sanitized via `ezyang/htmlpurifier` with a fixed small allowlist, rendered in a scriptless sandboxed `<iframe>` with its own CSP, external images opt-in only, attachments never trusted on their own MIME/disposition claim (magic-byte check before any inline delivery), and no email addresses displayed in the viewer's own UI (metadata only — see "Privacy" there for the body-text scope boundary). `Hidden`/`Off` are indistinguishable 404s, even to the list's own owner.
- **Untrusted input in `{}` templates**: `VariableResolver::resolve()` only recursively re-resolves a value that is a *plain string taken directly from a context array* — i.e. genuinely operator-authored config, like a `vorname: "{firstname}"` alias or `list-mail: "{list-name}@..."`. Two other kinds of value are always treated as terminal, even if they contain `{`, and are never re-parsed as a template:
  - **Callables** — `MailProcessor`'s `sender-name` derives its result from the incoming mail's raw `From:` header, which an external sender controls.
  - **`Literal`-wrapped values** (`Hengeb\Listig\Variable\Literal`) — every value `MailProcessor::buildMailContext()`/`buildRecipientContext()` puts into the sender/recipient context (`Member::$attributes`, `subaddress`, `mail`) is wrapped this way, because it ultimately comes from a directory/database/CSV row or a self-service subscribe request, not list config.

  Both exclusions are necessary and independent: (1) a crafted `From: "{sender-someAttribute}" <x@y>` sent to a list using the documented `smtp-from-name: "{sender-name} (via {display-name})"` example would, without the callable exclusion, get `sender-name`'s raw extracted text re-parsed as a template — leaking whatever `someAttribute` happens to be on the *sender's own* `Member::$attributes`, broadcast to every recipient via the outgoing From header, with **no `personalize:` misconfiguration required**. (2) Separately, a member whose own `firstname` (or any other attribute, however sourced — e.g. self-set via the public subscribe API) is literally the string `"{someOtherAttribute}"` would, without the `Literal` exclusion, have that attribute's value substituted into their personalized mail even when `someOtherAttribute` was **never itself included in `personalize:`** — the whitelist only gates the *top-level* placeholder actually written in the mail, not what a resolved value's own nested `{}` syntax would otherwise trigger during recursive resolution. Any future context-building code that puts sender/recipient/incoming-mail-derived data into a context array must wrap it in `Literal` for this reason — a plain string is fair game for the next `{...}` it contains, so it must always be config, never message/member data.

  This is a related but distinct protection from `ResolutionPurpose` (next bullet): `Literal`/callable exclusion stops *recursion into message/member data* regardless of who wrote the referencing template; `ResolutionPurpose` stops *reaching a specific credential key* regardless of who authored the referencing template (operator config included).
- **`personalize:` is a genuine trust boundary, not just a formatting preference**: since `Member::$attributes` is fully dynamic (see "Member attributes — fully dynamic"), whitelisting a key there exposes whatever that resolver's backing store happens to have under that name to every sender who can address the list — including a member writing `{key}` in their own mail's subject/body, which `BodyPersonalizer` will substitute per-recipient. Only whitelist keys that are safe for members to see about *themselves* (firstname, pronoun, ...); never add anything sourced from a column/attribute that isn't meant to be mail-visible. This is still worth getting right even with the `Literal` protection above, since `Literal` only stops a whitelisted key's *value* from being abused to reach a second, non-whitelisted key — the whitelisted key's own value is always shown as-is.
- **`ResolutionPurpose::Disclosed` blocks `VariableResolver::BLOCKED_KEYS` at resolution time, not by pre-filtering the context** (see "ResolutionPurpose" above) — this protects every `Disclosed` resolution uniformly, regardless of which code path triggered it. Concretely: `ListConfig::$displayName` is read directly in many places outside the mail-sending pipeline (UI templates, notification mail subjects, the `smtp-from-name` fallback); a list configured with `display-name: "{imap-password}"` must not leak that value just because some *other* code path reads `$list->displayName` directly, whether directly or via another template's recursive resolution. More significantly, `list-mail` (see "`list-mail`" above) is resolved *before* a `ListConfig` even exists — `InlineListProvider`/`YamlListProvider`/`SubaddressListProvider` resolve it against the raw, just-merged provider config, with no `ListConfig` instance to consult. Since the blocking lives in `VariableResolver` itself, `list-mail: "{mail-password}"` is blocked there too, independent of whether any `ListConfig` exists yet.

---

## Logging

Global log level configured in `config.yml` (default: `info`). Per-list override via `log-level` key.
Levels: `debug`, `info`, `warning`, `error`.
Log to stdout (Docker-friendly), structured (JSON) where possible.

### Debug logging

`Hengeb\Listig\Logging\Logger` (`debug()`, its only method) is a small, level-gated wrapper around `error_log()` — `LogLevel` (`Debug < Info < Warning < Error`, `src/Logging/LogLevel.php`) makes the four documented levels an actual, enforced ordering instead of a decorative config key: a message only reaches `error_log()` when the effective threshold is `debug` itself, since `debug()` is the *only* level `Logger` currently emits. The effective threshold is `'app.log-level'` (config.yml root default, resolved the same `getResolvedDefault()`-backed way as `'app.language'`/`'app.name'`) unless the call passes a specific list's `$list->logLevel` as the second argument, in which case that list's own `log-level` override (already resolved through the normal 5-level config merge, see "Configuration priority") applies instead — necessary because `bin/worker.php` builds one `Logger` for the whole process lifetime (see "Worker loop — config reload") while iterating many lists that may each set their own level.

This is scoped tracing, not a retrofit of the whole codebase's logging: the pre-existing ~44 `error_log()` calls throughout `src/`/`bin/` (IMAP failures, moderation errors, rate-limit hits, blocked-variable disclosures, ...) are deliberately **not** routed through `Logger` — they represent operational problems an operator should always see on stdout regardless of the configured level, and migrating all of them to be level-gated (so e.g. `log-level: error` would suppress today's unconditional warnings) was out of scope for what was actually asked; only new, previously-nonexistent low-priority tracing was added, gated behind `debug`. Call sites, all passing the relevant list's `logLevel` where one is in scope:

- **`AuthController::sendMagicLink()`** — one line per login *request* (email, before validation), then exactly one outcome line: link sent (list-scoped level), no matching member found, or rate-limited (both global-level, since no list is known yet in the negative cases).
- **`AuthController::verifyToken()`** — one line per successful magic-link login (global level — the token payload only carries `listCn` as a string at this point, not a `ListConfig` instance, and resolving one via `ListProvider::getList()` purely to pick a log threshold wasn't worth the extra lookup).
- **`AuthController::loginOidc()`** — one line per successful OIDC login (list-scoped level), mirroring the magic-link success line for parity between the two login methods.
- **`ImapPoller::poll()`** — one summary line per cycle when unseen UIDs exist ("found N unseen mail(s) ... UID(s) ..."), then one line per mail actually fetched (UID + Message-ID — deliberately not the subject, since "Never log MIME content, passwords, or tokens" under Security Notes is written as an unconditional rule and a debug log is not an exemption worth carving out for it).
- **`MailProcessor::process()`** — one summary line before the recipient loop (recipient count + `batch_id`), then one line per `QueueWriter::enqueue()` call (recipient address + `batch_id`) — covers "das Enqueuen für alle Mitglieder" end to end, one line per member.

Registered in `config/container.php`: `'app.log-level'` (the global default string) and `Logger::class` (constructed from it via `LogLevel::fromString()`), injected into `AuthController`, `ImapPoller`, and `MailProcessor` alongside their existing dependencies.

---

## Internationalization

Uses `symfony/translation` (`Symfony\Contracts\Translation\TranslatorInterface`), wired as a
singleton in `config/container.php`. Two catalogs, `translations/messages.de.yaml` and
`translations/messages.en.yaml`, loaded via `YamlFileLoader`. Fallback locale is always
`en` (`setFallbackLocales(['en'])`) — a key missing from the current locale's file resolves
to the English string instead of the raw key.

Templates do **not** use Latte's built-in `{_...}` tag/`TranslatorExtension` (it requires an
object implementing `Nette\Localization\Translator`, which is not an installable Composer
package under that name — verified against Packagist). Instead, the translator is passed as
a plain template variable and called directly: `{$translator->trans('login.heading')}`.
Inside `<script>` blocks, Latte forbids `{...}` print statements *inside* JS string quotes
(`scriptTagQuotesPass` compile error) — write `alert({$translator->trans('key')})`, not
`alert('{$translator->trans('key')}')`; Latte outputs the JS string literal itself,
correctly escaped for the script context.

### Config key: `language`

Just another config key, resolved through the normal `ConfigResolver`/`ListConfig` merge
chain — no special-casing:
- Global default: `language` at the root of `config.yml` (code-default `en`
  if absent), read via `ConfigResolver::getResolvedDefault()['language']` into the
  `'app.language'` container entry, exactly like `db-*`.
- Per-list override: same key via LDAP `description[]`, database `list_config`, or inline
  config — works automatically because `resolveListConfig()` already merges the root/default
  config into every list. Exposed as `ListConfig::$language` (`$this->raw['language'] ?? 'en'`).

### Rule: templates vs. PHP, global vs. list-scoped

- **Static labels/headings/buttons in templates** → `{$translator->trans('key')}`, no params.
- **Anything with interpolated values** (names, error messages, byte sizes) → resolved in
  PHP via the injected `TranslatorInterface` with `%placeholder%` params (Symfony's default
  syntax; no ICU MessageFormat — not needed for these strings) and passed to the
  template/mail as an already-translated string. Where possible, a number is placed next to
  a translated label instead of interpolated into it (e.g.
  `{$translator->trans('list.manage.moderation_queue')} ({count($moderationItems)})`) to
  avoid the placeholder question entirely.
- **No list context** (login, dashboard): use the translator's ambient locale
  (`app.language`, set at construction).
- **List context** (`ModerationMailer`, `BounceHandler`, `RejectionNotifier`,
  `QueueSender::notifyOwnerOfFailure`, `UnsubscribeController::notifyOwners`): pass
  `$list->language` explicitly as `trans()`'s 4th (`$locale`) argument — stateless, no
  mutation of shared translator state.
- **The list-scoped pages** (`templates/list/manage.latte` and `templates/list/index.latte`,
  both rendered by `ListController::manage()` — see "`/{listname}` — owner vs. non-owner view"):
  the controller calls `$this->translator->setLocale($list->language)` once, right before
  rendering either one — safe because each HTTP request runs in a fresh container (Slim,
  no long-running worker).

### Reject reasons are translation keys, not messages

`FilterResult::reject(string $reasonKey, array $reasonParams = [])` — `IncomingMailFilter`
returns keys like `'reject.size_exceeded'` with `['%max_size%' => $list->maxSize]`, not
literal English sentences. `RejectionNotifier::notify()` translates the key (and the
surrounding subject/body) using `$list->language` at send time.

---

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
- `Headers::addTextHeader($name, $value)` always creates an `UnstructuredHeader`, but `Headers::HEADER_CLASS_MAP` enforces a specific value class for some names and throws `LogicException` otherwise — `Message-ID` needs `addIdHeader()`, `Date`/`From`/`To`/`Cc`/`Bcc`/`Sender`/`Reply-To`/`Return-Path` each need their own dedicated `add*Header()` method too. `In-Reply-To`/`References` are the one deliberate exception (`UnstructuredHeader` *or* `IdentificationHeader` both allowed) — see "Header filter" for where this actually bit `MailProcessor`.
- `Email::attach()` always produces `Content-Disposition: attachment` with no `Content-ID`; `Email::embed()` produces `inline` but auto-generates its own Content-ID rather than accepting a specific pre-existing one. To preserve an incoming attachment's *exact* original Content-ID (required for `cid:` references copied verbatim into a forwarded/distributed body to keep resolving), build the `DataPart` manually: `(new DataPart(...))->asInline()->setContentId($id)`, then `$email->addPart($part)` — see "Attachments — preserving embedded (`cid:`) images" for where this actually bit `MailProcessor`.
