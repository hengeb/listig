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

**Access logging (`docker logs`)** — nginx's own access log is the canonical one: `docker/nginx.conf` sets `access_log /dev/stdout combined if=$loggable;`, where `$loggable` is built from two independent maps, ANDed together via string concatenation (`access_log`'s own `if=` only accepts a single variable, so both exclusions have to collapse into one): `map $request_uri $loggable_uri { ~^/_/health 0; default 1; }` excludes Docker's own `HEALTHCHECK` (`/_/health`, hit every ~30s — see "Health check" below), and `map $status $loggable_status { 404 0; 405 0; default 1; }` excludes plain 404s and 405s — the dominant shape of automated bot/scanner traffic (probes for `wp-content/`, PHP shells, etc., see "Quiet 404/405 logging" below), which otherwise drowns out anything actually worth seeing (5xx, real errors) in `docker logs`. `map "$loggable_uri$loggable_status" $loggable { 11 1; default 0; }` then combines them: only a request that's loggable by *both* criteria (`"11"`) is logged; any other combination is suppressed. `$status` is safe to key a `map` on here despite being a response-phase variable — `access_log`'s own `if=` is evaluated at the point the log line is actually written, after the response status is already final, same as `$request_uri`. Every status other than 404/405 (2xx/3xx/401/403/429/5xx/...) still logs exactly as before — this narrowly targets "URL doesn't exist"/"wrong method for this URL," never a real failure. `docker/php-fpm-pool.conf` (copied to `/usr/local/etc/php-fpm.d/zz-listig.conf` — the `zz-` prefix sorts it after the base image's own `docker.conf`/`zz-docker.conf`, so its directive wins) disables php-fpm's *own* access log entirely (`access.log = /dev/null`, overriding `docker.conf`'s `access.log = /proc/self/fd/2`) so every request is logged exactly once, through nginx, not twice.

**Quiet 404/405 logging** — `docker/nginx.conf`'s `location ~ \.php$ { return 404; }` (see "Routes") already intercepts most automated bot/scanner traffic (probes for `wp-content/`, PHP shells, etc.) before it ever reaches PHP-FPM, so those never generate a PHP-level log entry at all. A request that *doesn't* end in `.php` but still matches no route (e.g. `/wp-content/`) reaches Slim, which throws `Slim\Exception\HttpNotFoundException`; by default `$app->addErrorMiddleware($displayErrorDetails, true, true)` (`public/index.php` — see "Security Notes" for why `$displayErrorDetails` is `false`) logs every exception's full type/message/file/line/stack trace via `error_log()` — redundant for a 404 specifically (this class of request is overwhelmingly the same bot noise the `.php` rule already filters out, and — now that nginx's own access log excludes 404s too, see "Access logging" above — there is no access-log line left to be redundant *with* either, it would just be pure noise with nothing to justify it). A request whose *path* happens to match a registered route, but not for the HTTP method used, is the same story one level over: Slim throws `Slim\Exception\HttpMethodNotAllowedException` instead of a 404, but it's just as often the same bot/scanner noise, and just as redundant to log twice — confirmed live, an automated `GET /.git/HEAD` scan happened to path-match the `{listname}/{mail}` route (registered `PUT`/`DELETE` only, see "Routes") purely by segment count, producing both a full verbose PHP-level log entry *and* its own nginx access-log line for a probe with nothing to do with application logic. `docker/nginx.conf`'s `map $status $loggable_status` therefore excludes 405 the same way it already excludes 404 (see "Access logging" above — both are "not really an application-level event" cases, not real failures), and `src/Http/QuietBotNoiseErrorHandler.php` (a small `Slim\Handlers\ErrorHandler` subclass whose `writeToErrorLog()` is a no-op) is registered for *both* `HttpNotFoundException` and `HttpMethodNotAllowedException` via two `$errorMiddleware->setErrorHandler(...)` calls (same handler instance for both) in `public/index.php` — the response body/status is unaffected, only the log writes are skipped, on both layers, for both statuses. Every other exception type (a real 500, a config error, ...) still goes through Slim's default `ErrorHandler` and is logged in full on both layers, unchanged.

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
│   ├── index.php                     # Slim HTTP entry point
│   ├── favicon.ico / favicon.png / favicon.svg # served statically; only favicon.ico is actually picked up (browser default convention — no <link rel="icon"> in layout.latte), see "Routes"
│   └── assets/                       # served directly by nginx (location /assets/), never routed through Slim — see "Routes"
│       ├── style.css
│       ├── script.js                 # shared JS loaded on every page (getCsrfToken(), listigLogout()) — see "Static assets"
│       ├── archive-index.js          # templates/archive/index.latte's client-side thread toggle/quick filter — see "Threading"
│       ├── archive-show.js           # templates/archive/show.latte's image-toggle/HTML-text-toggle/delete button — see "Archive viewer"
│       ├── list-manage.js            # templates/list/manage.latte's moderation accept/reject — see "Moderation via UI"
│       ├── compose.js                # templates/compose.latte's address request + mailto redirect
│       ├── logo.svg                  # full wordmark
│       └── logo-mark.svg             # icon only, no baked-in text — see "App name (`app-name`)"
├── src/
│   ├── Imap/
│   │   ├── ImapPoller.php            # Polls IMAP via PhpImap\Mailbox; explicitly re-selects INBOX first (see "IMAP connection reuse across worker cycles"); checks UIDVALIDITY; returns (uid, uidvalidity, mime, mail: IncomingMail) tuples
│   │   ├── ImapArchiver.php          # Archives or deletes processed mails; deletes inbox mails older than 30 days; prunes archived mail per-list archive-max-age — see "Archive retention"
│   │   └── ImapMailboxFactory.php    # Builds/caches PhpImap\Mailbox connections per list, keyed by imap-* fingerprint, surviving across worker cycles via a hasImapStream() liveness check — see "IMAP connection reuse across worker cycles"; also computes absolute (top-level) IMAP folder paths — see "Archive folder path"
│   ├── Archive/                      # Web archive viewer backend — see "Archive viewer"
│   │   ├── ArchiveIndexer.php        # Writes archived_mail rows; called alongside (not from) ImapArchiver::archiveOrDelete()
│   │   ├── ArchiveSynchronizer.php   # Proactive reconciliation on opening the archive index, throttled per list per session — see "Proactive sync on opening the archive"
│   │   ├── ArchiveThreader.php       # Pure PHP: annotates a page of rows with depth/thread_size/is_thread_start
│   │   ├── ArchiveMailLocator.php    # Re-locates a message by Message-ID in the list's IMAP archive folder ($archiveFolder), on demand
│   │   ├── ArchiveMailNotFoundException.php # Thrown by ArchiveMailLocator::find() only after a full, successful SEARCH ALL scan confirms the mail is genuinely gone
│   │   ├── ArchiveMailResolver.php   # Locate-by-Message-ID + eager attachment-content caching, extracted so BounceController can reuse it — see "Bounce preview"
│   │   ├── ArchiveMailCache.php      # APCu cache of a fully-resolved archived mail, keyed by list+Message-ID — see "Archive mail cache — performance"
│   │   ├── AttachmentSafety.php      # isSafeInlineContent() magic-byte check + sanitizeFilename(), extracted so ModerationController can reuse it too
│   │   ├── CachedArchivedMail.php    # Serializable snapshot of an IncomingMail — textHtml/textPlain + CachedAttachment[]
│   │   ├── CachedAttachment.php      # Serializable snapshot of an IncomingMailAttachment, contents eagerly resolved
│   │   ├── ArchiveHtmlSanitizer.php  # HTMLPurifier config + cid: rewriting + external-resource gating
│   │   └── ByteFormatter.php         # Shared B/KB/MB/GB/TB formatting — PHP (ArchiveController) and the `formatBytes` Latte filter both use it
│   ├── Mail/
│   │   ├── MailProcessor.php         # Builds outgoing Email from IncomingMail; personalizes per recipient; enqueues
│   │   ├── BounceHandler.php         # Detects + forwards a bounce to the list's owners as multipart/mixed; resolves+authenticates the per-recipient bounce token before any automatic action — see "Bounce notice details" / "Bounce loop prevention" / "Automatic bounce actions"
│   │   ├── BounceCause.php           # Plain enum: bounce reasons an automatic action exists for — only Spam today, see "Automatic bounce actions"
│   │   ├── BounceCauseClassifier.php # Pure text classification of an already-authenticated bounce's reason into a BounceCause, or null — see "Automatic bounce actions"
│   │   ├── BounceMemberActionExecutor.php # Executes mark-invalid/restrict/remove for BounceHandler — see "Automatic bounce actions"
│   │   ├── BounceSuppressionList.php # DB-backed `restrict` bounce-action storage (bounce_suppressed_members), independent of any ListProvider — see "Automatic bounce actions"
│   │   ├── HeaderFilter.php          # Reads Authentication-Results / arbitrary headers (readHeader) from raw header string
│   │   ├── IncomingMailFilter.php    # Gates incoming mail (takes IncomingMail); returns FilterResult — see "IncomingMailFilter — check order"
│   │   ├── FilterResult.php          # final class (not enum — needs per-instance reason string): discard | bounce | reject | moderation | distribute
│   │   ├── NotificationMailer.php    # Sender-facing "your mail is pending moderation" notice — see "Moderation"; sends every notification via NullSenderEnvelope + X-Listig-Auto/Auto-Submitted — see "Bounce loop prevention"
│   │   ├── NullSenderEnvelope.php    # Envelope with MAIL FROM:<> (RFC 5321 null reverse-path), via Reflection — see "Bounce loop prevention"
│   │   ├── RejectionNotifier.php     # Sender-facing reject notice for every reject.* reason, with the original mail attached — see "Making clear which mail a reject/pending notice is about"
│   │   ├── ProcessingFailureTracker.php  # DB-backed per-mail attempt counter, bounds bin/worker.php's retry loop — see "Processing-failure retry limit"
│   │   ├── ProcessingFailureNotifier.php # Owner-facing "mail could not be processed after N attempts" notice, original mail attached — see "Processing-failure retry limit"
│   │   ├── ReplyTarget.php           # Value object: resolved recipient behind a `+r-` address
│   │   ├── ReplyTargetStore.php      # Creates/resolves the per-list `+r-{TOKEN}` addresses of the masked reply-to modes — see "Masked reply addresses"
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
│   │   ├── ListConfig.php            # Typed value object; property hooks; holds MemberResolver; createContext() for resolution; validates $name — see "Routes"
│   │   ├── ConfigResolver.php        # Merges config.yml blocks: use:, priority, $VAR substitution; also parses root lists:/restricted-members:/the global level of members:/owners:/member-resolver:/owner-resolver:/senders: — see "Global / provider / list levels"
│   │   ├── RestrictionList.php       # Sender restrictions (send/receive) — one instance built per list from its own global+provider+list levels — see "Sender restrictions"
│   │   ├── YamlIncludeResolver.php   # Resolves !include tags (see "File includes") for config.yml and YamlListProvider files
│   │   └── Enum/
│   │       ├── ReplyToBehavior.php   # 'list' | 'sender' | 'both' | 'nobody'
│   │       ├── PostAccess.php        # 'allow' | 'deny' | 'moderate' — used for both post-access-members and post-access-public
│   │       ├── AllowLeave.php        # 'direct' | 'moderated'
│   │       ├── ArchiveMode.php       # 'members' | 'owners' | 'public' | 'hidden' | 'off'
│   │       └── BounceAction.php      # 'none' | 'mark-invalid' | 'restrict' | 'remove' — see "Automatic bounce actions"
│   ├── Member/
│   │   ├── Member.php                # Value object: email (required) + attributes (everything else, fully dynamic per resolver — see "Member attributes — fully dynamic")
│   │   ├── MemberResolver.php        # Interface: getMembers(), getOwners(), findByEmail(), removeMember()
│   │   ├── MemberResolverFactory.php # Builds member-resolver source(s) (type: database/ldap/csv, single or composable list) and composes all three levels into one resolver — see "Global / provider / list levels"
│   │   ├── CompositeMemberResolver.php # Combines multiple independent MemberResolver sources (any level) for one list — see "Global / provider / list levels"
│   │   ├── NullMemberResolver.php    # No-op implementation
│   │   ├── InlineMemberResolver.php  # Resolves from inline config.yml member lists (plain "mail@x" string or firstname/lastname/mail/username map); removeMember is no-op
│   │   ├── LdapMemberResolver.php    # Resolves via LDAP DNs; removeMember removes DN from member attribute
│   │   ├── DatabaseMemberResolver.php # SELECT * from MariaDB members-table, any non-reserved column becomes an attribute; removeMember sets is_member = 0, then deletes row if no longer member or owner
│   │   ├── CsvMemberResolver.php      # Resolves via a shared flat CSV file (name,mail,is_member,is_owner reserved, any other column an attribute); re-reads per call, flock on write, addMember extends the header on demand
│   │   ├── AggregateMemberResolver.php # Searches all providers; used by AuthController
│   │   └── InvalidatedEmail.php       # Builds the `.BOUNCE_{reason}.{date}.invalid` placeholder for the `mark-invalid` bounce action — see "Automatic bounce actions"
│   ├── Provider/
│   │   ├── ListProvider.php          # Interface: getLists(): ListConfig[], getList(string $name): ?ListConfig
│   │   ├── AbstractListProvider.php  # Shared getLists()/getList()/reset()/resolvedProviderConfig(); subclasses implement loadLists() — see "Provider\AbstractListProvider"
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
│   │   ├── ModerationChecker.php     # Checks DB for overdue moderation items, sends reminders
│   │   └── ModerationResponseHandler.php # Detects +accept-/+reject- in To (raw header, not lowercased $mail->to), verifies HMAC + owner, dispatches accept/reject — see "Moderation"
│   ├── Token/
│   │   ├── TokenService.php          # Signs and verifies truncated-HMAC-SHA256 tokens, compact binary payload — see "Token Format"
│   │   └── ListFingerprint.php       # Short, non-cryptographic list-name fingerprint for bounce/accept/reject tokens — see "Token Format"
│   ├── OpenIdConnect/                # Optional OIDC login — see "Authentication (OIDC)"
│   │   ├── OpenIdConnectService.php  # Thin wrapper around jumbojett/openid-connect-php (Auth Code + PKCE)
│   │   └── OidcRedirectException.php # Turns the library's header()+exit redirect into a catchable PSR-7-friendly exception
│   ├── Crypto/
│   │   ├── KeyDerivation.php          # Static helper: HKDF-SHA256 subkeys from APP_SECRET, one per purpose
│   │   └── PasswordCrypto.php         # AES-256-CBC encrypt/decrypt for IMAP/SMTP passwords
│   ├── Queue/
│   │   ├── QueueWriter.php           # Stores mail + recipients in DB; takes a batch_id (see mail_queue schema)
│   │   ├── QueueSender.php           # Reads queue; uses SmtpConnectionFactory + TokenService (per-recipient signed bounce address); handles retries; discards spam-rejected batches — see "Sending batch" / "Automatic bounce actions"
│   │   └── SpamRejectionDetector.php # Trusted-provider SMTP "rejected as spam" detection — see "Sending batch"; isReliableDomain()/containsSpamIndicator() also reused by BounceHandler's own origin-authentication gate
│   ├── RateLimit/
│   │   └── RateLimiter.php           # Per-sender and global rate limiting (MariaDB-backed)
│   ├── Logging/
│   │   ├── Logger.php                # Level-gated debug() wrapper around error_log() — see "Debug logging"
│   │   └── LogLevel.php              # Debug < Info < Warning < Error enum, backs Logger's threshold comparison
│   └── Http/
│       ├── Controller/
│       │   ├── AuthController.php        # Magic-link login flow, optional OIDC login, logout
│       │   ├── DashboardController.php   # Member view: subscribed lists
│       │   ├── ComposeController.php     # First-mail-to-external form + masked address issuing — see "Masked reply addresses"
│       │   ├── ListController.php        # Owner manage page
│       │   ├── ListApiController.php     # Bearer-token list management API: subscribe/unsubscribe/encrypt-password
│       │   ├── ModerationController.php  # Accept/reject moderation items via API; preview a still-pending mail — see "Preview: pending mail"
│       │   ├── BounceController.php      # Preview a bounce mail (show/frame/attachment), located by Message-ID like the archive viewer — see "Bounce preview"
│       │   ├── QueueController.php       # Queue status API
│       │   ├── UnsubscribeController.php
│       │   └── ArchiveController.php     # Archive viewer: index/show/frame/attachment — see "Archive viewer"
│       ├── Middleware/
│       │   ├── AuthMiddleware.php        # Validates session, injects user identity, redirects to /_/login if absent
│       │   ├── OptionalAuthMiddleware.php # Like AuthMiddleware but never redirects — see "Archive viewer"
│       │   ├── CsrfMiddleware.php        # Validates X-CSRF-Token on state-changing requests
│       │   └── ApiTokenMiddleware.php    # Validates Bearer token against ListConfig::$apiToken
│       ├── RequestPath.php               # relativeTarget() helper shared by AuthMiddleware/ArchiveController for the OIDC deep-link "next" redirect — see "Deep-link redirect-back"
│       └── QuietBotNoiseErrorHandler.php # Suppresses the verbose exception log for a plain 404 or 405 — see "Quiet 404/405 logging"
├── templates/
│   ├── layout.latte           # Optionally imports /app/config/custom.latte (operator-mounted, not part of this tree) — see "Custom layout"
│   ├── login.latte
│   ├── compose.latte          # see "Masked reply addresses"
│   ├── dashboard.latte
│   ├── unsubscribe.latte
│   ├── subscribe-confirm.latte
│   ├── list/
│   │   ├── index.latte
│   │   └── manage.latte
│   └── archive/
│       ├── index.latte        # Threaded table view, quick filter, pagination
│       ├── show.latte         # Single message: metadata, attachments, embeds the frame — reused by ModerationController/BounceController via $baseUrl/$backUrl/$allowDelete params
│       ├── frame.latte        # Standalone doc for the sandboxed iframe — does NOT extend layout.latte
│       └── login_required.latte
├── translations/
│   ├── messages.de.yaml
│   └── messages.en.yaml
├── migrations/
│   ├── 001_initial.sql        # includes archived_mail — see "Archive viewer"; applied automatically, see "Database migrations"
│   ├── 002_moderation_queue_mail_metadata.sql # adds subject/sender_name/sender_mail/mail_date to moderation_queue, not backfilled
│   ├── 003_bounce_log_message_id.sql # adds message_id to bounce_log, not backfilled — see "Bounce preview"
│   ├── 004_processing_failures.sql   # new processing_failures table — see "Processing-failure retry limit"
│   ├── 005_archived_mail_sender_local_part.sql # adds sender_local_part to archived_mail, not backfilled — see "Archive viewer" Privacy
│   ├── 006_bounce_auto_actions.sql # adds queue_recipients.retry_not_before + bounce_suppressed_members table — see "Automatic bounce actions"
│   └── 007_reply_targets.sql      # reply_targets table — see "Masked reply addresses"
├── docker/
│   ├── Dockerfile             # php-fpm + nginx + worker, all in one image
│   ├── entrypoint.sh          # ENTRYPOINT: runs bin/migrate.php, then execs CMD (supervisord)
│   ├── compose.yaml           # Dev/build-from-source compose file
│   ├── nginx.conf             # proxies to 127.0.0.1:9000 (same container)
│   ├── php-fpm-pool.conf      # zz-listig.conf override — disables php-fpm's own access log — see "Access logging"
│   ├── supervisord.conf       # manages php-fpm, nginx, worker as three processes
│   └── php.ini                # display_errors=Off/log_errors=On — see "Security Notes"
├── deploy/                    # Simplest deployment: published image + MariaDB, no repo checkout — see "Docker Setup"
│   ├── compose.yml.example    # Flat layout — config.yml mounted from the same directory, no config/ subfolder
│   ├── .env.example
│   └── config.yml.example     # Single source of truth for the config.yml template — also used by "Building from source"
├── tests/                     # PHPUnit, require-dev only — see "Testing". Mirrors src/'s namespace under Hengeb\Listig\Tests\
├── phpunit.xml
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
        post-access-members: deny               # owners-only: no key of their own needed, they always post
        post-access-public: deny
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

### Root-level `lists:`

A **separate**, top-level `lists:` key (sibling of `list-providers:`/`filters:` — not the per-provider `lists:` map documented above, though it shares the same map-keyed-by-list-name shape) supplements or defines individual lists **regardless of which provider produces them**:

```yaml
lists:
  newsletter:                       # one of 10 lists a type: ldap provider produces
    member-resolver:
      - type: database               # additive — LDAP membership is never replaced, only supplemented
        members-table: newsletter_externals
  vereinsliste:
    owners:                          # additive too — see "Global / provider / list levels" below
      - admin1@example.org
      - admin2@example.org
  standalone:                        # not produced by ANY configured provider at all
    list-mail: standalone@example.org
    senders:
      - mail: chair@example.org

list-providers:
  staff:
    type: ldap
    ...   # produces "newsletter" and "vereinsliste" from the directory
```

Two things happen, matched purely by list name:

1. **A name also produced by a configured provider** (any type — LDAP, database, inline, yaml, subaddress) gets the root `lists:` entry merged in as an *additional* per-list source, on top of whatever that provider already resolved for it.
2. **A name produced by no provider at all** is defined from scratch via an **implicit `type: inline` provider** — `list-providers:` can be omitted entirely; using only `lists:` behaves exactly like `list-providers: { inline: { lists: <the same content> } }`. Implemented in the composite `ListProvider` built in `config/container.php`: after collecting every configured provider's `getLists()`, any root `lists:` name not among them is built via a synthetic `InlineListProvider('_root', $configResolver, ['lists' => <only the missing names>], $dbFactory)`. Built **lazily**, only once actually needed (not at container-build time) and cached for the rest of the cycle — eagerly resolving it would mean calling `getLists()` on every provider (including LDAP/database ones) just to find out which names are missing, forcing a premature connection even for a request that never touches those lists (see "Worker loop — config reload").

**`ConfigResolver::getListOverride(string $name): array`** (`$this->lists[$name] ?? []`) and **`getListOverrideNames(): array`** — `lists:` is parsed once in `processConfig()`, the same root-special-case treatment as `list-providers`/`filters` (excluded from the "is_array → named block" branch). A list's own provider-native `lists:` entry (LDAP `description[]`, a `config-table` row, or a provider's own `lists:` node for `type: inline`/`yaml`/`subaddress`) and this root-level override are merged into a single per-list source *before* being handed to the three-level mechanism below — see "Global / provider / list levels" — so the "list level" there always means the union of both.

**`lists:` itself is combined from every source, same as the six scoped keys** — the root's own direct `lists:` map plus each root-level `use:`-referenced named block's own `lists:` map (in `use:` order, root-direct merged in last), *not* just the config.yml root's own literal `lists:` key. This was a real, confirmed gap: `lists:` written inside a `use:`-referenced block (including one loaded via `!include`, e.g. to keep local overrides in a gitignored `config.local.yml`) was silently invisible before this fix — `processConfig()` only ever read `$config['lists']` directly, never looked inside `$this->namedBlocks`, so a whole `lists: testliste: { senders: [...] }` block could sit there, fully parsed and stored, and simply never reach `getListOverride()` at all. Unlike the six scoped keys (an *additive list* of independent sources), this is a *key merge per list name* (`array_merge()`, later source wins on a plain-key conflict) — `lists:` is a map, not a list of entries, so two sources defining the same list name combine that list's own keys rather than each contributing a separate item to concatenate. A key that is itself one of the six scoped keys (e.g. `lists: testliste: senders:`) still goes through the normal additive three-level mechanism afterwards, unaffected by this merge — this only decides *which single per-list override map* reaches that mechanism's list-level slot in the first place.

### Global / provider / list levels (`members:`, `owners:`, `member-resolver:`, `owner-resolver:`, `senders:`, `restricted-members:`)

Six config keys — five documented individually below (`senders:`, `restricted-members:`) plus the `members:`/`owners:`/`member-resolver:`/`owner-resolver:` keys already introduced under "`lists:` format" — share one mechanism: each can be set at **any or all** of three levels, and every level that sets it **always adds to** the others, never replaces:

```yaml
# Global — applies to every list in the whole instance
owners:
  - superadmin@example.org

list-providers:
  staff:
    type: ldap
    ...
    # Provider — applies to every list this provider produces
    senders:
      - mail: it-support@example.org
    lists:
      newsletter:
        # List — applies only to this one list
        member-resolver:
          - type: database
            members-table: newsletter_externals
        restricted-members:          # no lists:/except: needed — see "Sender restrictions" below
          - mail: abuser@example.org
            until: "2026-08-20"
```

`newsletter` above ends up with: LDAP directory membership (its provider's own native mechanism) **plus** the database source **plus** `superadmin@example.org` as an owner **plus** `it-support@example.org` as an authorized sender **plus** the one restriction entry — every level's contribution is a strict addition, never a replacement of another level's.

This is a **deliberate behavior change from an earlier version of this codebase**: a list's own inline `members:`/`owners:` used to *replace* what `member-resolver:` produced for that list (`InlineMemberResolver`'s old fallback-chain design). That exclusivity is gone — **every level, including list level, is now purely additive**. A list that previously used its own inline `members:` specifically to override its `member-resolver:` now gets the *union* of both instead; if that's not wanted, remove the `member-resolver:`/`owner-resolver:` (or the relevant global/provider-level entries) rather than relying on the list-level entry to exclude them.

**`AbstractListProvider::scopedLevels(string $key, array $listConfig): array`** — the shared primitive every list provider calls once per key, per list, returning *every* raw value contributing to that key across global, provider, and list (order: all global sources, then all provider sources, then the single list value) — identically for all six keys, no per-key special-casing. Each caller (`buildComposedResolver()`, the `senders:`/`restricted-members:` fold below) treats the return value as a flat list of independent sources to combine, never as a fixed 3-tuple — so a level contributing more than one source (see below) needs no special handling on the consumer side.

**A single "level" can itself have more than one source** — this is what actually makes `use:` work for these six keys, not just for ordinary scalar config values. `ConfigResolver::getGlobalScopedSources(string $key): array` returns the root's own direct value for `$key` (if set) *plus* the value of `$key` inside every named block the root's own `use:` references, in `use:` order — a `members:`/`owners:`/etc. entry set inside a block only reachable via `use:` (including one pulled in via `!include`, since that's spliced into the tree before any of this runs) is picked up exactly the same as a literal root-level entry, and both are additive, not one overriding the other. `ConfigResolver::getProviderScopedSources(string $key, array $providerConfig): array` is the symmetric provider-level equivalent, over that one provider's own `use:` list instead of the root's. Named blocks may not contain their own `use:` (see "Configuration priority"), so there is no further recursion to handle — one level of `use:`-expansion at each of the two levels is all there is.

```yaml
owners:
  - superadmin@example.org    # root-direct — a global source

use:
  - shared-owners              # root-level use: — every members:/owners:/etc. key
                                # inside this block is ALSO a global source

shared-owners:
  owners:
    - ops-team@example.org     # combines additively with superadmin@example.org above,
                                # not instead of it
```

This was a real gap, not just a hypothetical: before this existed, `owners:` (or any of the other five keys) written inside a `use:`-referenced block — including one loaded via `!include`, e.g. to keep a locally-overridden owner list in a separate, gitignored file — was silently inert. The block's own key content was still parsed and stored (`ConfigResolver::$namedBlocks`), but nothing ever looked inside it for these six keys specifically, since the global/provider "level" was originally read as a single literal value straight off `$config`/`$providerConfig`, never through the `use:`-expansion path ordinary keys go through. Confirmed live: `owners: !include config.local.yml` referenced only via a `use:`-listed block produced zero owners for every affected list until this fix, with no error — the exact kind of silent misconfiguration this codebase otherwise goes out of its way to avoid (compare the `filters:` `{}`-resolution bug under "Variable resolution in filter patterns", or the `Auth-Submitted` bounce-detection bug — both similarly silent before being fixed).

**`MemberResolverFactory::buildSources(array|null $config, array $resolvedProviderConfig): array`** (`MemberResolver[]`) — unchanged from before this generalization: normalizes a single level's raw `member-resolver:`/`owner-resolver:`/`members:`/`owners:` value into independent sources. `null`/`[]` → none; a single resolver-config map (has `type:` ∈ `database`/`ldap`/`csv`) → one element via the pre-existing `create()`; a sequential list → each entry classified the same way, a resolver-config becomes a real resolver, anything else (a bare string, or a map without a recognized `type:` — the exact shape `members:`/`owners:` entries already use) becomes a single-entry `InlineMemberResolver` (populated as *both* members and owners of itself — harmless, since a source built here only ever lands in one of `CompositeMemberResolver`'s two source lists, so only the matching side is ever queried). `InlineMemberResolver::toMember()` is `public static` so this — and `ListConfig::$authorizedSenders`, see "Additional senders" below — can reuse the exact same string/map-to-`Member` conversion `members:`/`owners:` already used.

**`MemberResolverFactory::buildComposedResolver(array $memberResolverLevels, array $membersLevels, array $ownerResolverLevels, array $ownersLevels, array $resolvedProviderConfig, ?MemberResolver $extraBase = null): MemberResolver`** — builds the final resolver for one list from all three levels of both `member-resolver:`+`members:` (member role) and `owner-resolver:`+`owners:` (owner role), calling `buildSources()` once per level and concatenating every level's sources (`array_merge`, order: `$extraBase`, then member-resolver global/provider/list, then members global/provider/list — same pattern for owners) into a single `CompositeMemberResolver`. `$extraBase`, when given, is unconditionally included in both roles — `LdapListProvider`'s own hardcoded `LdapMemberResolver`, which (unlike every other provider type) is never itself expressed via `member-resolver:` (see "type: ldap"). No "return unchanged if nothing configured" special case is needed — `CompositeMemberResolver` with empty source arrays already behaves like an empty resolver on its own.

**`src/Member/CompositeMemberResolver.php`** (`implements MemberResolver`) — combines independent `$memberSources`/`$ownerSources` arrays. `getMembers()`/`getOwners()` query only their own role's sources and merge-dedupe by lowercased email (first source in configuration order wins on an attribute conflict). `findByEmail()` searches both. `addMember()` tries each member source in order, the first that doesn't throw wins (most resolvers can't signal "not applicable" any other way — `DatabaseMemberResolver` upserts unconditionally, so it always "succeeds"; only `LdapMemberResolver` throws when no matching directory entry exists — so listing LDAP before a database fallback means "prefer LDAP if the person has an entry there"). `removeMember()` calls every source with `supportsRemoval()`, not just the first — the same address can plausibly be a member via more than one source at once, and each source's own `removeMember()` is already a silent no-op when the address isn't actually present there.

**`InlineMemberResolver`** — no fallback/override concept anymore: `__construct(array $members, array $owners)` takes two required, non-nullable arrays and nothing else. `supportsRemoval()` is unconditionally `false` (previously depended on whether a fallback was given) — correct, since `CompositeMemberResolver::supportsRemoval()` is already `true` as soon as *any* one of its sources supports it, independent of what any single inline source reports.

**Each provider gathers all six keys the same mechanical way**, at its own list-construction site (`InlineListProvider`/`YamlListProvider`/`SubaddressListProvider`'s `loadLists()`, `LdapListProvider`/`DatabaseListProvider`'s per-list load method): all six (`member-resolver`, `owner-resolver`, `members`, `owners`, `senders`, `restricted-members`) are excluded from the plain `$raw` config merge (`ConfigResolver::mergeBlock()` replaces rather than combines, so these six are never meaningful as plain `$raw[...]` values) and instead gathered explicitly via `scopedLevels()`:
- `member-resolver`/`members`/`owner-resolver`/`owners` → `MemberResolverFactory::buildComposedResolver()`.
- `senders` → each level normalized (a string is split via `ListConfig::splitCommaList()`, an array/null used as-is) and concatenated into `$raw['senders']` — consumed by `ListConfig::$authorizedSenders` exactly as before, just now sourced from three levels instead of one.
- `restricted-members` → each level normalized the same way (a string becomes one `['mail' => ...]` entry per address, an array/null used as-is) and concatenated into a single `RestrictionList` instance, passed as `ListConfig`'s new `$restrictions` constructor argument — see "Sender restrictions".

`SubaddressListProvider` is the one exception: `members:` at any level is *never* fed into the member-resolver composition for it, since for `type: subaddress` that key means the `{subaddress}`-template mechanism instead (`getMembers()` is always empty by design — see "type: subaddress"); only `owner-resolver:`/`owners:` go through the normal three-level composition there.

`filters:` deliberately does **not** get this three-level treatment — `SpamFilter`'s rule-based, `action:`-driven mechanism is structurally different enough (no resolver/addition concept to generalize) that unifying it wouldn't simplify anything; it stays a single, global, root-only key exactly as before.

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
- `owners:` uses the exact same inline mechanism as `type: inline`, so owner posting rights work identically (owners always post, no config key needed). `type: subaddress` lists have no static `members:`, so `getMembers()` is always empty and `post-access-members` is not meaningful for them — every non-owner sender is evaluated as public (`post-access-public`) instead.
- `{subaddress}` is a new mail-context variable — the matched extension for the current incoming mail (e.g. `alice` for `fwd+alice@example.org`), computed by `Hengeb\Listig\Mail\SubaddressExtractor` from the mail's `To`/`Cc` addresses relative to `list->mail`'s local part **and** domain (so `fwd+alice@other-domain.com` does not match). Resolves to an empty string when absent, like `{sender-firstname}` etc.
- If no `members[].mail` template references `{subaddress}` at all, the list degrades gracefully into a fixed-target alias — every mail (subaddressed or not) resolves to the same target(s), with no missing-subaddress rejection.
- Reserved subaddresses are rejected (`FilterResult::reject('reject.reserved_subaddress')`), not forwarded: `bounce` (exact — collides with the `{list->localPart}+bounce@{domain}` Sender header, `ListConfig::$localPart`) and the `accept-`/`reject-` prefixes (collide with moderation mailto addresses) are always reserved; a list may reserve more via the comma-separated `reserved-subaddresses` key. A mail with no subaddress at all is rejected with `reject.missing_subaddress`, but only if at least one member template actually requires one (see above).

### Spam filtering (`filters:`)

Third top-level key in `config.yml`, alongside the root config and `list-providers`. Globally *configured* — one `filters:` list applies to every list — but each mail is checked against it together with the specific list it was sent to, since a rule's pattern may reference that list's own `{}` variables (see below). Checked by `IncomingMailFilter` for every incoming mail on every list (see "IncomingMailFilter — check order"). Implemented by `Hengeb\Listig\Mail\SpamFilter`, constructed from `ConfigResolver::getFilters()`.

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
    to: "{list-mail}"              # was sent to — see "Variable resolution in filter patterns"
```

- Each entry is a map with one or more of `subject`, `body`, `from`, `to` as keys, plus an optional `action` key (any other key is a hard error at startup, fail fast, same philosophy as missing `$VAR`s). A single field key is just the common case; when an entry has more than one field key, **all** of that entry's conditions must match (AND) for the entry itself to match — different top-level entries are still ORed against each other (see below). `SpamFilter::normalizeRule()` turns each raw entry into `{conditions, action}`; `match()` returns the first fully-matching entry's action, or `null` if none matched.
- `action` is `reject` or `discard` — defaulting to whichever `filters-default-action` resolves to (`'app.filters-default-action'` in `config/container.php`, read the same `getResolvedDefault()`-backed way as `language`/`log-level`; unlike `filters:` itself, a plain scalar key needs no special-casing in `ConfigResolver::processConfig()` at all — only *array*-shaped root keys like `filters:`/`lists:` do), itself defaulting to `reject` (the original, pre-existing behavior) if the key is absent too. Validated in `SpamFilter`'s own constructor (not just at the `config/container.php` wiring call site) against the same `SpamFilter::ACTIONS` list a per-rule `action:` is checked against, so a typo'd `filters-default-action` fails the same way an invalid per-rule value already does. `action` is **not** a match condition itself — it's read and stripped from the entry before the field keys above are validated/compiled, so it can appear alongside any number of them without affecting what the rule matches on. An entry with only an `action` key and no field key at all (nothing to actually match on) is a hard startup error, same as an entry with zero keys.
  - `reject`: same reject *notification* pipeline as every other reject reason — `RejectionNotifier` notifies the sender (translation key `reject.spam`, e.g. "Spam message rejected" / "Spam-Nachricht abgelehnt") and the mail is marked seen.
  - `discard`: `FilterResult::discard(forceDelete: true)` — no notice to the sender at all (unlike `reject`), but still marked seen. Distinct from a bare `FilterResult::discard()` (the X-Loop case, `IncomingMailFilter` check 1), which deliberately leaves the mail sitting in the inbox for manual inspection rather than deleting it — named `discard`, not `delete`, for that broader "mail-handling outcome" sense (matching the internal `FilterResult` type), not because of what specifically happens to the IMAP message.
- **Either action deletes the mail outright** (`ImapArchiver::delete()`) rather than going through `ImapArchiver::archiveOrDelete()` — unlike every other reject reason (auth failure, size, rate limit, ...), a spam-filter match is never worth archiving, regardless of what the list's own `archive:` setting says for everything else; `reject`/`discard` set `FilterResult::$forceDelete = true` specifically for this. Confirmed live: a mail matching a `filters:` rule on a list with `archive: members` was deleted from the inbox outright, not moved into the archive folder the way a `reject.size_exceeded` mail on the same list still is.
- The value is matched literally (`str_contains(strtolower($value), strtolower($pattern))` — case-insensitive) **unless** it looks like a delimited PCRE pattern — starts with one of `/ # ~ % !`, and the same character reappears later followed by nothing but valid regex flags (`a-zA-Z`) to the end of the string. In that case it is passed as-is to `preg_match()` (case-sensitive unless the pattern's own flags say otherwise, e.g. `/ab+$/i`). An invalid regex in that form is also a hard startup error.
- Like every other config value, `filters:` supports `!include` (see "File includes"), so rules can be outsourced to their own file: `filters: !include filters.yml`.
- A matching rule is traced at `log-level: debug` (see "Debug logging") — which rule (1-based position), its action, and the resolved condition(s) it matched on.

#### Variable resolution in filter patterns

A pattern may contain `{}` variables, e.g. `from: "MAILER-DAEMON@{domain}"` to match against a specific list's own bounce-generating domain rather than a hardcoded one. Unlike almost every other `{}` site in this codebase, these are **not** resolved once at startup — `filters:` itself has no list in scope at all (it's parsed once, globally, by `ConfigResolver::processConfig()`, alongside `list-providers:`, before any specific list exists), so there is nothing to resolve `{domain}`/`{list-mail}`/etc. against yet at that point. This was confirmed live as a real, silent bug: a rule referencing `{domain}`/`{list-mail}` matched literally against those unresolved placeholder strings, which no real mail ever contains — the rule simply never fired, with no error or warning to say so.

Fixed by deferring resolution: `SpamFilter::normalizeRule()` keeps a condition's raw pattern text as-is (including any `{}`), and `SpamFilter::match(IncomingMail $mail, ListConfig $list)` — now takes the list being checked, not just the mail — resolves each condition's pattern against `$list->createContext()` fresh, inside `allConditionsMatch()`, only when the raw pattern actually contains a `{` (a plain `str_contains()` check, cheap, and skips building a context array at all for the common case of a rule with no variables). Resolution uses `VariableResolver::resolve()` under `ResolutionPurpose::Disclosed`, same as everywhere else — a pattern that references a blocked key (`{imap-password}`, ...) resolves to the classified placeholder rather than leaking it, safe by construction, not because filters: happens to be a special case.

One consequence of deferring resolution to match time: case-folding a literal (non-regex) pattern also has to happen then, not at `normalizeRule()` time as before, since the pattern isn't fully known until it's resolved against a specific list. Regex-ness (`isRegex()`) and startup-time regex-validity checking are unaffected and still happen once, on the raw pattern, at construction — a `{}` placeholder is always inert, valid PCRE syntax on its own (a `{` that doesn't form a numeric quantifier like `{2,4}` is just a literal character), so validating before resolution doesn't risk a false positive.

No escaping is applied to a resolved value used inside a regex pattern — if a list's own `{list-name}`/`{domain}`/etc. happens to contain a regex metacharacter, it's substituted verbatim and takes on its regex meaning, same as any other `{}` substitution elsewhere in this codebase (e.g. a footer or subject-label template). This is a known, accepted tradeoff, not a bug: operators writing `{}` inside a `/regex/` pattern are expected to understand what they're embedding it into.

### App name (`app-name`)

Root-level `config.yml` key, default `'Listig'` — the app's own display name, shown everywhere a page or mail addresses the app itself rather than a specific list (page `<title>`s, the header brand next to the logo mark, the login mail subject, the queue delivery-failure notice). Resolved via `'app.name'` in `config/container.php`, same `VariableResolver::resolve()`-backed pattern as `hostname`/`language` (see the block comment above `'app.hostname.resolved'`) — not blocked, not a credential, just a display string, so `{}` templates referencing other root keys work fine here too.

Every controller that renders a template, plus `QueueSender` (delivery-failure notice), takes `appName`/`$this->appName` accordingly:
- Templates receive it as the `appName` variable — used directly in `layout.latte`'s header/default `<title>` and every page's own `{block title}`, alongside `logo-mark.svg` in the header (see "Static assets" below).
- Translated strings that name the app take `'%app_name%' => $appName` as a `trans()` param — `auth.login_mail.subject`, `queue.failure_notice.body`, and each page-title key (`login.title`, `dashboard.title`, `unsubscribe_page.title`, `subscribe_page.title`).

This is a distinct concept from a *list's* `display-name` (see "`description` → `list-description`" for the analogous list-vs-member key-collision reasoning) — `app-name` names the whole Listig instance, not any one list.

**Static assets**: `public/assets/logo.svg` (full wordmark) and `public/assets/logo-mark.svg` (icon only, no baked-in text — used in the header precisely so it stays correct next to a configurable `appName` instead of always visually saying "Listig") are served directly by nginx's `location /assets/ { try_files $uri =404; }` block (see "Routes"), same as `style.css`/`script.js`/every other file there — no route or controller involved.

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
5. Per-list key-values from the provider (LDAP: `description[]`; database: `config-table` rows; inline: list-level keys)
6. Root-level `lists: <name>:` (see "Root-level `lists:`") — highest priority, applies uniformly regardless of provider type.

`members:`/`owners:`/`member-resolver:`/`owner-resolver:`/`senders:`/`restricted-members:` are exempt from this plain-value priority chain entirely — see "Global / provider / list levels": all three of their own levels (global, provider, list — the last being the union of level 5 and level 6 above) are always additive, never one overriding another.

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
- **A `{` immediately followed by a digit is never treated as a placeholder** — `walkPlaceholders()` passes it through as literal text instead of scanning for a matching `}`. Every variable name in this app is alphabetic/hyphenated (`domain`, `list-name`, `sender-firstname`, a member's own attribute name, ...), never digit-first, so this is an unambiguous way to leave a PCRE quantifier alone. This matters specifically for `filters:` (see "Spam filtering") — a regex pattern like `subject: /spa{5,}m/i` was, before this, corrupted by `SpamFilter`'s own `{}`-resolution pass (triggered by `str_contains($pattern, '{')`, needed for genuine `{}` variables in a pattern like `from: "MAILER-DAEMON@{domain}"`): `{5,}` was looked up as a variable named `5,`, found nowhere, and silently resolved to `''` per this class's own "key not found → empty string" rule — turning `/spa{5,}m/i` into `/spam/i` without any error. Confirmed live: the same rule matched correctly against a real "SPAAAAAM" (5+ a's) subject after this fix, and still left a genuine `{domain}`/nested-`{}`-in-filter-args placeholder elsewhere in the same string fully resolved, unaffected.

#### Member attributes — fully dynamic

`Member` has exactly one fixed field: `$email`. Everything else a resolver happens to know about a member — `firstname`, `lastname`, `username`, `pronoun`, an LDAP `employeeNumber`, a custom `title` column/key, anything — lives in `Member::$attributes` (`array<string, string>`), keyed by whatever name the backing store itself uses. **Nothing beyond `email` is hardcoded in `Member` or any resolver** (`is_member`/`is_owner`/`name` are reserved too, but structurally — they scope/filter rows, they never become attributes):

- **`type: database`**: `DatabaseMemberResolver` does `SELECT *` and exposes every column except `name`/`mail`/`is_member`/`is_owner` as an attribute. Add, rename, or remove columns in `list_members` freely — no code change needed. `addMember()` builds its `INSERT`/`ON DUPLICATE KEY UPDATE` column list dynamically from `Member::$attributes`; attribute names are validated as plain SQL identifiers (`^[A-Za-z_][A-Za-z0-9_]*$`) and backtick-quoted before being interpolated — this is what prevents SQL injection via a malicious attribute name, since PDO placeholders only cover values, not column names. An attribute naming a column that doesn't actually exist in the table still fails, just at the database (unknown column).
- **`type: csv`**: `CsvMemberResolver` exposes every CSV column except `name`/`mail`/`is_member`/`is_owner` as an attribute — whatever the file's header row currently has. `addMember()` extends the header with any new attribute key it's asked to write, backfilling `''` for every other row (see "CSV member file format").
- **`type: inline`**: every key in a `members:`/`owners:` entry except `mail` becomes an attribute verbatim (`InlineMemberResolver::toMember()`).
- **`type: ldap`**: `LdapMemberResolver` exposes *every* attribute of the directory entry (`Entry::getAttributes()`, first value of each) except `mail`, under its own LDAP name — `{cn}`, `{givenName}`, `{sn}`, `{employeeNumber}`, `{businessCategory}`, whatever the schema has. There is no translation to `pronoun`/`title`/etc. — a list defines its own mapping as a normal config key, e.g.:
  ```yaml
  pronoun: "{businessCategory}"
  ```
  Since these are just config keys, they go through the standard 5-level priority merge (see "Configuration priority") and are resolved lazily like any other `{}` template — settable once at the config.yml root, at list-provider level, or per list, exactly like `list-mail`'s provider-level default. `firstname`/`lastname` are the one pair that *doesn't* need a list-level alias for LDAP: `LdapMemberResolver::entryToMember()` fills `attributes['firstname']`/`['lastname']` from `givenName`/`sn` — the standard `inetOrgPerson` attributes every LDAP schema this app expects already has — as a fallback (`isset()`-guarded, so a directory that happens to carry its own real `firstname`/`lastname` attributes is never overwritten). This exists so `{firstname}`/`{lastname}` — used throughout the codebase for a person's name (mail personalization, `{sender-name}`, `ListConfig::resolveMemberDisplayName()` in the manage-page owner list, ...) — work for any LDAP-backed list without every operator having to redefine `firstname: "{givenName}"` / `lastname: "{sn}"` themselves; a list-level alias is still supported and, since a member's own attributes are consulted first (see below), simply becomes redundant once this fallback already filled the same value in. `LdapMemberResolver` additionally copies `cn` into `attributes['username']` unconditionally (not `isset()`-guarded, unlike `firstname`/`lastname`) — see "Privacy-preserving `username`" below.

**Resolution** (`MailProcessor::buildRecipientContext()`/`buildMailContext()`): `$recipient->attributes` (or, for the sender, `$senderMember->attributes` prefixed `sender-`) is exposed directly under each key's own name, with the canonical `mail`/`sender-mail` always set last so it can never be shadowed by a same-named attribute. A key a specific member simply doesn't have is absent from that member's context — the merge then falls through to whatever the list config defines for that key (e.g. a `pronoun: "{businessCategory}"` alias), and if nothing resolves it at all, `VariableResolver::resolve()` substitutes an empty string rather than leaking raw `{key}` syntax into a sent mail (see "Variable substitution").

A member with its own explicit attribute value therefore always takes precedence over a list-level alias for that same key — the alias is purely a fallback for providers (chiefly LDAP) that have no dedicated field of their own under that name.

##### Example: pronoun-based salutation

Turn a short code like `he`/`she` into a language-appropriate greeting via the `match` filter, chained with `default` for anyone with no pronoun set (see "Filters"): `personalize: pronoun,firstname` plus body text `{pronoun|match:he=>Lieber,she=>Liebe|default:Hallo} {firstname}`. For `type: database`/`csv`/`inline`, populate a `pronoun` column/key directly. For `type: ldap`, map it from whatever attribute the directory actually has, e.g. `pronoun: "{businessCategory}"`.

##### Privacy-preserving `username`

Two call sites need a non-email identifier for privacy — `MailProcessor` embeds it (instead of the raw address) in unsubscribe tokens and the `X-Original-Sender` header, and `AuthController` in login tokens — via `$member->attributes['username'] ?? $member->email`. For `type: database`/`csv`/`inline`, this is just another attribute like any other (populate a `username` column/key if wanted) — optional, with the same email fallback as any provider that doesn't set it, unchanged from before `Member` was genericized. For `type: ldap`, `LdapMemberResolver` is the **one deliberate exception** to full genericity: it duplicates `cn` into `attributes['username']` in addition to exposing it as `{cn}` under its real name. This exists specifically because `AuthController`'s initial email lookup has no *bounded* list in scope — `AggregateMemberResolver::findListAndMemberByEmail()` searches across every list a user might belong to before any one list is known, so the `username` convention can't rely on a per-list alias the way `pronoun` does — without this one hardcoded convention every LDAP-backed login/unsubscribe/reply would silently embed the plain email address instead. (Once a match is found, `AuthController` does have that one list in scope — it uses it to send the login mail through the list's own SMTP config, see "Authentication (Magic Link)" — the lookup phase itself is what's genuinely list-agnostic.)

**Why LDAP and not the other three:** this isn't arbitrary — `cn` is a schema-guaranteed field (a required attribute on the person object classes Listig expects), so copying it is reliable. Database/CSV/inline schemas are entirely operator-defined; there is no equivalent field to auto-derive a `username` from the way `cn` provides one for LDAP, so requiring one would mean rejecting any member row that doesn't happen to have a `username` column/key populated — a new, stricter requirement those three never had, for no clear benefit. An operator who wants the same privacy protection for a database/CSV/inline-backed list simply populates a `username` column/key themselves.

##### Additional addresses per member (`mail-aliases`)

A member/owner may have more than one legitimate address — LDAP's `mail` attribute is multi-valued by schema, and other backends can express the same idea via an extra column/key. Every resolver still only ever exposes **one** address as `Member::$email` (the first `mail` value for LDAP, whatever the `mail` column/key holds for the others) — deliberate, not a limitation worth lifting: `$email` is what's used as the actual delivery address (the recipient envelope in `MailProcessor::resolveRecipients()`, `{mail}` personalization, ...), and a single, stable target address is exactly what that needs. Every *additional* address instead becomes a `mail-aliases` attribute — always the same comma-separated string shape in the end (`Member::$attributes` is `array<string, string>`, see "Member attributes — fully dynamic"), same dual string/array convention `senders:`/`personalize:` already use (see `ListConfig::splitCommaList()`):

- **`type: ldap`** — `LdapMemberResolver::entryToMember()` takes `mail`'s first value as `$email` and joins every value beyond it into `attributes['mail-aliases']`, e.g. `'bob.smith@example.org,b@example.org'` for an entry whose `mail` is `[bob@example.org, bob.smith@example.org, b@example.org]`. Absent entirely (not an empty string) when the entry has only one `mail` value — the common case.
- **`type: inline`/`type: yaml`** — `InlineMemberResolver::toMember()` accepts `mail-aliases` as a YAML list (`mail-aliases: [a@x.org, b@x.org]`), natural for these already-structured formats, and joins it into the same comma-separated string; a `mail-aliases` already written as a plain string passes through unchanged (dual-shape, like everywhere else this pattern is used).
- **`type: csv`/`type: database`** — no code changes needed at all: both resolvers already expose *every* non-reserved column verbatim as a string attribute (see "Member attributes — fully dynamic"), so a plain `mail-aliases` column holding a comma-separated value (`"bob.smith@example.org,b@example.org"`) is picked up automatically by the exact same generic mechanism that already handles `firstname`/`pronoun`/etc.

**`ListConfig::matchEmail()`** (the shared private helper behind `findMemberInList()`/`findOwnerInList()` — and therefore `isMember()`/`isOwnedBy()`, which `IncomingMailFilter::checkPostAccess()`/`requiresModeration()` consult as the actual post-access gate) checks a candidate address against both a member's primary `$email` **and** their `mail-aliases`, so a sender writing from any of their addresses on file — not just the one Listig treats as primary — is still recognized as the same member/owner for posting-access purposes, regardless of which resolver produced them. Members are still recognized as such through the FIRST address only, in the sense that mail is still ever *delivered* to just that one address (unchanged) — this only widens *sender recognition*, never recipient expansion. A member with no `mail-aliases` attribute at all (the common case for every backend) makes `matchEmail()` degrade to the exact same single-address comparison it always did.

This was a real, confirmed gap before this existed, first found for LDAP specifically: `LdapMemberResolver::findByEmail()` (used for login and `{sender-*}` personalization lookups) already worked correctly for any alias address, since its LDAP search filter (`(mail={email})`) matches an entry if *any* of its multi-valued `mail` values equals the target — standard LDAP equality-filter semantics. But `matchEmail()` never touches LDAP (or any other backend) at all; it does a plain string comparison against the already-resolved `getMembers()`/`getOwners()` array, each `Member` carrying only its primary address — so a member sending from a non-primary alias was silently treated as a non-member/non-owner for post-access purposes specifically, even though every other lookup path already recognized them correctly. `mail-aliases` on the other three resolver types is a genuinely new capability (there was never an equivalent "the same person, more than one address" concept for them before), added for parity once the LDAP case was fixed.

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
| `reply-to` | `list` \| `sender` \| `both` \| `nobody` \| `masked-sender` \| `masked-both` | Reply-To behavior — `both` sets both list and sender addresses, *unless* the sender is already a list member, in which case it's just the list address (see "Headers to set on outgoing mail" for why); `masked-sender`/`masked-both` set a signed `{localPart}+r-{TOKEN}@{domain}` address instead of the sender's own — see "Masked reply addresses"; `nobody` sets a translated "please do not reply" display name on `noreply@{list->domain}.invalid` (replies are guaranteed undeliverable — `.invalid` per RFC 2606 — and the display name is what a mail client actually shows when Reply is clicked) |
| `post-access-members` | `allow` \| `deny` \| `moderate` | Whether list members may post (default: `allow`) |
| `post-access-public` | `allow` \| `deny` \| `moderate` | Whether non-members may post (default: `deny`) |
| `allow-leave` | `direct` \| `moderated` | Unsubscribe behavior |
| `archive` | `members` \| `owners` \| `public` \| `hidden` \| `off` | Archive instead of delete after processing, and who may view it in the web archive viewer — see "Archive access levels" (default: `off`) |
| `archive-folder` | string | Name of the IMAP folder archived mail is moved into (default: `Archive`), created as a top-level folder (sibling of INBOX) if it doesn't exist yet — see "Archive folder path" for why this needs its own explanation. Only relevant when `archive` is not `off` |
| `archive-max-age` | relative-time string, e.g. `30 days` | How long archived mail is kept before being deleted from the archive folder (default: unset — unbounded, kept forever, as before this key existed). See "Archive retention (`archive-max-age`)" |
| `max-per-sender` | integer | Rate limit: max mails per sender per 10 min (default: 5) |
| `max-size` | size string or integer | Max accepted mail size (default: `5M`). Accepts `5M`, `5MB`, `5MiB`, `5K`, `5KB`, `5KiB`, `5G`, `5GB`, `5GiB`, or plain bytes. Converted to bytes in `ListConfig`. |
| `list-label` | string | Prepended to subject as `$listLabel $subject` if not already present (case-insensitive) |
| `footer` | HTML string | Footer appended to every distributed mail. Empty string disables footer. |
| `personalize` | comma-separated keys, `off`, or empty | Whitelist of recipient-context variables allowed in body/subject |
| `log-level` | `debug` \| `info` \| `warning` \| `error` | Log verbosity for this list (inherits global default) |
| `language` | `de` \| `en` | Locale for this list's outgoing mails and manage page (inherits global default, code-default `en`) — see Internationalization |
| `api-token` | string | Bearer token for the list-management API (plaintext — see "List Management API"). Empty/absent = API disabled for this list |
| `public-subscribe` | `on` \| `off` | Whether `POST /{listname}/subscribe` accepts unauthenticated requests (default: `off`) — see "List Management API" |
| `sender-address-header` | `never` \| `external` \| `always` | Put the original sender's address into an `X-Original-Sender-Address` header (default `never`; `external` = only for non-members) — see "Masked reply addresses" |
| `bounce-action` | `none` \| `mark-invalid` \| `restrict` \| `remove` | Automatic action for a recognized, authenticated permanent bounce (user/mailbox unknown) or an escalated repeated temporary one (mailbox full) — default `none`. See "Automatic bounce actions" |

**`post-access-members`/`post-access-public` — owners have no key of their own.** List owners can always post, and are never moderated, regardless of what these two keys are set to — there is deliberately no `post-access-owners` (owners posting is not something an operator can restrict). "Owners only may post" is expressed by setting *both* keys to `deny`: `post-access-members: deny`, `post-access-public: deny`. `moderate` queues the mail for owner accept/reject via the normal moderation flow (see "Moderation") exactly as the old `moderation: on` did, just scoped to whichever sender class (members/public) is actually set to it, instead of applying list-wide to everyone who already cleared the (now-removed) single `post-access` gate. See `IncomingMailFilter::checkPostAccess()`/`requiresModeration()`.

### Additional senders (`senders:`)

A third category alongside members/owners/public: addresses allowed to post **without** becoming a member or owner — e.g. a board that should be able to write to the list but must not receive owner-only bounce mail (`NotificationMailer::sendToOwners()`/`BounceHandler` only ever address actual owners, untouched by this feature). Same inline entry shape as `members:`/`owners:` (a plain string, or a map with a required `mail` plus any other attribute keys), settable at any of the three levels — global (every list), provider (every list of that provider), or list (via a provider's own `lists:` node, or the root-level `lists:` mechanism) — see "Global / provider / list levels", always additive across all three:

```yaml
list-providers:
  main:
    lists:
      vereinsliste:
        senders:
          - mail: chair@example.org
```

`ListConfig::$authorizedSenders` (`Member[]`) reads `$raw['senders']`, already gathered from all three levels by the provider (see "Global / provider / list levels") — each level normalized through the same dual string-or-array shape `personalizeKeys`/`reservedSubaddresses` already handle: a plain YAML array is used as-is; a single comma-separated **string** — the shape an LDAP `description:senders:a@x.org, b@x.org` entry or a `config-table` row produces, since neither has nested structure — is split via `ListConfig::splitCommaList()` first. Either way each entry is converted via the `public` `InlineMemberResolver::toMember()`.

`ListConfig::isAuthorizedSender()`/`findAuthorizedSender()` are consulted in two places:
- `IncomingMailFilter::checkPostAccess()`/`requiresModeration()` — the same early-return that already exempts owners (`if ($list->isOwnedBy($senderEmail) || $list->isAuthorizedSender($senderEmail)) { return null; }` / `return false;`) — bypasses `post-access-public: deny`/`post-access-members: moderate` without granting any other owner privilege.
- `MailProcessor::process()`'s sender lookup (`$list->findMemberByEmail($senderEmail) ?? $list->findAuthorizedSender($senderEmail) ?? new Member($senderEmail)`) — so `{sender-*}` personalization (e.g. a custom From display name) still resolves correctly for a `senders:`-only poster, not just members/owners.

### Masked reply addresses (`reply-to: masked-sender` / `masked-both`)

Like `sender`/`both`, but the sender's address never appears in the mail: `Reply-To` is `{list->localPart}+r-{TOKEN}@{domain}` (`MailProcessor::setOutgoingHeaders()`). Only group members will be able to write to that address, and Listig relays the reply. Use cases: a shared contact address (`kontakt@`) that a group answers from, and protecting members' addresses from each other.

- Both modes use a **single** token address (no second `Reply-To` address — not all mail clients handle several). The copy to the group for `masked-both` is made server-side when the reply arrives, so unlike `both` no member-sender exemption is needed (the replier is excluded from the group copy).
- `ReplyTargetStore` (`src/Mail/ReplyTargetStore.php`, table `reply_targets`, migration 007): one row per `(list_cn, kind, target_key)`. `kind = member` stores the member's `username` attribute if present (LDAP: `cn`), else the address, and is resolved live against the current members when a reply arrives — an address change is followed automatically (with a `username`). `kind = external` stores the address. Rows unused for `ReplyTargetStore::MAX_AGE_DAYS` (180, also the token max age) are purged in the worker cleanup step.
- **Tokens are list-specific**: a separate row (hence token) per list for the same address; the payload carries `ListFingerprint`, and `ReplyTargetStore::find()` always looks up `(id, list_cn)` of the list the mail arrived on — the database check is the real boundary.
- **Receiving** (implemented): `ReplyTargetStore::extractToken()` reads `{localPart}+r-{TOKEN}@` from the *raw* To (fallback Delivered-To/X-Original-To) header — not `$mail->to`, which PhpImap lowercases (same reason as accept/reject). `IncomingMailFilter` step 7 then applies `checkMaskedReply()` instead of `checkPostAccess()` (skipped for `type: subaddress` lists): on a list that is not masked → `reject.reply_not_enabled` (so an old token can never leak a private reply into the group after a mode change); `restricted-members:` → `reject.sender_restricted`; sender not member/owner/`senders:` → `reject.reply_not_allowed`; token invalid/expired/other list/target gone → `reject.reply_target_unknown`. `post-access-members` (`deny`/`moderate`) applies only to `masked-both` (whose reply also reaches the group); `masked-sender` reaches one person and is never moderated. Size, SPF/DKIM and rate limit apply as always.
- **Relay** (`MailProcessor::process()`): the target is resolved live (`ReplyTargetStore::resolve()` → `ReplyTarget`, a member by `username` else address, owners included). Recipients (`resolveReplyRecipients()`): `masked-sender` → only the target; `masked-both` → the group minus the replier, plus an external target. Receive restrictions and bounce suppression apply to the target too. The mail goes out `From: <list address>` with `smtp-from-name`; its `Reply-To` is again the replier's own token (an anonymous back-and-forth between members). The visible To/Cc has the token address replaced by the list address (`replaceReplyAddressInRecipients()`). An **external** target gets a plain copy (`$externalEmail`): no list label, footer, `List-*`/`Precedence` headers, `Reply-To: <list address>` — an outsider can't use a token, so their answer goes through the normal list pipeline (`post-access-public`). A successful use touches `last_used_at`.
- **Archive**: a `masked-sender` reply is private — `bin/worker.php` deletes it from IMAP outright (`ImapArchiver::delete()`, regardless of the list's `archive:` setting) and skips `ArchiveIndexer::index()` (`ReplyTargetStore::isPrivateReply()`), so it is kept neither on IMAP nor in the web archive. Likewise a *rejected* mail to a `+r-` address (`ReplyTargetStore::isReplyMail()`) is deleted, not archived. `masked-both` replies are indexed like any distributed mail.
- **Web form for a first mail to an external address** (`GET /{listname}/compose`, `ComposeController`, `templates/compose.latte`, `public/assets/compose.js`; API `POST /_/api/compose/{listname}` behind `AuthMiddleware` + CSRF): the member enters the recipient, the server issues the signed `{localPart}+r-{TOKEN}@{domain}` address (`ReplyTargetStore::tokenFor()`) and returns a `mailto:` link, which the browser opens in the member's mail client — Listig sends nothing itself; the normal reply pipeline then relays the mail From the list address, with a plain copy for the external (its answers go to the list). Available only when `ListConfig::canComposeExternal($identity)`: a masked reply-to mode **and** `post-access-public` != `deny` (else the external's answer would be rejected); owners and `senders:` always, members unless `masked-both` combines with `post-access-members: deny` (masked-sender never reaches the list); never a `restricted-members:` sender. Otherwise 404 and the links (dashboard, `/{listname}` info and manage page) are hidden. Rate-limited to 20 per 10 minutes and user; the address must be valid, not the list's own and not `.invalid`. Deliberately no list of previous contacts — it would reveal external addresses to members who never dealt with them.
- `sender-address-header` (`never` default, `external`, `always`) adds `X-Original-Sender-Address` for members who need the real sender; headers are rarely visible in mail clients — the footer variable `{sender-mail}` is the visible alternative. Either exposes the address to every member; document this in a privacy policy.

### Sender restrictions (`restricted-members:`)

A mechanism (like `filters:`/`banned`-style global rules) for both a temporary, single-list write-only mute and a permanent, instance-wide send-**and**-receive ban — deliberately **one** schema rather than two separate ones, since both are the same underlying statement ("this address, this restriction, this scope") differing only in field values. Like the other five keys under "Global / provider / list levels", settable at any of the three levels, always additive:

```yaml
# Global — every list, unless narrowed by lists:/except: below
restricted-members:
  - mail: abuser@example.org
    lists: [mylist]              # scoped to these list(s); omitted entirely = every list
    until: "2026-08-20"          # optional; omitted = indefinite, until the entry is manually removed
  - mail: excluded@example.org
    receive: false                # also blocks receiving, on top of the always-implied write block (default true = write-only)
    # no "lists:" -> every list
  - mail: partial@example.org
    except: [board-internal]      # blocked everywhere except this one list

list-providers:
  main:
    lists:
      board-internal:
        # List level — lists:/except: are never needed here: an entry declared on
        # one specific list is only ever gathered into that one list's own
        # RestrictionList instance in the first place (see below), so it's
        # implicitly scoped to just this list already.
        restricted-members:
          - mail: troll@example.org
```

**Per-list construction, not one global instance** — each list provider builds its **own** `RestrictionList` for each list it produces, from that one list's own three gathered levels (global + this provider + this list, concatenated), and passes it as `ListConfig`'s `$restrictions` constructor argument. `ListConfig::isSenderRestricted(string $email)`/`isReceiverRestricted(string $email)` delegate to it with the list's own name already bound — no list name parameter needed from the caller, and no global container-wide `RestrictionList` service exists anymore.

**`lists:`/`except:` on a provider- or list-level entry need no special handling** — `RestrictionList::matches()` is completely unchanged: it checks `lists:`/`except:` against the list name it's given, regardless of which level an entry came from. This is automatically correct precisely *because* each list's `RestrictionList` instance only ever contains that one list's own already-gathered entries — a provider-level entry with no `lists:`/`except:` of its own reaches only the `RestrictionList` instances of that provider's own lists in the first place, so "applies to every list" already means "every list of this provider" without any extra filtering. A list-level entry that happened to carry a `lists:`/`except:` naming a *different* list would simply be inert — harmless, not worth guarding against.

**`src/Config/RestrictionList.php`** (unchanged internals) — `isSendRestricted(string $listName, string $email)`/`isReceiveRestricted(...)` walk the entry list: an entry matches if the email matches (case-insensitive), it hasn't expired (`until` unset or still in the future), `lists:` is unset or contains `$listName`, and `except:` is unset or does **not** contain `$listName`. `isReceiveRestricted()` additionally requires `receive: false` on the entry. `except:` is deliberately **not** validated against `lists:` being absent — both filters just run independently in sequence, `except` wins on the (rare) case of a list appearing in both.

- **Sending**: `IncomingMailFilter::checkPostAccess()` checks `$list->isSenderRestricted($senderEmail)` **first**, before even the owner/`senders:` early-return — an instance-wide ban is meant to be absolute, overriding owner status too. Rejects with `reject.sender_restricted`, going through the normal `RejectionNotifier` pipeline like any other `reject.*` reason (no silent discard).
- **Receiving**: `MailProcessor::resolveRecipients()` filters `$list->isReceiverRestricted($member->email)` out of the expanded recipient list, alongside the pre-existing original-To/Cc exclusion — this is what lets a receive-restriction override even a still-active LDAP group membership (see "Member attributes — fully dynamic": `getMembers()` reflects the directory live; this filter runs *after* that, independent of what the directory itself reports).

### Archive access levels

`archive` (`ArchiveMode` — `src/Config/Enum/ArchiveMode.php`) replaced an earlier plain `on`/`off` boolean. Four of the five values archive the mail identically at the IMAP level — `ImapArchiver::archiveOrDelete()` moves the raw original into the list's archive folder (`$archiveFolder`, see "`archive-folder`" above) on its own IMAP mailbox instead of deleting it — and differ only in who may view it through the web archive viewer (see "Archive viewer" below):

- `members` — visible to list members (and owners)
- `owners` — visible to owners only
- `public` — visible to anyone, no login required
- `hidden` — archived, but exposed to no one via the UI, not even the owner — a retention-only mode (compliance/backup) distinct from `off`, which doesn't keep the mail at all
- `off` (default) — not archived; deleted after processing, as before

### Archive folder path

`ImapArchiver::archiveOrDelete()` creates the archive folder (if it doesn't exist) via `PhpImap\Imap::createmailbox()` directly with a fully-qualified `{host:port/imap/secure}FolderName` path built by `ImapMailboxFactory::getAbsoluteFolderPath()` — deliberately **not** via `PhpImap\Mailbox::createMailbox($name)`. The reason is a real bug this fix replaced: `Mailbox::createMailbox()` resolves `$name` *relative to whichever mailbox is currently selected* on that `Mailbox` instance — and every `Mailbox` this app hands out is always connected with `INBOX` selected (`ImapMailboxFactory::createMailbox()`'s own connection string always ends `.../imap/ssl}INBOX`) — so `createMailbox('Archive')` actually created a folder *nested under INBOX* (`INBOX.Archive` on a `.`-delimited server), not a top-level one. `Mailbox::moveMail($uid, $folder)` (used right after, to actually move the mail there) and `Mailbox::switchMailbox($folder)` (used by `ArchiveMailLocator::find()` to view it, with its own default `$absolute = true`) both target the **top-level** folder name unprefixed — so the folder that got created and the folder those two methods looked for were never the same one, and every single archive attempt failed with `imap_mail_move()`'s `"Could not move messages!"`, even though the (wrong, nested) folder visibly existed on the server. Building the correct absolute path once in `ImapMailboxFactory` (shared with nothing else needing it, currently) and creating it via the low-level `Imap::createmailbox()` call sidesteps `Mailbox`'s relative-path assembly entirely, matching what `moveMail()`/`switchMailbox()` already expected.

### Archive retention (`archive-max-age`)

Optional per-list key — a relative-time string PHP's `\DateTimeImmutable` constructor accepts (`"30 days"`, `"6 months"`, ...), the same format `ImapArchiver::deleteOldMails()` already uses internally for the fixed 30-day INBOX rule. Unset (the default) means unbounded retention, unchanged from before this key existed — archived mail is never automatically deleted unless an operator opts in per list.

`ListConfig::$archiveMaxAge` (`?string`) exposes the raw, `{}`-resolved config value as an operator wrote it (e.g. `"30 days"`) — used by `templates/list/manage.latte`'s overview table to show the human-readable duration itself, not a computed date. `ListConfig::$archiveMaxAgeCutoff` (`?\DateTimeImmutable`) builds on it, resolving via `new \DateTimeImmutable("-$raw")` — throws `\RuntimeException` on anything unparseable (fail-fast, same philosophy as an invalid `filters:` regex or a missing `$VAR`), naming the list and the offending value in the message. Since this is a property hook evaluated lazily (not at container-build time), the throw actually surfaces the first time something reads it — `ImapArchiver::pruneArchive()`'s one call site in `bin/worker.php`, wrapped in its own per-list `try`/`catch` (same isolation as `deleteOldMails()` right above it), so a typo on one list logs loudly every cycle without crashing the whole worker.

The manage page's "Übersicht" table (`templates/list/manage.latte`) shows an `archive` row alongside the other config fields (`reply-to`, `post-access-members`, `post-access-public`, ...), same untranslated-raw-enum-value convention already used for those: `{$list->archive->value}` (`off`/`members`/`owners`/`public`/`hidden`), with `({$list->archiveMaxAge ?? …archive_unlimited})` appended in parentheses whenever archiving isn't `off` — `archive-max-age`'s own raw string if set, else the translated `list.manage.archive_unlimited` ("unbefristet"/"unlimited"). `archive: off` shows no parenthetical at all, since nothing is being retained either way.

`ImapArchiver::pruneArchive(ListConfig $list): int` — a sibling of `deleteOldMails()`, but targets the list's own archive folder (`switchMailbox($list->archiveFolder)`, absolute/top-level — see "Archive folder path" above) instead of INBOX, and uses this per-list cutoff instead of the fixed 30 days. No-ops (returns `0`) when `archive: off`, no `archive-max-age` is configured, or IMAP isn't set up for the list. Deliberately has no database dependency at all — only IMAP-specific classes touch IMAP, only database-specific classes run SQL (see "Coding Conventions") — so it never touches `archived_mail` itself.

`bin/worker.php` calls it right after `deleteOldMails()`, per list, and — only when the return value is `> 0` — follows up with `ArchiveSynchronizer::sync($list)` to reconcile `archived_mail` (removes the now-stale index rows for whatever was just deleted; see "Archive viewer" below for what `sync()` itself does). Gating the sync behind "actually pruned something" matters: `sync()` pays for a full `SEARCH ALL` + `FETCH OVERVIEW` scan of the archive folder (documented cost: ~550ms for a 20-message folder, growing with folder size), and once a list's archive has caught up to its configured max-age, most subsequent cycles prune nothing — so the expensive reconciliation scan is naturally skipped on those cycles instead of running unconditionally every `sleep-seconds`. The `ArchiveMailCache` APCu cache is deliberately **not** proactively invalidated by a prune — its 300s TTL self-heals faster than this background sweep runs again, so a stale cache hit for a just-pruned mail is a non-issue in practice.

### Archive viewer

Routes (`Http/Controller/ArchiveController.php`), all registered outside the blanket-`AuthMiddleware` group (`public/index.php`) under `OptionalAuthMiddleware` (`Http/Middleware/OptionalAuthMiddleware.php` — like `AuthMiddleware` but never redirects; exposes `$_SESSION['user']` or `null` as the `user` request attribute and lets the controller decide). Whether login is required at all depends on the specific list's `archive` value, which isn't known until the controller resolves `{listname}` — a per-list decision `AuthMiddleware`'s blanket redirect can't express at route-group level:

| Method | Path | Access |
|---|---|---|
| GET | `/{listname}/archive` | Threaded table view, quick filter, pagination (1000/page) |
| GET | `/{listname}/archive/{id}` | Single message: metadata, attachment list, embeds the frame |
| GET | `/{listname}/archive/{id}/frame` | Sanitized HTML body, sandboxed — see below |
| GET | `/{listname}/archive/{id}/attachment/{index}` | Attachment download / inline embed |

`{id}` is `archived_mail.id` (surrogate PK), not an IMAP UID. `ArchiveController::checkAccess()` (single method, all 4 actions): `Off`/`Hidden` → 404 for everyone including the owner; `Public` → always allowed; `Members`/`Owners` → requires a session and `isMember()`/`isOwnedBy()`. Archive routes sit behind `OptionalAuthMiddleware`, not `AuthMiddleware` (see below), so `checkAccess()` implements its own version of the same OIDC deep-link redirect `AuthMiddleware` does elsewhere: with `'oidc.enabled'` true (constructor arg, wired in `container.php`) it 302s straight to `/_/login/oidc?next=...` — same `RequestPath::relativeTarget()` helper, same round trip back to the exact archive URL once login succeeds, see "Deep-link redirect-back". Only without OIDC configured does a missing session fall back to the translated "please log in" page (HTTP 401, its own login link, no return-URL — the magic-link flow has no "next" concept to hook into).

**Deleting an archived mail** — `DELETE /_/api/archive/{listname}/{id}` (`ArchiveController::delete()`) is the one archive-viewer action that is *not* in the table above: it's registered under `/_/api` alongside `/_/api/queue/...`, behind the normal `AuthMiddleware` + `CsrfMiddleware` group, not `OptionalAuthMiddleware` — deleting must require a real session and `isOwnedBy()` even for an `archive: public` list, where *viewing* requires neither. Triggered by a "Löschen"/"Delete" button in `templates/archive/show.latte` (rendered only when the controller-computed `isOwner` is true), wired up by `public/assets/archive-show.js`'s `deleteArchivedMail()` (confirm dialog, then `fetch(..., {method: 'DELETE'})` with the CSRF header, redirecting to the list's archive index on success — same `getCsrfToken()`/i18n-via-data-attributes pattern as `list-manage.js`). The controller deletes in this order: `ArchiveMailLocator::delete()` (IMAP — finds the UID by Message-ID in the archive folder, `deleteMail()` + `expungeDeletedMails()`; returns `false` rather than throwing if the mail's already gone, since that's the same end state as a successful delete), then `ArchiveMailCache::delete()` (evicts any cached snapshot — see "Archive mail cache" below, otherwise a viewer who had it open moments ago would keep seeing it until the TTL expires), then `ArchiveIndexer::remove()` (the `archived_mail` row itself — the same method `ArchiveMailNotFoundException` handling already uses for a mail found missing on IMAP, see below).

**Index (`archived_mail` table, `migrations/001_initial.sql`)** — populated by `Archive/ArchiveIndexer.php`, called *alongside*, not from within, `ImapArchiver::archiveOrDelete()` — only at the 3 call sites representing a successful distribute (`bin/worker.php`'s `isDistribute` branch, `ModerationController::accept()`, `ModerationResponseHandler::processAccept()`). Deliberately not inside `archiveOrDelete()` itself: that method also runs for bounce/reject outcomes, which were never sent to the list and must not appear in a member-facing archive. Keyed by `message_id` (not `imap_uid`/`imap_uidvalidity` like `moderation_queue`/`imap_seen`) — an IMAP UID is scoped per folder, and archiving moves the mail from INBOX into the archive folder, where it gets a new UID `ImapArchiver` never learns; `Message-ID` is the only stable key. `ArchiveIndexer::normalize()` strips the value's `<>` before storing it, so `archived_mail.message_id` is always the bare id. `Archive/ArchiveMailLocator.php` re-locates the actual body/attachments on demand (`switchMailbox($list->archiveFolder)`, then a linear scan — see below) whenever a single message is opened — the index table only ever serves the list/thread view, never mail content. Both a genuinely missing message and an IMAP-level failure degrade to "mail unavailable" for the current request (rather than a 500), but the two are no longer indistinguishable to the caller: `find()` throws `Archive\ArchiveMailNotFoundException` specifically when a full, successful `SEARCH ALL` scan completed without a match (logged there) — i.e. the mail is confirmed gone from the archive folder, not just unreachable right now — while every other failure (connect/search/fetch exception) still just logs and returns `null`, same as before. `ArchiveController::locateMail()` catches that specific exception and calls `ArchiveIndexer::remove($list->name, $messageId)`, deleting the now-stale `archived_mail` row — so a mail deleted straight from the IMAP archive folder (outside Listig, e.g. by an operator or another mail client) also disappears from the list/thread view, not just the single-message page. This happens lazily, the moment a viewer actually opens that message (`show()`/`frame()`/`attachment()` → `locateMail()`) — there is deliberately no periodic job re-checking every indexed row against IMAP; a mail nobody re-opens keeps its index row until someone does. A transient IMAP outage must never trigger this — that's exactly why the exception is only thrown after a *successful* search that legitimately found nothing, not on a connection/search/fetch failure.

**Proactive sync on opening the archive (`Archive/ArchiveSynchronizer.php`)** — the lazy, open-one-message reconciliation above only ever catches a single mail going missing, and only once someone opens it. `ArchiveController::index()` (the table/thread view) additionally calls `ArchiveSynchronizer::sync($list)` — throttled to once per `ArchiveController::SYNC_INTERVAL_SECONDS` (5 minutes) per list *per session* (`$_SESSION['archive_synced'][$list->name]`, checked/set by `ArchiveController::syncIfDue()`) — to catch mail removed directly from the IMAP archive folder outside Listig entirely (an operator or another mail client deleting a message by hand), not just mail Listig itself already knows might be gone.

`sync()` always pays for one `SEARCH ALL` + `FETCH OVERVIEW` scan of the whole archive folder (Message-ID per message, no body — same call shape as `findUidByMessageId()` below, including the same `$disableServerEncoding = true` workaround) to build the current set of Message-IDs actually on IMAP, then diffs it against `SELECT message_id FROM archived_mail WHERE list_cn = ...` via `array_diff_key()`. Deliberately one-directional — only `archived_mail` rows whose Message-ID is no longer on IMAP get removed (`ArchiveIndexer::remove()`, no fetch needed); a Message-ID found on IMAP but missing from `archived_mail` is left alone. An earlier version also auto-indexed that second case (one `getMail()` fetch + `ArchiveIndexer::index()`, "just like a normal distribute") — that was a real bug, confirmed live: `bin/worker.php` moves a bounced *or rejected* mail's raw MIME into the exact same archive folder as a distributed one (`ImapArchiver::archiveOrDelete()` runs for all three outcomes — see "IncomingMailFilter — check order"), but only ever calls `ArchiveIndexer::index()` for an actual distribute, precisely so bounce/reject mail stays off the member-facing archive (see `ArchiveIndexer`'s own docblock). Nothing on the raw IMAP message distinguishes "a distribute Listig just hasn't indexed yet" from "a reject/bounce Listig never intended to index" — so add-missing necessarily mis-indexed every rejected mail as soon as anyone opened the archive after it landed on IMAP. Remove-missing has no equivalent ambiguity: an indexed Message-ID that's gone from IMAP should always be removed, whatever the reason.

The `SYNC_INTERVAL_SECONDS` throttle exists because the overview scan's cost is the same shape as `ArchiveMailLocator`'s single-message lookup — ~550ms for a 20-message folder, growing with folder size (see "Archive mail cache — performance" below) — which would otherwise be paid on *every* archive index page load, not just when opening one message. Session-scoped rather than global/DB-tracked: it's purely a "don't hammer IMAP on every reload" throttle, not a correctness guarantee — a fresh session (or simply waiting out the interval) always re-syncs, and the timestamp is recorded even when `sync()` finds nothing to change or fails outright (a transient IMAP error there degrades to "nothing to do", same graceful-failure handling as `ArchiveMailLocator::find()` — retrying on every single request while IMAP is down would defeat the point of throttling at all).

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

**Attachments** — served from `CachedAttachment::$contents`, eagerly fetched once per `ArchiveMailCache` entry rather than live from IMAP on every request (see "Archive mail cache — performance" below; the underlying `IncomingMailAttachment::getContents()` call is still what actually performs each fetch, just moved to cache-population time). `X-Content-Type-Options: nosniff` always, plus `Content-Disposition: inline` whenever `AttachmentSafety::isSafeInlineContent()` verifies the content — deliberately *regardless* of the mail's own claimed disposition (cid-embedded or a plain attachment are treated the same, see below), on a small whitelist (`INLINE_SAFE_MIME_TYPES`: `png`/`jpeg`/`gif`/`webp`/`pdf` — deliberately not `svg`, which can carry scripts). The claimed MIME type alone is never trusted: images are re-verified via `getimagesizefromstring()` (decodes and reports the real format), PDF via its `%PDF-` magic-bytes header (no lightweight PHP PDF decoder exists, but that prefix is specific enough that an accidental false-positive on a mislabeled non-PDF is implausible). Everything else is forced `attachment` regardless of what the mail claims — and every attachment link in `show.latte` carries `target="_blank" rel="noopener"`, so a safe-inline file opens in a new tab instead of triggering a download prompt, while an unsafe one still downloads (the browser, not this app, decides based on the response headers).

**Attachment list (`show.latte`, above the mail body, not below)** — a single attachment shows its name and size directly; two or more collapse into a `<details>` summary (`archive.show.attachments_summary`, "*N* attachments (*total size*)") that expands to the full per-file list, name and size each. Sizes come from `IncomingMailAttachment::$sizeInBytes` — populated from the MIME `BODYSTRUCTURE`'s own byte count during the normal `getMail()` parse, so listing sizes never needs a separate content fetch. Formatting (`Archive/ByteFormatter.php`, B/KB/MB/GB/TB) is shared between PHP (the collapsed summary's `%size%` param) and Latte (the `formatBytes` filter, registered in `config/container.php`, per-file sizes) — one rule, not two independently-maintained ones.

**Image previews (`show.latte`, below the mail body)** — a second, separate rendering of just the image-typed attachments (`$imageAttachments`, filtered by `str_starts_with($attachment->mimeType, 'image/')` — a UI hint only, not the security-relevant check; that's `AttachmentSafety::isSafeInlineContent()`, applied independently when the browser actually requests the file), each as a bordered thumbnail box (filename + `<img>` pointing at the same `/attachment/{index}` URL) linking to the full attachment. This is intentionally separate from the summary list above — a purely visual complement, not a replacement — and only ever includes non-cid attachments; images already shown inline in the body via a `cid:` rewrite are excluded from both (`ArchiveController::isEmbeddedInline()`), since showing those a second time would be redundant.

**"Load external content" is a real notice, not just a bare button** (`show.latte`'s `.notice` box, modeled on Roundcube's/Thunderbird's own wording) — a warning icon, an explanatory sentence (`archive.show.external_content_notice`), and the action button (`archive.show.load_images`, labelled "Erlauben"/"Allow") together, rather than a button alone with no context for why images are missing. Clicking it removes the notice and reloads the iframe with `?loadImages=1`, same underlying mechanism as before. The notice only renders when `$hasExternalContent` is true (`ArchiveController::show()` computing it via `ArchiveHtmlSanitizer::hasExternalResources()`, gating a `{if}` in `show.latte`) — it previously rendered unconditionally under every mail regardless of whether it actually had any off-origin image to block, which was misleading for a plain-text-only mail or an HTML one with no external images at all (confirmed live against the archived test mails: only the one containing an actual external image showed the notice after the fix, the rest didn't). `hasExternalResources()` runs the same cid:-rewrite + HTMLPurifier pass `render()` does (so a `cid:`-embedded image is never mistaken for external — `isExternal()`'s `^(https?:)?//` pattern doesn't match `cid:` anyway) and then scans for any off-origin `img[src]`/`[srcset]`, sharing the DOM-walk (`findExternalImages()`) with `stripExternalResources()` rather than duplicating it — both operate on the *same already-parsed* `\DOMElement` tree in `stripExternalResources()`'s case (parsing once, finding, then mutating and calling `saveHTML()` on that one tree), since re-parsing a second copy just to search it would return elements belonging to a different tree than the one about to be saved.

**HTML/plain-text toggle** (`show.latte`, only rendered when `$hasPlainAlternative` is true — i.e. the mail actually has *both* parts, computed in `ArchiveController::show()`) — two pill buttons reload the iframe with `?view=html` / `?view=text`; `ArchiveHtmlSanitizer::render()`'s new `$view` parameter forces the plaintext branch even when `$textHtml` is present, the one deliberate override of its normal HTML-if-present default.

**Timestamps are always UTC in the database** (`archived_mail.mail_date`, written via PHP's own default timezone, not the viewer's) — every template that displays one (`archive/index.latte`'s table, `archive/show.latte`'s metadata) renders the raw UTC value as the element's text content (a no-JS fallback) but also sets `data-utc="{iso-8601-with-Z}"` on it; a small unconditional script at the bottom of `layout.latte` finds every `[data-utc]` element on the page and replaces its text with `new Date(...).toLocaleString()` once the DOM is ready, converting to the viewer's own browser locale/timezone with no server-side per-user preference needed.

**Privacy** — table/single-message views show only `sender_name` (display name, `IncomingMail::$fromName`) — never a full email address; From/Reply-To/To/Cc are never rendered anywhere in this feature's own UI. When a mail's From header carries no display name at all (`sender_name` stays `NULL`, see `ArchiveIndexer::index()`), the fallback is `sender_local_part` (`migrations/005_archived_mail_sender_local_part.sql`, e.g. `"jdoe"` from `"jdoe@example.com"`) rather than going straight to the translated `archive.unknown_sender` placeholder — a nameless mail from a real, distinguishable sender previously looked identical to every other nameless one. Deliberately **only** the local part, never the full address, preserving the same never-show-a-full-address boundary — a local part alone isn't a deliverable address on its own. `templates/archive/index.latte` (both the visible cell and the `data-sender` quick-filter attribute) and `templates/archive/show.latte` both fall through `sender_name ?? sender_local_part ?? archive.unknown_sender`; `show.latte` is also reused by `ModerationController`/`BounceController` for `moderation_queue`/`bounce_log` rows, which have no `sender_local_part` column at all — the `??` chain degrades harmlessly to the translated placeholder for those, unchanged from before. This is scoped to metadata **we** display — an address appearing in a mail's own body text (e.g. a signature) is shown as-is (sanitized for safety, not redacted for privacy).

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
- Logs and substitutes an empty string for a key not found in any context — unless called with `quiet: true` (5th param, default `false`), which suppresses just that one log line (cycle detection and blocked-key logging are unaffected) and threads through recursive/filter-arg resolution. Used by `ListConfig::resolveMemberDisplayName()`, where a member/owner with no `firstname`/`lastname` at all (e.g. added via a bare-string `owners:`/`members:` entry, see "Global / provider / list levels") is the routine case, not a misconfiguration worth logging.

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
    public function supportsInvalidation(): bool;
    public function invalidateEmail(string $listName, string $email, string $reason): void;
}
```

`invalidateEmail()`/`supportsInvalidation()` back the `mark-invalid` automatic bounce action (see "Automatic bounce actions") — mirrors `removeMember()`/`supportsRemoval()` exactly. Replaces the member's own address in place with `Member\InvalidatedEmail::build($email, $reason)` rather than deleting the record outright.

| Implementation | type | Description |
|---|---|---|
| `LdapMemberResolver` | `ldap` | Resolves member/owner DNs via LDAP; every directory attribute except `mail` becomes a `Member::$attributes` entry under its own name (plus a `username` = `cn` convenience copy — see "Member attributes — fully dynamic"); `removeMember` removes the DN from the `member` attribute; `supportsRemoval` always `true`; `addMember` adds it — but only if a directory entry matching the email already exists, else throws |
| `DatabaseMemberResolver` | `database` | `SELECT *`s `members-table` via `DatabaseConnectionFactory` + context config, exposing every non-reserved column as an attribute; `removeMember` sets `is_member = 0`, then deletes row if `is_member = 0 AND is_owner = 0`; `supportsRemoval` always `true`; `addMember` upserts dynamically from `Member::$attributes` (validated as SQL identifiers), preserving existing `is_owner` |
| `CsvMemberResolver` | `csv` | Reads/writes a flat CSV file (`name,mail,is_member,is_owner` reserved, any other header column exposed as an attribute), shared across lists like `members-table`; re-reads on every call, writes take an exclusive `flock`; `supportsRemoval` always `true`; `addMember` extends the header for new attribute keys — see "CSV member file format" |
| `InlineMemberResolver` | — | A fixed, statically-configured set of members/owners — the "bare inline entry" building block for one level (global/provider/list) of `members:`/`owners:`, or one entry of `member-resolver:`/`owner-resolver:` that isn't a resolver config (see "Global / provider / list levels"). Each entry is a plain email string or a map with a required `mail` key plus any other keys, all becoming attributes verbatim. `removeMember` always throws (a request-scoped in-memory removal can never persist — config.yml is never rewritten, and a fresh instance is built from it on every request anyway) and `supportsRemoval` is always `false` — no fallback/override concept anymore; combining an `InlineMemberResolver` with any other source (from any level) is `CompositeMemberResolver`'s job |
| `NullMemberResolver` | — | Returns empty arrays; `removeMember` is a no-op; `supportsRemoval` `false` (no backing store at all); `addMember` throws |
| `AggregateMemberResolver` | — | Searches across all providers; used by `AuthController` to find any list a user belongs to; `supportsRemoval` `false`; `addMember`/mutating calls throw (lookup only) |

`addMember()` is used by `ListApiController` (see "List Management API") for both immediate (`PUT`) and double-opt-in-confirmed subscriptions. Callers must treat the `\RuntimeException` as a real error (e.g. HTTP `409`), not swallow it — an LDAP-backed list silently "succeeding" without actually adding a non-existent-directory-entry member would be worse than an explicit failure.

`supportsInvalidation()`/`invalidateEmail()`: `true`/implemented for `LdapMemberResolver` (instance-wide — a directory entry's `mail` isn't scoped per list, see "Automatic bounce actions"), `DatabaseMemberResolver`/`CsvMemberResolver` (naturally per-list, since `mail` is its own row per list there); `false`/throws for `InlineMemberResolver`/`NullMemberResolver`/`AggregateMemberResolver`, exactly mirroring their own `supportsRemoval()`/`removeMember()`.

`supportsRemoval()` — checked via `ListConfig::$supportsUnsubscribe` (a property hook, like every other derived `ListConfig` value — see "ListConfig with property hooks" — not a method, since `MemberResolver::supportsRemoval()` itself is; the interface it belongs to is method-based throughout) — lets a caller find out *before* calling `removeMember()` whether it would actually persist anything, rather than either silently no-op'ing (previously the case for `NullMemberResolver` and static-inline `InlineMemberResolver`, both of which "succeeded" without ever removing anyone) or throwing. `DashboardController` only shows the "Unsubscribe" link when `allowLeave === Direct` *and* `$supportsUnsubscribe`; `UnsubscribeController`'s direct-unsubscribe branch and `ListApiController::unsubscribe()` (`DELETE /{listname}/{mail}`) both check it (or catch the `\RuntimeException`) before claiming success — see "Unsubscribe endpoint".

`member-resolver`/`owner-resolver` can be configured as a sub-object on `type: inline` and `type: database` providers, with `type: database`, `type: ldap`, or `type: csv` (`{type: csv, file: /path/to/members.csv}`) — and, since `MemberResolverFactory::buildSources()`, as a *list* of such sub-objects (or bare inline entries) too. `type: ldap` (the list provider) always includes `LdapMemberResolver` for every list it produces (`$extraBase` in `MemberResolverFactory::buildComposedResolver()`), independent of any `member-resolver`/`owner-resolver` configured at any level for it — every configured level only ever adds to it, never replaces it.

For `type: inline` and `type: yaml`: `members`/`owners`/`member-resolver`/`owner-resolver` are all independently additive across all three levels (global/provider/list) — see "Global / provider / list levels" for the full mechanism and the deliberate behavior change from the old exclusive-override design. A list with none of the six keys set at any level (global, provider, or list) simply gets an empty `CompositeMemberResolver` for that role — no members, no error.

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
enum ReplyToBehavior: string { case List = 'list'; case Sender = 'sender'; case Both = 'both'; case Nobody = 'nobody'; }
enum PostAccess: string { case Allow = 'allow'; case Deny = 'deny'; case Moderate = 'moderate'; }
enum AllowLeave: string { case Direct = 'direct'; case Moderated = 'moderated'; }
enum ArchiveMode: string { case Members = 'members'; case Owners = 'owners'; case Public = 'public'; case Hidden = 'hidden'; case Off = 'off'; }
```

### ListConfig with property hooks

```php
class ListConfig {
    public string $name;  // provider-agnostic identifier (LDAP: cn); constructor throws if this is "_" (reserved for /_/... system routes) or contains anything outside [A-Za-z0-9_-] — see "Routes"
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

- **`resolve($raw)`, default `ResolutionPurpose::Disclosed`** — the default for everything: `$displayName`, `$description`, `$replyTo`, `$postAccessMembers`, `$postAccessPublic`, `$allowLeave`, `$archive`, `$archiveFolder`, `$maxPerSender`, `$maxSize`, `$publicSubscribe`, `$logLevel`, `$language`, and — despite being `VariableResolver::BLOCKED_KEYS` themselves — `$imapPort`/`$imapSecure`/`$smtpPort`/`$smtpSecure` too. These four are numeric/enum properties (`(int)` cast, `'ssl'|'tls'|'none'` comparison): resolved under `Trusted`, a value like `smtp-port: "{imap-password}"` could silently become the leading digits of the actual password cast to an int, which could then surface via a connection-failure error message — a *fragment* leak that casting makes easy to miss. Staying on `Disclosed` here means these four properties can no longer reference `{mail-user}`/`{mail-password}`/`{mail-host}` or any other blocked key — a deliberate trade-off in favor of the leak protection, since none of them actually need to (there's no `mail-port`/`mail-secure` fallback level to reach).
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
    id                BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    mail_queue_id     VARCHAR(64) NOT NULL REFERENCES mail_queue(id),
    envelope_to       VARCHAR(255) NOT NULL,
    attempts          TINYINT UNSIGNED NOT NULL DEFAULT 0,
    last_attempt_at   DATETIME NULL,
    status            ENUM('pending','sent','failed') NOT NULL DEFAULT 'pending',
    error             TEXT NULL,
    retry_not_before  DATETIME NULL
);
```

`retry_not_before` (added by `migrations/006_bounce_auto_actions.sql`) — set by `QueueSender::markBounced()` only for a `BounceCause::MailboxFull` bounce, to the point in time before which `sendBatch()` must not attempt this (list, recipient) pair again — see "Automatic bounce actions" > "Soft bounces: defer, then escalate".

`mail_queue_id`'s `REFERENCES` has no `ON DELETE CASCADE` — MariaDB still enforces it as a real constraint (auto-named `queue_recipients_ibfk_1`), so any code deleting a `mail_queue` row must delete that row's `queue_recipients` children first, or the delete fails with `"Cannot delete or update a parent row: a foreign key constraint fails"`. `QueueSender::purgeCompletedEntries()` (the renamed, broadened `purgeStaleFailedEntries()` — no longer restricted to `status = 'failed'`, see "Automatic bounce actions" > "Queue retention") does this correctly: its own stale-row delete (`status != 'pending' AND last_attempt_at < NOW() - INTERVAL 30 DAY`), followed by a `NOT EXISTS` sweep for now-childless `mail_queue` rows. `sendOne()` itself no longer deletes anything on completion (the removed `cleanupQueueEntry()`) — a completed row now always waits for this periodic purge instead.

### `moderation_queue`

No `token` column: accept/reject tokens embed `list_cn`/`imap_uid`/`imap_uidvalidity`
and are HMAC-signed (see Token Format), so verifying a reply never needs a DB lookup.
This table only tracks that an item is pending moderation and when it was created/reminded.

`subject`/`sender_name`/`sender_mail`/`mail_date` (added by `migrations/002_moderation_queue_mail_metadata.sql`,
not backfilled — `NULL` for any row queued before this migration ran) mirror `archived_mail`'s
own subject/sender_name/mail_date columns: a snapshot of the moderated mail's own metadata,
populated once by `ModerationMailer::send()` from the already-parsed `IncomingMail` at the point
the item is first queued (and again, unchanged, on every overdue-reminder resend via
`ModerationChecker::checkOverdue()`, which re-fetches the same `IncomingMail` by UID to pass
through) — so both the moderation request mail's body and the manage page's moderation queue
table (`ListController::getModerationItems()`, `templates/list/manage.latte`) can show subject/
sender/timestamp without a live IMAP fetch per item. `sender_mail` is never displayed directly —
`getModerationItems()` formats it into a `sender_display` field ("Name <mail>", or the bare
address if the sender set no display name), matching `ModerationMailer`'s own `%sender%`
formatting for the request mail.

```sql
CREATE TABLE moderation_queue (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    list_cn         VARCHAR(255) NOT NULL,
    imap_uid        BIGINT UNSIGNED NOT NULL,
    imap_uidvalidity BIGINT UNSIGNED NOT NULL,
    created_at      DATETIME NOT NULL,
    reminded_at     DATETIME NULL,
    subject         VARCHAR(500) NULL,
    sender_name     VARCHAR(255) NULL,
    sender_mail     VARCHAR(255) NULL,
    mail_date       DATETIME NULL,
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

`message_id` (added by `migrations/003_bounce_log_message_id.sql`, not backfilled — `NULL` for
any row logged before this migration ran, or whose bounce mail had no Message-ID at all) —
bare Message-ID of the bounce mail itself (`HeaderFilter::readMessageId()`, same normalization
`ArchiveIndexer` applies), populated once by `BounceHandler::logBounce()`. Lets the manage
page's bounce table offer a click-through preview (`BounceController`, see "Bounce preview")
the same way `archived_mail.message_id` lets the archive viewer re-locate a distributed mail —
without persisting an IMAP UID, which is meaningless once `ImapArchiver::archiveOrDelete()`
moves the bounce into the archive folder (or deletes it outright, if `archive: off`) right
after this row is written.

```sql
CREATE TABLE bounce_log (
    id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    list_cn     VARCHAR(255) NOT NULL,
    sender      VARCHAR(255) NOT NULL,
    subject     VARCHAR(500) NULL,
    message_id  VARCHAR(255) NULL,
    bounced_at  DATETIME NOT NULL,
    INDEX idx_list_time (list_cn, bounced_at)
);
```

Entries older than 90 days deleted each worker cycle.

### `processing_failures`

Added by `migrations/004_processing_failures.sql`. Tracks how many times `bin/worker.php` has
retried a specific incoming mail after an exception anywhere in its per-mail processing pipeline
— see "Processing-failure retry limit". Keyed the same way as `imap_seen`/`moderation_queue`,
since it identifies the same kind of thing: one specific message on one specific list's IMAP
mailbox, not-yet-resolved-either-way.

```sql
CREATE TABLE processing_failures (
    id                BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    list_cn           VARCHAR(255) NOT NULL,
    imap_uid          BIGINT UNSIGNED NOT NULL,
    imap_uidvalidity  BIGINT UNSIGNED NOT NULL,
    attempts          TINYINT UNSIGNED NOT NULL DEFAULT 0,
    last_error        TEXT NULL,
    first_attempt_at  DATETIME NOT NULL,
    last_attempt_at   DATETIME NOT NULL,
    UNIQUE KEY uq_list_uid (list_cn, imap_uid, imap_uidvalidity)
);
```

Normally short-lived — a row is deleted (`ProcessingFailureTracker::clear()`) the same cycle the
mail either succeeds or hits `ProcessingFailureTracker::MAX_ATTEMPTS` and is given up on. Rows
older than 31 days are swept as a safety net each worker cycle (same retention as `imap_seen`),
in case the give-up sequence itself kept failing and left a row stuck.

### `bounce_suppressed_members`

Added by `migrations/006_bounce_auto_actions.sql`. Backs the `restrict` automatic bounce action
(see "Automatic bounce actions") — written/read exclusively via `BounceSuppressionList`
(`src/Mail/BounceSuppressionList.php`), independent of any list's own `ListProvider`/
`MemberResolver` backend.

```sql
CREATE TABLE bounce_suppressed_members (
    id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    list_cn      VARCHAR(255) NOT NULL,
    envelope_to  VARCHAR(255) NOT NULL,
    reason       VARCHAR(64)  NOT NULL,
    created_at   DATETIME     NOT NULL,
    UNIQUE KEY uq_list_recipient (list_cn, envelope_to)
);
```

No automatic expiry — an address stays suppressed until an owner removes it (there is currently
no UI action for that, only the read-only manage-page listing, see "Automatic bounce actions")
or an operator deletes the row directly.

---

## Core Processing Logic

### Worker loop (`bin/worker.php`)

The worker runs as a single process. If a cycle takes longer than `sleep-seconds`, the next cycle starts immediately after — no overlap protection needed since it is single-threaded.

`sleep-seconds` (step 5, default 60) and `batch-size` (step 3, default 50) are config.yml root keys, like any other setting there — resolved by the `'worker.sleep-seconds'`/`'worker.batch-size'` container entries (`config/container.php`) via `ConfigResolver::getResolvedDefault()`. Neither has an env var of its own; reference `$SOME_VAR` in config.yml (e.g. `sleep-seconds: $WORKER_SLEEP_SECONDS`) if the value should come from the environment instead.

#### Worker loop — config reload

The worker's container (and everything built from it — `ConfigResolver`, every `ListProvider`, all `ListConfig` objects) is built exactly once, before the loop starts, and kept for the entire process lifetime. Every `ListProvider` implementation also memoizes `getLists()`/`getList()` internally the first time it succeeds (`private ?array $lists = null; if ($this->lists !== null) return ...;`) — but unlike a plain in-process cache with no expiry, this is bounded to **one worker cycle**: `ListProvider::reset()` (implemented by every provider — sets `$lists = null`, forcing the next `getLists()`/`getList()` call to re-query its backing store) is called once per iteration, right before the sleep. So an LDAP `description[]` entry, a `config-table` row, or a `type: yaml` provider file's contents are re-read fresh every cycle, without needing a process restart — a change made between two cycles is visible on the very next one, at most `sleep-seconds` later. (The **web/API side has no equivalent concern**: `public/index.php` builds a brand new container, and therefore fresh, unmemoized providers, on every single HTTP request — config changes there are visible on the very next request regardless.)

`ImapMailboxFactory::reset()` used to be called at this same call site, on the same every-cycle schedule — it no longer is (see "IMAP connection reuse across worker cycles" below). Directory/config data (`ListProvider::reset()`'s own concern) and IMAP *connections* (`ImapMailboxFactory`'s) turned out to need genuinely different reset policies once looked at closely: a provider's cached directory data has no way to know on its own whether it's gone stale (an LDAP edit or a `config-table` row change is invisible to Listig until it re-queries), so time-bounding it to one cycle is the only option: whereas a cached IMAP *connection*'s liveness is directly, cheaply checkable (see below) — so it no longer needs a blanket, schedule-driven invalidation at all.

What `reset()` does *not* cover: `$this->providerConfig` (a provider's own raw `list-providers.*` entry) and anything the `ConfigResolver` itself resolved from `config.yml`'s structure (named blocks, `use:`, root-level defaults, `filters:`) are parsed once at container build time and never re-parsed mid-process — a provider's `reset()` only re-runs its *query* against that same, still-process-lifetime-fixed provider config. So editing `config.yml` itself — adding/removing a `list-providers` entry, changing a named block, a root default, `filters:` — still requires the full container rebuild a process restart gives you; `reset()` only shortens the previously-unbounded staleness window for the *external data* each provider reads (LDAP directory, DB rows, a YAML file), which is exactly the case that used to be invisible "not just until the next `sleep-seconds` cycle, but indefinitely, until the process actually restarts."

To still catch a `config.yml` structural change without a manual restart, the worker separately watches the file's mtime once per loop iteration and exits cleanly (`exit(0)`) the moment it changes:

```php
clearstatcache(true, $watchedFile);  // filemtime() is cached per-process — without
                                      // this, every check after the first would keep
                                      // returning the original mtime forever
$currentMtime = @filemtime($watchedFile) ?: null;
if ($currentMtime !== $configMtimes[$i]) {
    error_log("Listig: $watchedFile changed on disk — restarting worker to reload configuration.");
    exit(0);
}
```

`docker/supervisord.conf`'s `[program:worker]` already has `autorestart=true`, so supervisord immediately restarts the process — which rebuilds the container from scratch, re-parsing `config.yml`'s structure fresh (unlike a provider's own `reset()`, which re-queries the same, unchanged provider config — see above). A full process restart, rather than trying to invalidate the whole container in place, is deliberate: it's simpler, and guarantees a completely consistent state with no risk of a partially-stale `ConfigResolver`.

This watches every file `ConfigResolver::getIncludedFiles()` returns, not just `config.yml` itself — `config.yml`'s own path is always the first entry (it's `YamlIncludeResolver::parseFile()`'s own top-level call), followed by every file spliced in via `!include`, at any nesting depth. This closes a real, previously-documented gap: a `!include`d fragment of `config.yml` (e.g. `owners: !include config.local.yml`, often used to keep local overrides in a gitignored file) is spliced into the tree once at parse time, before `reset()` has any effect — editing *that* file used to need either a manual restart or a no-op re-save of `config.yml` itself to be picked up at all, silently. `YamlIncludeResolver` is the only place that ever knows which files a given parse actually read (`$lastParsedFiles`, reset at the start of each *top-level* `parseFile()` call — detected via `$visited === []`, which only a genuine top-level call ever passes); `ConfigResolver::__construct()` captures that list into its own instance state immediately after its own top-level call, specifically so a *later*, unrelated `parseFile()` call — `YamlListProvider` parsing its own list file through this same resolver — can never silently clobber it out from under a caller that already read it.

A `type: yaml` provider's own `file:` is deliberately **not** part of this watched set — unlike an `!include`d fragment, its content is already re-read fresh every worker cycle via `reset()` (see above), so watching it for a restart would only cause an unnecessary one: dropping every open IMAP connection and rebuilding the whole container for a change that was already being picked up live, with no restart needed at all.

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
        - DELETE FROM processing_failures WHERE last_attempt_at < NOW() - INTERVAL 31 DAY (safety net, see below)
    5. sleep(sleep-seconds, see 'worker.sleep-seconds' above)
```

### IMAP connection reuse across worker cycles

`ImapMailboxFactory` caches one `PhpImap\Mailbox` per list's `imap-*` fingerprint (host/port/user/secure — see its own `fingerprint()`), and that cache now survives across worker cycles, not just within one. Before this, `bin/worker.php` called `ImapMailboxFactory::reset()` at the same call site as `ListProvider::reset()` (end of every cycle, right before the sleep) — dropping every cached `Mailbox` unconditionally meant every list paid for a full LOGIN/TLS handshake again on the very next cycle, even though the existing connection was, in the overwhelming majority of cycles, still perfectly healthy. `reset()` is no longer called there (see "Worker loop — config reload" above for why it and `ListProvider::reset()` turned out to need different policies).

**Liveness check, not a blanket schedule.** `ImapMailboxFactory::getMailbox()` now checks a cached `Mailbox` before handing it out: `Mailbox::hasImapStream()` — a thin, side-effect-free wrapper around `imap_ping()` on the connection's own already-open stream (`is_resource($this->imapStream) && imap_ping($this->imapStream)`, per php-imap's own source). This was chosen over the alternatives available in the library:
- `Mailbox::getImapStream()` (the default, `$forceConnection = true` variant) already transparently pings-and-reconnects internally on every real IMAP call (every one of `Mailbox`'s own methods — `searchMailbox()`, `getMail()`, `statusMailbox()`, ... — calls it first) — but as a side effect of *any* such call, and it repairs the *same* PHP object's stream in place rather than letting `getMailbox()` hand out a fresh one. That distinction matters here specifically because of the folder-selection issue below.
- A genuine no-op IMAP round trip (e.g. re-running `statusMailbox()` just to see if it succeeds) would be real protocol work, not just "is the socket still open" — exactly the SELECT/SEARCH-weight check a liveness probe should avoid paying for on every single `getMailbox()` call.

A dead connection is discarded from the cache and rebuilt via the existing `createMailbox()` (a fresh `Mailbox`, not a repaired one) — deliberately, not just repaired in place, for a second reason beyond the connection itself: `PhpImap\Mailbox` tracks which folder is currently selected as mutable state on the object (`switchMailbox()` rewrites `$imapPath` in place, see "Archive folder path"), and `ImapArchiver::pruneArchive()` switches the shared cached `Mailbox` to the list's archive folder and never switches it back. Under the old reset()-every-cycle design this never mattered, because every cycle started with a brand-new `Mailbox` freshly constructed pointing at INBOX. Now that the same object can persist across cycles, `ImapPoller::poll()` — always the first IMAP-touching call for a list in every cycle (see the loop pseudocode above) — explicitly re-selects INBOX at its own start (`$mailbox->switchMailbox('INBOX')`) rather than assuming a possibly-reused `Mailbox` is already positioned there; `archiveOrDelete()`/`deleteOldMails()`, which run later in the same cycle and rely on the same "currently on INBOX" assumption without ever selecting it themselves, are correct again as soon as `poll()` has. A freshly reconnected `Mailbox` (the liveness-check-failed path) is unaffected by this either way, since `createMailbox()` always starts a new one at INBOX by construction.

**Does this correctly recover from a server-side idle timeout?** Yes — worked through explicitly, since this is the main real-world scenario the whole change is about: many IMAP servers close a connection that's been idle for some period (commonly around 30 minutes). The next time that list is due to be polled (up to `sleep-seconds` later), `getMailbox()` runs `hasImapStream()` against the now-closed connection. `imap_ping()` on a closed stream returns `false` (or the resource/`IMAP\Connection` check itself already fails, depending on exactly how the server closed it — either way `hasImapStream()` returns `false`), so the stale entry is discarded and `createMailbox()` builds a fresh one — the *same* fresh-LOGIN path that ran unconditionally every cycle before this change, just now only paid for when actually needed. `ImapPoller::poll()`'s own explicit `switchMailbox('INBOX')` immediately after `getMailbox()` then re-selects INBOX on this brand-new connection too (a harmless no-op there, since a freshly constructed `Mailbox` is already on INBOX — but keeping it unconditional avoids a special case for "was this cached or fresh").

**Error handling is unchanged.** If the reconnect attempt itself fails (server unreachable, credentials no longer valid, ...), it surfaces as an exception from whatever `Mailbox` method needed the stream — the same `try`/`catch` `bin/worker.php` already has around `$imapPoller->poll($list)` catches it and logs "IMAP poll failed for list ...", exactly as it would have for any other IMAP failure. No new exception type or handling path was introduced; the liveness check's only job is making sure a *known-dead* cached connection is never silently handed to `ImapPoller`/`ImapArchiver` in the first place, rather than one of their own calls failing with whatever cryptic error a half-dead stream happens to produce.

### Processing-failure retry limit (`ProcessingFailureTracker`, `ProcessingFailureNotifier`)

Every branch of step 1c above (`ModerationResponseHandler::handle()`, `IncomingMailFilter::filter()`, `BounceHandler::handle()`, `RejectionNotifier::notify()`, `ModerationMailer::send()`, `MailProcessor::process()`, and the `markSeen()`/`archiveOrDelete()`/`ArchiveIndexer::index()` calls around them) runs inside one `try` per mail in `bin/worker.php`. Originally, an uncaught exception anywhere in there was just `error_log()`'d and the loop moved on to the next mail — but since none of `markSeen()`/`archiveOrDelete()` had run yet, the mail stayed unseen and was re-fetched and re-crashed on *every single subsequent cycle*, forever, with the only trace being that repeating log line. Confirmed live: a non-conformant Content-ID (see "Non-conformant Content-IDs" above, now separately fixed) retried every ~20s for several minutes straight with zero owner-facing signal.

`ProcessingFailureTracker` (`src/Mail/ProcessingFailureTracker.php`) bounds this: a new `processing_failures` table (`migrations/004_processing_failures.sql`), keyed like `imap_seen`/`moderation_queue` by `(list_cn, imap_uid, imap_uidvalidity)`, tracks an `attempts` counter per mail — persisted in the DB, not an in-memory counter, so it survives a worker restart between cycles the same way `imap_seen` does. `bin/worker.php`'s per-mail `catch` now calls `recordFailure()` (upsert + return the new count) instead of just logging; while `attempts < ProcessingFailureTracker::MAX_ATTEMPTS` (3, matching `queue_recipients`' own give-up threshold — see "queue.failure_notice" — same "3 tries, then stop and tell someone" philosophy applied to incoming-mail processing instead of outgoing queue sending), it still just retries next cycle as before. Once the limit is reached, the mail is given up on: `ProcessingFailureNotifier::notify()` emails the list owners (translation key `processing_failure.owner_notice`, original mail attached as `message/rfc822`, same pattern as `BounceHandler`/`ModerationMailer`) with the mail's subject/sender, the attempt count, and the exception message, then `markSeen()` + `archiveOrDelete()` run so the mail finally leaves the retry loop (archived or deleted per the list's own `archive:` setting, same as any other terminal outcome), and the `processing_failures` row is cleared. A failure during this give-up sequence itself (owner notify, mark seen, archive) is caught separately and logged rather than crashing the whole worker cycle — the row is deliberately left in place so the mail is retried (and give-up re-attempted) next cycle instead of silently falling out of tracking.

On the success path, `bin/worker.php`'s per-mail processing was refactored from a `continue`-heavy inline block into a closure (`$processIncomingMail`, still holding the exact same branch logic — every `continue;` became a `return;`) specifically so there is exactly one call site, right after it returns without throwing, to call `ProcessingFailureTracker::clear()` — regardless of which of the branches inside actually handled the mail. Without a single success point, clearing the tracker correctly would have needed a matching `clear()` call added at every one of the six `continue`/end-of-function exits inside the old inline block, an easy place to miss one and leave a stale row (or worse, an under-counted retry limit) behind.

A `processing_failures` row is normally short-lived — cleared within the same cycle it either succeeds or hits the give-up path — so the cleanup-step `DELETE ... WHERE last_attempt_at < NOW() - INTERVAL 31 DAY` (same retention as `imap_seen`) is a safety net for the one case that doesn't self-resolve: the give-up sequence itself repeatedly failing (e.g. sending the owner notification keeps erroring), which would otherwise leave the row behind indefinitely.

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
  2. the recipient's domain (`$envelopeTo`) is in the effective trusted-domain set — `SpamRejectionDetector::BUILTIN_DOMAINS` (gmail.com, gmx.de/net, web.de, outlook.com/hotmail.com/live.com, icloud.com/me.com/mac.com, yahoo.com, aol.com, t-online.de, …) merged with the optional root-level `reliable-spam-reporters:` config.yml key (a plain array of domain strings, instance-wide — no per-list/per-provider concept, unlike the "Global / provider / list levels" six keys). This stays a trust boundary for treating another party's SMTP response as authoritative — `reliable-spam-reporters:` can only **add** domains an operator has deliberately chosen to extend that trust to, never replace or narrow `BUILTIN_DOMAINS`, which is always part of the merged set regardless of config. Without either layer, a malicious or misconfigured SMTP server could forge a "spam" response to make Listig discard mail for recipients it has nothing to do with — extending the list is therefore a real trust decision an operator makes deliberately, not a casual setting.
  3. `strtolower($e->getMessage() . ' ' . $e->getDebug())` contains `'spam'`

**`reliable-spam-reporters:` reads from every source, root-direct and `use:`-referenced blocks alike, always concatenated** (`ConfigResolver::getReliableSpamReporters()`) — the root's own direct value plus each root-level `use:`-referenced named block's own value (including one loaded via `!include`), in `use:` order, via the same `collectGlobalSources()` helper the six scoped keys' global level uses (see "Global / provider / list levels"), just without any provider/list level of its own. This was a real, confirmed gap when the key was first introduced, worse than the analogous `owners:`/`lists:` gaps fixed earlier: `reliable-spam-reporters:` wasn't just invisible when set inside a `use:`-block — a plain **root-direct** `reliable-spam-reporters: [...]` didn't work *at all*, in any position. The root-key loop in `processConfig()` only special-cases a fixed set of keys (`list-providers`/`filters`/`lists`/the six scoped keys) before falling through to "any other array value becomes a named block, inert unless referenced via `use:`" — `reliable-spam-reporters` wasn't in that fixed set, so it silently became exactly such an inert block itself, and `SpamRejectionDetector` always fell back to just `BUILTIN_DOMAINS`, no error. Confirmed live before the fix: `getResolvedDefault()['reliable-spam-reporters']` was undefined even with the key set directly at config.yml's own root.
- On a match, `QueueSender::discardBatchAsSpam()` aborts immediately (no 3-attempt wait) and marks the current recipient **and every other still-`pending` `queue_recipients` row sharing the same `mail_queue.batch_id`** as `failed` — i.e. every remaining copy of the same original mail, across every list it was addressed to, personalized or not (see `mail_queue.batch_id` in "Database Schema" for why a shared `batch_id`, not a shared `mail_queue_id`, is required to find them). Rows already `sent` are untouched.
- Discarded copies are marked `failed`, not deleted outright — same as any other delivery failure, they stay visible/retryable/deletable via the manage page's queue status (`QueueController`) until `purgeStaleFailedEntries()` purges them after 30 days.
- The list owner is notified once per discarded batch (translation key `queue.spam_rejected`), not once per discarded recipient.

### Envelope separation

```php
$mailer->send(
    new RawMessage($mimeString),
    new Envelope(
        new Address("{$list->localPart}+bounce@{$list->domain}"),  // Envelope-From
        [new Address($recipient->envelopeTo)]                      // Envelope-To
    )
);
```

`Sender` header in MIME: `{$list->localPart}+bounce@{$list->domain}` — same value as the Envelope-From above, built from `ListConfig::$localPart` (the local part of the list's own `mail` address, e.g. `it` for `it@example.org`), **not** `$list->name`/`{list-cn}` — those commonly differ (a list named `it-team` may have `mail: it@example.org`), and a bounce address built from the internal list name has no reason to be a real, deliverable mailbox at all. No per-recipient VERP: this is the same address for every recipient of a given send (see "Bounce notice details" below for how a bounced recipient is still identified, via the DSN's own `Final-Recipient` field, not the envelope).
Visible `To`/`Cc` header: the original mail's own `To`/`Cc` addresses, copied verbatim by `MailProcessor::buildOutgoingEmail()` — never the expanded member list, and never the actual per-recipient envelope target (that's the `Envelope` above). This was documented but not actually implemented for a while: `new Email()` starts with no address header at all, and unlike `Message::ensureValidity()` (which requires at least one of To/Cc/Bcc), `Message::toString()` — what `QueueWriter::enqueue()` actually calls to serialize into `mail_queue.mime` — never checks for one, so the omission produced valid-looking, silently header-less mail rather than an error.

---

## Mail Processing Details

### IncomingMailFilter — check order

1. **X-Loop** present (any value) → discard silently
2. **Spam filter**: any rule in `filters:` (config.yml, global, see "Spam filtering") matches → `action: reject` (default): reject, notify sender; `action: discard`: silently dropped, no notice. Either way the mail is *deleted* outright, never archived — regardless of the list's own `archive:` setting (unlike every other reject reason below, which still go through the normal `archiveOrDelete()`).
3. **Bounce** (any match below) → log to `bounce_log`, forward to owner as `multipart/mixed` (Part 1: `text/plain` with metadata — see "Bounce notice details" below; Part 2: `message/rfc822` with full original bounce mail):
   - `Auto-Submitted` present and ≠ `no`
   - `X-Auto-Response-Suppress` present
   - `Content-Type: multipart/report; report-type=delivery-status`
   - `From` contains `MAILER-DAEMON` or `postmaster` (case-insensitive)
   - Subject matches `/^(delivery status|mail delivery failed|undelivered mail)/i`
   - `Auto-Submitted: auto-replied` alone (RFC 3834 auto-responder), `X-Auto-Response-Suppress` alone and `Precedence: auto_reply` are **not** bounces — see step 3b.
3b. **Auto-reply** (out-of-office etc.; only reached if step 3 didn't match, i.e. no DSN/`MAILER-DAEMON`/`auto-generated`) → `FilterResult::discard(forceDelete: true)`: silently dropped and deleted, no `bounce_log` row, no owner notice. Forwarding these was pure noise and could trip `BounceHandler`'s circuit breaker, suppressing real bounces. Implemented by `IncomingMailFilter::isAutoReply()`.
4. **Subaddress validation** (`type: subaddress` lists only, see "type: subaddress — subaddress forwarding"): reserved subaddress (`bounce`, `accept-*`, `reject-*`, or list-configured `reserved-subaddresses`) → reject, notify sender; no subaddress at all while at least one member template requires one → reject, notify sender
5. **Authentication-Results**: SPF or DKIM = `fail` → reject, notify sender
6. **Size**: raw MIME size > `max-size` → reject, notify sender
7. **Post-access** (`IncomingMailFilter::checkPostAccess()`; for a mail to a `+r-` masked-reply address `checkMaskedReply()` instead — see "Masked reply addresses"): a `restricted-members:` hit → reject (`reject.sender_restricted`), notify sender — checked *first*, overriding even owner status (see "Sender restrictions"). Owners and `senders:` addresses (see "Additional senders") then always pass; a member or public sender whose respective `post-access-members`/`post-access-public` is `deny` → reject (`reject.members_denied`/`reject.public_denied`), notify sender. `allow` and `moderate` both pass here — deciding between them happens later, at step 9, after rate limiting.
8. **Rate limit**: exceeded → reject, notify sender
9. **Moderation with no owners** (`IncomingMailFilter::requiresModeration()` — owners never moderated; only reached when the sender's `post-access-members`/`post-access-public` is `moderate`): list has zero owners → reject (`reject.no_owners`), notify sender — a moderation item nobody can ever accept/reject would otherwise vanish silently instead of being distributed or bounced back with feedback

**Spam filter checked before bounce detection** — the opposite of every other check, which all stay *after* bounce detection specifically because a real bounce may legitimately fail auth/lack a valid subaddress/etc. (see below). This one reversal is deliberate: it lets an operator write a `filters:` rule matching a particular unwanted bounce (e.g. a known noisy auto-responder, or a specific `MAILER-DAEMON` host) and have it silently dropped via `action: discard` instead of always being logged to `bounce_log` and forwarded to the owner. Before this reordering, bounce detection ran first and a spam-content match against a bounce mail was unreachable — the mail was always handled as a bounce regardless of what `filters:` said. The tradeoff: **any** `filters:` rule that happens to also match real bounce content will now intercept that bounce before it's ever logged/forwarded, not just ones an operator intentionally wrote for that purpose — a broad `subject: /error/i` rule, say, would now swallow bounces mentioning "error" in the subject too, silently. Confirmed live: a mail with `From: MAILER-DAEMON@...` that also matched a `filters:` rule was rejected/discarded as spam and never reached `isBounce()` at all; the same mail without a matching rule was still correctly classified as a bounce, unchanged.

Bounces are still checked before Authentication-Results and Subaddress validation, for the reasons those two sections already had: `MAILER-DAEMON` mails may legitimately lack valid SPF/DKIM, and address-routing validity is a separate concern from content-based filtering. Note `bin/worker.php` already routes `+accept-*`/`+reject-*` mail through `ModerationResponseHandler` before `IncomingMailFilter::filter()` is ever reached, so the `accept-`/`reject-` check here is defense-in-depth; the `bounce` check is load-bearing, since bounce detection above is content-based and a non-standard bounce sent to `+bounce` would otherwise fall through. The no-owners check is last since it's only relevant once a mail has already cleared every other gate and would otherwise be headed for moderation; `ModerationMailer::send()` still independently checks (and logs, then no-ops) for empty owners too, as a defense-in-depth backstop against a list losing its last owner *after* an item is already in `moderation_queue`.

`PhpImap\Mailbox::getMailHeaderFieldValue()` (populates `IncomingMail::$autoSubmitted`, among others) is typed to always return `string`, using `''` for "header absent" — **never** `null`, despite `IncomingMailHeader`'s own `@var string|null` docblock claiming otherwise. `IncomingMailFilter::isBounce()`'s `Auto-Submitted` check must test `!== null && !== ''`, not just `!== null` — the latter is true for every mail lacking the header (i.e. essentially all normal mail), misclassifying it as a bounce.

#### Bounce notice details

`BounceHandler::forwardToOwners()` extracts a few fields from the raw bounce MIME via `HeaderFilter::readHeader()` (already generic enough to scan any raw text block, not just a header block) and includes them in the Part 1 text/plain body, best-effort — a bounce that isn't a standard RFC 3464 delivery-status notification (or omits these fields) falls back to the `bounce.unknown` translation string per missing field, never a blank or literal placeholder:

- **Ursache/Reason** (`%reason%`) — `Diagnostic-Code` (preferred, human-readable, e.g. `smtp; 550 5.1.1 ...: User unknown`) falling back to the terser `Status` (e.g. `5.1.1`), both RFC 3464 fields living in the bounce's own `message/delivery-status` part.
- **Fehlgeschlagener Empfänger/Failed recipient** (`%failed_recipient%`) — RFC 3464's `Final-Recipient` (falling back to `Original-Recipient`), stripped of its `rfc822;` address-type prefix. This is the specific address delivery failed for — Listig has no per-recipient VERP in its own `Envelope-From` (`{list->localPart}+bounce@{domain}` is the same for every recipient, see "Envelope separation"), so this DSN field is the *only* way to learn which member's address actually bounced.
- **Ursprünglicher Absender/Original sender** (`%original_sender%`) — the `From:` header of the *attached original message* (found by searching for `From:` only from the raw MIME's `message/rfc822` marker onward), not the outer bounce's own `From:` (typically `MAILER-DAEMON@...`, already shown separately as `%sender%`).

`readHeader()`'s "first occurrence anywhere in the text" behavior is safe for `Diagnostic-Code`/`Final-Recipient` specifically because a standard DSN's delivery-status part always precedes the attached original message, so there's no risk of accidentally matching something inside the original mail's own headers/body instead.

#### Bounce loop prevention

A bounce-forward (`BounceHandler::forwardToOwners()`) is itself an outgoing mail, sent via `NotificationMailer::sendToOwners()` — which means it can itself bounce. Without a guard against that, the new bounce would be logged and forwarded again exactly like any other, producing another notification for the owner's server to possibly reject again, and so on. Confirmed live: a single distributed mail rejected as spam by one owner's server produced roughly 100 consecutive bounces this way before the guards below existed.

Three independent layers, from most to least targeted:

1. **`NotificationMailer`'s own output is marked and de-fanged.** Every mail it sends (bounce forwards, moderation/unsubscribe notices, queue failure notices — anything routed through `NotificationMailer::send()`) carries an `X-Listig-Auto: notification` header (`NotificationMailer::AUTO_HEADER`) plus `Auto-Submitted: auto-generated`, and is sent through a null-sender envelope (`MAIL FROM:<>`, RFC 5321's null reverse-path — see `NullSenderEnvelope` below) rather than the implicit envelope-from-address `Mailer::send()` would otherwise derive from the `From:` header. A compliant receiving MTA is specifically supposed to never generate a DSN in response to a null-reverse-path message (that's the entire point of the convention — it's what real bounce/DSN messages themselves use as their own envelope sender, precisely so a bounce can't itself bounce) — so on a well-behaved server, the loop is cut off at the SMTP layer before a second bounce is even generated. `Auto-Submitted` is the same signal `IncomingMailFilter::isBounce()` already checks for on the *receiving* side (see "IncomingMailFilter — check order"), included here for the servers that do honor it even without full null-envelope handling.
2. **`BounceHandler::isBounceOnOwnNotification()`** — the layer that actually matters when step 1 doesn't fully stop a bounce from arriving anyway (not every mail server is well-behaved). Mirrors `extractOriginalSender()`'s own approach: search for `X-Listig-Auto` only from the raw bounce MIME's first `message/rfc822` marker onward, i.e. inside the *attached original message*, not the outer bounce's own headers. If it's present, this bounce is a bounce *on one of Listig's own notifications* rather than on a genuine member/owner-authored mail — `handle()` still calls `logBounce()` (the manage page's bounce table stays a complete record either way), but skips `forwardToOwners()` entirely, so no second notification is ever generated in the first place.
3. **Bounce-log circuit breaker** — a last-resort safety net for the case where even the attached-original detection above doesn't catch it (e.g. a DSN generator that reformats or truncates the attached original enough to lose the header). `BounceHandler::circuitBreakerTripped()` counts `bounce_log` rows for the list within the last `CIRCUIT_BREAKER_WINDOW_MINUTES` minutes (15, using the existing `idx_list_time (list_cn, bounced_at)` index — a single indexed `COUNT(*)`, not a new query shape) and skips `forwardToOwners()` once that count exceeds `CIRCUIT_BREAKER_THRESHOLD` (5) — capping the worst case at a handful of forwarded mails instead of the ~100 seen before this existed, regardless of what shape the loop takes.

**`NullSenderEnvelope` (`src/Mail/NullSenderEnvelope.php`)** — symfony/mailer 7.4 (the exact version pinned in `composer.lock`) has no supported way to build an `Envelope` with an empty sender at all: `Address::__construct()` always validates via `egulias/email-validator` and rejects an empty address, `Envelope::setSender()` independently regex-validates for an `@`, and `Address` is `final`, so it can't be subclassed to skip validation either. `NullSenderEnvelope extends Envelope` (not final) and, in its own constructor, deliberately skips `parent::__construct()` (which would call the validating `setSender()`) — it builds an `Address` via `ReflectionClass::newInstanceWithoutConstructor()` with both private properties (`address`, `name`) set to `''` via `ReflectionProperty`, then writes that directly into `Envelope`'s own private `$sender` property, again via `ReflectionProperty`, bypassing `setSender()`'s validation a second time. This is Reflection reaching into a third-party library's private internals — a real trade-off, isolated deliberately in one small, single-purpose class rather than spread across `NotificationMailer` — but it's the only way to produce a literal `MAIL FROM:<>`: `SmtpTransport::doMailFromCommand()` builds that command straight from `getSender()->getEncodedAddress()` with no validation of its own, so an empty address there is handled correctly once it actually gets that far.

Setting a `Return-Path` header on the message instead is not an alternative — confirmed by reading `symfony/mailer`'s own source: `AbstractTransport::send()` only derives an envelope from the message's own headers (`DelayedEnvelope::getSenderFromHeaders()`, which does check `Sender`, then `Return-Path`, then `From`, in that order) when `Envelope::create($message)` is called, i.e. when `Mailer::send()` is invoked with `$envelope === null`. Listig never does that — every call site (`QueueSender::sendOne()`, `NotificationMailer::send()`) always passes an explicit `Envelope`/`NullSenderEnvelope` object — so that header-based fallback path is never reached, and a `Return-Path` header would have zero effect on the actual SMTP envelope sender here regardless of its value. `NullSenderEnvelope`'s Reflection approach remains the only way to produce a literal `MAIL FROM:<>` with this library/version.

### Automatic bounce actions

A bounce can arrive asynchronously — over IMAP, polled in the worker loop's own step 1, potentially several cycles after the original mail was distributed — *while* `QueueSender::sendBatch()` is still working through the rest of the very same batch in later cycles (a large `batch-size`-bounded send can span many worker cycles). Before this existed, an async bounce and the ongoing queue send were two entirely disconnected mechanisms: `BounceHandler` only ever logged the bounce and forwarded it to the owners, regardless of what the bounce's own content said — even a DSN whose `Diagnostic-Code`/`Status` plainly said "rejected as spam" from a large, reliable provider had no effect at all on the remaining `queue_recipients` rows for that same original mail, which kept being sent to every other recipient exactly as if nothing had happened. This is the deliberate async counterpart to `QueueSender`'s existing **synchronous** spam handling (`SpamRejectionDetector`, checked inline inside `sendOne()`'s own `catch` block when `$mailer->send()` itself throws) — that one only ever sees a *live* SMTP-level rejection in the same connection; it has no way to react to a rejection that comes back later, out of band, as an ordinary incoming mail to the list's own inbox.

#### Why a DSN's own content can never be trusted directly

RFC 3464 delivery-status notifications carry **no cryptographic authentication at all** — every field in a DSN's body (`Final-Recipient`, the attached original message's own `Message-ID`, `Diagnostic-Code`) is plain text anyone able to deliver mail into the list's own inbox fully controls, the same way `IncomingMailFilter::isBounce()`'s own detection (`Auto-Submitted`, `multipart/report`, a `From: MAILER-DAEMON@...`) is itself trivially spoofable content, not a verified signal. Two design iterations were tried and rejected before landing on the current one, each closing one gap while leaving another open — both are documented here because the reasoning explains why the final design needs *all three* of its layers, not because either intermediate approach still exists in the code:

1. **Trust the DSN's claimed `Final-Recipient` domain alone.** Rejected immediately: an attacker could claim *any* address on a genuinely reliable domain (e.g. `alice@gmail.com`) bounced, without ever having sent or received anything through that domain's real infrastructure at all.
2. **Also require the claimed `Final-Recipient` to be a real recipient of the batch found via the attached message's Message-ID** (a `batchHasRecipient()` binding check that existed briefly during development). This closed gap 1 for a recipient *outside* the batch, but not for a recipient *inside* it: any genuine member of the same batch already knows the real Message-ID (from their own copy's headers) and could forge a "bounce" claiming a *co-recipient's* address, still without needing any relationship to that co-recipient's real mail server.
3. **The design actually shipped** closes both: it never trusts *any* DSN-claimed identity at all (not `Final-Recipient`, not the attached Message-ID) — "which recipient/batch" is decided purely from Listig's own per-recipient bounce address, and "is the content trustworthy" is decided by authenticating the bounce's own transport-level origin, not by reading anything self-reported inside it.

#### 1. Which recipient: a signed, per-recipient bounce address (VERP)

`QueueSender::sendOne()` no longer uses one fixed `{list->localPart}+bounce@{list->domain}` envelope-from for every recipient of a send. Each recipient gets its own: `{list->localPart}+bounce+{token}@{list->domain}`, where `{token}` is `TokenService::sign('bounce', $listCn, $recipientId)` — `$recipientId` being that recipient's own `queue_recipients.id` (see "Token Format", 7-day max age, same window as unsubscribe/accept/reject). This is VERP (Variable Envelope Return Path), but with a signed, unguessable suffix rather than a sequential or otherwise-derivable one.

Since a genuine DSN is addressed back to the original message's own envelope-from (that's the entire point of the envelope-from/Return-Path mechanism), the bounce arrives back at Listig addressed to *that exact* per-recipient address. `BounceHandler::resolveVerifiedRecipient()` decodes it:

- `extractBounceToken()` reads the raw (unparsed, case-preserved — see "Token Format" for why `$mail->to` can't be used here, same reasoning as the accept/reject token) `To`/`Delivered-To`/`X-Original-To` headers for the `+bounce+{token}@` pattern.
- The token is verified via `TokenService::verify()` (wrong signature, expired, or wrong purpose → treated as absent, not fatal).
- Its `$listCn` is cross-checked against the list the bounce actually arrived on (defense in depth, same principle as `UnsubscribeController`'s own `{listname}`-vs-token check).
- `QueueSender::findRecipientById()` looks up the real `queue_recipients` row (`envelope_to`, `batch_id`, `list_cn`) — `null` if it no longer exists (aged out of `purgeCompletedEntries()`'s 30-day retention, see "Queue retention: keeping completed entries around" below), in which case there is nothing left to act on anyway, same graceful "nothing pending" outcome used throughout this class.

Nobody can forge a bounce "on behalf of" a co-recipient this way: the token for row *N* is never exposed to any recipient other than the one row *N* was actually sent to (it rides in the SMTP envelope, not the mail body), and deriving a valid token for a *different* row without the server's HMAC key is computationally infeasible — the identical trust model already used for login/unsubscribe/accept/reject tokens.

**`mail_queue.message_id` and the `batchHasRecipient()`/`findBatchIdsByMessageId()` methods from design iteration 2 above were removed entirely** once this shipped — no longer needed, since the token directly names the exact row, with no DSN-content search step at all.

#### 2. Is the content trustworthy: authenticating the bounce's own origin

Knowing *which* real recipient a bounce claims to be about still isn't enough on its own — a malicious member could, in principle, learn their *own* genuine token (some providers show `Return-Path` under "view original") and hand-craft a fake bounce for their *own* row, without their real mailbox ever having rejected anything. How much this actually matters, though, depends entirely on the blast radius of the action a `BounceCause` drives — and that's why the two checks below are no longer applied uniformly to every cause (an earlier version of this design did apply both everywhere; that was tightened after a live test with a real DNS-failure bounce exposed why it was more than the threat model actually needed — see below).

1. **`hasNullReturnPath()`** — required for **every** cause, unconditionally. The bounce's own `Return-Path` header (added by Listig's own receiving mail server at final delivery, not attacker-influenced) must be the empty/null form (`<>`), the same RFC 3464/5321 convention `NullSenderEnvelope` itself uses for Listig's own outgoing notifications. Reputable providers do **not** let an ordinary authenticated user submit mail with a null envelope-from via their normal submission path — that's specifically reserved for their own internal systems, as a defense against backscatter/spam abuse on their end, not a Listig-specific assumption. This rules out a forged bounce sent through the recipient's own *real account*, and costs nothing to keep for every cause.
2. **`isDkimAuthenticated()`** — `HeaderFilter::readAuthResults()`'s `dkim` must be `pass` **and** its `dkimDomain` (the signature's own `header.d=` parameter, extracted from the *same* `Authentication-Results` value as the `dkim=` verdict, not just "the first `header.d=` found anywhere") must equal the verified recipient's own domain. This rules out a forged bounce sent from *outside* that domain's infrastructure entirely — but **only `BounceCause::Spam` requires it** (and even there, as an alternative to point 3 below, not unconditionally); `UserUnknown`/`MailboxFull` deliberately don't call it at all.

**Why DKIM is Spam-only, not a blanket requirement:** the token from point 1 above (`resolveVerifiedRecipient()`) already guarantees a forged bounce can never claim to be about anyone but the forger's own row — the token for recipient *N* only ever reaches recipient *N*'s own inbox headers (see "Which recipient" above). For `UserUnknown`/`MailboxFull`, whose actions (`mark-invalid`/`restrict`/`remove`/defer) only ever touch that *one* recipient's own subscription, the worst a forged self-bounce can do is let a member sabotage their own subscription — no worse than what they could already achieve with real mail infrastructure of their own (self-hosting a domain that genuinely bounces its own mail), or simply by asking to be unsubscribed. That's an accepted, self-inflicted-only risk, not a gap worth closing with a cryptographic check. `BounceCause::Spam` is the one exception: `abortBatchForBounce()`'s action reaches *every other pending recipient of the batch*, not just the forger — a malicious member could otherwise disrupt delivery to people who never consented to anything, which is why Spam alone still requires authentication beyond the null-envelope check, plus the further `isReliableDomain()` bar inside `abortBatchForBounce()` itself (see below).

This design change directly resolved a real, live-confirmed dead end: a genuine "domain doesn't exist" DNS-failure bounce (`Status: 5.4.4`, generated by the *sender's own* relay, since the target domain was never even reached) structurally can **never** carry a DKIM signature at all — there is no remote domain to sign it. Under the old blanket-DKIM design, this entire class of `UserUnknown` bounce (arguably the most common one in practice — typos, decommissioned domains) could never trigger `bounce-action`, regardless of how the reliable-domain question was resolved. Dropping DKIM for `UserUnknown`/`MailboxFull` fixes this without reintroducing the risk DKIM was meant to close, since — as established above — that risk was already bounded to self-harm by the token, independent of DKIM.

3. **`isFromTrustedRelay()`** (added after a second live-confirmed gap, this time for `Spam` itself) — an alternative to DKIM, not a replacement for it; either satisfies the requirement. There are two structurally different ways a real "reported as spam" bounce reaches Listig, not one:
   - **Async DSN, signed by the recipient's own domain** — the recipient's mail server accepted the message into its own queue and only later (e.g. after a deeper content scan) generated and sent back a DSN itself. This is what `isDkimAuthenticated()` verifies, and it's the shape the original design assumed.
   - **Live SMTP-time rejection, reflected by the *operator's own* outbound relay** — confirmed live in production: a recipient's mail server (a real, `BUILTIN_DOMAINS`-listed provider) rejected a message *during the live SMTP session itself* (`Diagnostic-Code: smtp; 550-5.7.0 Message considered as spam...` — RFC 3464's `smtp;` diagnostic type means this text is the literal SMTP reply, quoted verbatim from that live session). When the operator's own outbound mail routes through their own relay/smarthost rather than Listig connecting directly to the recipient's MX (the common case — `smtp-host` in config.yml points at that relay, not at every possible recipient domain's own MX), `QueueSender::sendOne()`'s own `$mailer->send()` call never sees this rejection at all: it succeeds against the *local* relay, and only that relay's own later, independent delivery attempt to the recipient fails. The relay then generates *its own* bounce reflecting that failure, which is what eventually reaches Listig via IMAP — and since the recipient's domain itself never generated or sent anything in this shape, there is no DSN of theirs to DKIM-authenticate, for the exact same structural reason a DNS-failure bounce can't carry one either (point 2 above). Under the DKIM-only design, this — arguably the *more* common shape for a live-classified spam rejection, not an edge case — could never trigger `bounce-action` regardless of how reliable the recipient's domain was.

   Since none of the bounce's own *content* is trustworthy on its own (same reasoning as everywhere else in this class — an outsider submitting mail into Listig's inbox controls every field), `isFromTrustedRelay()` instead checks the *connection(s)* the bounce actually arrived over — but a naive "check the topmost `Received:` header's IP" design (the first version of this check) turned out to be **completely ineffective**, confirmed against a real production bounce: the topmost header was `Received: from mail.example.org ([10.11.0.5]) by mail.example.org with LMTP ... (envelope-from <>) for <...>`. `10.11.0.5` is this operator's *own* Docker-internal IP — but that's true of **every** message that ever lands in that mailbox, genuine or forged: a combined send+receive mail server (Postfix accepting a message over SMTP, then handing it to its own mailbox via LMTP — the common self-hosted setup) always shows this exact same final, innermost hop, *regardless of whether the message was genuinely generated locally or merely externally SMTP-submitted moments earlier and then delivered locally*. Matching only the topmost IP would have let an outside attacker forge a "spam" bounce for any address, submit it via ordinary SMTP to this same server, and still pass — exactly the gap the whole authentication design exists to close.

   The topmost hop *alone* can't tell "genuinely locally generated" apart from "externally submitted, then locally delivered" — but walking **every** `Received:` header can. In this real bounce, the header immediately behind the LMTP one was `Received: by mail.example.org (Postfix)` — no `from` clause at all. That's the actual proof: this message was injected directly into the local Postfix queue by a local process (Postfix's own bounce-generation logic), never received over any external SMTP connection. An attacker's forged bounce, by contrast, would necessarily show a *real* `from ATTACKER-HOST (... [ATTACKER-IP])` hop somewhere in the chain — added by the receiving server itself the moment the attacker's SMTP client connected, and impossible for the attacker to suppress or fake away regardless of what other `Received:`-looking text they stuff into their own submitted body, since the genuine one is always prepended above it by trusted infrastructure. `HeaderFilter::readAllConnectingIps()` (not the single-hop `readConnectingIp()` the first version used — since removed) returns every hop's IP, skipping any `Received:` header with no `from` clause (a local injection contributes nothing, positive or negative) and any whose `from` clause carries no bracketed IP at all.

   `isFromTrustedRelay()` rejects if **any** of those IPs is a genuinely public, routable address (`HeaderFilter::isPublicIp()` — false for RFC 1918/RFC 4193 private ranges, loopback, and other reserved ranges). Confirmed live against the real bounce above: `readAllConnectingIps()` on its outer headers returns only `['10.11.0.5']` (the LMTP hop; the local-injection hop behind it contributes nothing), which `isPublicIp()` correctly reports as private — so `isFromTrustedRelay()` returns `true` with **zero configuration** for this operator's actual deployment (a single mail server on a private Docker network handling both outbound sending and inbound delivery).

   This is **deliberately config-free, with no operator-configurable trust list at all** — no `smtp-host`-DNS-resolution fallback and no explicit IP allowlist either, both considered and rejected: DNS can differ from what was true when a specific historical bounce was generated (load-balanced/rotated IPs), and an explicit list is one more setting an operator has to get right, for a check whose only job is distinguishing "stayed within a private network" from "touched the public internet" — something `HeaderFilter::isPublicIp()` already answers on its own, no operator input needed. A deployment whose real relay path genuinely crosses a public IP boundary (e.g. an external smarthost/SaaS relay) simply won't authenticate `Spam` via this path — `isDkimAuthenticated()` remains available whenever the recipient's own domain does sign an async DSN, and otherwise the bounce is still logged and forwarded to the owner, just without the automatic batch-abort.

**`isDkimAuthenticated()`/`isFromTrustedRelay()` deliberately don't also require `$envelopeTo`'s domain to be one `SpamRejectionDetector` already trusts** (`BUILTIN_DOMAINS`/`reliable-spam-reporters:`) — that's a separate, additional bar `abortBatchForBounce()` applies on its own, since "is this bounce genuinely authenticated" and "do we trust the claimed domain's opinion instance-wide" are independent questions, both needed only for Spam's cross-recipient blast radius. See `abortBatchForBounce()`'s own docblock, and its extra `isReliableDomain()` check specifically.

A bounce also has to represent a **final** outcome, not an interim status: `BounceHandler::isFinalDeliveryOutcome()` reads RFC 3464's per-recipient `Action:` field (`message/delivery-status` part) and requires it to be `failed` (or absent — some non-standard bounce generators omit it entirely, treated as final rather than blocking everything, the same fail-open choice already made for every other best-effort DSN field extraction in this class). `Action: delayed` means the sending MTA is still retrying and this is merely a courtesy notice, not a final result — acting on it (aborting a batch, marking an address invalid, deferring a "mailbox full" recipient a second time, ...) based on a delivery that might still succeed would be premature. This gate applies to every cause, including `Spam` — a "delayed" notice whose text happens to mention "spam" was never meant to trigger anything either.

#### 3. What the content says: BounceCause / BounceCauseClassifier

Only once a bounce has passed all the gates above does its `Diagnostic-Code`/`Status` text get classified at all. **`BounceCause` (`src/Mail/BounceCause.php`)** — a plain (non-string-backed) enum, like `ResolutionPurpose`, since this is an internal classification result, never a config.yml value. Three cases:

- `Spam` — reported as spam by a reliable domain; aborts the rest of the batch (`BounceHandler::abortBatchForBounce()`). Still requires the reliable-domain check that all causes originally shared — but as of the correction described above, only `Spam` still does, since only its action reaches beyond the bounced recipient themselves.
- `UserUnknown` — permanent: mailbox/user/domain doesn't exist, or the relay refuses it; drives the list's own configurable `bounce-action`.
- `MailboxFull` — temporary: mailbox full; defers that recipient's *future* sends, escalating to `bounce-action` after repeated occurrences (see "Soft bounces: defer, then escalate" below).

Adding a further cause is three small, independent edits: a new case here, a new check in `BounceCauseClassifier::classify()`, and a new `match` arm in `BounceHandler::applyAutomaticAction()` — every verification layer above already applies uniformly to *any* cause, not just these three, since it concerns whether a bounce can be trusted at all, not what its content says.

**`BounceCauseClassifier` (`src/Mail/BounceCauseClassifier.php`)** — deliberately pure text classification, no dependencies at all: `classify(?string $reason): ?BounceCause`. Checked in order: `SpamRejectionDetector::containsSpamIndicator($reason)` (unchanged, checked first — a rare overlap between causes, e.g. a spam-rejection worded to also mention "does not exist", resolves as `Spam`); then `UserUnknown`, via Enhanced Status Codes (RFC 3463) `5.1.1`/`5.1.2`/`5.1.3`/`5.1.6`/`5.1.10` ("bad destination mailbox/system address", §3.2) **and** `4.4.3`/`5.4.3`/`4.4.4`/`5.4.4` ("directory server failure"/"unable to route", §3.5 — what Postfix actually emits for a DNS lookup failure on the recipient's own domain, i.e. "domain doesn't exist"), matched word-boundary-aware anywhere in the text (`(?<![\d.])5\.1\.1(?![\d.])`, so `5.1.10` and `5.1.1` are never confused with each other or with an unrelated longer number containing the same digits as a substring) — falling back to a keyword list (`user unknown`, `no such user`, `recipient address rejected`, `mailbox unavailable`, `does not exist`, `unrouteable address`, `host or domain name not found`, `name service error`, `host not found`, `unable to route`, ...) for a bounce with no clean status code; then `MailboxFull`, via `4.2.2`/`5.2.2` plus keywords (`mailbox full`, `quota exceeded`, `over quota`, `insufficient system storage`). It no longer takes a failed-recipient address or does any domain-trust check itself — that entire concern lives in `BounceHandler::isDkimAuthenticated()`/`abortBatchForBounce()` above, applied to `BounceCause::Spam` only (see "Is the content trustworthy" above for why the other two causes skip it).

**`BounceHandler::extractClassificationText(string $rawMime): ?string`** — confirmed live as a real, not just theoretical, gap: a genuine Postfix "domain doesn't exist" bounce had `Diagnostic-Code: X-Postfix; Host or domain name not found. Name service error for name=... type=AAAA: Host not found` (free text, no status code anywhere in it) alongside a perfectly clean, separate `Status: 5.4.4` — and the owner notice's own `%reason%` field is built from `extractDiagnostic()`, which *prefers* `Diagnostic-Code` and never even looks at `Status` when it's present. Before this existed, `applyAutomaticAction()` classified using `extractDiagnostic()`'s output too, so the classifier never saw the one field that actually carried a recognizable code — the bounce arrived, authenticated cleanly, but resolved to "keine"/"none" regardless. `extractClassificationText()` concatenates **both** `Diagnostic-Code` and `Status` and is what `applyAutomaticAction()` actually classifies from now — `extractDiagnostic()` is unchanged and still governs the owner-facing `%reason%` text (the more human-readable of the two, still just one field), so display and classification deliberately no longer read the exact same extraction.

**A third source: `BounceHandler::hasQuotedSpamFlag(string $rawMime): bool`** — confirmed live as a real, third gap distinct from the two above: a web.de bounce's own `message/delivery-status` part carried only the generic, uninformative `Status: 5.0.0` (RFC 3463 §3.8, "other/undefined status") and *no* `Diagnostic-Code` at all — nothing for `BounceCauseClassifier` to work with, regardless of how thoroughly `extractClassificationText()` searches those two fields. The actual verdict was present, just somewhere else entirely: the *quoted original message's own headers* carried `X-Spam-Flag: YES` — SpamAssassin's own convention, but widely emulated across many self-hosted and hosted mail systems (Rspamd included, in compatibility mode), not specific to web.de. `hasQuotedSpamFlag()` checks for either `X-Spam-Flag: YES` or `X-Spam-Status: Yes` (SpamAssassin's other, arguably more common, header — `X-Spam-Status: Yes, score=... required=... tests=...`), matched by the header's *value* starting with "yes" — not merely the header's presence, since the header *name* itself already contains the substring "spam" regardless of value, and `X-Spam-Flag: NO` is exactly as common as `YES`. A positive match appends the literal word `spam` to the text `extractClassificationText()` builds, which `BounceCauseClassifier`'s existing `SpamRejectionDetector::containsSpamIndicator()` check (already first in its `classify()` order) picks up with no changes needed there at all.

This needed its own scoping fix first: `hasQuotedSpamFlag()` must search *within* the quoted original's own headers, not the outer bounce's — confirmed live as a genuine, easy-to-conflate gotcha in this exact bounce: the *outer* DSN (from `mailer-daemon@web.de`) carried its own, unrelated `X-Spam-Flag: NO` (web.de's opinion of the notification *it* was sending out), while the *quoted original* carried `X-Spam-Flag: YES` (web.de's opinion of the message that actually got rejected) — reading the first occurrence anywhere in the raw text, as a plain `HeaderFilter::readHeader()` call would, finds the wrong one. Worse, the *existing* scoping boundary — `extractOriginalSender()`/`isBounceOnOwnNotification()`/`isFromTrustedRelay()` all previously looked only for a `message/rfc822` marker — turned out not to be general enough either: web.de doesn't attach a full `message/rfc822` original at all, only a `text/rfc822-headers` part (RFC 3798's headers-only variant). Confirmed live: against this exact bounce, `stripos($rawMime, 'message/rfc822')` returned `false` unconditionally, which meant `extractOriginalSender()` always showed "unbekannt"/"unknown" for this bounce shape (now fixed, a side effect of this same change), and — more seriously — `isFromTrustedRelay()` had no boundary to cut the raw text at all, so the *quoted original's own* `Received:` chain (which passes through whatever infrastructure originally relayed that message — a genuinely public IP in this exact case, unrelated to whether *this bounce* is genuine) silently leaked into the hop-scan meant to cover only the bounce's own transport.

**`BounceHandler::findQuotedOriginalOffset(string $rawMime): ?int`** — the shared fix: returns the earlier of `message/rfc822`/`text/rfc822-headers`'s positions (or null if neither appears), now used by all four methods that need to draw this same boundary, in either direction — `extractOriginalSender()`/`hasQuotedSpamFlag()` search *from* it onward (the quoted original itself), `isBounceOnOwnNotification()` likewise (its own `X-Listig-Auto` check), while `isFromTrustedRelay()` searches *up to* it (the outer bounce's own transport only).

None of this needs its own authentication layer — `hasQuotedSpamFlag()`'s result is just another piece of content inside a bounce whose *origin* (not its content) is already gated by the null-envelope/`isDkimAuthenticated()`/`isFromTrustedRelay()` checks in `applyAutomaticAction()` before classification ever runs, the same trust boundary `Diagnostic-Code`/`Status` already rely on.

**A distinct gap surfaced while verifying this fix against the real bounce above, considered and deliberately left unfixed**: neither `isDkimAuthenticated()` nor `isFromTrustedRelay()` actually authenticates *this* bounce, despite `hasQuotedSpamFlag()` now correctly finding `X-Spam-Flag: YES`. The `Final-Recipient` was `fenchel-schnitzel@posteo.de`, but the quoted original's own `Received:` header showed final delivery `for <sherian.y@web.de>` — i.e. posteo.de forwards that mailbox to a web.de account, and it was *web.de's* infrastructure, not posteo.de's, that actually rejected the (forwarded) message and generated the bounce. `isDkimAuthenticated()` requires the DKIM-signing domain to equal `domainOf($envelopeTo)` (`posteo.de`) — but the bounce is legitimately signed `d=web.de`, so it fails; `isFromTrustedRelay()` also fails, since web.de's own IP is a genuine public address. Mailbox forwarding is common enough (most consumer providers offer it) that the bounce-generating domain differing from the original recipient's own domain is a real, recurring case, not an edge case.

The obvious fix — accept a DKIM signature from *any* domain in `BUILTIN_DOMAINS`/`reliable-spam-reporters`, not just one matching `domainOf($envelopeTo)` — was considered and rejected: it would reopen exactly the cross-recipient DoS the domain-match requirement exists to prevent. Forwarding is entirely recipient-controlled and unauditable by Listig — nothing distinguishes an operator's own member setting up a benign personal forward from a malicious member deliberately forwarding their own subscription to a domain known to actively reject spam at SMTP time (web.de itself, confirmed live, is exactly such a domain). Since the token is bound only to that member's own row (see "Which recipient" above), they'd get a genuinely DKIM-signed, reliable-domain "spam" bounce addressed to their own valid VERP token, on demand — and `abortBatchForBounce()`'s action reaches every *other* pending recipient of the batch, not just the forwarder. ARC (Authenticated Received Chain, RFC 8617) is the standards-track mechanism actually designed to verify a forwarding chain cryptographically, but verifying a multi-hop ARC signature chain is substantially more complex than anything else in this class and not universally deployed enough to rely on — not attempted here. The accepted trade-off: a `Spam`-cause bounce whose recipient has forwarded their mailbox elsewhere, and where the downstream domain is the one that rejected it, won't trigger the automatic batch-abort — the bounce is still logged and the owner still notified (now with the correctly extracted `X-Spam-Flag` reason visible), just without automation for this one narrow shape.

#### Queue retention: keeping completed entries around

Before this feature, `QueueSender::cleanupQueueEntry()` deleted a `mail_queue` row (and its `queue_recipients` children) the moment its last recipient reached `sent` — in practice, within the same worker cycle it was sent in. That was fine for the original `Spam` cause (a synchronous or near-synchronous rejection), but a **soft bounce can legitimately arrive days later**, well after the row that actually needs correcting is long gone — and `BounceHandler::resolveVerifiedRecipient()`'s token-decoded `queue_recipients.id` lookup depends on that row still existing.

**`cleanupQueueEntry()` was removed.** `sendOne()` no longer deletes anything on completion — a `queue_recipients` row now stays around, whatever its final status, until `QueueSender::purgeCompletedEntries()` (the renamed, broadened `purgeStaleFailedEntries()`) deletes it: `status != 'pending' AND last_attempt_at < NOW() - INTERVAL 30 DAY`, then sweeps now-orphaned `mail_queue` rows — the same query shape as before, just no longer restricted to `status = 'failed'`. This is a **deliberate, accepted storage cost**: a successfully sent mail's MIME body (and attachments) now persists for up to 30 days per recipient instead of being deleted within the same cycle. 30 days matches the retention already used elsewhere (`bounce_log`, `imap_seen`, `processing_failures`) and comfortably covers even a slow mailbox-full give-up sequence.

Retaining completed rows is what makes two things possible without a separate tracking table:

- **`QueueSender::markBounced(int $recipientId, string $errorTag, ?\DateTimeImmutable $retryNotBefore = null): void`** — retroactively corrects that one row's own outcome (`status = 'failed'`, `error = $errorTag`) once an authenticated bounce proves a `sent` row actually bounced later. Called once, centrally, in `BounceHandler::applyAutomaticAction()` for **every** recognized cause (not just the ones with a further automatic action), so the manage page's queue status always reflects reality. `$errorTag` is one of three fixed `BOUNCE:SPAM`/`BOUNCE:USER_UNKNOWN`/`BOUNCE:MAILBOX_FULL` constants (`BounceHandler::errorTagFor()`) — a recognizable prefix distinct from an ordinary SMTP failure's own free-form error text.
- **`QueueSender::countRecentBounces(string $listCn, string $envelopeTo, string $errorTag): int`** — "how many times has this (list, recipient) pair bounced with this tag" answered by a plain `COUNT(*)` against the now-retained history, naturally bounded to the last 30 days since older rows are purged — no separate interval parameter needed.

An **earlier design** for the mailbox-full case used a dedicated `soft_bounce_tracking` table instead of extending retention — dropped once it became clear that keeping `queue_recipients` around a while longer already gives the same information for free, plus the ability to correct history, without a second place to keep in sync.

`QueueController::status()` (the manage page's own queue-status API) needed a matching `AND qr.status != 'sent'` filter — it previously had no status filter or `LIMIT` at all, relying entirely on `sent` rows vanishing almost immediately. Without the filter, an active list's 30-day history of successfully-sent mail would flood that owner-facing, unpaginated view.

#### Soft bounces: defer, then escalate

A single `MailboxFull` bounce is not itself cause for the configured `bounce-action` — mailboxes fill up and get cleaned out again all the time. `BounceHandler::handleMailboxFull()`:

1. The centrally-called `markBounced()` (see above) already set `retry_not_before` on the bounced row to `now + bounce-defer-days` (default 5) — computed in PHP from the *specific list's* own setting, not baked into a shared SQL interval (see below for why).
2. `countRecentBounces()` checks how many times this (list, recipient) pair has bounced with `BOUNCE:MAILBOX_FULL` so far. Below `bounce-escalate-after` (default 2): return a "deferred" description (`bounce.auto_action.mailbox_full_deferred`, `%days%`/`%count%`) — nothing else happens.
3. At or above the threshold — i.e. this address kept bouncing even after being given time to recover — escalate to `BounceHandler::applyConfiguredAction()`, the same dispatch a permanent `UserUnknown` bounce drives (see below).

**`QueueSender::sendBatch()`'s own SELECT** skips a currently-deferred recipient via `AND NOT EXISTS (SELECT 1 FROM queue_recipients qr2 JOIN mail_queue mq2 ON mq2.id = qr2.mail_queue_id WHERE mq2.list_cn = mq.list_cn AND LOWER(qr2.envelope_to) = LOWER(qr.envelope_to) AND qr2.retry_not_before > NOW())` — a self-join against the same, now-retained table, not a separate one. `retry_not_before` is a plain per-row timestamp rather than an interval computed inside that query deliberately: `sendBatch()` serves every list in one pass, so it has no way to know *which* list's own `bounce-defer-days` should apply to a given row — computing the cutoff once, in PHP, at the point a specific list is already known (`markBounced()`'s call site), sidesteps that entirely. This is also why `bounce-defer-days`/`bounce-escalate-after` are **root-level, instance-wide** settings (`'app.bounce-defer-days'`/`'app.bounce-escalate-after'`, `config/container.php`, defaults 5/2) rather than per-list config — only the eventual *consequence* (`bounce-action`) needs to be list-scoped, since it's applied entirely inside `BounceHandler`, where the specific list is always known.

**"Resend the original mail" was considered and rejected.** Even with extended retention, the original `mail_queue.mime` reflects whatever the mail looked like *at the time it was first sent* — resending it days later would be stale (wrong "now" for time-sensitive content) and semantically odd. Deferring only ever affects **future, independently-triggered distributions** to that recipient (the next time the list sends anything at all) — never a resend of the specific mail that bounced.

#### Executing the action: `bounce-action` (`none`/`mark-invalid`/`restrict`/`remove`)

**`src/Config/Enum/BounceAction.php`** (string-backed, per "Coding Conventions") and `ListConfig::$bounceAction` (5-level list config, default `none` — no automatic mutation of member data until an operator opts in explicitly, same safe-by-default philosophy as `archive: off`). `BounceHandler::applyConfiguredAction(ListConfig $list, string $envelopeTo, BounceCause $cause): string` dispatches on it, delegating the three data-mutating cases to **`BounceMemberActionExecutor`** (`src/Mail/BounceMemberActionExecutor.php`) — extracted out of `BounceHandler` so that class stays focused on detection/classification. Each of its three methods wraps the actual work in its own `try`/`catch`: a failure (LDAP unreachable, a DB error) must never prevent `BounceHandler` from still forwarding the triggering bounce to the owners — it's reported as part of the returned description instead, not thrown.

- **`none`** — still returns a description distinct from `noAutomaticAction()`'s own "none" (`bounce.auto_action.recognized_no_action`, `%cause%`): a cause *was* recognized, an operator has simply chosen not to act on it automatically. Worth saying explicitly rather than looking identical to "nothing matched at all".
- **`mark-invalid`** — `MemberResolver::invalidateEmail(string $listName, string $email, string $reason): void` / `supportsInvalidation(): bool` (new interface methods, mirroring `removeMember()`/`supportsRemoval()` exactly) replace the member's own address in place with **`Member\InvalidatedEmail::build($email, $reasonCode)`** — `{email}.BOUNCE_{reasonCode}.{YYYY-MM-DD}.invalid` (human-readable date, not a Unix timestamp; the `.invalid` RFC 2606 placeholder-domain convention already used elsewhere in this codebase). One shared static builder, used identically by every backend that implements it, so the format can't drift apart between them.
  - **`LdapMemberResolver`** — `mail` is multi-valued by schema (see "Additional addresses per member (`mail-aliases`)"). The value to replace is found by **value comparison, not array position** — the entry's own attribute order isn't guaranteed stable, and `Member::$email` only ever reflected whichever value happened to be first when this `Member` was last resolved. `removeAttributeValues()`/`addAttributeValues()` operate on values, so every *other* `mail` value (aliases) is left untouched regardless of order or count. `$listName` is deliberately ignored: a directory entry's `mail` attribute belongs to the person, not to any one list's group membership, so invalidating is unavoidably **instance-wide** — it affects every list this person belongs to, not just the one whose bounce triggered it. This asymmetry with the other two backends is inherent to LDAP's schema, not something to "fix".
  - **`DatabaseMemberResolver`**/**`CsvMemberResolver`** — `mail` is scoped per `(name, mail)` row/entry, so invalidating is naturally **per-list**: only the row for the specific list that triggered it changes; the same address's row under a different list (if any) is untouched.
  - **`InlineMemberResolver`**/**`NullMemberResolver`**/**`AggregateMemberResolver`** — `supportsInvalidation()` → `false`, `invalidateEmail()` throws — the exact existing `removeMember()`/`addMember()` pattern for a store that can't persist a runtime mutation at all.
  - **`CompositeMemberResolver`** — invalidates on every source with `supportsInvalidation() === true`, not just the first (same reasoning as its own `removeMember()`).
- **`restrict`** — adds to **`bounce_suppressed_members`** (new table, `migrations/006_bounce_auto_actions.sql`) via **`BounceSuppressionList`** (`src/Mail/BounceSuppressionList.php`, a small DB-gated collaborator like `RateLimiter` — `MailProcessor` may not run SQL itself, per "Coding Conventions"). Deliberately a **dedicated table, independent of the list's own `ListProvider`/`MemberResolver` backend** (LDAP/database/csv/inline) — not an extension of the existing, purely config-derived `restricted-members:`/`RestrictionList` mechanism, which is rebuilt fresh from `config.yml`/LDAP/DB-config-table every cycle by all 5 `ListProvider` implementations; making *that* dynamically writable would mean touching every one of them. A dedicated table ships independently of that generalization (left as a documented, possible follow-up) while still reusing the same underlying idea: an address here is skipped at send time. `MailProcessor::resolveRecipients()` checks `BounceSuppressionList::isSuppressed()` alongside the existing `!$list->isReceiverRestricted($m->email)` filter.
  - **Manage-page visibility**: `bounce_suppressed_members` is populated at runtime, not authored by the operator the way `restricted-members:` config is — so unlike that (which has no UI at all, confirmed by inspection: an operator can only see it by reading `config.yml`/LDAP/DB directly), an auto-suppressed address needs to be discoverable somehow, or an owner has no way to know why someone stopped receiving mail. `ListController::manage()` (owner branch) loads `BounceSuppressionList::listForOwner($list->name)` and `templates/list/manage.latte` renders a new card — address, reason, timestamp — **only when non-empty** (`n:if="count($suppressedMembers) > 0"`), same "don't show an empty section" convention as the rest of that page.
- **`remove`** — reuses the existing `ListConfig::removeMember()`/`$supportsUnsubscribe` unchanged; no new mechanism needed.

**The owner notice always states what Listig did, even when the answer is "nothing".** `BounceHandler::applyAutomaticAction()` never returns null — it always returns a translated description, which `bounce.owner_notice.body` embeds via a normal `%auto_action%` placeholder (a new "Automatische Reaktion: %auto_action%" / "Automatic response: %auto_action%" line, alongside the existing `%reason%`/`%failed_recipient%`/etc. fields), exactly like every other field in that body. The overwhelmingly common case — the bounce doesn't resolve to a verified recipient, isn't a final outcome, isn't authenticated, no `BounceCause` is recognized, or one is recognized but nothing was actually left pending to act on (`abortBatchForBounce()` falls back to the same "none" case here) — resolves to `bounce.auto_action.none` ("keine"/"none") rather than the line disappearing or the field going blank. This was a deliberate design choice, not just tidiness: an owner reading the notice should always be able to tell *whether* Listig reacted automatically, not have to infer "no line present" as meaning "no reaction".

`BounceHandler::handle()` runs `applyAutomaticAction()` — the resolve/authenticate/classify/execute pipeline above — **before** the bounce-loop-prevention circuit breaker check (see "Bounce loop prevention"), not after: the automatic action is a protective measure against the underlying distributed mail itself, independent of whether the owner actually gets notified about *this particular* bounce, and a burst of many bounces in a short window (exactly the situation the circuit breaker exists to throttle notification volume for) is precisely the situation where the automatic action matters most. It still runs after `isBounceOnOwnNotification()` though — a bounce on one of Listig's own notifications (moderation request, login mail, ...) was never itself sent through `QueueSender::sendOne()`'s per-recipient token scheme, so resolving/authenticating it would always be a harmless no-op, but skipping it there avoids the wasted lookup.

Note `%failed_recipient%`/`%reason%` in that same body remain sourced from the DSN's own self-reported `Final-Recipient`/`Diagnostic-Code` (`extractFailedRecipient()`/`extractDiagnostic()`) — display only, shown to the owner exactly as the remote server phrased them, and never consulted for the automatic-action decision itself (which relies solely on the token-verified recipient, the authenticated-origin checks, and the final-outcome check above).

### Header filter

`HeaderFilter::readAuthResults(string $headersRaw): array{spf, dkim, dkimDomain}` — parses the `Authentication-Results` header from the raw header block and returns SPF/DKIM pass/fail strings, plus the DKIM signature's own `header.d=` signing domain (`dkimDomain`, read from the *same* `Authentication-Results` value as the `dkim=` verdict, not just the first `header.d=` found anywhere — null if `dkim` isn't `pass` or the parameter is absent). `dkimDomain` exists specifically for `BounceHandler::isDkimAuthenticated()` — see "Automatic bounce actions" — to verify a bounce's DKIM signature genuinely belongs to the domain it's being trusted for.

`MailProcessor` builds the outgoing `Email` from scratch via `IncomingMail` fields, so there is no explicit header blocklist. Infrastructure headers (`DKIM-Signature`, `Received`, `Authentication-Results`, `ARC-*`, `Return-Path`) are simply never copied to the fresh outgoing `Email`. Threading headers (`Message-ID`, `In-Reply-To`, `References`, `Date`) are preserved — but not all via the same `Headers` method: symfony/mime's `Headers::HEADER_CLASS_MAP` enforces a specific value class for some header names, rejecting `addTextHeader()`'s always-`UnstructuredHeader` result outright (`LogicException: The "..." header must be an instance of "..." (got "UnstructuredHeader")`). `Message-ID` must be `addIdHeader()` (an `IdentificationHeader`, constructed from the bare id — the raw value's `<>` are stripped first, `IdentificationHeader::getBodyAsString()` re-adds them) and `Date` must be `addDateHeader()` (a `DateHeader`, constructed from a parsed `\DateTimeImmutable`, not the raw string). `In-Reply-To`/`References` are the exception: their `HEADER_CLASS_MAP` entry allows `UnstructuredHeader` *or* `IdentificationHeader` (deliberately lenient, "to allow users entering the original email's Message-ID, even if that is no valid msg-id" — the library's own comment), so `addTextHeader()` continues to work for those two. Each header is preserved best-effort in its own `try`/`catch` — a malformed value from the sending MTA (unparseable `Date`, a `Message-ID` that fails `Address`'s RFC validation) is logged and skipped rather than blocking distribution of an otherwise-fine mail.

### Attachments — preserving embedded (`cid:`) images

`buildOutgoingEmail()` copies `$mail->textHtml`/`$mail->textPlain` into the outgoing body verbatim — any `cid:` references an incoming HTML body contains (e.g. `<img src="cid:part1.ACmwPHTY.OIw3acmz@hengeb.de">`) are never rewritten, so whichever attachment part they point at must survive distribution with the *same* Content-ID and an `inline` disposition, or the reference resolves to nothing in the recipient's mail client. `Email::attach()` cannot do this: it always builds a plain `DataPart` with `Content-Disposition: attachment` and no `Content-ID` at all, regardless of what the original attachment looked like — silently breaking every embedded image on every distributed mail (confirmed live: an incoming mail with one `cid:`-embedded image and one ordinary attached image produced identical `attachment`-disposition parts for both, and Thunderbird rendered a broken-image icon where the embed should have been). `Email::embed()` isn't a fix either — it calls `(new DataPart(...))->asInline()`, but has no parameter for pinning a *specific* pre-existing Content-ID; without one it lazily generates its own via `getContentId()`'s `generateContentId()` fallback, which would never match the id already baked into the copied HTML body.

The fix: for each `IncomingMailAttachment` where `$attachment->disposition === 'inline'` and `$attachment->contentId` is non-empty, build the part manually — `(new DataPart($attachment->getContents(), $attachment->name, $contentType))->asInline()->setContentId($attachment->contentId)`, added via `$email->addPart()` — preserving the exact original id (`IncomingMailAttachment::$contentId` is already bare, without angle brackets, matching both `DataPart::setContentId()`'s expected format and the bare `cid:...` reference already in the HTML). Every other attachment (no Content-ID, or `disposition === 'attachment'`) continues through the plain `$email->attach(...)` path unchanged.

**Non-conformant Content-IDs** — `DataPart::setContentId()` requires an "@" (RFC 2045-style msg-id syntax: `local-part@domain`) and throws `InvalidArgumentException` otherwise; the same requirement is enforced a second time, independently, wherever `getPreparedHeaders()` actually serializes the id (`Headers::setHeaderBody('Id', 'Content-ID', ...)` → `IdentificationHeader::setIds()` → `new Address($id)`, which runs the same "does it look like `local-part@domain`" validation) — so there is no way to bypass the first check (e.g. writing `$this->cid` directly) and still emit a genuinely non-conformant `Content-ID` header via symfony/mime's normal API. Confirmed live from a real sender (an Authentik-generated notification via Amazon SES): `Content-ID: <logo>` — no `@` at all — which, uncaught, crashed `MailProcessor::process()` entirely before any recipient was enqueued; `bin/worker.php`'s outer per-mail `catch` then logged the error and `continue`d, leaving the mail unseen and unarchived, so it was refetched and re-crashed on *every single worker cycle* indefinitely (see "Processing-failure retry limit" below for why that no longer happens either way).

Falling back to a plain (non-inline) attachment for such a part would "fix" the crash but silently break the embed for every recipient, even though the original, non-conformant mail displayed it just fine in the sender's own client — not an acceptable trade-off. The actual fix: `buildOutgoingEmail()` first scans every inline attachment's Content-ID; any that doesn't contain `@` gets a synthesized replacement (`$cid . '@listig.invalid'` — the same `.invalid` (RFC 2606) placeholder-domain convention already used for `ReplyToBehavior::Nobody`'s `noreply@{domain}.invalid`, i.e. syntactically valid and deliberately never meant to be dereferenced) recorded in a `$cidRewrites` map. Every `cid:$oldId` occurrence in `$mail->textHtml` is then rewritten to `cid:$newId` **before** the body is set on the outgoing `Email` — the reference and the embed must always agree on the same id, or it resolves to nothing either way, so the body has to be fixed up first. The attachment loop then calls `setContentId($cidRewrites[$cid] ?? $cid)`, and only if *that* still throws (some other, still-unfixable malformation) does it fall back to the old safety net: `try`/`catch (\Throwable)`, plain `$email->attach(...)`, logged via `error_log()` — matching the same "malformed value from the sending MTA, skip and move on" philosophy as the header-preservation loop below, just as a last resort rather than the first response to a merely-missing `@`.

### Headers to set on outgoing mail

| Header | Value |
|---|---|
| `From` | `smtp-from-name <list-mail>` — `smtp-from-name` may contain mail-context variables |
| `Sender` | `{list->localPart}+bounce@{list->domain}` — local part of the list's own mail address, not `{list-cn}` (see "Envelope separation") |
| `Reply-To` | List address (`List`), original sender (`Sender`), both (`Both`), or a translated "please do not reply" display name on `noreply@{list->domain}.invalid` (`Nobody`) — see `ReplyToBehavior` |
| `X-Original-Sender` | Sender's CN — only when the sender's own address is in Reply-To (`Sender`/`Both`; CN not email — privacy) |
| `List-Id` | `<{name}.{domain}>` — uses `name` (stable identifier, not `display-name` which may change) |
| `List-Post` | `<mailto:{mail}>`, or `NO` if both `post-access-members` and `post-access-public` are `deny` (owners-only — see "`post-access-members`/`post-access-public`") |
| `List-Help` | `<mailto:{owner-mail}>` — added whenever the list has at least one owner (not conditional on post-access) |
| `List-Unsubscribe` | `<https://{hostname}/{list-name}/unsubscribe?token={TOKEN}>` |
| `List-Unsubscribe-Post` | `List-Unsubscribe=One-Click` |
| `Precedence` | `list` |
| `X-Loop` | List mail address |
| `X-Original-To` | Original `To` header value |

`List-Id` uses `name` rather than `display-name` because it is a stable machine-readable identifier that should not change when the human-readable name is updated.

**No `X-Forwarded-From`.** An earlier version of `MailProcessor::setOutgoingHeaders()` unconditionally added `X-Forwarded-From: {sender's raw address}` to every distributed mail — a real privacy leak, inconsistent with `X-Original-Sender`'s own deliberate choice to expose only the sender's CN, never the address, and directly contradicting the very claim made below ("the sender's real address is never otherwise visible to recipients") one paragraph over in the same file. Confirmed live (before removal): every recipient of a distributed mail could read the original sender's exact address via "view all headers," regardless of the list's `reply-to`/`archive` settings or the sender's own privacy expectations. Removed outright rather than switched to a CN-based value — no known use case in this codebase needed it, so the smallest fix was to simply stop sending it.

**`reply-to: both` and list-member senders** — `MailProcessor::setOutgoingHeaders()` computes `$exposesSenderAddress` once, before building `Reply-To`, and reuses it for the `X-Original-Sender` decision below: `true` for `Sender` always, for `Both` only when `!$list->isMember($senderEmail)`, `false` for `List`/`Nobody`. The reasoning is a duplicate-delivery problem, not a privacy one (the sender's real address is never otherwise visible to recipients — the distributed mail's own `From` is always the *list's* address, per the `From` row above, so `Reply-To` is the only place it can leak at all, now that `X-Forwarded-From` is gone): list distribution already reaches every member, sender included, so if a member's own mail also carries their personal address in `Reply-To`, a mail client that sends a reply to *every* `Reply-To` address (e.g. "Reply All") delivers one copy straight to that address and a second copy via the list redistribution — the same reply, twice, in the same inbox. A non-member sender has no such second path (they're not on the list, so redistribution never reaches them), so for them `both` keeps behaving as its name says.

### Subject label

If `list-label` configured (and not empty string):
- `str_contains($subject, $label)` case-insensitive — skip if already present
- Otherwise: `$subject = "$listLabel $subject"` (label used as-is, no brackets added by Listig)

### Body/subject personalization (`BodyPersonalizer`)

All MIME manipulation uses symfony/mime on decoded content — never raw string replacement.

Subject: RFC 2047 decode → whitelist-gated substitution → RFC 2047 re-encode. The decode step is guarded by `str_contains($value, '=?')` — in practice the subject reaching here is *already* plain, decoded UTF-8 (php-imap decodes `$mail->subject` on parse, well before `MailProcessor::buildOutgoingEmail()`/`applySubjectLabel()` ever touch it), so this is normally a no-op; without the guard, calling `iconv_mime_decode()` on a plain string that merely contains literal non-ASCII bytes (no actual `=?...?=` encoded-word) silently **strips every umlaut** — confirmed live, `iconv_mime_decode()` treats its input as a raw MIME header (7-bit clean outside encoded-words) and `ICONV_MIME_DECODE_CONTINUE_ON_ERROR` drops whatever it can't map under that assumption instead of erroring. This is exactly why every distributed mail's subject lost its umlauts before the guard existed.
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

1. Incoming mail from a sender whose `post-access-members`/`post-access-public` (whichever applies) is `PostAccess::Moderate` — see `IncomingMailFilter::requiresModeration()`; size check passes first
2. `ModerationMailer::send(ListConfig $list, IncomingMail $mail, int $imapUid, int $uidValidity, string $rawMime)` sends to all owners:
   - `From`: list address; `Reply-To`: the accept address itself — so an owner can just hit "Reply" in their mail client to approve, without needing to compose a new message or click the `mailto:` link. Rejecting still requires acting on the `Reject:` line explicitly (there's only one Reply-To slot, and accept is the more common action) — see "Reply-To header" below.
   - `Content-Type: multipart/mixed`:
     - **Part 1** (`text/plain`): the moderated mail's own subject/sender/date, then metadata + mailto links as plain text (**no HTML part** — prevents token leakage in replies):
       ```
       Subject: {subject}
       From: {sender-name} <{sender-mail}>
       Date: {date}

       Accept: mailto:{local-part}+accept-{TOKEN}@example.org?subject=accept
       Reject: mailto:{local-part}+reject-{TOKEN}@example.org?subject=reject
       ```
       `{local-part}` is `ListConfig::$localPart` (the local part of the list's own `mail` address), **not** `$list->name`/`{list-cn}` — same reasoning as the bounce address (see "Envelope separation"): they commonly differ, and only the real mailbox's local part is guaranteed deliverable back into the list's own IMAP inbox where `ModerationResponseHandler` can find it. `{TOKEN}` is the normal base64 token (see "Token Format") — recovering it intact from a reply's raw `To` header, rather than the lowercased `$mail->to`, is what makes mail-reply accept/reject actually work; see "Token Format" for why.
       `?subject=accept`/`?subject=reject` is a `mailto:` query parameter — mail clients pre-fill the compose window's Subject with it, but it plays no role in `ModerationResponseHandler::detectAction()` (which only ever looks at the `To` address) and is stripped from the actual outgoing `To:` header, so it can't interfere with token detection. Added purely because a mail with a genuinely empty Subject made some mail clients warn the owner before sending; not applied to `$acceptAddress`/`$rejectAddress` themselves, which are also used bare for the `Reply-To` header below and must stay valid, query-free addresses there.
       Sourced directly from the already-parsed `IncomingMail` passed in (`$mail->subject`/`$mail->fromName`/`$mail->fromAddress`/`$mail->date`), not re-read from `$rawMime` — same fields, and same `"{$senderName} <{$senderMail}>"` formatting, persisted to `moderation_queue`'s `subject`/`sender_name`/`sender_mail`/`mail_date` columns (see "Database Schema") so the manage page's moderation queue table can show the same information without a live IMAP fetch.
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

**Reject via the manage-page button** (`ModerationController::reject()`, `POST /_/api/moderation/{id}/reject` — see "Moderation via UI") follows the exact same reject contract as step 7 above: fetch the `IncomingMail` by UID, `RejectionNotifier::notify(..., 'reject.moderation_declined')`, `markSeen()`, `archiveOrDelete()`, then delete the `moderation_queue` row. It did not originally — it only deleted the row, leaving the sender un-notified and the mail stuck in the inbox forever (never marked seen, never archived/deleted) — a UI reject and a mail-reply reject must have identical end states, not two different ones depending on which path an owner happens to use.

`allow-leave: moderated`: when a member requests unsubscription, send a plain notification mail to all owners: "User {firstname} {lastname} ({mail}) has requested removal from list {display-name}." Owner must remove manually in LDAP.

### Overdue reminder

Find rows where `created_at < NOW() - 7 days` and (`reminded_at IS NULL` or `reminded_at < NOW() - 7 days`). Resend moderation mail, update `reminded_at`.

### Moderation via UI

- `POST /_/api/moderation/{id}/accept`
- `POST /_/api/moderation/{id}/reject`

Require valid session (owner of that list) + `X-CSRF-Token`.

The manage page's moderation queue table (`ListController::getModerationItems()`,
`templates/list/manage.latte`) shows Subject/Sender/Received columns alongside Accept/Reject,
reading `moderation_queue`'s `subject`/`sender_display` (see "Database Schema")/`mail_date`
columns directly — no live IMAP fetch. `mail_date` falls back to `created_at` for a row queued
before the metadata columns existed (the migration doesn't backfill). Each row is itself
clickable (`class="clickable-row"`, whole-row `onclick` plus a real `<a>` on the Subject cell
for no-JS/keyboard/open-in-new-tab access) and opens a full preview of the still-pending mail
— see "Preview: pending mail" below. The Accept/Reject buttons call `event.stopPropagation()`
first so clicking one doesn't also navigate the row away.

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
"DatabaseConnectionFactory") rendered correctly bare (`.../moderation/7`), but a `string` value
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
"Archive viewer"), `show()`/`frame()` are plain `AuthMiddleware`-protected routes (same group as
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

### Bounce preview

Clicking a row in the manage page's bounce table (`templates/list/manage.latte`) opens the same
read-only preview as the moderation queue, at `GET /{listname}/bounce/{id}` (`{id}` is
`bounce_log.id`) — `BounceController::show()`/`frame()`/`attachment()`, again reusing
`archive/show.latte`/`frame.latte`. Unlike a pending moderation mail (still sitting in the
INBOX, fetched by IMAP UID), a bounce mail has **already** been archived into the list's archive
folder — or deleted outright, if `archive: off` — by `ImapArchiver::archiveOrDelete()`, which
runs right after `BounceHandler::logBounce()` writes the `bounce_log` row (see `IncomingMailFilter
— check order`). So a bounce is located the same way the archive viewer locates any other
archived mail: by Message-ID, not by UID.

**`ArchiveMailResolver` (`src/Archive/ArchiveMailResolver.php`)** — the "locate by Message-ID,
eagerly cache attachment contents while the IMAP connection is still open" logic (previously a
private `ArchiveController::locateMail()` method, see "Archive mail cache — performance") was
extracted into its own class specifically so `BounceController` could reuse it instead of a
second copy. It deliberately does **not** decide what happens when `ArchiveMailNotFoundException`
is thrown (a confirmed-gone mail, per a full successful `SEARCH ALL` that found nothing) — that
cleanup differs per caller: `ArchiveController::locateMail()` still removes the now-stale
`archived_mail` row itself; `BounceController::locateMail()` has no equivalent index to clean up
and just returns `null` (the row stays, `message_id` still set, and the next time someone opens
it the same lookup — and the same "not found" — simply happens again).

A `bounce_log` row whose `message_id` is `NULL` (logged before `migrations/003_bounce_log_message_id.sql`,
or the bounce mail had no Message-ID at all) is rendered as **not clickable at all** in the
table — `manage.latte` only adds the `clickable-row` class/`onclick` when `message_id !== null`,
rather than making every row clickable and having `BounceController` immediately show a
"mail unavailable" preview for the un-locatable ones.

**Owner-only, always a real session** — same reasoning and the same `AuthMiddleware`/
`OptionalAuthMiddleware` split as the moderation preview (`show()`/`frame()` need a session;
`attachment()` sits in the archive/moderation `OptionalAuthMiddleware` group instead, since the
sandboxed frame's `cid:`-rewritten `<img>` requests carry no cookie — see "Preview: pending
mail" above for the full reasoning). Its attachment token uses its own dedicated purpose,
`bounce-attachment`, so it can't be replayed against the archive/moderation grants or vice versa.

**Bounce's own sender is shown as-is, unlike archive/moderation** — `show.latte`'s metadata table
normally shows only a display name, never a raw address (see "Privacy" under Archive viewer).
`BounceController::show()` passes `bounce_log.sender` (the bounce mail's own `From`, typically
`MAILER-DAEMON@...`) into that same slot regardless, because the manage page's bounce table right
next to it already shows that exact same address in its own "Sender" column — there is nothing
left to redact that isn't already on the same page, and it identifies the *remote MTA* that
generated the bounce, not a list member.

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

Confirmed live as a real, not just theoretical, problem: the original design (`json_encode()` the payload, then a full, untruncated hex HMAC-SHA256 digest, joined with a `.`) made `bounce`/`accept`/`reject` tokens — the three embedded directly in an email address local-part (`{list->localPart}+bounce+{TOKEN}@...`, `+accept-{TOKEN}@...`, `+reject-{TOKEN}@...`) — exceed RFC 5321's 64-byte local-part limit for anything but the very shortest list names, sometimes by a wide margin (well over 100 bytes for `accept`/`reject`). Three independent changes fixed this, all applied uniformly to every purpose (not just the three that needed it, for consistency and because shorter tokens are a nice-to-have for the URL-embedded purposes too):

1. **Compact binary payload encoding, not JSON.** Each `string|int|null` value gets a 1-byte type tag (`TokenService::TYPE_STRING`/`TYPE_INT`/`TYPE_NULL`) followed — for `string`/`int` — by an unsigned LEB128 varint (`encodeVarint()`/`decodeVarint()` — 7 payload bits per byte, high bit = "more bytes follow") for either the string's byte length or the integer's own value; `null` needs no further bytes at all, just its own type tag. This keeps the same "no payload shape known in advance" property the JSON encoding had (`decodePayload()` reads a stream of tagged values with no schema), while costing far fewer bytes: no quoting/braces/commas, and — the larger win — an integer costs only as many bytes as its actual magnitude needs (e.g. 1-2 bytes for a small ID) instead of up to 10 ASCII digits for a Unix timestamp. `TYPE_NULL` specifically exists because `ListApiController::requestSubscribe()` signs `$body['firstname'] ?? null` (and `lastname`/`username` likewise) — a genuinely absent field, later distinguished from an explicit empty string by `attributesFromBody()`'s own `!== null` filter — which the JSON encoding round-tripped for free but the first version of this binary encoding didn't handle at all (confirmed live: it threw rather than silently mis-encoding, since `encodePayload()` rejects anything that isn't `string`/`int`/`null` outright).
2. **Truncated HMAC, not a full digest.** `TokenService::HMAC_BYTES = 12` (96 bits) — RFC 2104/NIST SP 800-107 both explicitly allow a truncated MAC as long as the remaining length still gives an adequate security margin against forgery; 96 bits is comfortably beyond any realistic brute-force capability even across a token's full multi-day validity window, especially given none of the token-verifying endpoints are individually rate-limited (only *requesting* a login link is).
3. **Payload and signature share one base64 blob, no `.` separator.** Since `HMAC_BYTES` is fixed, `verify()` doesn't need a delimiter to find the boundary — it base64-decodes the whole token once, then slices off the last `HMAC_BYTES` bytes as the signature and treats everything before that as the payload. This also means the two pieces round to base64's 3-byte encoding boundary *together* rather than each separately, which — combined with base64 packing 6 bits/character against hex's 4 (hex was the original encoding for the signature; base64 replaced it as part of this same change) — costs noticeably fewer characters than the two-part `payload.hmac` shape ever could.

Together, these took a typical `bounce`/`accept`/`reject` token from well over 100 characters down to roughly 30-35 (see the short purpose codes below for the remaining piece of that reduction), comfortably inside the local-part budget even with the `+bounce+`/`+accept-`/`+reject-` prefix.

### Short purpose codes

Every purpose is signed as a single-character string, not the readable full word — `'b'` not `'bounce'`, `'a'`/`'r'` not `'accept'`/`'reject'`, and so on for every purpose, including the ones with no local-part length constraint at all (query-parameter purposes benefit too, and consistency avoids a "which purposes are abbreviated" special case). `TokenService` needed no changes for this: `$purpose` is still just an arbitrary `string` as far as it's concerned, compared for equality — the short codes are purely a convention each call site's `sign()`/`verify()` pair agrees on, not a registry `TokenService` itself owns (preserving "adding a new purpose never requires touching `TokenService`").

| Full purpose | Code | Used by |
|---|---|---|
| login | `l` | `AuthController` |
| unsubscribe | `u` | `MailProcessor`, `DashboardController`, `ListController` (sign) / `UnsubscribeController` (verify) |
| accept | `a` | `ModerationMailer` (sign) / `ModerationResponseHandler` (verify) |
| reject | `r` | `ModerationMailer` (sign) / `ModerationResponseHandler` (verify) |
| bounce | `b` | `QueueSender::sendOne()` (sign) / `BounceHandler::resolveVerifiedRecipient()` (verify) |
| subscribe | `s` | `ListApiController` |
| archive-attachment | `v` | `ArchiveController` |
| moderation-attachment | `m` | `ModerationController` |
| bounce-attachment | `n` | `BounceController` |
| reply | `p` | `ReplyTargetStore` — payload `ListFingerprint::of($listCn), $replyTargetId`, max age 180 days |

`accept`/`reject` are the one case where the short code and the *visible* address tag genuinely differ: `ModerationMailer::send()` still builds `{list->localPart}+accept-{TOKEN}@...`/`+reject-{TOKEN}@...` (the full word, unabbreviated — an owner-facing `mailto:` address, not itself byte-constrained the way the token portion is) while signing the token itself with `'a'`/`'r'`. `ModerationResponseHandler::detectAction()` still extracts the full word from that address (`'/' . preg_quote($localPart, '/') . '\+(accept|reject)-(.+?)@/i'`, unchanged) since that's also what drives the accept-vs-reject dispatch and error-log messages elsewhere in `handle()` — only the value actually passed to `TokenService::verify()` needs to match what was signed, so `ModerationResponseHandler::TOKEN_PURPOSE_MAP` (`['accept' => 'a', 'reject' => 'r']`) translates just before that one call, nothing else in the method.

### `ListFingerprint` — bounding the list name's own contribution

Even with both changes above, `bounce`/`accept`/`reject` tokens had one more unbounded cost: `$listCn` itself, embedded raw as a string, has no length an operator is required to respect (a longer list name simply made the token longer, reopening the same 64-byte problem for any list with a long enough name — confirmed by direct calculation, not just for the specific list name that first surfaced the issue). `Hengeb\Listig\Token\ListFingerprint::of(string $listCn): int` (`crc32($listCn) & 0xFF`) replaces the raw string with a single byte for these three purposes specifically — every other purpose (`login`/`unsubscribe`/`subscribe`/the `*-attachment` purposes) is a URL query parameter with no such constraint, and still signs/returns the full, real list name, since those callers (e.g. `AuthController::verifyToken()` setting `$_SESSION['user']['listCn']`) genuinely need it back, not just a match/mismatch verdict.

This is safe specifically *because* the fingerprint is only ever used as the existing defense-in-depth "does this token actually belong to this list" sanity check (same principle as `UnsubscribeController`'s own `{listname}`-vs-token check) — never the token's actual security boundary, which remains the HMAC signature over the whole payload, fingerprint included. A forged fingerprint value is unreachable without first breaking the signature; an accidental collision between two differently-named lists (deliberately possible at only 256 distinct values — collisions are far more likely than with a full hash, by design) only ever weakens that secondary check for an operator with a large number of lists, not the actual security of any individual token, and a Listig instance anywhere near 256 lists is far outside this project's realistic scale.

### `accept`/`reject` — referencing `moderation_queue.id`, like `bounce` already referenced `queue_recipients.id`

The original `accept`/`reject` payload — `$listCn, $imapUid, $imapUidvalidity` — had a second problem beyond the raw list name: `$imapUidvalidity` is commonly itself a full Unix timestamp (many IMAP servers derive it from the mailbox's creation time), costing as much as the token's own timestamp field a second time over. Fixed the same way the `bounce` token already solved an analogous problem for `queue_recipients` (see "Automatic bounce actions" → "1. Which recipient"): reference the `moderation_queue` row by its own `id` instead of embedding `imap_uid`/`imap_uidvalidity` directly.

This required reordering `ModerationMailer::send()`: the `INSERT INTO moderation_queue` now runs *before* the accept/reject tokens are signed (previously after), since the tokens need the row's own `id` to exist first. Getting that `id` back correctly on *both* the genuine-new-item and reminder-resend (duplicate-key) paths needed one more fix, confirmed empirically against MariaDB: the previous `ON DUPLICATE KEY UPDATE id = id` (a deliberate no-op, chosen specifically so `ROW_COUNT()` — and therefore `$isNewItem` — stays `0` on a resend) never touches `LAST_INSERT_ID()` at all on the duplicate-key path, so `PDO::lastInsertId()` would return stale or wrong data for a resend. `ON DUPLICATE KEY UPDATE id = LAST_INSERT_ID(id)` fixes this: confirmed live, `LAST_INSERT_ID(id)` evaluates to the *existing* row's own `id` — still a no-op on the column's actual value, so `ROW_COUNT()`/`$isNewItem` are completely unaffected — while also setting the session's `LAST_INSERT_ID()` to that same value as a side effect, so `lastInsertId()` now reliably returns the correct row id either way.

`ModerationResponseHandler::handle()` mirrors this on the verify side: decodes `[ListFingerprint::of($listCn), $itemId]`, checks the fingerprint, then `SELECT id, list_cn, imap_uid, imap_uidvalidity FROM moderation_queue WHERE id = :id` — a single lookup that both resolves the real `imap_uid`/`imap_uidvalidity` (no longer signed into the token at all) and doubles as the exact same idempotency check the old `(list_cn, imap_uid, imap_uidvalidity)`-keyed lookup already provided (a re-sent reminder or a double-click, after the row was already deleted by a prior accept/reject, correctly finds nothing and stops).

Each call site defines its own payload shape and max age, and destructures the same way on both ends — purposes named here by their full, readable word; see the short-code table above for what's actually signed into the token itself:

| Purpose | `sign()` payload | Max age | Used by |
|---|---|---|---|
| `login` | `$listCn, $userCn` | 5 minutes | `AuthController` |
| `unsubscribe` | `$listCn, $userCn` | 7 days | `MailProcessor` (sign) / `UnsubscribeController` (verify) |
| `accept` / `reject` | `ListFingerprint::of($listCn), $moderationQueueId` | 7 days | `ModerationMailer` (sign) / `ModerationResponseHandler` (verify) |
| `bounce` | `ListFingerprint::of($listCn), $recipientId` (`queue_recipients.id`) | 7 days | `QueueSender::sendOne()` (sign) / `BounceHandler::resolveVerifiedRecipient()` (verify) — see "Automatic bounce actions" |

URL-safe Base64 (`+`→`-`, `/`→`_`, no padding) — the entire token (payload and truncated signature together, see above), safe in mail `+` addresses.

An `accept`/`reject`/`bounce` token rides in an email address's local-part (`{list->localPart}+accept-{TOKEN}@{list->domain}`, `{list->localPart}+bounce+{TOKEN}@{list->domain}`, see Moderation / "Automatic bounce actions") — `PhpImap\Mailbox` parses every recipient address through `mb_strtolower()` before the app ever sees it (`possiblyGetEmailAndNameFromRecipient()`), which would corrupt a mixed-case base64 token if the token were read from `$mail->to`/`$mail->cc`. Rather than change the token encoding (base64 is kept, unchanged, for all purposes), `ModerationResponseHandler::detectAction()`/`BounceHandler::extractBounceToken()` both read the address straight out of the raw, unparsed header instead (`HeaderFilter::readHeader($mail->headersRaw, 'To')` and, for a bounce, also `Delivered-To`/`X-Original-To` as fallbacks) — case exactly as the sending mail client/server wrote it — and regex-match against that string directly, never touching the lowercased `$mail->to`/`$mail->cc` arrays for this purpose. Confirmed live: a real reply's `$mail->to` key showed an all-lowercase token where the raw header still had the original mixed case, and `TokenService::verify()` only succeeds against the latter.

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

### Password verification (`POST .../encrypt-password`)

Before encrypting and persisting a submitted password, `ListApiController::encryptPassword()` verifies it actually logs in via `ImapMailboxFactory::verifyPassword($list, $password)` — a one-off `PhpImap\Mailbox` built from the list's *current* `imap-host`/`imap-user` (unaffected by the password being submitted) plus the *candidate plaintext* password, bypassing both the shared connection cache and `$list->imapPassword` entirely. A typo would otherwise only surface later, as a silent IMAP failure on the next poll cycle (see "Optional IMAP config" below), rather than an immediate, actionable error to whoever is provisioning the list. `verifyPassword()` just calls `getImapStream()` and lets a login/connection failure propagate as `PhpImap\Exceptions\ConnectionException`; the controller catches `\Throwable` broadly and responds `422` without ever calling `PasswordCrypto::encrypt()`/`setListConfigValue()` — the bad password is never persisted.

Verification only runs when `$list->imapHost !== ''` — a list still mid-setup with no host configured at all (e.g. `api-token` set but nothing else yet, see "Optional IMAP config") has nothing to connect to, so the password is stored unverified in that case, exactly as before this existed.

`verifyPassword()` deliberately never calls `$mailbox->disconnect()` itself — `PhpImap\Mailbox::__destruct()` already does that once the local variable goes out of scope, matching the only other place in this codebase that manages a `Mailbox` lifecycle (`ImapMailboxFactory::reset()`, which just drops cached instances and lets garbage collection trigger the destructor). Confirmed live: calling `disconnect()` explicitly *and* letting the destructor call it again moments later throws `ValueError: IMAP\Connection is already closed` from the second call — a real quirk of `ext-imap`'s PHP 8.1+ object-based connection handle (throws on re-use where the old resource-based API just returned `false`), not something to work around with a guard; simply not calling it twice avoids it entirely.

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

### HTML escaping — never use `|escapeHtml`

Latte's `Engine` auto-escapes every `{...}` output expression for its surrounding context (HTML text, an attribute value, `<script>`, ...) by default — no explicit filter is ever needed for correctness, in any context, and none of these templates disable that behavior. `|escapeHtml` (`Latte\Essential\CoreExtension`, backed by `HtmlHelpers::escapeText()`) exists as a built-in filter, but it returns a **plain string**, not a value Latte's compiler recognizes as already-safe — so a value piped through it explicitly gets escaped twice: once by the filter, once again by the engine's own auto-escaping of the print expression. The result is corrupted double-encoded output (`&amp;lt;` instead of `&lt;`, rendering as the literal text `&lt;` in the browser instead of `<`) for any value containing `<`, `>`, `&`, `"`, or `'` — invisible for plain alphanumeric content, which is why ~43 pre-existing `{$value|escapeHtml}` call sites across every `.latte` template went unnoticed until the moderation queue table (see "Moderation via UI") started rendering real mail subjects/sender names, which routinely contain `&`.

Fixed by removing `|escapeHtml` everywhere (confirmed via `Latte\Engine::compile()` on all 9 template files, plus targeted `renderToString()` tests with `<`/`>`/`&`-containing values in both text and attribute (`href="..."`) context) — write `{$value}`, not `{$value|escapeHtml}`. If a future template genuinely needs to bypass auto-escaping (rare — inserting pre-sanitized HTML, e.g. the archive viewer's sanitized mail body), that's `|noescape`, the opposite direction, not `|escapeHtml`.

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

**`getTemplate()`/`getTemplateName()`** (`config/container.php`, registered on the `Engine`) — let a `custom.latte` block find out which page it's actually rendering into, since plain `$this` inside a template is deprecated since Latte 3.1. Latte auto-injects the current `Latte\Runtime\Template` instance into any custom function whose first parameter is typed `Runtime\Template`, so both are called with **no arguments** from within a template (`{getTemplate()}`, `{getTemplateName()}`) — Latte supplies the instance itself. `getTemplate()` is the raw escape hatch (returns the `Template` object as-is, for anything not covered by the second function). `getTemplateName(): string` is the common case: the path of the **originally-requested** template, relative to `templates/` — e.g. `getTemplateName() == "dashboard.latte"` or `getTemplateName() == "list/manage.latte"` — usable from inside `custom.latte`'s own blocks too, not just the entry template itself, so an operator can render different `custom_header`/`custom_head`/etc. content depending on which page is actually being shown (`{if getTemplateName() === 'dashboard.latte'}...{/if}`).

Implemented by walking `Template::getReferringTemplate()` to its root (`null` referrer) and stripping everything up to and including the last `/templates/` in `getName()`. Two things make this work reliably rather than by luck:
- `{layout}`/`{extends}` (how every page reaches `layout.latte`) does **not** create a new, separately-referenced `Template` instance — a `{block}` defined in the entry template (e.g. `dashboard.latte`'s own `content` block) still runs as that *same* `Template` object, so it's already at the chain's root with no walking needed.
- `{import}` (how `layout.latte` reaches `custom.latte`) **does** create a new instance, linked back via `getReferringTemplate()`/`getReferenceType() === 'import'` to whichever template imported it — walking that link is what lets code running *inside* `custom.latte` still find its way back to the actual entry template.

`getName()` returns the exact string a controller passed to `renderToString()` — every controller uses the same pattern, `__DIR__ . '/../../../templates/...'` (see e.g. `DashboardController::index()`, `ListController::manage()`), so the `..` segments stay in the string unresolved; taking everything after the *last* `/templates/` occurrence is what turns that into the clean relative form (`dashboard.latte`, `list/manage.latte`) regardless of how many `..`s precede it. Confirmed live (isolated Latte render, mirroring this exact controller path-construction pattern): `getTemplateName()` returned the identical value both from a block defined directly in the entry template and from `custom.latte`'s own imported block.

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

**Deep-link redirect-back** — unlike the magic-link flow (no "next" concept to hook into — it's deliberately interrupted, the user leaves the browser entirely to click a link in their mail client), OIDC *does* support returning to the originally-requested page, since the whole round trip to the IdP and back happens within one continuous browser session. Two call sites trigger it, both via the shared `Http\RequestPath::relativeTarget()` helper (current path + query string):
  - `AuthMiddleware` — every route behind it (`/`, `/{listname}`, `/_/api/...`). When it intercepts an unauthenticated request and `'oidc.enabled'` is true (constructor arg, wired in `public/index.php`), it skips `/_/login`'s form entirely and redirects straight to `/_/login/oidc?next={urlencoded current path+query}` — a user hitting a bookmarked/shared deep link (e.g. `/mylist`) goes directly to the IdP, never sees the login form, and lands back on `/mylist` after authenticating.
  - `ArchiveController::checkAccess()` — the archive viewer's `Members`/`Owners` routes sit behind `OptionalAuthMiddleware` instead (see "Archive access levels"), which never redirects on its own, so `AuthMiddleware`'s logic never ran for them; `checkAccess()` does the exact same OIDC-enabled check and 302 itself, in the one place a missing session is detected (`$email === null`), before ever falling back to the translated "please log in" page.

  Without OIDC configured, both fall back to their pre-existing behavior exactly as before (plain `/_/login` redirect / the login-required page) — the magic-link flow has nothing to attach a "next" to.

`AuthController::loginOidc()` carries `next` across the round trip the same way regardless of which of the two triggered it, via `$_SESSION['oidc_next']` — not a query param appended to the IdP's own authorization URL, since the IdP fully controls what it appends to its registered `redirect_uri` on the way back (no room for one of our own), whereas the session cookie survives the round trip for free (same browser, same `PHPSESSID`). Set only on the *initial* leg, only when a `next` param is actually present (a plain visit to `/_/login/oidc`, e.g. the login page's own SSO button, never sets it); read and cleared on the *callback* leg, falling back to `/` if absent — exactly the pre-existing behavior for a non-deep-link OIDC login. `AuthController::sanitizeNext()` is the gate: `next` ultimately originates from a query string an attacker fully controls (a crafted deep link to this app), so only a same-origin relative path is ever accepted — rejects an empty value, anything not starting with a single `/` (a full URL), a scheme-relative `//evil.example` (browsers resolve that as `https://evil.example`, not a path), a backslash-led `/\evil.example` (some browsers normalize `\` to `/`), and — as defense in depth on top of the prefix check — anything `parse_url()` can still extract a scheme or host from.

Setting `$_SESSION['oidc_next']` on the initial leg needs an explicit `session_start()`/`session_write_close()` around it, not a bare `$_SESSION[...] = ...`: `jumbojett/openid-connect-php`'s own `requestAuthorization()` calls its `commitSession()` (→ `session_write_close()`) right before redirecting to the IdP, to release the session lock before the browser leaves for what could be a slow round trip — by the time `OpenIdConnectService::authenticate()` returns the redirect URL to `loginOidc()`, the session is already closed. A plain `$_SESSION` write past that point only touches the in-memory superglobal and is silently lost — confirmed live (a deployment with Authelia configured): the session file on disk had `openid_connect_nonce`/`_state`/`_code_verifier` from the library's own commit, but no `oidc_next`, and the callback leg read back nothing. Re-opening (`session_start()`), writing, and closing again (`session_write_close()`) fixes it — the reopen reads the same file the library just wrote, so its keys survive alongside the new one.

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
segment — one requirement is that no list is ever named `_` (enforced fail-fast in
`ListConfig::__construct()`, see "ListConfig with property hooks").

`ListConfig::__construct()` also fail-fast rejects a list name containing anything outside
`[A-Za-z0-9_-]` (`ListConfig::VALID_NAME_PATTERN`) — a positive allowlist, not a blocklist of
specific bad characters. This exists specifically to keep a name from colliding with
`docker/nginx.conf`'s `location ~ \.php$ { return 404; }`: that rule matches on the URL path
alone, with no awareness of which names are actually configured lists, so a list literally named
e.g. `news.php` would have every one of its web routes (manage page, archive viewer, unsubscribe
link, moderation preview, List Management API) silently 404 at the nginx layer, before Slim ever
sees the request — while mail distribution over IMAP/SMTP (which never touches nginx) kept working
regardless, making the list look fine until someone actually clicked a generated link. Since every
provider constructs its lists through this one class, the check applies uniformly regardless of
where the name comes from (LDAP `cn`, a `config-table`/CSV/database row, a `list-providers`/`lists:`
YAML key).

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
| GET | `/{listname}/compose` | user | Form for a first mail to an external address — see "Masked reply addresses" |
| POST | `/_/api/compose/{listname}` | user | Issue the masked address for the entered recipient (returns a `mailto:` link) |
| GET | `/{listname}/moderation/{id}` | owner | Preview a still-pending mail — see "Preview: pending mail" |
| GET | `/{listname}/moderation/{id}/frame` | owner | Preview: sandboxed HTML body |
| GET | `/{listname}/moderation/{id}/attachment/{index}` | owner (or signed token) | Preview: attachment download/inline |
| GET | `/{listname}/bounce/{id}` | owner | Preview a bounce mail — see "Bounce preview" |
| GET | `/{listname}/bounce/{id}/frame` | owner | Preview: sandboxed HTML body |
| GET | `/{listname}/bounce/{id}/attachment/{index}` | owner (or signed token) | Preview: attachment download/inline |
| GET | `/_/api/queue/{listname}` | owner | Queue status |
| DELETE | `/_/api/queue/{id}` | owner | Delete failed entry |
| POST | `/_/api/queue/{id}/retry` | owner | Retry failed entry |
| DELETE | `/_/api/archive/{listname}/{id}` | owner | Permanently delete a single archived mail (IMAP + index) — see "Deleting an archived mail" |
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

Static assets (CSS/JS/images) live under `public/assets/` as plain files — `style.css`, `script.js`
plus per-page JS (`archive-index.js`, `archive-show.js`, `list-manage.js`), and `logo.svg`/
`logo-mark.svg` (see "App name (`app-name`)") — never routed through Slim at all. nginx
(`docker/nginx.conf`) has an explicit `location /assets/ { try_files $uri =404; }` block serving
these directly, and a fallback `location / { try_files $uri /index.php$is_args$args; }` that only
reaches the Slim front controller when no real file matches — so `public/assets/...` needs no
reserved-name carve-out of its own. `public/favicon.ico`/`.png`/`.svg` sit directly under `public/`
instead (outside `/assets/`) and are picked up the same way, via the `location /` fallback finding
the real file before it reaches `index.php` — only `favicon.ico` is actually referenced anywhere
(the browser's own default `/favicon.ico` request; `layout.latte` has no explicit `<link rel="icon">`
of its own, so an operator wanting the `.png`/`.svg` variant linked needs to add one via the
`custom_head` block, see "Custom layout"). Only `index.php` itself is ever passed to php-fpm
(`location = /index.php`); any other `.php` request is rejected with `404`
(`location ~ \.php$ { return 404; }` — see "Quiet 404/405 logging" for how that interacts with Slim's
own exception logging).

### Member dashboard (`/`)

Per subscribed list: mail address, display name (`display-name` || `cn`), description (`text`), "Unsubscribe" button if `AllowLeave::Direct` **and** `ListConfig::$supportsUnsubscribe` — the latter hides the button for a list whose member store can't actually persist a removal (static inline config.yml members, or none configured), instead of showing a button that would previously "succeed" without doing anything.

`DashboardController::index()` includes a list if the viewer is a member **or** an owner of it (`isMember() || isOwnedBy()`) — not just a member. An owner who isn't also a subscribed member (a valid setup — e.g. an LDAP group's `owner:` attribute need not overlap with its `member:` one) previously never appeared here at all, which meant `/{listname}` (the owner manage page) had no discoverable entry point anywhere in the UI for such an owner, not even via this dashboard — see "`/{listname}` — owner vs. non-owner view" below for the matching fix on the other end. Since that route now renders a reduced info page for a non-owner too rather than a 403 (see below), the card's own display name links to `/{listname}` for **every** list shown here (`$listLinks`), member or owner alike — not just owned ones (`$manageLinks`, the owner-only subset), which additionally gets a more prominent "Verwalten"/"Manage" button next to "Unsubscribe" (itself only offered when the viewer is actually a member — an owner-only entry has nothing to unsubscribe from). The archive link (when the list's archive mode makes it reachable at all) lives in the same button row as "Manage"/"Unsubscribe", not as a separate plain inline link.

### `/{listname}` — owner vs. non-owner view

`ListConfig::createContext()`'s `{list-url}` (`https://{hostname}/{list-name}`) is embedded in **every** distributed mail via `list-label`/footer/etc. and reaches every recipient, not just owners — so `ListController::manage()` cannot simply 403 a non-owner the way it used to. It now branches on `isOwnedBy()`:

A stale/mistyped list name at this exact URL is therefore routine, not an edge case — confirmed live: visiting `{list-url}` for a list that no longer exists returned a completely blank page (`(new Response())->withStatus(404)` — a bodyless response, not Slim's own styled "Not Found" page). Fixed by `throw`ing `Slim\Exception\HttpNotFoundException($request)` instead, the same exception an unmatched route already produces — this route is already behind `AuthMiddleware`, and unlike the archive viewer's own deliberate Hidden/Off masquerade (see "Archive viewer" — bare 404s there hide *whether an authenticated viewer has access*, a genuine privacy boundary), a nonexistent list name has nothing to hide, so there's no reason to withhold the normal, informative 404 page. `ArchiveController::index()`/`show()` had the identical bug for the same reason (their own `$list === null` check, which runs *before* `checkAccess()`'s own intentionally-silent 404s) and got the identical fix — `frame()`/`attachment()` deliberately keep their bare, bodyless 404s, since those are sub-resource endpoints (sandboxed-iframe content, a file download) with no HTML page expected either way. `BounceController`/`ModerationController`'s own `show()`/`frame()` (see "Bounce preview"/"Preview: pending mail") share one `loadOwnedItem()` helper each for the same item/list-not-found check, so the fix there is a `bool $notFoundAsException` parameter on that shared helper instead of a bare `throw`: `show()` passes `true` (a real page, gets the styled 404), `frame()` leaves it `false` (sandboxed iframe content, stays bare) — same distinction, just threaded through a shared helper both call.

- **Owner** → the full manage page (`templates/list/manage.latte`, unchanged): list address/display name/description, owners (firstname+lastname only, no email), member count only, moderation queue, queue status, bounce stats.
- **Non-owner** (still requires a session — this route stays behind `AuthMiddleware`, only the ownership check inside it changed) → `renderInfo()` renders `templates/list/index.latte` instead: display name, mail, description, owners, an archive link (only if `archive: public`, or `archive: members` **and** the viewer is actually a member — a non-member must not be handed a link that 401s), and an "Unsubscribe" button (only if the viewer is a member **and** `AllowLeave::Direct` **and** `$supportsUnsubscribe` — the exact same three-part gate `DashboardController` already uses for the same list). No moderation/queue/bounce data is ever computed or passed to this branch at all, not just hidden in the template — `getModerationItems()`/`getQueueStatus()`/`getBounceStats()` are only ever called in the owner branch.

Both views render each owner via `ListConfig::resolveMemberDisplayName()`, `trim("$firstname $lastname") ?: $member->email` — not just `"$firstname $lastname"`, and resolved with `quiet: true` (see `VariableResolver::resolve()`'s own docblock) so a member with neither attribute doesn't spam the log. An owner added via a bare-string `owners:` entry at global/provider/list level (see "Global / provider / list levels") carries no attributes at all, so `{firstname}`/`{lastname}` always resolve empty for it — expected, routine, and not worth logging, unlike a genuinely misconfigured alias elsewhere. Falling back to the member's own email — always present — guarantees *something* recognizable instead of blank space, regardless of which source added the owner. (An LDAP-backed member/owner, by contrast, resolves `{firstname}`/`{lastname}` directly from its own attributes now — see `LdapMemberResolver::entryToMember()`'s `givenName`/`sn` fallback below — so this empty-attributes case is specific to non-LDAP/bare-string sources, not LDAP-backed lists in general anymore.)

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
- **Slim's own `$displayErrorDetails` is a separate flag from `display_errors`, and must independently stay `false` in production.** `public/index.php`'s `$app->addErrorMiddleware($displayErrorDetails, $logErrors, $logErrorDetails)` controls whether Slim's *own* exception handler puts the caught exception's type/message/file/line/stack trace into the HTTP *response body* — entirely independent of php.ini, since Slim catches the exception itself before it would ever become a raw PHP error. Confirmed live as a real leak: an automated `GET /.git/HEAD` scan happened to path-match the `{listname}/{mail}` route (registered `PUT`/`DELETE` only, see "Routes" — any two-segment path scanners commonly probe, `/wp-admin/x`, `/.env/y`, etc., matches the same way), producing a `405` whose response body — sent to that anonymous, unauthenticated request — included `/app/vendor/slim/slim/Slim/Middleware/RoutingMiddleware.php` and a full call stack. Fixed by passing `false` for `$displayErrorDetails` while leaving `$logErrors`/`$logErrorDetails` `true` — the exact same "log everything server-side, show the client nothing" split `display_errors=Off`/`log_errors=On` already establishes for PHP-level errors, just Slim's own independent equivalent of it. Confirmed live after the fix: the same request now returns a generic `405 Method Not Allowed` page with no file paths or trace, while `docker logs` still shows the full detail.
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
- **`SpamFilter::match()`** — one line per matched `filters:` rule (list-scoped level): the rule's 1-based position among `filters:` entries (not the internal 0-based array index — matches how an operator would refer to "the third rule" in their own `filters.yml`), its `action`, and every condition that matched with the *resolved* pattern it was actually compared against (post-`{}`-substitution, not the raw config text) — e.g. `Listig: filters: rule #2 matched (action: discard) — subject: "spam", from: "MAILER-DAEMON@hengeb.de"`. Nothing is logged when no rule matches at all.

Registered in `config/container.php`: `'app.log-level'` (the global default string) and `Logger::class` (constructed from it via `LogLevel::fromString()`), injected into `AuthController`, `ImapPoller`, `MailProcessor`, and `SpamFilter` alongside their existing dependencies.

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

### Making clear which mail a reject/pending notice is about

`RejectionNotifier::notify(ListConfig $list, IncomingMail $mail, ?string $rawMime, string $reasonKey, array $reasonParams = [])`
takes the `IncomingMail` itself (not just the sender's bare address, as before) and the raw
MIME — `reject.notice.body` includes `%subject%`/`%date%` (same fields, same fallback for a
missing/unparseable `Date` header, as `ModerationMailer`'s own metadata — see "Moderation"),
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
- **Moderated** (`ModerationMailer::send()`'s `pending_notice`, see "Moderation") — reuses the
  exact same `$mail`/`$rawMime`/`$mailDate` it already computed for the owners' own copy above
  it in the same method, no extra IMAP fetch needed.
- **Moderation declined** (`ModerationResponseHandler::processReject()` and
  `ModerationController::reject()`, both `reject.moderation_declined` via the same
  `RejectionNotifier`) — neither originally fetched the raw MIME (only the parsed
  `IncomingMail`, for the sender's address); both now also call `ImapPoller::fetchByUid()`
  for it, best-effort — a `null` result (mail gone from IMAP between the two fetches) still
  sends the notice, just without the attachment, rather than blocking it entirely.

---

## Testing

`tests/` (PHPUnit, `require-dev`-only — never installed in the production image, see "Docker Setup"; `docker/Dockerfile` already runs `composer install --no-dev`, and `.dockerignore`/host-side `vendor/` isolation means a dev install on the host can never leak into a build either way) mirrors `src/`'s namespace under `Hengeb\Listig\Tests\` (`composer.json`'s `autoload-dev`). Run via `composer test` (aliases to `phpunit`, config in `phpunit.xml`) or `vendor/bin/phpunit` directly; a single file/directory can be targeted the normal PHPUnit way (`vendor/bin/phpunit tests/Config/ListConfigTest.php`).

Scope is deliberately the **pure-logic layer** — classes that don't touch IMAP/LDAP/SQL/SMTP directly and so need no live infrastructure or mocking framework beyond PHPUnit's own stubs: `VariableResolver`/`VariableFilter`, `ConfigResolver`, `ListConfig`, `RestrictionList`, `YamlIncludeResolver`, the `MemberResolver` implementations that don't need a live connection (`InlineMemberResolver`, `CompositeMemberResolver`, `CsvMemberResolver` against a real temp file, `LdapMemberResolver::entryToMember()` — a pure transformation testable against a fake `Symfony\Component\Ldap\Entry`, no LDAP connection ever opened), `MemberResolverFactory`, `SpamFilter`, `SpamRejectionDetector`, `HeaderFilter`, `SubaddressExtractor`, `FilterResult`, `TokenService`, `ListFingerprint`, `PasswordCrypto`, `KeyDerivation`, `ArchiveThreader`, `ByteFormatter`, `AttachmentSafety`, `NullSenderEnvelope`, `BounceCauseClassifier`, `Member\InvalidatedEmail`. Deliberately **not** covered: anything requiring a real IMAP/LDAP/SMTP/DB connection (`ImapPoller`, `ImapArchiver`, `LdapListProvider`/`DatabaseListProvider`'s own query methods, `QueueSender`, `ModerationMailer`, `BounceSuppressionList`, `BounceMemberActionExecutor`, `BounceHandler` itself, ...) or a full Slim HTTP request/response cycle (the `Http\Controller\*` classes) — those are verified the way the rest of this document describes: patched onto the live test instance (`docker cp`, worker/php-fpm restart, health check, then a targeted one-off script or real request against actual LDAP/DB/IMAP) rather than through this suite. `LdapMemberResolver::invalidateEmail()`/`removeMember()`/`addMember()` remain untested here too, for the same reason `entryToMember()` is the *only* piece of that class covered — they all need a real `connect()`'d LDAP session.

A `Reflection*` escape hatch (no `setAccessible(true)` — a no-op since PHP 8.1, and itself deprecated as of 8.5, see below) is used sparingly, only where a class genuinely has no other way to set up a fixture: `PhpImap\IncomingMail::$textPlain`/`$textHtml` are private with a lazy `__get()` that fetches from a live IMAP data part and no public setter at all, so `SpamFilterTest` seeds a fixed body via `new \ReflectionProperty($mail, 'textPlain')`. `LdapMemberResolverTest` calls the private `entryToMember()` directly via `ReflectionMethod`, since it's the one pure-transformation piece of an otherwise LDAP-connected class.

Writing this suite surfaced a few small, real issues in `src/` along the way (not test-authoring mistakes) — fixed as part of adding the tests, not left for later: `CsvMemberResolver`'s `fgetcsv()`/`fputcsv()` calls omitted PHP 8.5's newly-required `$escape` parameter (deprecated, a future version changes the default) — now passed explicitly (`self::CSV_ESCAPE = '\\'`, matching today's actual default byte-for-byte) at all four call sites. `YamlIncludeResolver::parseFile()`'s `file_get_contents()` emitted a native PHP warning on a missing file even though the very next line already checks for `=== false` and converts it into a clean `\RuntimeException` — `@`-suppressed to match the same "check the return value, don't let the native warning leak" convention already used elsewhere (e.g. `SpamFilter`'s `@preg_match`, `AttachmentSafety`'s `@getimagesizefromstring`).

**A test that deliberately exercises an `error_log()` call must declare `$this->expectErrorLog();`.** PHPUnit 12's `TestCase` redirects the `error_log` ini setting to a private per-test capture file before every test and, in teardown, either asserts that capture is non-empty (if `expectErrorLog()` was called) or — if it wasn't, and something was captured anyway — prints the raw captured text straight to the console, interleaved with the progress dots. A project-wide `<ini name="error_log" value="/dev/null"/>` in `phpunit.xml` does **not** fix this: PHPUnit's own per-test redirect overrides it regardless (confirmed live — `ini_get('error_log')` inside a test returns PHPUnit's own temp path, never the configured one), so the only correct fix is calling `expectErrorLog()` in each test that intentionally triggers logging (`VariableResolverTest`'s not-found/cycle/blocked-key cases, `VariableFilterTest`'s unknown-filter case, ...) — never a leading `@` on the call under test, which suppresses PHP errors/warnings but has no effect on `error_log()` itself. A test whose whole point is proving something *stays silent* (e.g. `quiet: true`) should deliberately omit the call instead — if suppression ever broke, PHPUnit's own unexpected-output print would surface it.

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
