# Project structure

Annotated directory tree.

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
│   ├── favicon.ico / favicon.png / favicon.svg # served statically; only favicon.ico is actually picked up (browser default convention — no <link rel="icon"> in layout.latte), see "Routes" (docs/reference/routes.md)
│   └── assets/                       # served directly by nginx (location /assets/), never routed through Slim — see "Routes" (docs/reference/routes.md)
│       ├── style.css
│       ├── script.js                 # shared JS loaded on every page (getCsrfToken(), listigLogout()) — see "Static assets" (docs/architecture/web-ui.md)
│       ├── archive-index.js          # templates/archive/index.latte's client-side thread toggle/quick filter — see "Threading"
│       ├── archive-show.js           # templates/archive/show.latte's image-toggle/HTML-text-toggle/delete button — see "Archive viewer" (docs/architecture/archive.md)
│       ├── dom-morph.js              # listigMorph(): patches a container to new HTML node by node (keeps unchanged nodes) — used by list-manage.js's live refresh, see "Manage page live refresh" (docs/architecture/web-ui.md)
│       ├── list-manage.js            # templates/list/manage.latte's moderation accept/reject — see "Moderation via UI" (docs/architecture/moderation.md)
│       ├── compose.js                # templates/compose.latte's address request + mailto redirect
│       ├── logo.svg                  # full wordmark
│       └── logo-mark.svg             # icon only, no baked-in text — see "App name (`app-name`)" (docs/architecture/web-ui.md)
├── src/
│   ├── Imap/
│   │   ├── ImapPoller.php            # Polls IMAP via PhpImap\Mailbox; explicitly re-selects INBOX first (see "IMAP connection reuse across worker cycles" (docs/architecture/worker-and-queue.md)); checks UIDVALIDITY; returns (uid, uidvalidity, mime, mail: IncomingMail) tuples
│   │   ├── ImapArchiver.php          # Archives or deletes processed mails; deletes inbox mails older than 30 days; prunes archived mail per-list archive-max-age — see "Archive retention" (docs/architecture/archive.md)
│   │   └── ImapMailboxFactory.php    # Builds/caches PhpImap\Mailbox connections per list, keyed by imap-* fingerprint, surviving across worker cycles via a hasImapStream() liveness check — see "IMAP connection reuse across worker cycles" (docs/architecture/worker-and-queue.md); also computes absolute (top-level) IMAP folder paths — see "Archive folder path" (docs/architecture/archive.md)
│   ├── Archive/                      # Web archive viewer backend — see "Archive viewer" (docs/architecture/archive.md)
│   │   ├── ArchiveIndexer.php        # Writes archived_mail rows; called alongside (not from) ImapArchiver::archiveOrDelete()
│   │   ├── ArchiveSynchronizer.php   # Proactive reconciliation on opening the archive index, throttled per list per session — see "Proactive sync on opening the archive"
│   │   ├── ArchiveThreader.php       # Pure PHP: annotates a page of rows with depth/thread_size/is_thread_start
│   │   ├── ArchiveMailLocator.php    # Re-locates a message by Message-ID in the list's IMAP archive folder ($archiveFolder), on demand
│   │   ├── ArchiveMailNotFoundException.php # Thrown by ArchiveMailLocator::find() only after a full, successful SEARCH ALL scan confirms the mail is genuinely gone
│   │   ├── ArchiveMailResolver.php   # Locate-by-Message-ID + eager attachment-content caching, extracted so BounceController can reuse it — see "Bounce preview" (docs/architecture/bounces.md)
│   │   ├── ArchiveMailCache.php      # APCu cache of a fully-resolved archived mail, keyed by list+Message-ID — see "Archive mail cache — performance" (docs/architecture/archive.md)
│   │   ├── AttachmentSafety.php      # isSafeInlineContent() magic-byte check + sanitizeFilename(), extracted so ModerationController can reuse it too
│   │   ├── CachedArchivedMail.php    # Serializable snapshot of an IncomingMail — textHtml/textPlain + CachedAttachment[]
│   │   ├── CachedAttachment.php      # Serializable snapshot of an IncomingMailAttachment, contents eagerly resolved
│   │   ├── ArchiveHtmlSanitizer.php  # HTMLPurifier config + cid: rewriting + external-resource gating
│   │   └── ByteFormatter.php         # Shared B/KB/MB/GB/TB formatting — PHP (ArchiveController) and the `formatBytes` Latte filter both use it
│   ├── Mail/
│   │   ├── MailProcessor.php         # Builds outgoing Email from IncomingMail; personalizes per recipient; enqueues
│   │   ├── BounceHandler.php         # Detects + forwards a bounce to the list's owners as multipart/mixed; resolves+authenticates the per-recipient bounce token before any automatic action — see "Bounce notice details" (docs/architecture/bounces.md) / "Bounce loop prevention" / "Automatic bounce actions"
│   │   ├── BounceCause.php           # Plain enum: bounce reasons an automatic action exists for (Spam, UserUnknown, MailboxFull), see "Automatic bounce actions" (docs/architecture/bounces.md)
│   │   ├── BounceCauseClassifier.php # Pure text classification of an already-authenticated bounce's reason into a BounceCause, or null — see "Automatic bounce actions" (docs/architecture/bounces.md)
│   │   ├── BounceMemberActionExecutor.php # Executes mark-invalid/restrict/remove for BounceHandler — see "Automatic bounce actions" (docs/architecture/bounces.md)
│   │   ├── BounceSuppressionList.php # DB-backed `restrict` bounce-action storage (bounce_suppressed_members), independent of any ListProvider — see "Automatic bounce actions" (docs/architecture/bounces.md)
│   │   ├── HeaderFilter.php          # Reads Authentication-Results / arbitrary headers (readHeader) from raw header string
│   │   ├── IncomingMailFilter.php    # Gates incoming mail (takes IncomingMail); returns FilterResult — see "IncomingMailFilter — check order" (docs/architecture/mail-processing.md)
│   │   ├── FilterResult.php          # final class (not enum — needs per-instance reason string): discard | bounce | reject | moderation | distribute
│   │   ├── NotificationMailer.php    # Shared helper for every system notification (owner notices, pending-moderation notice to the sender, ...) — see "Moderation" (docs/architecture/moderation.md); sends every notification via NullSenderEnvelope + X-Listig-Auto/Auto-Submitted — see "Bounce loop prevention" (docs/architecture/bounces.md)
│   │   ├── NullSenderEnvelope.php    # Envelope with MAIL FROM:<> (RFC 5321 null reverse-path), via Reflection — see "Bounce loop prevention" (docs/architecture/bounces.md)
│   │   ├── ReplyThreadStore.php      # `+re-` tag of the archive's "reply" button: issues/resolves signed tokens over archived_mail.id (ADR-0020)
│   │   ├── SenderNoticePolicy.php    # Single decision point: notice to the sender yes/no, with/without original (ADR-0018)
│   │   ├── SenderAuthenticator.php   # DMARC-aligned authentication of the From address from the trusted Authentication-Results
│   │   ├── OrganizationalDomain.php  # Organizational domain heuristic for relaxed alignment (no PSL)
│   │   ├── AuthResultsHeader.php     # Parsed Authentication-Results header (RFC 8601)
│   │   ├── NoticeDecision.php        # Result of SenderNoticePolicy::decide()
│   │   ├── RejectionNotifier.php     # Sender-facing reject notice for every reject.* reason, with the original mail attached — see "Making clear which mail a reject/pending notice is about" (docs/architecture/mail-processing.md)
│   │   ├── ProcessingFailureTracker.php  # DB-backed per-mail attempt counter, bounds bin/worker.php's retry loop — see "Processing-failure retry limit" (docs/architecture/worker-and-queue.md)
│   │   ├── ProcessingFailureNotifier.php # Owner-facing "mail could not be processed after N attempts" notice, original mail attached — see "Processing-failure retry limit" (docs/architecture/worker-and-queue.md)
│   │   ├── ReplyTarget.php           # Value object: resolved recipient behind a `+r-` address
│   │   ├── ReplyTargetStore.php      # Creates/resolves the per-list `+r-{TOKEN}` addresses of the masked reply-to modes — see "Masked reply addresses" (docs/architecture/masked-replies.md)
│   │   ├── SpamFilter.php            # Global content filter from filters: in config.yml; matches subject/body/from/to via str_contains or /regex/
│   │   ├── BodyPersonalizer.php      # Replaces variables in decoded body/subject via VariableResolver
│   │   ├── FooterAppender.php        # Appends footer to symfony/mime object (always if configured)
│   │   └── SubaddressExtractor.php   # Extracts the +subaddress from an incoming mail's To/Cc relative to list->mail; used by IncomingMailFilter and MailProcessor for type: subaddress lists
│   ├── Variable/
│   │   ├── VariableResolver.php      # Static helper; VariableResolver::resolve($template, $contexts, $purpose)
│   │   ├── ResolutionPurpose.php     # Trusted | Disclosed — gates VariableResolver::BLOCKED_KEYS at resolution time; see "ResolutionPurpose" (docs/architecture/variables.md)
│   │   ├── VariableFilter.php        # Applies |filter:args pipeline segments (match, lowercase, uppercase) to a resolved variable value
│   │   └── Literal.php               # Marks a context value terminal (never recursively re-resolved) — wraps sender/recipient/Member data; see "Untrusted input in {} templates"
│   ├── Config/
│   │   ├── ListConfig.php            # Typed value object; property hooks; holds MemberResolver; createContext() for resolution; validates $name — see "Routes" (docs/reference/routes.md)
│   │   ├── ConfigResolver.php        # Merges config.yml blocks: use:, priority, $VAR substitution; also parses root lists:/restricted-members:/the global level of members:/owners:/member-resolver:/owner-resolver:/senders: — see "Global / provider / list levels" (docs/architecture/config.md)
│   │   ├── RestrictionList.php       # Sender restrictions (send/receive) — one instance built per list from its own global+provider+list levels — see "Sender restrictions" (docs/architecture/providers-and-members.md)
│   │   ├── YamlIncludeResolver.php   # Resolves !include tags (see "File includes" (docs/architecture/config.md)) for config.yml and YamlListProvider files
│   │   └── Enum/
│   │       ├── ReplyToBehavior.php   # 'list' | 'sender' | 'both' | 'nobody' | 'masked-sender' | 'masked-both' — see "Masked reply addresses" (docs/architecture/masked-replies.md)
│   │       ├── JoinPolicy.php        # 'open' | 'invite' | 'request' — join-policy, see "Visibility and join policy" (docs/architecture/web-ui.md)
│   │       ├── Visibility.php        # 'public' | 'members' | 'hidden' — visibility, same section
│   │       ├── PostAccess.php        # 'allow' | 'deny' | 'moderate' — used for both post-access-members and post-access-public
│   │       ├── AllowLeave.php        # 'direct' | 'moderated'
│   │       ├── ArchiveMode.php       # 'members' | 'owners' | 'public' | 'hidden' | 'off'
│   │       ├── SenderNotices.php     # 'authenticated' | 'always' | 'never' — see "Sender notices" (docs/architecture/mail-processing.md)
│   │       ├── SenderAddressHeader.php # 'never' | 'external' | 'always' — see "Masked reply addresses" (docs/architecture/masked-replies.md)
│   │       └── BounceAction.php      # 'none' | 'mark-invalid' | 'restrict' | 'remove' — see "Automatic bounce actions" (docs/architecture/bounces.md)
│   ├── Member/
│   │   ├── Member.php                # Value object: email (required) + attributes (everything else, fully dynamic per resolver — see "Member attributes — fully dynamic" (docs/architecture/providers-and-members.md))
│   │   ├── MemberResolver.php        # Interface: getMembers(), getOwners(), findByEmail(), removeMember()
│   │   ├── MemberResolverFactory.php # Builds member-resolver source(s) (type: database/ldap/csv, single or composable list) and composes all three levels into one resolver — see "Global / provider / list levels" (docs/architecture/config.md)
│   │   ├── CompositeMemberResolver.php # Combines multiple independent MemberResolver sources (any level) for one list — see "Global / provider / list levels" (docs/architecture/config.md)
│   │   ├── NullMemberResolver.php    # No-op implementation
│   │   ├── InlineMemberResolver.php  # Resolves from inline config.yml member lists (plain "mail@x" string or firstname/lastname/mail/username map); removeMember is no-op
│   │   ├── LdapMemberResolver.php    # Resolves via LDAP DNs; removeMember removes DN from member attribute
│   │   ├── DatabaseMemberResolver.php # SELECT * from MariaDB members-table, any non-reserved column becomes an attribute; removeMember sets is_member = 0, then deletes row if no longer member or owner
│   │   ├── CsvMemberResolver.php      # Resolves via a shared flat CSV file (name,mail,is_member,is_owner reserved, any other column an attribute); re-reads per call, flock on write, addMember extends the header on demand
│   │   ├── AggregateMemberResolver.php # Searches all providers; used by AuthController
│   │   └── InvalidatedEmail.php       # Builds the `.BOUNCE_{reason}.{date}.invalid` placeholder for the `mark-invalid` bounce action — see "Automatic bounce actions" (docs/architecture/bounces.md)
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
│   │   └── MigrationRunner.php       # Applies pending migrations/*.sql, tracked in schema_migrations — see "Database migrations" (docs/reference/database-schema.md)
│   ├── Smtp/
│   │   └── SmtpConnectionFactory.php # Creates/caches symfony/mailer transports per SMTP config fingerprint;
│   │                                 # closes and reopens connection when smtp-host/port/user/secure changes
│   ├── Moderation/
│   │   ├── ModerationMailer.php      # Sends moderation-request mail to owners
│   │   ├── ModerationChecker.php     # Checks DB for overdue moderation items, sends reminders
│   │   └── ModerationResponseHandler.php # Detects +accept-/+reject- in To (raw header, not lowercased $mail->to), verifies HMAC + owner, dispatches accept/reject — see "Moderation" (docs/architecture/moderation.md)
│   ├── Token/
│   │   ├── TokenService.php          # Signs and verifies truncated-HMAC-SHA256 tokens, compact binary payload — see "Token Format" (docs/architecture/security-and-tokens.md)
│   │   └── ListFingerprint.php       # Short, non-cryptographic list-name fingerprint for bounce/accept/reject tokens — see "Token Format" (docs/architecture/security-and-tokens.md)
│   ├── OpenIdConnect/                # Optional OIDC login — see "Authentication (OIDC)" (docs/architecture/web-ui.md)
│   │   ├── OpenIdConnectService.php  # Thin wrapper around jumbojett/openid-connect-php (Auth Code + PKCE)
│   │   └── OidcRedirectException.php # Turns the library's header()+exit redirect into a catchable PSR-7-friendly exception
│   ├── Crypto/
│   │   ├── KeyDerivation.php          # Static helper: HKDF-SHA256 subkeys from APP_SECRET, one per purpose
│   │   └── PasswordCrypto.php         # AES-256-CBC encrypt/decrypt for IMAP/SMTP passwords
│   ├── Queue/
│   │   ├── QueueWriter.php           # Stores mail + recipients in DB; takes a batch_id (see mail_queue schema)
│   │   ├── QueueSender.php           # Reads queue; uses SmtpConnectionFactory + TokenService (per-recipient signed bounce address); handles retries; discards spam-rejected batches — see "Sending batch" (docs/architecture/worker-and-queue.md) / "Automatic bounce actions"
│   │   └── SpamRejectionDetector.php # Trusted-provider SMTP "rejected as spam" detection — see "Sending batch" (docs/architecture/worker-and-queue.md); isReliableDomain()/containsSpamIndicator() also reused by BounceHandler's own origin-authentication gate
│   ├── RateLimit/
│   │   └── RateLimiter.php           # Per-sender and global rate limiting (MariaDB-backed)
│   ├── Logging/
│   │   ├── Logger.php                # Level-gated debug() wrapper around error_log() — see "Debug logging" (docs/architecture/logging.md)
│   │   └── LogLevel.php              # Debug < Info < Warning < Error enum, backs Logger's threshold comparison
│   └── Http/
│       ├── ListActions.php       # Single decision point for the per-list buttons (Info/Manage, Archive, Write, external mail, Unsubscribe) — see "List action buttons" (docs/architecture/web-ui.md)
│       ├── ListNavigation.php    # Result of ListActions::forViewer(): the buttons + whether the viewer may post
│       ├── Controller/
│       │   ├── AuthController.php        # Magic-link login flow, optional OIDC login, logout
│       │   ├── DashboardController.php   # Member view: subscribed lists
│       │   ├── ComposeController.php     # First-mail-to-external form + masked address issuing — see "Masked reply addresses" (docs/architecture/masked-replies.md)
│       │   ├── ListController.php        # Owner manage page
│       │   ├── JoinController.php        # POST /_/api/join/{listname}: the "Join" button of join-policy: open lists — see "Visibility and join policy" (docs/architecture/web-ui.md)
│       │   ├── ListApiController.php     # Bearer-token list management API: subscribe/unsubscribe/encrypt-password
│       │   ├── ModerationController.php  # Accept/reject moderation items via API; preview a still-pending mail — see "Preview: pending mail" (docs/architecture/moderation.md)
│       │   ├── BounceController.php      # Preview a bounce mail (show/frame/attachment), located by Message-ID like the archive viewer — see "Bounce preview" (docs/architecture/bounces.md)
│       │   ├── QueueController.php       # Queue status API
│       │   ├── UnsubscribeController.php
│       │   └── ArchiveController.php     # Archive viewer: index/show/frame/attachment — see "Archive viewer" (docs/architecture/archive.md)
│       ├── Middleware/
│       │   ├── AuthMiddleware.php        # Validates session, injects user identity, redirects to /_/login if absent
│       │   ├── OptionalAuthMiddleware.php # Like AuthMiddleware but never redirects — see "Archive viewer" (docs/architecture/archive.md)
│       │   ├── CsrfMiddleware.php        # Validates X-CSRF-Token on state-changing requests
│       │   └── ApiTokenMiddleware.php    # Validates Bearer token against ListConfig::$apiToken
│       ├── RequestPath.php               # relativeTarget() helper shared by AuthMiddleware/ArchiveController for the OIDC deep-link "next" redirect — see "Deep-link redirect-back" (docs/architecture/web-ui.md)
│       └── QuietBotNoiseErrorHandler.php # Suppresses the verbose exception log for a plain 404 or 405 — see "Quiet 404/405 logging" (docs/architecture/deployment.md)
├── templates/
│   ├── layout.latte           # Optionally imports /app/config/custom.latte (operator-mounted, not part of this tree) — see "Custom layout" (docs/architecture/web-ui.md)
│   ├── login.latte
│   ├── compose.latte          # see "Masked reply addresses" (docs/architecture/masked-replies.md)
│   ├── list-actions.latte     # Button row of one list, included by every list page (dashboard, list/*, archive/*)
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
│   ├── 001_initial.sql        # includes archived_mail — see "Archive viewer" (docs/architecture/archive.md); applied automatically, see "Database migrations" (docs/reference/database-schema.md)
│   ├── 002_moderation_queue_mail_metadata.sql # adds subject/sender_name/sender_mail/mail_date to moderation_queue, not backfilled
│   ├── 003_bounce_log_message_id.sql # adds message_id to bounce_log, not backfilled — see "Bounce preview" (docs/architecture/bounces.md)
│   ├── 004_processing_failures.sql   # new processing_failures table — see "Processing-failure retry limit" (docs/architecture/worker-and-queue.md)
│   ├── 005_archived_mail_sender_local_part.sql # adds sender_local_part to archived_mail, not backfilled — see "Archive viewer" (docs/architecture/archive.md) Privacy
│   ├── 006_bounce_auto_actions.sql # adds queue_recipients.retry_not_before + bounce_suppressed_members table — see "Automatic bounce actions" (docs/architecture/bounces.md)
│   └── 007_reply_targets.sql      # reply_targets table — see "Masked reply addresses" (docs/architecture/masked-replies.md)
├── docker/
│   ├── Dockerfile             # php-fpm + nginx + worker, all in one image
│   ├── entrypoint.sh          # ENTRYPOINT: runs bin/migrate.php, then execs CMD (supervisord)
│   ├── compose.yaml           # Dev/build-from-source compose file
│   ├── nginx.conf             # proxies to 127.0.0.1:9000 (same container)
│   ├── php-fpm-pool.conf      # zz-listig.conf override — disables php-fpm's own access log — see "Access logging" (docs/architecture/deployment.md)
│   ├── supervisord.conf       # manages php-fpm, nginx, worker as three processes
│   └── php.ini                # display_errors=Off/log_errors=On — see "Security Notes" (docs/architecture/security-and-tokens.md)
├── deploy/                    # Simplest deployment: published image + MariaDB, no repo checkout — see "Docker Setup" (docs/architecture/deployment.md)
│   ├── compose.yml.example    # Flat layout — config.yml mounted from the same directory, no config/ subfolder
│   ├── .env.example
│   └── config.yml.example     # Single source of truth for the config.yml template — also used by "Building from source"
├── docs/                      # Architecture notes, references, ADRs — see CLAUDE.md for the index
├── tests/                     # PHPUnit, require-dev only — see "Testing" (docs/architecture/testing.md). Mirrors src/'s namespace under Hengeb\Listig\Tests\
├── phpunit.xml
├── phpstan.neon                    # PHPStan level 5; phpstan-baseline.neon holds the findings accepted at introduction
├── .github/workflows/ci.yml        # tests + static analysis, then build/publish — see Deployment "CI"
├── LICENSE
├── README.md
└── composer.json
```

---
