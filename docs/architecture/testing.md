# Testing

Test scope, conventions and live verification.

## Testing

`tests/` (PHPUnit, `require-dev`-only — never installed in the production image, see [Docker Setup](deployment.md#docker-setup); `docker/Dockerfile` already runs `composer install --no-dev`, and `.dockerignore`/host-side `vendor/` isolation means a dev install on the host can never leak into a build either way) mirrors `src/`'s namespace under `Hengeb\Listig\Tests\` (`composer.json`'s `autoload-dev`). Run via `composer test` (aliases to `phpunit`, config in `phpunit.xml`) or `vendor/bin/phpunit` directly; a single file/directory can be targeted the normal PHPUnit way (`vendor/bin/phpunit tests/Config/ListConfigTest.php`).

Scope is deliberately the **pure-logic layer** — classes that don't touch IMAP/LDAP/SQL/SMTP directly and so need no live infrastructure or mocking framework beyond PHPUnit's own stubs: `VariableResolver`/`VariableFilter`, `ConfigResolver`, `ListConfig`, `RestrictionList`, `YamlIncludeResolver`, the `MemberResolver` implementations that don't need a live connection (`InlineMemberResolver`, `CompositeMemberResolver`, `CsvMemberResolver` against a real temp file, `LdapMemberResolver::entryToMember()` — a pure transformation testable against a fake `Symfony\Component\Ldap\Entry`, no LDAP connection ever opened), `MemberResolverFactory`, `SpamFilter`, `SpamRejectionDetector`, `HeaderFilter`, `SubaddressExtractor`, `FilterResult`, `TokenService`, `ListFingerprint`, `PasswordCrypto`, `KeyDerivation`, `ArchiveThreader`, `ByteFormatter`, `AttachmentSafety`, `NullSenderEnvelope`, `BounceCauseClassifier`, `Member\InvalidatedEmail`, `IncomingMailFilter` (with stubbed `RateLimiter`/`ReplyTargetStore`). Deliberately **not** covered: anything requiring a real IMAP/LDAP/SMTP/DB connection (`ImapPoller`, `ImapArchiver`, `LdapListProvider`/`DatabaseListProvider`'s own query methods, `QueueSender`, `ReplyTargetStore` (MySQL-specific upsert), `ModerationMailer`, `BounceSuppressionList`, `BounceMemberActionExecutor`, `BounceHandler` itself, ...) or a full Slim HTTP request/response cycle (the `Http\Controller\*` classes) — those are verified the way the rest of this document describes: patched onto the live test instance (`docker cp`, worker/php-fpm restart, health check, then a targeted one-off script or real request against actual LDAP/DB/IMAP) rather than through this suite. `LdapMemberResolver::invalidateEmail()`/`removeMember()`/`addMember()` remain untested here too, for the same reason `entryToMember()` is the *only* piece of that class covered — they all need a real `connect()`'d LDAP session.

A `Reflection*` escape hatch (no `setAccessible(true)` — a no-op since PHP 8.1, and itself deprecated as of 8.5, see below) is used sparingly, only where a class genuinely has no other way to set up a fixture: `PhpImap\IncomingMail::$textPlain`/`$textHtml` are private with a lazy `__get()` that fetches from a live IMAP data part and no public setter at all, so `SpamFilterTest` seeds a fixed body via `new \ReflectionProperty($mail, 'textPlain')`. `LdapMemberResolverTest` calls the private `entryToMember()` directly via `ReflectionMethod`, since it's the one pure-transformation piece of an otherwise LDAP-connected class.

Writing this suite surfaced a few small, real issues in `src/` along the way (not test-authoring mistakes) — fixed as part of adding the tests, not left for later: `CsvMemberResolver`'s `fgetcsv()`/`fputcsv()` calls omitted PHP 8.5's newly-required `$escape` parameter (deprecated, a future version changes the default) — now passed explicitly (`self::CSV_ESCAPE = '\\'`, matching today's actual default byte-for-byte) at all four call sites. `YamlIncludeResolver::parseFile()`'s `file_get_contents()` emitted a native PHP warning on a missing file even though the very next line already checks for `=== false` and converts it into a clean `\RuntimeException` — `@`-suppressed to match the same "check the return value, don't let the native warning leak" convention already used elsewhere (e.g. `SpamFilter`'s `@preg_match`, `AttachmentSafety`'s `@getimagesizefromstring`).

**A test that deliberately exercises an `error_log()` call must declare `$this->expectErrorLog();`** — see [PHPUnit 12 and `error_log()`](../library-notes.md#phpunit-12-tests-that-trigger-error_log-must-call-expecterrorlog).


## Live verification

Everything that needs real LDAP/IMAP/SMTP/DB is verified on a running container instead of in the suite:

1. Copy the changed files with `docker cp` (loop over `git status --short` with `while read f`; in zsh an unquoted `$files` variable is *not* word-split).
2. Run `php bin/migrate.php` inside the container, then restart the processes: `supervisorctl -c /etc/supervisor/supervisord.conf restart worker php-fpm`.
3. Check `/_/health` and `docker logs`.
4. Exercise the change with a one-off PHP script (`docker cp` it into the container, `php /tmp/x.php`, delete it afterwards). For code that enqueues mail, substitute a capturing `QueueWriter` subclass so nothing is actually sent, and delete any rows the script created.

Rules learned the hard way:

- **Run one-off scripts as `docker exec -u www-data`.** As root they compile Latte templates into `/tmp/latte` owned by root; php-fpm (`www-data`) then fails with `Latte\RuntimeException: Unable to create file '/tmp/latte/…lock'` and the whole web UI returns errors. If it happens: delete the root-owned files in `/tmp/latte` and `chown -R www-data:www-data /tmp/latte`.
- Files copied with `docker cp` exist only in that container; they are gone after the container is recreated or the image pulled. Commit and let CI build the image for anything permanent.
- A bind-mounted config file (e.g. `config.local.yml`) must be edited **in place** (open, truncate, write), not replaced via a new file or rename — a new inode breaks the mount. The worker notices the change (mtime watch) and restarts itself.
- The SMTP account of a list usually only accepts that list's own address as sender, so a test mail from "an external sender" can only be sent as the list itself.
