<?php

declare(strict_types=1);

namespace Hengeb\Listig\Config;

use Hengeb\Listig\Config\Enum\AllowLeave;
use Hengeb\Listig\Config\Enum\ArchiveMode;
use Hengeb\Listig\Config\Enum\ModerationMode;
use Hengeb\Listig\Config\Enum\PostAccess;
use Hengeb\Listig\Config\Enum\ReplyToBehavior;
use Hengeb\Listig\Member\Member;
use Hengeb\Listig\Member\MemberResolver;
use Hengeb\Listig\Member\NullMemberResolver;
use Hengeb\Listig\Variable\Literal;
use Hengeb\Listig\Variable\ResolutionPurpose;
use Hengeb\Listig\Variable\VariableResolver;

class ListConfig
{
    /**
     * Reserved for system routes (GET /_/health, /_/login, /_/api/..., see public/index.php)
     * — a list literally named "_" would be indistinguishable from those by segment count.
     */
    private const string RESERVED_NAME = '_';

    public function __construct(
        public readonly string $name,
        public readonly string $mail,
        private readonly array $raw,
        private readonly MemberResolver $memberResolver = new NullMemberResolver(),
        /**
         * Non-null only for type: subaddress lists — each entry's `mail` (and optional
         * firstname/lastname/username) is a template containing {subaddress}, resolved
         * per incoming mail by MailProcessor rather than statically at startup.
         */
        public readonly ?array $subaddressMemberTemplates = null,
    ) {
        if ($this->name === self::RESERVED_NAME) {
            throw new \RuntimeException(
                "List name '_' is reserved for system routes (/_/...) and cannot be used"
            );
        }
    }

    /** @return Member[] */
    public function getMembers(): array
    {
        return $this->memberResolver->getMembers($this->name);
    }

    /** @return Member[] */
    public function getOwners(): array
    {
        return $this->memberResolver->getOwners($this->name);
    }

    /**
     * Resolves a profile by email via the underlying MemberResolver, regardless of
     * whether that email is actually subscribed to this list. For LDAP-backed lists
     * this searches the whole directory — use isMember()/isOwnedBy() (or
     * findMemberInList()/findOwnerInList()) when access control is what you need.
     */
    public function findMemberByEmail(string $email): ?Member
    {
        return $this->memberResolver->findByEmail($email);
    }

    /** @throws \RuntimeException if the underlying member store cannot actually persist a removal */
    public function removeMember(string $email): void
    {
        $this->memberResolver->removeMember($this->name, $email);
    }

    /**
     * Whether removeMember() can actually persist a removal for this list — false
     * for a list with no configured member store, or one backed by static inline
     * config.yml members. Check this before offering self-service unsubscribe
     * (the "Unsubscribe" dashboard link, the direct-unsubscribe flow) rather than
     * attempting removeMember() and having it silently no-op or throw.
     */
    public bool $supportsUnsubscribe {
        get => $this->memberResolver->supportsRemoval();
    }

    /** @throws \RuntimeException if the underlying member store cannot accept new members */
    public function addMember(Member $member): void
    {
        $this->memberResolver->addMember($this->name, $member);
    }

    /** Returns the matching entry from getMembers(), scoped to this list, or null. */
    public function findMemberInList(string $email): ?Member
    {
        return self::matchEmail($email, $this->getMembers());
    }

    /**
     * Resolves a member by the privacy-preserving identifier embedded in an
     * unsubscribe token (see CLAUDE.md "Privacy-preserving username") — the
     * inverse of how that identifier was derived when the token was signed
     * ($recipient->attributes['username'] ?? $recipient->email, in
     * MailProcessor::process() and DashboardController::index()).
     * findMemberInList()/findMemberByEmail() only ever match against
     * Member::$email, never a username, so they cannot reverse this lookup —
     * for an LDAP-backed member, $userCn is the LDAP cn, not an email address,
     * and searching `(mail=$userCn)` never matches anything.
     */
    public function findMemberInListByUserCn(string $userCn): ?Member
    {
        foreach ($this->getMembers() as $member) {
            if (($member->attributes['username'] ?? $member->email) === $userCn) {
                return $member;
            }
        }
        return null;
    }

    /**
     * Resolves a display name ("firstname lastname") for a member/owner shown in
     * the web UI (list/manage.latte, list/index.latte) — {firstname}/{lastname}
     * are ordinary config-key aliases (e.g. `firstname: "{givenName}"` for an
     * LDAP-backed list with no dedicated firstname field of its own — see
     * CLAUDE.md "Member attributes — fully dynamic"), so reading
     * $member->attributes['firstname'] directly (as this method's callers used
     * to) never resolves them: that key is only ever resolved lazily, through
     * VariableResolver, against a context built from both this list's own
     * config and the member's own attributes (which must come first, and be
     * Literal-wrapped, exactly like MailProcessor::buildRecipientContext() —
     * mail-derived member data must never be re-parsed as a further template,
     * see "Untrusted input in {} templates"). Falls back to `username` (see
     * "Privacy-preserving `username`") when both resolve empty — e.g. no
     * firstname/lastname alias configured at all.
     */
    public function resolveMemberDisplayName(Member $member): string
    {
        $memberContext = array_map(fn(string $v) => new Literal($v), $member->attributes);
        $memberContext['mail'] = new Literal($member->email);
        $contexts = [$this->createContext(), $memberContext];

        $firstname = VariableResolver::resolve('{firstname}', $contexts);
        $lastname = VariableResolver::resolve('{lastname}', $contexts);

        return trim("$firstname $lastname") ?: ($member->attributes['username'] ?? '');
    }

    /** Returns the matching entry from getOwners(), scoped to this list, or null. */
    public function findOwnerInList(string $email): ?Member
    {
        return self::matchEmail($email, $this->getOwners());
    }

    public function isMember(string $email): bool
    {
        return $this->findMemberInList($email) !== null;
    }

    public function isOwnedBy(string $email): bool
    {
        return $this->findOwnerInList($email) !== null;
    }

    /** @param Member[] $members */
    private static function matchEmail(string $email, array $members): ?Member
    {
        $email = strtolower($email);
        foreach ($members as $member) {
            if (strtolower($member->email) === $email) {
                return $member;
            }
        }
        return null;
    }

    /**
     * Resolved as a template against ResolutionPurpose::Disclosed (the default) —
     * unlike imapUser/imapPassword/etc., this is read directly in many places
     * (UI templates, notification mail subjects, the smtp-from-name fallback),
     * so a list configured with e.g. `display-name: "{imap-password}"` must not
     * be able to leak that value just because someone reads this property
     * directly, the same way it already couldn't via {display-name} referenced
     * from another template (list-label, footer, ...) — see CLAUDE.md
     * "Untrusted input in {} templates".
     */
    public string $displayName {
        get {
            $raw = $this->raw['display-name'] ?? null;
            return $raw === null ? $this->name : $this->resolve($raw);
        }
    }

    public ReplyToBehavior $replyTo {
        get => ReplyToBehavior::from($this->resolve((string) ($this->raw['reply-to'] ?? 'list')));
    }

    public PostAccess $postAccess {
        get => PostAccess::from($this->resolve((string) ($this->raw['post-access'] ?? 'members')));
    }

    public ModerationMode $moderation {
        get => ModerationMode::from($this->resolve((string) ($this->raw['moderation'] ?? 'off')));
    }

    public AllowLeave $allowLeave {
        get => AllowLeave::from($this->resolve((string) ($this->raw['allow-leave'] ?? 'direct')));
    }

    public ?string $footer {
        get => array_key_exists('footer', $this->raw) ? ($this->raw['footer'] ?? null) : null;
    }

    public ?string $listLabel {
        get => array_key_exists('list-label', $this->raw) ? ($this->raw['list-label'] ?? null) : null;
    }

    /**
     * Members/Owners/Public/Hidden all archive the raw mail (move to the IMAP archive
     * folder, see $archiveFolder below, instead of deleting it) — they differ only in
     * who may view it through the web archive viewer (Http/Controller/ArchiveController.php):
     * Hidden archives it but exposes it to no one. Off deletes it as before. See
     * CLAUDE.md "Archive access levels".
     */
    public ArchiveMode $archive {
        get => ArchiveMode::from($this->resolve((string) ($this->raw['archive'] ?? 'off')));
    }

    /**
     * Name of the IMAP folder archived mail is moved into (see ImapArchiver::archiveOrDelete()
     * and ArchiveMailLocator::find(), the only two places that touch it) — configurable per
     * list since some IMAP setups reserve/already use "Archive" for something else, or a
     * provider's own webmail names its own archive folder differently (e.g. "Archives").
     */
    public string $archiveFolder {
        get => $this->resolve((string) ($this->raw['archive-folder'] ?? 'Archive'));
    }

    public int $maxPerSender {
        get => (int) $this->resolve((string) ($this->raw['max-per-sender'] ?? 5));
    }

    public int $maxSize {
        get => self::parseSize($this->resolve((string) ($this->raw['max-size'] ?? '5M')));
    }

    public ?string $smtpFromName {
        get => $this->raw['smtp-from-name'] ?? null;
    }

    /**
     * The list's description. Raw config key is `list-description` (not bare
     * `description`) so it can't collide with a member-level `description`
     * attribute (e.g. a real LDAP person attribute), same reasoning as
     * `list-mail` vs. a member's own `mail`. Providers that read a native
     * `description`-named field (LDAP description[] sub-key, database
     * list_config row) rename it to `list-description` on ingest — see
     * ConfigResolver::resolveListConfig().
     *
     * Resolved as a template against ResolutionPurpose::Disclosed, same as
     * $displayName and for the same reason: read directly in UI templates, so
     * `list-description: "{imap-password}"` must not leak that value there.
     */
    public ?string $description {
        get {
            $raw = $this->raw['list-description'] ?? null;
            return $raw === null ? null : $this->resolve($raw);
        }
    }

    public string $imapHost {
        get => $this->resolve($this->raw['imap-host'] ?? $this->raw['mail-host'] ?? '', ResolutionPurpose::Trusted);
    }

    public int $imapPort {
        get => (int) $this->resolve((string) ($this->raw['imap-port'] ?? 993));
    }

    public string $imapUser {
        get => $this->resolve($this->raw['imap-user'] ?? $this->raw['mail-user'] ?? '', ResolutionPurpose::Trusted);
    }

    public string $imapPassword {
        get => $this->resolve($this->raw['imap-password'] ?? $this->raw['mail-password'] ?? '', ResolutionPurpose::Trusted);
    }

    // Default depends on imapPort: the well-known implicit-TLS port (993) defaults
    // to 'ssl', anything else to 'tls' (STARTTLS) — safer than blindly assuming
    // implicit TLS on a non-standard port, which would simply fail to connect.
    public string $imapSecure {
        get => $this->resolve($this->raw['imap-secure'] ?? self::defaultSecureForPort($this->imapPort, 993));
    }

    public string $smtpHost {
        get => $this->resolve($this->raw['smtp-host'] ?? $this->raw['mail-host'] ?? '', ResolutionPurpose::Trusted);
    }

    public int $smtpPort {
        get => (int) $this->resolve((string) ($this->raw['smtp-port'] ?? 587));
    }

    public string $smtpUser {
        get => $this->resolve($this->raw['smtp-user'] ?? $this->raw['mail-user'] ?? '', ResolutionPurpose::Trusted);
    }

    public string $smtpPassword {
        get => $this->resolve($this->raw['smtp-password'] ?? $this->raw['mail-password'] ?? '', ResolutionPurpose::Trusted);
    }

    // Default depends on smtpPort: the well-known implicit-TLS port (465) defaults
    // to 'ssl', anything else (587, 25, ...) to 'tls' (STARTTLS).
    public string $smtpSecure {
        get => $this->resolve($this->raw['smtp-secure'] ?? self::defaultSecureForPort($this->smtpPort, 465));
    }

    private static function defaultSecureForPort(int $port, int $implicitTlsPort): string
    {
        return $port === $implicitTlsPort ? 'ssl' : 'tls';
    }

    public string $logLevel {
        get => $this->resolve($this->raw['log-level'] ?? 'info');
    }

    /**
     * Bearer token for the list-management API (PUT/DELETE/subscribe/encrypt-password).
     * Empty = API disabled for this list. Deliberately NOT template-resolved,
     * unlike everything else here — this is a credential the caller must present
     * verbatim; allowing indirection here would only add complexity/attack
     * surface (e.g. accidental sharing via a shared alias) for no real benefit.
     */
    public string $apiToken {
        get => $this->raw['api-token'] ?? '';
    }

    /** Whether POST .../subscribe accepts unauthenticated requests (public self-service double opt-in). */
    public bool $publicSubscribe {
        get => $this->resolve((string) ($this->raw['public-subscribe'] ?? 'off')) === 'on';
    }

    /**
     * Whether this list has enough IMAP config to poll — allows a list to exist
     * (e.g. while being set up via the management API) without a host/password
     * yet; ImapPoller/ImapArchiver skip such lists instead of erroring.
     */
    public bool $isImapConfigured {
        get => $this->imapHost !== ''
            && ($this->raw['imap-password'] ?? $this->raw['mail-password'] ?? '') !== '';
    }

    /**
     * Locale for this list's outgoing mails and its manage page. Just another config
     * key, resolved through the same merge chain as everything else (global default,
     * overridable per list via LDAP description[]/DB list_config/inline config) — no
     * special-casing needed here beyond the code-default fallback.
     */
    public string $language {
        get => $this->resolve($this->raw['language'] ?? 'en');
    }

    /** Domain part of the list's mail address — e.g. "example.org" for "list@example.org". */
    public string $domain {
        get => substr(strrchr($this->mail, '@'), 1);
    }

    /** @return string[] */
    public array $personalizeKeys {
        get {
            $raw = $this->raw['personalize'] ?? '';
            if ($raw === 'off' || $raw === '') {
                return ['list-url'];
            }
            return array_merge(['list-url'], self::splitCommaList($raw));
        }
    }

    /** Extra reserved subaddresses beyond the built-in bounce/accept-/reject- set (comma-separated, like `personalize`). */
    public array $reservedSubaddresses {
        get {
            $raw = (string) ($this->raw['reserved-subaddresses'] ?? '');
            return array_map('strtolower', self::splitCommaList($raw));
        }
    }

    /**
     * Splits a comma-separated config value (`personalize`, `reserved-subaddresses`)
     * into trimmed, non-empty entries. `preg_split` on a run of commas and/or
     * whitespace, rather than plain `explode(',', ...)` (each entry individually
     * trimmed afterwards either way) — so `key1, key2, key3` and `key1,key2,key3`
     * always produce the identical array, and a doubled/stray separator
     * (`key1,, key2`, a trailing comma, ...) can never leave a spurious
     * empty-string entry in the result the way plain `explode()` would.
     *
     * @return string[]
     */
    private static function splitCommaList(string $raw): array
    {
        $raw = trim($raw);
        if ($raw === '') {
            return [];
        }
        return array_values(array_filter(
            array_map('trim', preg_split('/[,\s]+/', $raw)),
            fn(string $v) => $v !== '',
        ));
    }

    /**
     * True if any member-template's `mail` references {subaddress} — a type: subaddress
     * list without one is then an invalid recipient, not just "no subaddress used".
     */
    public bool $requiresSubaddress {
        get {
            foreach ($this->subaddressMemberTemplates ?? [] as $entry) {
                $mailTemplate = is_string($entry) ? $entry : ($entry['mail'] ?? '');
                if (str_contains($mailTemplate, '{subaddress}')) {
                    return true;
                }
            }
            return false;
        }
    }

    /**
     * Returns the context array for this list: all merged config keys plus the
     * computed list-* variables. Pass to VariableResolver::resolve() as one entry
     * in the $contexts array.
     *
     * Global defaults at the front establish the imap-user/imap-password →
     * mail-user/mail-password fallback chain. Explicit raw-config values override
     * them because array_merge gives priority to later entries.
     */
    public function createContext(): array
    {
        // Global defaults + all merged config keys, i.e. everything a raw 'hostname'
        // template (e.g. 'lists.{domain}') could reference. Built without the
        // computed list-* block below, both because 'name'/'mail' need stripping
        // first (they get canonical list-* names) and because resolving hostname
        // against a context that itself needs hostname would recurse — same
        // bootstrap-context pattern as a provider's own list-mail resolution
        // (see "list-mail" in CLAUDE.md), not $this->resolve() (which builds its
        // context from this method).
        $baseContext = array_merge(
            [
                'imap-user'     => '{mail-user}',
                'imap-password' => '{mail-password}',
                'smtp-user'     => '{mail-user}',
                'smtp-password' => '{mail-password}',
            ],
            array_diff_key($this->raw, array_flip(['name', 'mail'])),
        );

        $rawHostname = $this->raw['hostname'] ?? null;
        $hostname = $rawHostname !== null
            ? VariableResolver::resolve((string) $rawHostname, [$baseContext])
            : '';
        if ($hostname === '') {
            $hostname = gethostname() ?: 'localhost';
        }

        return array_merge(
            $baseContext,
            // Computed list-* variables (highest priority, override raw config).
            // 'hostname' has no list- prefix — it's a deployment-level setting, not
            // something that genuinely varies per list, unlike list-domain (derived
            // from this list's own mail address).
            [
                'list-name'         => $this->name,
                'list-mail'         => $this->mail,
                'list-domain'       => $this->domain,
                'hostname'          => $hostname,
                'list-url'          => "https://{$hostname}/{$this->name}",
                'display-name'      => $this->raw['display-name'] ?? $this->name,
                'list-display-name' => $this->raw['display-name'] ?? $this->name,
            ]
        );
    }

    /**
     * Resolves a {variable} or plain value against this list's full context.
     * Blocking of VariableResolver::BLOCKED_KEYS (passwords, hostnames, ...)
     * happens inside VariableResolver itself, keyed off $purpose — not by
     * pre-filtering the context handed to it, since that couldn't work for
     * resolution that happens before a ListConfig exists (e.g. a provider's
     * own list-mail bootstrap resolution).
     *
     * $purpose defaults to Disclosed (least-privilege default) — every
     * property here uses that except imapUser/imapPassword/smtpUser/
     * smtpPassword, which pass Trusted explicitly because they must be able to
     * fall back to {mail-user}/{mail-password} even though those are
     * themselves blocked keys (`mail-user` sets both `imap-user` and
     * `smtp-user` unless overridden individually — the one deliberate,
     * documented case of a credential referencing another credential). Every
     * other property — including imap-host/-port/-secure and
     * smtp-host/-port/-secure, which do NOT need the Trusted fallback — stays
     * on the Disclosed default: a numeric property resolved without this
     * protection could otherwise leak a fragment of a real secret (e.g.
     * `smtp-port: "{imap-password}"` would silently produce the leading
     * digits of the actual password as a port number, which can then surface
     * via a connection-failure error message).
     */
    private function resolve(string $raw, ResolutionPurpose $purpose = ResolutionPurpose::Disclosed): string
    {
        if (!str_contains($raw, '{')) {
            return $raw;
        }
        return VariableResolver::resolve($raw, [$this->createContext()], $purpose);
    }

    private static function parseSize(string $value): int
    {
        if (preg_match('/^(\d+)\s*(GiB)$/i', $value, $m)) {
            return (int) $m[1] * 1_073_741_824;
        }
        if (preg_match('/^(\d+)\s*(GB|G)$/i', $value, $m)) {
            return (int) $m[1] * 1_000_000_000;
        }
        if (preg_match('/^(\d+)\s*(MiB)$/i', $value, $m)) {
            return (int) $m[1] * 1_048_576;
        }
        if (preg_match('/^(\d+)\s*(MB|M)$/i', $value, $m)) {
            return (int) $m[1] * 1_000_000;
        }
        if (preg_match('/^(\d+)\s*(KiB)$/i', $value, $m)) {
            return (int) $m[1] * 1_024;
        }
        if (preg_match('/^(\d+)\s*(KB|K)$/i', $value, $m)) {
            return (int) $m[1] * 1_000;
        }
        return (int) $value;
    }
}
