<?php

declare(strict_types=1);

namespace Hengeb\Listig\Config;

use Hengeb\Listig\Config\Enum\AllowLeave;
use Hengeb\Listig\Config\Enum\ArchiveMode;
use Hengeb\Listig\Config\Enum\BounceAction;
use Hengeb\Listig\Config\Enum\JoinPolicy;
use Hengeb\Listig\Config\Enum\PostAccess;
use Hengeb\Listig\Config\Enum\ReplyToBehavior;
use Hengeb\Listig\Config\Enum\SenderAddressHeader;
use Hengeb\Listig\Config\Enum\SenderNotices;
use Hengeb\Listig\Config\Enum\Visibility;
use Hengeb\Listig\Member\InlineMemberResolver;
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

    /**
     * Letters, digits, underscore, hyphen only — a positive allowlist rather than
     * blocking specific bad characters one at a time. In particular this rules out
     * a dot, so a name like "news.php" is rejected here rather than silently
     * producing a list whose every web route (manage page, archive viewer,
     * unsubscribe link, moderation preview, List Management API) 404s at the nginx
     * layer before Slim ever sees the request — docker/nginx.conf's
     * `location ~ \.php$ { return 404; }` matches on the URL path alone, with no
     * awareness of which names are actually configured lists. Mail distribution
     * over IMAP/SMTP would keep working regardless (it never touches nginx), which
     * would make such a list look fine until someone actually clicked a link.
     */
    private const string VALID_NAME_PATTERN = '/^[A-Za-z0-9_-]+$/';

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
        /**
         * Already fully assembled for this one list from all three levels
         * (global/provider/list `restricted-members:`, see docs/architecture/config.md "Global /
         * provider / list levels") by whichever ListProvider built this
         * ListConfig — see isSenderRestricted()/isReceiverRestricted().
         */
        private readonly RestrictionList $restrictions = new RestrictionList([]),
    ) {
        if ($this->name === self::RESERVED_NAME) {
            throw new \RuntimeException(
                "List name '_' is reserved for system routes (/_/...) and cannot be used"
            );
        }
        if (!preg_match(self::VALID_NAME_PATTERN, $this->name)) {
            throw new \RuntimeException(
                "List name '{$this->name}' is invalid — only letters, digits, underscore, and hyphen are allowed"
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

    /** Mirror of $supportsUnsubscribe for addMember() — whether a "Join" button can work at all. */
    public bool $supportsJoin {
        get => $this->memberResolver->supportsAddition();
    }

    /**
     * Replaces $email with its invalidated placeholder (see
     * Member\InvalidatedEmail) — the `mark-invalid` automatic bounce action,
     * see docs/architecture/bounces.md "Automatic bounce actions".
     *
     * @throws \RuntimeException if the underlying member store cannot actually persist this
     */
    public function invalidateEmail(string $email, string $reason): void
    {
        $this->memberResolver->invalidateEmail($this->name, $email, $reason);
    }

    /** Mirrors $supportsUnsubscribe for invalidateEmail() — see MemberResolver::supportsInvalidation(). */
    public bool $supportsInvalidation {
        get => $this->memberResolver->supportsInvalidation();
    }

    /**
     * A `restricted-members:` hit (any of the three levels) blocking $email from posting to this list — see
     * docs/architecture/providers-and-members.md "Sender restrictions".
     */
    public function isSenderRestricted(string $email): bool
    {
        return $this->restrictions->isSendRestricted($this->name, $email);
    }

    /** A `restricted-members:` hit with `receive: false` also blocking $email from receiving mail distributed by this list. */
    public function isReceiverRestricted(string $email): bool
    {
        return $this->restrictions->isReceiveRestricted($this->name, $email);
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
     * unsubscribe token (see docs/architecture/providers-and-members.md "Privacy-preserving username") — the
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
     * docs/architecture/providers-and-members.md "Member attributes — fully dynamic"), so reading
     * $member->attributes['firstname'] directly (as this method's callers used
     * to) never resolves them: that key is only ever resolved lazily, through
     * VariableResolver, against a context built from both this list's own
     * config and the member's own attributes (which must come first, and be
     * Literal-wrapped, exactly like MailProcessor::buildRecipientContext() —
     * mail-derived member data must never be re-parsed as a further template,
     * see "Untrusted input in {} templates"). Falls back to the member's own
     * email when both resolve empty — e.g. an owner added via a bare-string
     * `owners:` entry (global/provider/list level, see "Global / provider /
     * list levels") carries no attributes at all, so there's nothing for
     * {firstname}/{lastname} to resolve even when a list otherwise has a
     * working alias for real directory-backed members. Resolved with
     * `quiet: true` (see VariableResolver's own docblock) — a bare-string
     * entry having no name to show is the expected, routine case for this
     * method specifically, not a misconfiguration worth an error_log line.
     */
    public function resolveMemberDisplayName(Member $member): string
    {
        $memberContext = array_map(fn(string $v) => new Literal($v), $member->attributes);
        $memberContext['mail'] = new Literal($member->email);
        $contexts = [$this->createContext(), $memberContext];

        $firstname = VariableResolver::resolve('{firstname}', $contexts, quiet: true);
        $lastname = VariableResolver::resolve('{lastname}', $contexts, quiet: true);

        return trim("$firstname $lastname") ?: $member->email;
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

    /**
     * `senders:` — addresses allowed to post without being a member or owner
     * (e.g. a board that may write to the list but shouldn't receive owner-only
     * bounce mail). Inline entries only (same shape as members:/owners:), no
     * resolver composition — see docs/architecture/providers-and-members.md
     * "Additional senders".
     *
     * $raw['senders'] is a plain YAML array when set via inline config.yml or
     * root-level `lists:`, but a single comma-separated string when it comes
     * from an LDAP `description[]` entry (a flat, multi-valued attribute with
     * no nested structure) — same dual shape personalizeKeys/reservedSubaddresses
     * already handle, reusing splitCommaList() for the string case.
     *
     * @return Member[]
     */
    public array $authorizedSenders {
        get {
            $raw = $this->raw['senders'] ?? [];
            $entries = is_string($raw) ? self::splitCommaList($raw) : $raw;
            return array_map(InlineMemberResolver::toMember(...), $entries);
        }
    }

    /**
     * Whether $identity (the session's `user.email`, which is the member's `username`
     * where one exists, else the address) may start a mail to an external address via
     * the web form (ComposeController) — see docs/architecture/masked-replies.md "Masked reply addresses". Needs a
     * masked reply-to mode (the token is the only way back in) and `post-access-public`
     * != deny (else the external's answer would be rejected). Owners and `senders:`
     * addresses may always; a member may unless masked-both is combined with
     * `post-access-members: deny` (masked-sender never reaches the list, so that
     * setting doesn't apply). A `restricted-members:` sender never may.
     */
    public function canComposeExternal(string $identity): bool
    {
        if (!$this->replyTo->isMasked() || $this->postAccessPublic === PostAccess::Deny) {
            return false;
        }

        ['owner' => $owner, 'sender' => $sender, 'member' => $member] = $this->resolveActor($identity);
        $who = $owner ?? $sender ?? $member;
        if ($who === null || $this->isSenderRestricted($who->email)) {
            return false;
        }
        if ($owner !== null || $sender !== null) {
            return true;
        }
        return $this->replyTo === ReplyToBehavior::MaskedSender || $this->postAccessMembers !== PostAccess::Deny;
    }

    /**
     * Who may write to the list by plain mail, for deciding whether to offer a "write to the
     * list" / "reply" mailto: link — mirrors IncomingMailFilter::checkPostAccess() (a
     * `restricted-members:` hit never, owners and `senders:` always, a member per
     * `post-access-members`, everyone else per `post-access-public`; `moderate` counts as
     * allowed). $identity is the session identity (address or username); null = an anonymous
     * viewer of a public archive, who can only be judged as an outsider. Always false for
     * `type: subaddress` lists, where a plain mail to the list address is not valid.
     * Keep in sync with checkPostAccess() — ListConfigTest checks both agree.
     */
    public function canPost(?string $identity): bool
    {
        if ($this->subaddressMemberTemplates !== null) {
            return false;
        }
        if ($identity === null) {
            return $this->postAccessPublic !== PostAccess::Deny;
        }

        ['owner' => $owner, 'sender' => $sender, 'member' => $member] = $this->resolveActor($identity);
        $who = $owner ?? $sender ?? $member;
        if ($this->isSenderRestricted($who->email ?? $identity)) {
            return false;
        }
        if ($owner !== null || $sender !== null) {
            return true;
        }
        return ($member !== null ? $this->postAccessMembers : $this->postAccessPublic) !== PostAccess::Deny;
    }

    /**
     * Whether the archive viewer would let $identity (null = anonymous) in — the single rule
     * behind ArchiveController::checkAccess() and every "Archive" button. `off`/`hidden`
     * are never viewable, not even by owners.
     */
    public function canViewArchive(?string $identity): bool
    {
        return match ($this->archive) {
            ArchiveMode::Public => true,
            ArchiveMode::Authenticated => $identity !== null,
            ArchiveMode::Members => $identity !== null && ($this->isMember($identity) || $this->isOwnedBy($identity)),
            ArchiveMode::Owners => $identity !== null && $this->isOwnedBy($identity),
            default => false,
        };
    }

    /** @return array{owner: ?Member, sender: ?Member, member: ?Member} by address, alias or username */
    private function resolveActor(string $identity): array
    {
        return [
            'owner' => $this->findOwnerInList($identity) ?? $this->findByUsername($this->getOwners(), $identity),
            'sender' => $this->findAuthorizedSender($identity),
            'member' => $this->findMemberInList($identity) ?? $this->findMemberInListByUserCn($identity),
        ];
    }

    /** @param Member[] $members */
    private function findByUsername(array $members, string $username): ?Member
    {
        foreach ($members as $m) {
            if (($m->attributes['username'] ?? $m->email) === $username) {
                return $m;
            }
        }
        return null;
    }

    public function isAuthorizedSender(string $email): bool
    {
        return self::matchEmail($email, $this->authorizedSenders) !== null;
    }

    public function findAuthorizedSender(string $email): ?Member
    {
        return self::matchEmail($email, $this->authorizedSenders);
    }

    /**
     * Matches $email against each member's primary address (Member::$email) or
     * any of their `mail-aliases` — an extra attribute every resolver type can
     * populate its own way (LDAP: every `mail` value beyond the first;
     * inline/yaml: a `mail-aliases:` YAML list or string; csv/database: an
     * ordinary extra column) but which always ends up the same comma-separated
     * string shape, see docs/architecture/providers-and-members.md "Additional addresses per member
     * (`mail-aliases`)". This is what makes findMemberInList()/findOwnerInList()
     * — and therefore isMember()/isOwnedBy(), the actual post-access gate in
     * IncomingMailFilter — recognize a sender writing from any address on file,
     * not just their primary one. A member with no `mail-aliases` attribute at
     * all (the common case for every backend) makes this degrade to the exact
     * same single-address comparison as before.
     *
     * @param Member[] $members
     */
    private static function matchEmail(string $email, array $members): ?Member
    {
        $email = strtolower($email);
        foreach ($members as $member) {
            if (strtolower($member->email) === $email) {
                return $member;
            }
            $aliases = $member->attributes['mail-aliases'] ?? '';
            if ($aliases !== '' && in_array($email, array_map('strtolower', self::splitCommaList($aliases)), true)) {
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
     * from another template (list-label, footer, ...) — see docs/architecture/security-and-tokens.md
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

    /**
     * Owners have no config key of their own — they always post, never
     * moderated (see IncomingMailFilter::checkPostAccess()/requiresModeration()).
     * Members and public are independently configurable; default 'allow' keeps
     * the previous implicit behavior for members (no post-access/moderation
     * configured at all previously meant "members may post, no moderation").
     */
    public PostAccess $postAccessMembers {
        get => PostAccess::from($this->resolve((string) ($this->raw['post-access-members'] ?? 'allow')));
    }

    /** Default 'deny' matches the old default (`post-access: members` — public/non-members excluded unless explicitly opened up). */
    public PostAccess $postAccessPublic {
        get => PostAccess::from($this->resolve((string) ($this->raw['post-access-public'] ?? 'deny')));
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
     * docs/architecture/archive.md "Archive access levels".
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

    /**
     * Raw archive-max-age config value (already {}-resolved) as an operator wrote
     * it, e.g. "30 days" — null if not configured (unbounded retention). Exposed
     * separately from $archiveMaxAgeCutoff below so the manage page's overview
     * table can show the human-readable duration itself, not a computed date.
     */
    public ?string $archiveMaxAge {
        get {
            $raw = $this->resolve((string) ($this->raw['archive-max-age'] ?? ''));
            return $raw === '' ? null : $raw;
        }
    }

    /**
     * How long archived mail is kept before ImapArchiver::pruneArchive() deletes it
     * from the archive folder — parsed from $archiveMaxAge (PHP's \DateTimeImmutable
     * constructor accepts relative-time strings like "30 days", same format
     * ImapArchiver::deleteOldMails() already uses internally for the fixed 30-day
     * INBOX rule). null (not configured, the default) means unbounded retention —
     * unchanged, pre-existing behavior. Throws on an unparseable value (fail-fast,
     * same philosophy as an invalid filters: regex or a missing $VAR) — caught at
     * pruneArchive()'s one call site in bin/worker.php, isolated per list so one
     * list's typo doesn't crash the cycle.
     */
    public ?\DateTimeImmutable $archiveMaxAgeCutoff {
        get {
            $raw = $this->archiveMaxAge;
            if ($raw === null) {
                return null;
            }
            try {
                return new \DateTimeImmutable("-$raw");
            } catch (\Throwable $e) {
                throw new \RuntimeException("List '{$this->name}' has an invalid archive-max-age value '$raw' (expected e.g. \"30 days\"): " . $e->getMessage());
            }
        }
    }

    /**
     * `trusted-authserv-id`: authserv-id(s) of the receiving MTA — a string, comma/space
     * separated, or a YAML list; lowercase. Empty/unset/"" = the topmost Authentication-Results
     * header is believed. Set = only headers with one of these ids count
     * (HeaderFilter::parseAuthResults(), ADR-0019). Normal override chain, not additive.
     *
     * @var string[]
     */
    public array $trustedAuthservIds {
        get {
            $raw = $this->raw['trusted-authserv-id'] ?? [];
            $ids = [];
            foreach (is_array($raw) ? $raw : [$raw] as $item) {
                foreach (preg_split('/[\s,]+/', $this->resolve((string) $item), -1, PREG_SPLIT_NO_EMPTY) as $id) {
                    $ids[] = strtolower($id);
                }
            }
            return array_values(array_unique($ids));
        }
    }

    public SenderNotices $senderNotices {
        get => SenderNotices::from($this->resolve((string) ($this->raw['sender-notices'] ?? 'authenticated')));
    }

    /**
     * Minimum seconds between two notices to the same address (`sender-notice-interval`):
     * plain seconds or a relative time like "1 hour" / "30 minutes"; 0 disables throttling.
     * Default 1 hour, at most 1 day (rate_limit rows are kept one day). Throws on invalid values.
     */
    public int $senderNoticeInterval {
        get {
            $raw = trim($this->resolve((string) ($this->raw['sender-notice-interval'] ?? '1 hour')));
            if (ctype_digit($raw)) {
                $seconds = (int) $raw;
            } else {
                $base = new \DateTimeImmutable('@0');
                $target = preg_match('/^\d+\s*(second|minute|hour|day)s?$/i', $raw) ? $base->modify("+$raw") : false;
                if ($target === false) {
                    throw new \RuntimeException("List '{$this->name}' has an invalid sender-notice-interval '$raw' (expected seconds or e.g. \"1 hour\")");
                }
                $seconds = $target->getTimestamp();
            }
            if ($seconds > 86400) {
                throw new \RuntimeException("List '{$this->name}': sender-notice-interval must not exceed 1 day");
            }
            return $seconds;
        }
    }

    public int $maxPerSender {
        get => (int) $this->resolve((string) ($this->raw['max-per-sender'] ?? 5));
    }

    /**
     * The automatic action for a recognized, authenticated permanent bounce
     * (BounceCause::UserUnknown) or an escalated repeated temporary one
     * (BounceCause::MailboxFull) — see docs/architecture/bounces.md "Automatic bounce actions".
     * Default `none`: no automatic mutation of member data until an operator
     * opts in explicitly, same safe-by-default philosophy as `archive: off`.
     */
    /**
     * Default 'never'. See MailProcessor::setOutgoingHeaders() / docs/architecture/masked-replies.md "Masked
     * reply addresses".
     */
    public SenderAddressHeader $senderAddressHeader {
        get => SenderAddressHeader::from($this->resolve((string) ($this->raw['sender-address-header'] ?? 'never')));
    }

    public BounceAction $bounceAction {
        get => BounceAction::from($this->resolve($this->raw['bounce-action'] ?? 'none'));
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

    /** How someone becomes a member (`join-policy`, default `invite`) — only `open` is implemented; see JoinPolicy. */
    public JoinPolicy $joinPolicy {
        get => JoinPolicy::from($this->resolve((string) ($this->raw['join-policy'] ?? 'invite')));
    }

    /** Who gets to see this list in the web UI (`visibility`, default `members`) — see isVisibleTo(). */
    public Visibility $visibility {
        get => Visibility::from($this->resolve((string) ($this->raw['visibility'] ?? 'members')));
    }

    /**
     * Whether $identity (an authenticated session's address; null = a guest, who sees no list at
     * all) may see this list in the dashboard and on its `/{listname}` page. Owners always do.
     * `members`: members too; `public`: every authenticated user. This hides the list's *listing*
     * only — it does not change who may read the archive (`archive`) or who receives mail.
     */
    public function isVisibleTo(?string $identity): bool
    {
        if ($identity === null) {
            return false;
        }
        ['owner' => $owner, 'member' => $member] = $this->resolveActor($identity);
        return match ($this->visibility) {
            Visibility::Public => true,
            Visibility::Members => $owner !== null || $member !== null,
            Visibility::Hidden => $owner !== null,
        };
    }

    /**
     * Whether someone who leaves can put themselves straight back: an `open` list that stays
     * visible to non-members (`visibility: public`) and whose store can add members. Leaving such a
     * list needs no confirmation — it is undone with one click; any other list asks first.
     */
    public function canRejoinAfterLeaving(): bool
    {
        return $this->joinPolicy === JoinPolicy::Open
            && $this->visibility === Visibility::Public
            && $this->supportsJoin;
    }

    /**
     * Whether the "Join" button is offered to $identity: an authenticated user who can see the list
     * and is not yet a member, on an `open` list whose member store can take new members.
     */
    public function canJoin(?string $identity): bool
    {
        return $identity !== null
            && $this->joinPolicy === JoinPolicy::Open
            && $this->supportsJoin
            && $this->isVisibleTo($identity)
            && $this->resolveActor($identity)['member'] === null;
    }

    /**
     * Whether this list has enough IMAP config to poll — allows a list to exist
     * (e.g. while being set up via the management API) without a host/password
     * yet; ImapPoller/ImapArchiver skip such lists instead of erroring.
     */
    public bool $isImapConfigured {
        get => $this->imapHost !== '' && $this->imapPassword !== '';
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

    /**
     * Local part of the list's mail address — e.g. "list" for "list@example.org".
     * Used to build the bounce address ({$localPart}+bounce@{$domain}, see
     * MailProcessor's Sender header and QueueSender's Envelope-From): it must be
     * a subaddress of the list's own real mailbox, not of $name/{list-cn} — the
     * two commonly differ (list name "it-team" but mail "it@example.org"), and a
     * bounce address built from $name has no reason to be routable to any real
     * mailbox at all, breaking bounce handling silently.
     */
    public string $localPart {
        get => substr($this->mail, 0, strrpos($this->mail, '@'));
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
     * Shared with every ListProvider's senders:/restricted-members: level-gathering
     * (the LDAP description[] string case — see docs/architecture/config.md "Global / provider /
     * list levels").
     *
     * @return string[]
     */
    public static function splitCommaList(string $raw): array
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
        // (see "list-mail" in docs/architecture/config.md), not $this->resolve() (which builds its
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
