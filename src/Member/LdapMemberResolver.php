<?php

declare(strict_types=1);

namespace Hengeb\Listig\Member;

use Symfony\Component\Ldap\Ldap;
use Symfony\Component\Ldap\Entry;

class LdapMemberResolver implements MemberResolver
{
    private ?Ldap $ldap = null;

    /**
     * @param string|null $groupDn base DN to search the list's group under (`ldap-list-dn`); the
     *        directory's base DN when null
     * @param string|null $groupFilter extra filter every list group must match (`ldap-filter`,
     *        e.g. "(objectClass=mailGroup)"); with null a group is found by its `cn` alone, as before
     * @param string|null $emptyGroupMember DN of a placeholder entry (a user without a mail
     *        address) kept in `member` while a group would otherwise be empty, for schemas that
     *        require at least one member (`groupOfNames`); never reported as a member. With null the
     *        last member is simply removed.
     */
    public function __construct(
        private readonly string $ldapHost,
        private readonly string $baseDn,
        private readonly string $bindDn,
        private readonly string $bindPassword,
        private readonly ?string $groupDn = null,
        private readonly ?string $groupFilter = null,
        private readonly ?string $emptyGroupMember = null,
    ) {
    }

    /**
     * The search filter for the group of list `$name`: its `cn` (escaped by the caller), and-ed with
     * the configured group filter so that an entry that merely shares the name — a person, another
     * kind of group — is never taken for the list's group.
     */
    public static function buildGroupFilter(?string $groupFilter, string $escapedName): string
    {
        $cn = "(cn={$escapedName})";
        $groupFilter = trim((string) $groupFilter);
        if ($groupFilter === '') {
            return $cn;
        }
        if ($groupFilter[0] !== '(') {
            $groupFilter = "({$groupFilter})";
        }
        return "(&{$groupFilter}{$cn})";
    }

    /** DNs compared as LDAP does for our purposes: case-insensitive, whitespace around `,` and `=` ignored. */
    public static function sameDn(string $a, string $b): bool
    {
        $normalize = fn(string $dn) => strtolower(preg_replace('/\s*([,=])\s*/', '$1', trim($dn)));
        return $normalize($a) === $normalize($b);
    }

    /** @param string[] $dns */
    public static function containsDn(array $dns, string $dn): bool
    {
        foreach ($dns as $candidate) {
            if (self::sameDn($candidate, $dn)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param string[] $dns
     * @return string[] without the placeholder entry
     */
    public static function withoutPlaceholder(array $dns, ?string $placeholder): array
    {
        if ($placeholder === null || $placeholder === '') {
            return $dns;
        }
        return array_values(array_filter($dns, fn(string $dn) => !self::sameDn($dn, $placeholder)));
    }

    public function getMembers(string $name): array
    {
        return $this->resolveDns($this->getMemberDns($name, 'member'));
    }

    public function getOwners(string $name): array
    {
        return $this->resolveDns($this->getMemberDns($name, 'owner'));
    }

    public function findByEmail(string $email): ?Member
    {
        $ldap = $this->connect();
        $results = $ldap->query($this->baseDn, "(mail={$this->escape($email)})")->execute();

        foreach ($results as $entry) {
            return $this->entryToMember($entry);
        }

        return null;
    }

    public function supportsRemoval(): bool
    {
        return true;
    }

    public function supportsAddition(): bool
    {
        return true;
    }

    public function removeMember(string $listName, string $email): void
    {
        $ldap = $this->connect();

        // Resolve user DN by email
        $userResults = $ldap->query($this->baseDn, "(mail={$this->escape($email)})")->execute();
        $userDn = null;
        foreach ($userResults as $entry) {
            $userDn = $entry->getDn();
            break;
        }

        if ($userDn === null) {
            return; // User not found — already removed or never existed
        }

        $groupEntry = $this->findGroupEntry($listName);
        if ($groupEntry === null) {
            return;
        }
        $currentMembers = $groupEntry->getAttribute('member') ?? [];
        if (!self::containsDn($currentMembers, $userDn)) {
            return;
        }

        // A schema that demands at least one `member` would reject removing the last one: put the
        // placeholder in first, so the group never becomes empty.
        $lastRealMember = count(self::withoutPlaceholder($currentMembers, $this->emptyGroupMember)) === 1;
        if ($lastRealMember && $this->emptyGroupMember !== null && $this->emptyGroupMember !== ''
            && !self::containsDn($currentMembers, $this->emptyGroupMember)) {
            $this->addAttributeValue($groupEntry, 'member', $this->emptyGroupMember);
        }
        $this->removeAttributeValue($groupEntry, 'member', $userDn);
    }

    /**
     * Adds $member to the list's LDAP `member` attribute. LDAP-backed lists can
     * only subscribe emails that already have a matching directory entry — there
     * is no DN to add otherwise, and creating directory users is out of scope
     * here. Callers (e.g. the double opt-in subscribe API) must surface this as
     * a clear error rather than a silent failure.
     */
    public function addMember(string $listName, Member $member): void
    {
        $ldap = $this->connect();

        $userResults = $ldap->query($this->baseDn, "(mail={$this->escape($member->email)})")->execute();
        $userDn = null;
        foreach ($userResults as $entry) {
            $userDn = $entry->getDn();
            break;
        }

        if ($userDn === null) {
            throw new \RuntimeException(
                "Cannot add member '{$member->email}': no matching directory entry found. " .
                "LDAP-backed lists can only subscribe existing directory users."
            );
        }

        $groupEntry = $this->findGroupEntry($listName);
        if ($groupEntry === null) {
            throw new \RuntimeException("List '$listName' not found in LDAP");
        }

        $currentMembers = $groupEntry->getAttribute('member') ?? [];
        if (!self::containsDn($currentMembers, $userDn)) {
            $this->addAttributeValue($groupEntry, 'member', $userDn);
        }
        // The placeholder only exists to keep an empty group valid; drop it once a real member is in.
        foreach ($currentMembers as $dn) {
            if ($this->emptyGroupMember !== null && self::sameDn($dn, $this->emptyGroupMember)) {
                $this->removeAttributeValue($groupEntry, 'member', $dn);
                break;
            }
        }
    }

    public function supportsInvalidation(): bool
    {
        return true;
    }

    /**
     * $listName is deliberately unused — a directory entry's `mail` attribute
     * belongs to the person, not to any one list's group membership, so there
     * is no per-list scope to honor here; invalidating necessarily affects
     * every list this person belongs to. See MemberResolver::invalidateEmail()'s
     * own docblock.
     *
     * `mail` is multi-valued by schema (see docs/architecture/providers-and-members.md "Additional addresses
     * per member (mail-aliases)") — the value to replace is found by *value*,
     * not by position/index, since the entry's own attribute order isn't
     * guaranteed stable and Member::$email only ever reflected whichever
     * value happened to be first at the time this Member was last resolved.
     * removeAttributeValues()/addAttributeValues() operate on values, not
     * positions, so every *other* mail value (aliases) is left untouched
     * regardless of how many there are or what order they're in.
     */
    public function invalidateEmail(string $listName, string $email, string $reason): void
    {
        $ldap = $this->connect();
        $results = $ldap->query($this->baseDn, "(mail={$this->escape($email)})")->execute();

        foreach ($results as $entry) {
            $mailValues = $entry->getAttribute('mail') ?? [];
            $matchedValue = null;
            foreach ($mailValues as $value) {
                if (strtolower($value) === strtolower($email)) {
                    $matchedValue = $value;
                    break;
                }
            }

            if ($matchedValue === null) {
                return; // Already changed/removed since — nothing to invalidate.
            }

            $invalidated = InvalidatedEmail::build($email, $reason);
            $this->removeAttributeValue($entry, 'mail', $matchedValue);
            $this->addAttributeValue($entry, 'mail', $invalidated);
            return;
        }
    }

    private function getMemberDns(string $name, string $attribute): array
    {
        $entry = $this->findGroupEntry($name);
        $dns = $entry?->getAttribute($attribute) ?? [];

        return self::withoutPlaceholder($dns, $this->emptyGroupMember);
    }

    private function findGroupEntry(string $name): ?Entry
    {
        $ldap = $this->connect();
        $filter = self::buildGroupFilter($this->groupFilter, $this->escape($name));
        foreach ($ldap->query($this->groupDn ?? $this->baseDn, $filter)->execute() as $entry) {
            return $entry;
        }
        return null;
    }

    private function resolveDns(array $dns): array
    {
        $ldap = $this->connect();
        $members = [];

        foreach ($dns as $dn) {
            $results = $ldap->query($dn, '(objectClass=*)', ['scope' => 'base'])->execute();
            foreach ($results as $entry) {
                $members[] = $this->entryToMember($entry);
            }
        }

        return $members;
    }

    /**
     * Exposes every attribute of the directory entry under its own name (e.g.
     * {cn}, {givenName}, {sn}, {employeeNumber}, {businessCategory}, ...) — no
     * fixed mapping to pronoun/title/etc. A list can still define its own
     * mapping as a normal config key for anything not covered below, e.g.
     * `pronoun: "{businessCategory}"`, resolved lazily per recipient — see
     * MailProcessor::buildRecipientContext() and docs/architecture/providers-and-members.md
     * "Example: pronoun-based salutation".
     *
     * Two exceptions, both populated here unconditionally/as-fallback rather
     * than requiring a per-list config alias, since `firstname`/`lastname` are
     * meant to be usable for a person's name everywhere in this codebase
     * (mail personalization, {sender-name}, resolveMemberDisplayName() in the
     * owner/member UI, ...) without every LDAP-backed list having to redefine
     * the same `firstname: "{givenName}"` / `lastname: "{sn}"` aliases:
     * - 'username': duplicated from 'cn' unconditionally — two privacy-sensitive
     *   call sites need a non-email identifier with no list/alias context
     *   available to fall back to a per-list mapping — MailProcessor's
     *   unsubscribe-token signing and X-Original-Sender header, and
     *   AuthController's login-token signing, which runs before any specific
     *   list is known at all (AggregateMemberResolver searches across all of
     *   them).
     * - 'firstname'/'lastname': filled in from 'givenName'/'sn' — the standard
     *   inetOrgPerson attributes an LDAP schema already guarantees — only as a
     *   fallback (`isset()`-guarded), so a directory that happens to carry its
     *   own real 'firstname'/'lastname' attributes (non-standard, but not
     *   impossible) is never overwritten by this convenience copy. A list-level
     *   `firstname:`/`lastname:` config alias (still supported, unchanged) is
     *   evaluated for a member's *own* attributes first anyway — see
     *   ListConfig::resolveMemberDisplayName() — so this fallback is what
     *   actually fires whenever no such alias is configured at all.
     * - 'mail-aliases': every `mail` value *beyond* the first, comma-joined
     *   (same dual string/array shape `senders:`/`personalize:` already use —
     *   see ListConfig::splitCommaList()). `Member::$email` itself stays the
     *   entry's *first* `mail` value only — used as the actual delivery
     *   address (recipient envelope, {mail} personalization, ...), where a
     *   single, stable address is exactly what's wanted. `mail-aliases`
     *   exists purely so ListConfig::matchEmail() (isMember()/isOwnedBy(),
     *   the actual post-access gate) can recognize a sender writing from any
     *   of their directory's `mail` values, not just the one Listig happens
     *   to use as their primary address — see docs/architecture/providers-and-members.md "Additional addresses
     *   per member (`mail-aliases`)".
     */
    private function entryToMember(Entry $entry): Member
    {
        $mailValues = $entry->getAttribute('mail') ?? [];
        $mail = $mailValues[0] ?? '';

        $attributes = [];
        foreach ($entry->getAttributes() as $attributeName => $values) {
            if ($attributeName === 'mail') {
                continue;
            }
            $attributes[$attributeName] = $values[0] ?? '';
        }
        if (count($mailValues) > 1) {
            $attributes['mail-aliases'] = implode(',', array_slice($mailValues, 1));
        }
        if (isset($attributes['cn'])) {
            $attributes['username'] = $attributes['cn'];
        }
        if (!isset($attributes['firstname']) && isset($attributes['givenName'])) {
            $attributes['firstname'] = $attributes['givenName'];
        }
        if (!isset($attributes['lastname']) && isset($attributes['sn'])) {
            $attributes['lastname'] = $attributes['sn'];
        }

        return new Member($mail, $attributes);
    }

    private function addAttributeValue(Entry $entry, string $attribute, string $value): void
    {
        $this->connect()->getEntryManager()->addAttributeValues($entry, $attribute, [$value]);
    }

    private function removeAttributeValue(Entry $entry, string $attribute, string $value): void
    {
        $this->connect()->getEntryManager()->removeAttributeValues($entry, $attribute, [$value]);
    }

    private function connect(): Ldap
    {
        if ($this->ldap === null) {
            $this->ldap = Ldap::create('ext_ldap', ['connection_string' => $this->ldapHost]);
            $this->ldap->bind($this->bindDn, $this->bindPassword);
        }
        return $this->ldap;
    }

    private function escape(string $value): string
    {
        return ldap_escape($value, '', LDAP_ESCAPE_FILTER);
    }
}
