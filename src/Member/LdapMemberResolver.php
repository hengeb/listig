<?php

declare(strict_types=1);

namespace Hengeb\Listig\Member;

use Symfony\Component\Ldap\Ldap;
use Symfony\Component\Ldap\Entry;

class LdapMemberResolver implements MemberResolver
{
    private ?Ldap $ldap = null;

    public function __construct(
        private readonly string $ldapHost,
        private readonly string $baseDn,
        private readonly string $bindDn,
        private readonly string $bindPassword,
    ) {
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

        // Find the group entry by name
        $groupResults = $ldap->query($this->baseDn, "(cn={$this->escape($listName)})")->execute();
        foreach ($groupResults as $groupEntry) {
            $currentMembers = $groupEntry->getAttribute('member') ?? [];
            if (in_array($userDn, $currentMembers, true)) {
                $ldap->getEntryManager()->removeAttributeValues($groupEntry, 'member', [$userDn]);
            }
            break;
        }
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

        $groupResults = $ldap->query($this->baseDn, "(cn={$this->escape($listName)})")->execute();
        foreach ($groupResults as $groupEntry) {
            $currentMembers = $groupEntry->getAttribute('member') ?? [];
            if (!in_array($userDn, $currentMembers, true)) {
                $ldap->getEntryManager()->addAttributeValues($groupEntry, 'member', [$userDn]);
            }
            return;
        }

        throw new \RuntimeException("List '$listName' not found in LDAP");
    }

    private function getMemberDns(string $name, string $attribute): array
    {
        $ldap = $this->connect();
        $results = $ldap->query($this->baseDn, "(cn={$this->escape($name)})")->execute();

        foreach ($results as $entry) {
            return $entry->getAttribute($attribute) ?? [];
        }

        return [];
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
     * fixed mapping to firstname/lastname/pronoun/etc. A list defines its own
     * mapping as a normal config key, e.g. `pronoun: "{businessCategory}"` or
     * `firstname: "{givenName}"`, resolved lazily per recipient — see
     * MailProcessor::buildRecipientContext() and CLAUDE.md "Pronoun / salutation
     * personalization".
     *
     * The one exception is 'username': it is duplicated from 'cn' under this
     * well-known key because two privacy-sensitive call sites need a non-email
     * identifier with no list/alias context available to fall back to a
     * per-list mapping — MailProcessor's unsubscribe-token signing and
     * X-Original-Sender header, and AuthController's login-token signing, which
     * runs before any specific list is known at all (AggregateMemberResolver
     * searches across all of them). Every other attribute stays fully dynamic.
     */
    private function entryToMember(Entry $entry): Member
    {
        $mail = ($entry->getAttribute('mail') ?? [])[0] ?? '';

        $attributes = [];
        foreach ($entry->getAttributes() as $attributeName => $values) {
            if ($attributeName === 'mail') {
                continue;
            }
            $attributes[$attributeName] = $values[0] ?? '';
        }
        if (isset($attributes['cn'])) {
            $attributes['username'] = $attributes['cn'];
        }

        return new Member($mail, $attributes);
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
