<?php

declare(strict_types=1);

namespace Hengeb\Listig\Member;

/**
 * Combines multiple independent MemberResolver sources for one list — built by
 * MemberResolverFactory::buildComposedResolver() to let a list's members/owners
 * come from more than one place, and more than one level (global/provider/list,
 * always additive), at once (e.g. LDAP directory membership plus a database of
 * external members, or LDAP owners plus a couple of inline system-administrator
 * addresses configured at provider level). See CLAUDE.md "Global / provider /
 * list levels".
 *
 * $memberSources and $ownerSources are independent — getMembers() only ever
 * queries the former, getOwners() only the latter, even if the same resolver
 * instance happens to appear in both (the common case: a list's own base
 * resolver, e.g. LdapMemberResolver, backs both roles unless overridden
 * separately).
 */
class CompositeMemberResolver implements MemberResolver
{
    /**
     * @param MemberResolver[] $memberSources
     * @param MemberResolver[] $ownerSources
     */
    public function __construct(
        private readonly array $memberSources,
        private readonly array $ownerSources,
    ) {
    }

    public function getMembers(string $name): array
    {
        return self::mergeUnique(array_map(fn(MemberResolver $r) => $r->getMembers($name), $this->memberSources));
    }

    public function getOwners(string $name): array
    {
        return self::mergeUnique(array_map(fn(MemberResolver $r) => $r->getOwners($name), $this->ownerSources));
    }

    public function findByEmail(string $email): ?Member
    {
        foreach ([...$this->memberSources, ...$this->ownerSources] as $source) {
            $member = $source->findByEmail($email);
            if ($member !== null) {
                return $member;
            }
        }
        return null;
    }

    /**
     * Tries each member source in configured order; the first one that doesn't
     * throw wins (e.g. prefer an LDAP directory entry, fall back to a database
     * row) — most resolvers can't actually signal "not applicable" any other
     * way (DatabaseMemberResolver upserts unconditionally, so it always
     * "succeeds"; only LdapMemberResolver throws when no matching directory
     * entry exists). Throws the last exception if every source does.
     */
    public function addMember(string $listName, Member $member): void
    {
        $lastError = null;
        foreach ($this->memberSources as $source) {
            try {
                $source->addMember($listName, $member);
                return;
            } catch (\RuntimeException $e) {
                $lastError = $e;
            }
        }
        throw $lastError ?? new \RuntimeException("No member source configured for list '$listName'");
    }

    /**
     * Removes from every source that supports it, not just the first — the
     * same address can plausibly be a member via more than one source at
     * once, and each source's own removeMember() is already a silent no-op
     * when the address isn't actually present there.
     */
    public function removeMember(string $listName, string $email): void
    {
        foreach ($this->memberSources as $source) {
            if ($source->supportsRemoval()) {
                $source->removeMember($listName, $email);
            }
        }
    }

    public function supportsRemoval(): bool
    {
        foreach ($this->memberSources as $source) {
            if ($source->supportsRemoval()) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param array<Member[]> $memberLists
     * @return Member[]
     */
    private static function mergeUnique(array $memberLists): array
    {
        $byEmail = [];
        foreach ($memberLists as $members) {
            foreach ($members as $member) {
                $key = strtolower($member->email);
                // First source in configuration order wins on an attribute conflict.
                $byEmail[$key] ??= $member;
            }
        }
        return array_values($byEmail);
    }
}
