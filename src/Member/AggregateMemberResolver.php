<?php

declare(strict_types=1);

namespace Hengeb\Listig\Member;

use Hengeb\Listig\Provider\ListProvider;

/**
 * Searches all lists across all configured providers.
 * Used for auth: any email that is member or owner of any list may log in.
 */
class AggregateMemberResolver implements MemberResolver
{
    public function __construct(
        private readonly ListProvider $listProvider,
    ) {
    }

    public function getMembers(string $name): array
    {
        return [];
    }

    public function getOwners(string $name): array
    {
        return [];
    }

    public function findByEmail(string $email): ?Member
    {
        // Deliberately uses findMemberInList()/findOwnerInList() (scoped to each
        // list's member/owner attributes) instead of $list->findMemberByEmail(),
        // which for LDAP-backed lists resolves ANY entry with a matching mail
        // attribute in the whole base DN — regardless of whether it is actually
        // subscribed to any list. Using that here would let anyone present in the
        // directory log in, even non-subscribers.
        foreach ($this->listProvider->getLists() as $list) {
            $member = $list->findMemberInList($email) ?? $list->findOwnerInList($email);
            if ($member !== null) {
                return $member;
            }
        }

        return null;
    }

    public function removeMember(string $listName, string $email): void
    {
        // Not applicable for aggregate resolver
    }

    public function addMember(string $listName, Member $member): void
    {
        throw new \RuntimeException('Not applicable for aggregate resolver — used for lookup only.');
    }
}
