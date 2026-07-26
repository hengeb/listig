<?php

declare(strict_types=1);

namespace Hengeb\Listig\Member;

class NullMemberResolver implements MemberResolver
{
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
        return null;
    }

    public function removeMember(string $listName, string $email): void
    {
        // No-op: no backing store
    }

    public function supportsRemoval(): bool
    {
        return false;
    }

    public function addMember(string $listName, Member $member): void
    {
        throw new \RuntimeException('Cannot add members: this list has no configured member store.');
    }
}
