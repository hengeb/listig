<?php

declare(strict_types=1);

namespace Hengeb\Listig\Member;

interface MemberResolver
{
    /** @return Member[] */
    public function getMembers(string $name): array;

    /** @return Member[] */
    public function getOwners(string $name): array;

    public function findByEmail(string $email): ?Member;

    public function removeMember(string $listName, string $email): void;

    /**
     * Adds $member to the list's member store. Throws \RuntimeException if the
     * underlying store cannot represent new members (static inline/YAML config,
     * or — for LDAP — no directory entry matching $member->email was found).
     */
    public function addMember(string $listName, Member $member): void;
}
