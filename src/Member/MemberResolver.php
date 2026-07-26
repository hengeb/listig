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
     * Whether removeMember() can actually persist a removal for this list, as
     * opposed to silently no-op'ing (no backing store at all) or mutating a
     * throwaway in-memory copy that reverts on the next request (static inline
     * config). Checked by DashboardController before showing an "Unsubscribe"
     * link, and by UnsubscribeController before attempting a direct unsubscribe
     * — both need to know this without actually calling removeMember(), which
     * would either do nothing or throw.
     */
    public function supportsRemoval(): bool;

    /**
     * Adds $member to the list's member store. Throws \RuntimeException if the
     * underlying store cannot represent new members (static inline/YAML config,
     * or — for LDAP — no directory entry matching $member->email was found).
     */
    public function addMember(string $listName, Member $member): void;
}
