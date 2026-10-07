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

    /**
     * Whether invalidateEmail() can actually persist an invalidation, mirroring
     * supportsRemoval()'s own reasoning — checked before attempting it so a
     * caller (BounceMemberActionExecutor) can fall back or report clearly
     * instead of relying on a silent no-op or a caught exception.
     */
    public function supportsInvalidation(): bool;

    /**
     * Replaces $email, in place, with Member\InvalidatedEmail::build($email,
     * $reason) — used by the `mark-invalid` automatic bounce action (see
     * docs/architecture/bounces.md "Automatic bounce actions") so a permanently bouncing address
     * stops being deliverable/matchable without deleting the underlying
     * member record outright. $listName is provided for parity with
     * removeMember()/addMember() and is honored by backends whose storage is
     * genuinely scoped per list (database, csv) — LdapMemberResolver ignores
     * it, since a directory entry's `mail` attribute belongs to the person,
     * not to any one list's group membership, so an invalidation there is
     * unavoidably instance-wide (see its own docblock).
     *
     * Throws \RuntimeException if the underlying store cannot persist this at
     * all (static inline/YAML config) — same contract as removeMember().
     */
    public function invalidateEmail(string $listName, string $email, string $reason): void;
}
