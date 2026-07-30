<?php

declare(strict_types=1);

namespace Hengeb\Listig\Member;

use Hengeb\Listig\Config\ListConfig;
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
        return $this->findListAndMemberByEmail($email)['member'] ?? null;
    }

    /**
     * Like findByEmail(), but also returns which list the match came from —
     * AuthController needs the list itself (not just the Member) to send the
     * login mail through that list's own SMTP config and to embed the correct
     * list in the login token, instead of an arbitrary fixed list.
     *
     * @return array{list: ListConfig, member: Member}|null
     */
    public function findListAndMemberByEmail(string $email): ?array
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
                return ['list' => $list, 'member' => $member];
            }
        }

        return null;
    }

    /**
     * Resolves a member within a *specific* list from the identifier embedded in a
     * login token — sendMagicLink() signs that token with
     * $member->attributes['username'] ?? $member->email (see CLAUDE.md
     * "Privacy-preserving username"), specifically so the emailed link doesn't
     * carry a plaintext address for an LDAP-backed member. This is the inverse
     * lookup verifyToken() needs once that token round-trips back: matches on
     * username first, falling back to a plain email match for members with no
     * username attribute — mirroring the same fallback used when the identifier
     * was created — so the caller can recover the member's *real* email for the
     * session (see AuthController::verifyToken()).
     *
     * @return array{list: ListConfig, member: Member}|null
     */
    public function findMemberInListByUserCn(string $listCn, string $userCn): ?array
    {
        $list = $this->listProvider->getList($listCn);
        if ($list === null) {
            return null;
        }

        foreach ([...$list->getMembers(), ...$list->getOwners()] as $member) {
            if (($member->attributes['username'] ?? $member->email) === $userCn) {
                return ['list' => $list, 'member' => $member];
            }
        }

        return null;
    }

    public function removeMember(string $listName, string $email): void
    {
        // Not applicable for aggregate resolver
    }

    public function supportsRemoval(): bool
    {
        return false;
    }

    public function addMember(string $listName, Member $member): void
    {
        throw new \RuntimeException('Not applicable for aggregate resolver — used for lookup only.');
    }
}
