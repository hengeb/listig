<?php

declare(strict_types=1);

namespace Hengeb\Listig\Member;

class InlineMemberResolver implements MemberResolver
{
    /** @var Member[]|null null = not overridden inline, defer to $fallback */
    private ?array $members;

    /** @var Member[]|null null = not overridden inline, defer to $fallback */
    private ?array $owners;

    /**
     * Each entry is either a plain email string, or a map with a required `mail`
     * key plus any other keys (firstname, lastname, pronoun, or anything else) —
     * everything except `mail` becomes Member::$attributes verbatim, under its
     * own key name; nothing beyond `mail` is hardcoded here.
     * $members/$owners are independent: pass null (not []) for whichever one should
     * defer to $fallback instead of being statically configured — e.g. inline
     * owners with members still coming from a database/ldap/csv member-resolver.
     *
     * @param array<string|array{mail: string}>|null $members
     * @param array<string|array{mail: string}>|null $owners
     */
    public function __construct(
        ?array $members,
        ?array $owners,
        private readonly MemberResolver $fallback = new NullMemberResolver(),
    ) {
        $this->members = $members !== null ? array_map(self::toMember(...), $members) : null;
        $this->owners = $owners !== null ? array_map(self::toMember(...), $owners) : null;
    }

    private static function toMember(string|array $entry): Member
    {
        if (is_string($entry)) {
            return new Member($entry);
        }
        $attributes = $entry;
        unset($attributes['mail']);
        return new Member($entry['mail'], $attributes);
    }

    public function getMembers(string $name): array
    {
        return $this->members ?? $this->fallback->getMembers($name);
    }

    public function getOwners(string $name): array
    {
        return $this->owners ?? $this->fallback->getOwners($name);
    }

    public function findByEmail(string $email): ?Member
    {
        $email = strtolower($email);
        foreach (array_merge($this->members ?? [], $this->owners ?? []) as $member) {
            if (strtolower($member->email) === $email) {
                return $member;
            }
        }
        return $this->fallback->findByEmail($email);
    }

    public function supportsRemoval(): bool
    {
        return $this->members === null ? $this->fallback->supportsRemoval() : false;
    }

    public function removeMember(string $listName, string $email): void
    {
        if ($this->members === null) {
            $this->fallback->removeMember($listName, $email);
            return;
        }
        // Static inline config — mutating $this->members here would only affect
        // this request's in-memory copy (a fresh instance is built from config.yml
        // on every request, see "Worker loop — config reload"); it can never
        // actually persist. Throw instead of silently discarding the request —
        // callers must check supportsRemoval() first (see MemberResolver interface)
        // to avoid this in the first place, e.g. to hide an "Unsubscribe" button.
        throw new \RuntimeException(
            'Cannot remove members from an inline (config.yml) list at runtime — members are statically configured.'
        );
    }

    public function addMember(string $listName, Member $member): void
    {
        if ($this->members === null) {
            $this->fallback->addMember($listName, $member);
            return;
        }
        throw new \RuntimeException(
            'Cannot add members to an inline (config.yml) list at runtime — members are statically configured.'
        );
    }
}
