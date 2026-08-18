<?php

declare(strict_types=1);

namespace Hengeb\Listig\Member;

/**
 * A fixed, statically-configured set of members/owners — the "bare inline
 * entry" building block MemberResolverFactory::buildSources() wraps every
 * plain string/mail-map entry in, at any of the three configurable levels
 * (global/provider/list — see CLAUDE.md "Global / provider / list levels").
 * No fallback/override concept anymore: composing multiple sources (this one
 * plus a database/LDAP/csv resolver, from any level) is CompositeMemberResolver's
 * job, not this class's — every source it's given is unconditionally additive.
 */
class InlineMemberResolver implements MemberResolver
{
    /** @var Member[] */
    private array $members;

    /** @var Member[] */
    private array $owners;

    /**
     * Each entry is either a plain email string, or a map with a required `mail`
     * key plus any other keys (firstname, lastname, pronoun, or anything else) —
     * everything except `mail` becomes Member::$attributes verbatim, under its
     * own key name; nothing beyond `mail` is hardcoded here. One exception:
     * `mail-aliases` may be written as a YAML list (`mail-aliases: [a@x.org,
     * b@x.org]`) — natural for `type: inline`/`type: yaml`'s already-structured
     * config, unlike the flat comma-separated string CSV/database columns are
     * limited to (see CLAUDE.md "Additional addresses per member (`mail-aliases`)"
     * for the mechanism this mirrors) — toMember() joins it into the same
     * comma-separated string shape every other source uses, since
     * Member::$attributes is always array<string, string>. A `mail-aliases`
     * written as a plain string already (or omitted) passes through unchanged.
     *
     * @param array<string|array{mail: string}> $members
     * @param array<string|array{mail: string}> $owners
     */
    public function __construct(array $members, array $owners)
    {
        $this->members = array_map(self::toMember(...), $members);
        $this->owners = array_map(self::toMember(...), $owners);
    }

    /** Shared with MemberResolverFactory::buildSources() and ListConfig::$authorizedSenders. */
    public static function toMember(string|array $entry): Member
    {
        if (is_string($entry)) {
            return new Member($entry);
        }
        $attributes = $entry;
        unset($attributes['mail']);
        if (isset($attributes['mail-aliases']) && is_array($attributes['mail-aliases'])) {
            $attributes['mail-aliases'] = implode(',', $attributes['mail-aliases']);
        }
        return new Member($entry['mail'], $attributes);
    }

    public function getMembers(string $name): array
    {
        return $this->members;
    }

    public function getOwners(string $name): array
    {
        return $this->owners;
    }

    public function findByEmail(string $email): ?Member
    {
        $email = strtolower($email);
        foreach ([...$this->members, ...$this->owners] as $member) {
            if (strtolower($member->email) === $email) {
                return $member;
            }
        }
        return null;
    }

    public function supportsRemoval(): bool
    {
        return false;
    }

    public function removeMember(string $listName, string $email): void
    {
        // Static inline config — mutating $this->members here would only affect
        // this request's in-memory copy (a fresh instance is built from config.yml
        // on every request, see "Worker loop — config reload"); it can never
        // actually persist. Throw instead of silently discarding the request —
        // callers must check supportsRemoval() first (see MemberResolver interface)
        // to avoid this in the first place, e.g. to hide an "Unsubscribe" button.
        throw new \RuntimeException(
            'Cannot remove members from an inline (config.yml) source at runtime — statically configured.'
        );
    }

    public function addMember(string $listName, Member $member): void
    {
        throw new \RuntimeException(
            'Cannot add members to an inline (config.yml) source at runtime — statically configured.'
        );
    }
}
