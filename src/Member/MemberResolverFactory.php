<?php

declare(strict_types=1);

namespace Hengeb\Listig\Member;

use Hengeb\Listig\Database\DatabaseConnectionFactory;

/**
 * Builds the MemberResolver configured under a list-providers entry's optional
 * `member-resolver` block (`database` | `ldap` | none). Shared by
 * InlineListProvider, DatabaseListProvider, and YamlListProvider, which all
 * support the same sub-config shape.
 */
class MemberResolverFactory
{
    public function __construct(
        private readonly ?DatabaseConnectionFactory $dbFactory = null,
    ) {
    }

    /** @param array<string, string|null>|null $resolverConfig */
    public function create(?array $resolverConfig, array $resolvedProviderConfig): MemberResolver
    {
        if ($resolverConfig === null) {
            return new NullMemberResolver();
        }

        return match ($resolverConfig['type'] ?? '') {
            'database' => new DatabaseMemberResolver(
                $this->dbFactory ?? throw new \RuntimeException(
                    'DatabaseMemberResolver requested but no DatabaseConnectionFactory available'
                ),
                $resolvedProviderConfig,
                $resolverConfig['members-table'] ?? 'list_members',
            ),
            'ldap' => new LdapMemberResolver(
                $resolverConfig['ldap-host'],
                $resolverConfig['ldap-base-dn'],
                $resolverConfig['ldap-bind-dn'],
                $resolverConfig['ldap-bind-password'],
            ),
            'csv' => new CsvMemberResolver(
                $resolverConfig['file'] ?? throw new \RuntimeException('CsvMemberResolver requires a "file" config key'),
            ),
            default => new NullMemberResolver(),
        };
    }

    /**
     * Normalizes a `member-resolver:`/`owner-resolver:`/`members:`/`owners:` raw
     * config value into a list of independent MemberResolver sources — used to
     * let a list combine more than one member/owner source (see
     * CompositeMemberResolver). Accepts:
     * - null/[] — no sources.
     * - a single resolver-config map (has `type:` — `database`/`ldap`/`csv`) —
     *   backward-compatible with the pre-existing single-resolver `member-resolver:`
     *   shape, one element via create().
     * - a sequential list, each entry either a resolver-config map (same `type:`
     *   check) or a bare inline entry (string, or a map without a recognized
     *   `type:` — the same shape `members:`/`owners:` entries already use),
     *   converted via InlineMemberResolver::toMember() and wrapped in a single
     *   InlineMemberResolver per entry.
     *
     * @param array<string, mixed>|array<int, array<string, mixed>|string>|null $config
     * @return MemberResolver[]
     */
    public function buildSources(array|null $config, array $resolvedProviderConfig): array
    {
        if ($config === null || $config === []) {
            return [];
        }

        if (self::isResolverConfig($config)) {
            return [$this->create($config, $resolvedProviderConfig)];
        }

        $sources = [];
        foreach ($config as $entry) {
            if (is_array($entry) && self::isResolverConfig($entry)) {
                $sources[] = $this->create($entry, $resolvedProviderConfig);
                continue;
            }
            // Bare inline entry (string, or a map with `mail` — same shape
            // members:/owners: already use) — InlineMemberResolver's own
            // constructor does the toMember() conversion, so $entry is passed
            // through as-is here. Populated as both members and owners of its
            // own InlineMemberResolver; harmless, since a source built here is
            // only ever placed into one of CompositeMemberResolver's two source
            // lists, so only the matching getMembers()/getOwners() side is ever
            // queried.
            $sources[] = new InlineMemberResolver([$entry], [$entry]);
        }
        return $sources;
    }

    /** @param array<string, mixed> $entry */
    private static function isResolverConfig(array $entry): bool
    {
        return in_array($entry['type'] ?? null, ['database', 'ldap', 'csv'], true);
    }

    /**
     * Wraps $base with any extra member/owner sources found in $override
     * (root-level `lists: <name>:` — see CLAUDE.md "Root-level lists:") —
     * additive, never replacing $base, so a list's own directory/database
     * membership is never lost, only supplemented. `member-resolver:`/
     * `owner-resolver:` and `members:`/`owners:` are equally valid here (the
     * latter just for the common case of adding a few bare addresses, without
     * needing to spell out a full resolver-config).
     *
     * @param array<string, mixed> $override
     */
    public function applyOverride(MemberResolver $base, array $override, array $resolvedProviderConfig): MemberResolver
    {
        $extraMembers = array_merge(
            $this->buildSources($override['member-resolver'] ?? null, $resolvedProviderConfig),
            $this->buildSources($override['members'] ?? null, $resolvedProviderConfig),
        );
        $extraOwners = array_merge(
            $this->buildSources($override['owner-resolver'] ?? null, $resolvedProviderConfig),
            $this->buildSources($override['owners'] ?? null, $resolvedProviderConfig),
        );

        if ($extraMembers === [] && $extraOwners === []) {
            return $base;
        }

        return new CompositeMemberResolver(
            [$base, ...$extraMembers],
            [$base, ...($extraOwners !== [] ? $extraOwners : [$base])],
        );
    }
}
