<?php

declare(strict_types=1);

namespace Hengeb\Listig\Member;

use Hengeb\Listig\Database\DatabaseConnectionFactory;

/**
 * Builds member/owner resolvers from config.yml's `member-resolver:`/
 * `owner-resolver:`/`members:`/`owners:` — a single resolver-config
 * (`database`/`ldap`/`csv`), a list of them mixed with bare inline entries
 * (buildSources()), or the full three-level (global/provider/list) additive
 * composition for one list (buildComposedResolver()). Shared by every list
 * provider.
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
     * Builds the final MemberResolver for one list, composing every configured
     * source across all three levels (global config.yml root, provider, list —
     * see CLAUDE.md "Global / provider / list levels") for both roles, always
     * additively — there is no more "base vs. override" distinction; every
     * source, from any level, simply contributes to the union. $extraBase, when
     * given, is unconditionally included in both roles — LdapListProvider's own
     * hardcoded LdapMemberResolver, which (unlike every other provider type) is
     * never expressed via member-resolver: at all (see CLAUDE.md "type: ldap").
     *
     * @param array<int, mixed> $memberResolverLevels member-resolver: sources, global/provider/list (see AbstractListProvider::scopedLevels())
     * @param array<int, mixed> $membersLevels members: sources, global/provider/list
     * @param array<int, mixed> $ownerResolverLevels owner-resolver: sources, global/provider/list
     * @param array<int, mixed> $ownersLevels owners: sources, global/provider/list
     */
    public function buildComposedResolver(
        array $memberResolverLevels,
        array $membersLevels,
        array $ownerResolverLevels,
        array $ownersLevels,
        array $resolvedProviderConfig,
        ?MemberResolver $extraBase = null,
    ): MemberResolver {
        $base = $extraBase !== null ? [$extraBase] : [];

        $memberSources = array_merge(
            $base,
            $this->buildSourcesFromLevels($memberResolverLevels, $resolvedProviderConfig),
            $this->buildSourcesFromLevels($membersLevels, $resolvedProviderConfig),
        );
        $ownerSources = array_merge(
            $base,
            $this->buildSourcesFromLevels($ownerResolverLevels, $resolvedProviderConfig),
            $this->buildSourcesFromLevels($ownersLevels, $resolvedProviderConfig),
        );

        return new CompositeMemberResolver($memberSources, $ownerSources);
    }

    /**
     * @param array<int, mixed> $levels
     * @return MemberResolver[]
     */
    private function buildSourcesFromLevels(array $levels, array $resolvedProviderConfig): array
    {
        return array_merge(...array_map(
            fn($raw) => $this->buildSources($raw, $resolvedProviderConfig),
            $levels,
        ));
    }
}
