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
}
