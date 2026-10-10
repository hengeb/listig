<?php

declare(strict_types=1);

namespace Hengeb\Listig\Config;

use Hengeb\Listig\Variable\ResolutionPurpose;
use Hengeb\Listig\Variable\VariableResolver;

/**
 * Resolves `{key}` placeholders in the connection settings of a provider / the database
 * (`ldap-host`, `ldap-base-dn`, `ldap-bind-dn`, `ldap-list-dn`, `ldap-filter`, `ldap-empty-group-member`,
 * `db-host`, `db-port`, `db-name`, `db-user`) against the same merged config, so a DN can be composed
 * from another key: `ldap-bind-dn: "cn=admin,{ldap-base-dn}"`.
 *
 * These values are only ever used to connect — never shown to anybody — so they are resolved
 * `Trusted`: they may reference blocked keys (`{mail-user}`) which a user-visible template may not
 * (ADR-0014). The passwords (`ldap-bind-password`, `db-password`) are deliberately left untouched: a
 * password may legitimately contain `{...}`, which must not be read as a placeholder.
 */
final class ConnectionConfig
{
    private const array KEYS = [
        'ldap-host', 'ldap-base-dn', 'ldap-bind-dn', 'ldap-list-dn', 'ldap-filter', 'ldap-empty-group-member',
        'db-host', 'db-port', 'db-name', 'db-user',
    ];

    /**
     * @param array<string, mixed> $config the merged config the connection values come from (also the lookup context)
     * @param array<string, mixed> $fallbackContext looked up when a key is not in $config
     * @return array<string, mixed> $config with the connection values resolved
     */
    public static function resolve(array $config, array $fallbackContext = []): array
    {
        foreach (self::KEYS as $key) {
            $value = $config[$key] ?? null;
            if (is_string($value) && str_contains($value, '{')) {
                $config[$key] = VariableResolver::resolve($value, [$fallbackContext, $config], ResolutionPurpose::Trusted);
            }
        }
        return $config;
    }
}
