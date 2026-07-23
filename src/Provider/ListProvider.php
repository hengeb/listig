<?php

declare(strict_types=1);

namespace Hengeb\Listig\Provider;

use Hengeb\Listig\Config\ListConfig;

interface ListProvider
{
    /** @return ListConfig[] */
    public function getLists(): array;

    public function getList(string $name): ?ListConfig;

    /**
     * Persists a single config key/value for an existing list in this provider's
     * backing store (LDAP description[] entry, DB config-table row). Throws
     * \RuntimeException if the provider's backing store is read-only at runtime
     * (inline config.yml, YAML file) or the list doesn't exist in this provider.
     */
    public function setListConfigValue(string $listName, string $key, string $value): void;
}
