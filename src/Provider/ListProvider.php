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
     * Discards any cached list-directory data (LDAP entries, DB config-table
     * rows, a type: yaml provider's file contents, ...) so the next
     * getLists()/getList() call re-reads the backing store instead of reusing
     * data fetched earlier in this same process. Called once per worker cycle
     * (see bin/worker.php, mirroring ImapMailboxFactory::reset()) — without it,
     * a provider that succeeded once would otherwise keep serving that first
     * result for the worker's entire lifetime (see CLAUDE.md "Worker loop —
     * config reload").
     */
    public function reset(): void;

    /**
     * Persists a single config key/value for an existing list in this provider's
     * backing store (LDAP description[] entry, DB config-table row). Throws
     * \RuntimeException if the provider's backing store is read-only at runtime
     * (inline config.yml, YAML file) or the list doesn't exist in this provider.
     */
    public function setListConfigValue(string $listName, string $key, string $value): void;
}
