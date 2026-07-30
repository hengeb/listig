<?php

declare(strict_types=1);

namespace Hengeb\Listig\Provider;

use Hengeb\Listig\Config\ConfigResolver;
use Hengeb\Listig\Config\ListConfig;

/**
 * Shared "list directory query result" caching every ListProvider needs (see
 * ListProvider::reset()), plus the getLists()/getList() lookup logic built on
 * top of it — before this class existed, both were identical or near-identical
 * copy-pasted boilerplate in every concrete provider. getLists()/getList()
 * only ever differ in *how* $lists gets populated; that part is what
 * loadLists() implements per subclass.
 */
abstract class AbstractListProvider implements ListProvider
{
    /** @var array<string, ListConfig>|null */
    protected ?array $lists = null;

    private ?array $resolvedProviderConfigCache = null;

    public function __construct(
        protected readonly string $name,
        protected readonly ConfigResolver $configResolver,
        protected readonly array $providerConfig,
    ) {
    }

    /**
     * Queries this provider's backing store and returns every list it
     * defines, keyed by list name. Called at most once per reset() cycle —
     * getLists()/getList() cache the result in $this->lists.
     *
     * Return null (rather than throwing) for a transient failure that should
     * be retried on the very next call within the same cycle instead of being
     * cached as "no lists at all" — LdapListProvider is the one subclass that
     * needs this (an LDAP outage must not look identical to "directory has
     * zero lists" for the rest of the cycle). Every other subclass either
     * succeeds or throws (a config/data error, not a transient one —
     * propagates uncaught, same as before this class existed).
     *
     * @return array<string, ListConfig>|null
     */
    abstract protected function loadLists(): ?array;

    public function getLists(): array
    {
        if ($this->lists !== null) {
            return array_values($this->lists);
        }

        $lists = $this->loadLists();
        if ($lists === null) {
            return [];
        }

        $this->lists = $lists;
        return array_values($this->lists);
    }

    /**
     * Default lookup: load everything, then pick one out. DatabaseListProvider
     * overrides this — a single targeted row fetch is cheaper than loading
     * every list just to answer one lookup when $lists isn't cached yet.
     */
    public function getList(string $name): ?ListConfig
    {
        $this->getLists();
        return $this->lists[$name] ?? null;
    }

    /** @see ListProvider::reset() */
    public function reset(): void
    {
        $this->lists = null;
    }

    /**
     * Provider-level resolved config (root use:/direct + this provider's own
     * use:/direct — no per-list overrides). Cached for the process lifetime,
     * not reset()-bounded like $lists: it's derived purely from config.yml's
     * own structure, which only ever changes via a full process restart (see
     * CLAUDE.md "Worker loop — config reload").
     */
    protected function resolvedProviderConfig(): array
    {
        return $this->resolvedProviderConfigCache ??= $this->configResolver->resolveListConfig($this->providerConfig);
    }
}
