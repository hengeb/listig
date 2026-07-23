<?php

declare(strict_types=1);

namespace Hengeb\Listig\Provider;

use Hengeb\Listig\Config\ConfigResolver;
use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Member\LdapMemberResolver;
use Symfony\Component\Ldap\Entry;
use Symfony\Component\Ldap\Ldap;

class LdapListProvider implements ListProvider
{
    private ?Ldap $ldap = null;
    private ?array $lists = null;

    public function __construct(
        private readonly ConfigResolver $configResolver,
        private readonly array $providerConfig,
    ) {
    }

    public function getLists(): array
    {
        if ($this->lists !== null) {
            return array_values($this->lists);
        }

        try {
            $entries = $this->queryLists();
        } catch (\Throwable $e) {
            // LDAP unreachable: log, return empty, do NOT cache so the next cycle retries
            error_log("Listig: LDAP connection failed for list provider ({$this->providerConfig['ldap-host']}): " . $e->getMessage());
            return [];
        }

        $this->lists = [];

        foreach ($entries as $entry) {
            try {
                $list = $this->entryToListConfig($entry);
                if ($list !== null) {
                    $this->lists[$list->name] = $list;
                }
            } catch (\Throwable $e) {
                $name = ($entry->getAttribute('cn') ?? [])[0] ?? 'unknown';
                error_log("Listig: Failed to load LDAP list '$name', skipping: " . $e->getMessage());
            }
        }

        return array_values($this->lists);
    }

    public function getList(string $name): ?ListConfig
    {
        $this->getLists();
        return $this->lists[$name] ?? null;
    }

    private function queryLists(): array
    {
        $ldap = $this->connect();
        $listDn = $this->providerConfig['ldap-list-dn'] ?? $this->providerConfig['ldap-base-dn'];
        $filter = $this->providerConfig['ldap-filter'] ?? '(objectClass=mailGroup)';

        return $ldap->query($listDn, $filter)->execute()->toArray();
    }

    private function entryToListConfig(Entry $entry): ?ListConfig
    {
        $name = ($entry->getAttribute('cn') ?? [])[0] ?? null;
        $mail = ($entry->getAttribute('mail') ?? [])[0] ?? null;

        if ($name === null || $mail === null) {
            return null;
        }

        // Parse description[] key:value pairs
        $descriptions = $entry->getAttribute('description') ?? [];
        $listOverrides = [];
        foreach ($descriptions as $desc) {
            if (preg_match('/^([^:]+):(.*)$/', $desc, $m)) {
                $listOverrides[trim($m[1])] = trim($m[2]);
            }
        }

        $raw = $this->configResolver->resolveListConfig($this->providerConfig, $listOverrides);
        $raw['name'] = $name;
        $raw['mail'] = $mail;

        $memberResolver = $this->createMemberResolver();

        return new ListConfig($name, $mail, $raw, $memberResolver);
    }

    /**
     * Replaces the description[] value(s) for $key with a single new "$key:$value"
     * entry (LDAP's description attribute is multi-valued and stores unrelated
     * keys side by side, so existing values for other keys must be preserved).
     */
    public function setListConfigValue(string $listName, string $key, string $value): void
    {
        $ldap = $this->connect();
        $listDn = $this->providerConfig['ldap-list-dn'] ?? $this->providerConfig['ldap-base-dn'];
        $filter = "(&(objectClass=mailGroup)(cn={$this->escape($listName)}))";

        $entry = null;
        foreach ($ldap->query($listDn, $filter)->execute() as $e) {
            $entry = $e;
            break;
        }

        if ($entry === null) {
            throw new \RuntimeException("List '$listName' not found in LDAP");
        }

        $descriptions = $entry->getAttribute('description') ?? [];
        $prefix = "{$key}:";
        $toRemove = array_values(array_filter($descriptions, fn($d) => str_starts_with($d, $prefix)));

        $entryManager = $ldap->getEntryManager();
        if ($toRemove !== []) {
            $entryManager->removeAttributeValues($entry, 'description', $toRemove);
        }
        $entryManager->addAttributeValues($entry, 'description', ["{$key}:{$value}"]);

        // Invalidate cache so a subsequent getLists()/getList() in this request re-reads.
        $this->lists = null;
    }

    private function escape(string $value): string
    {
        return ldap_escape($value, '', LDAP_ESCAPE_FILTER);
    }

    private function createMemberResolver(): LdapMemberResolver
    {
        return new LdapMemberResolver(
            $this->providerConfig['ldap-host'],
            $this->providerConfig['ldap-base-dn'],
            $this->providerConfig['ldap-bind-dn'],
            $this->providerConfig['ldap-bind-password'],
        );
    }

    private function connect(): Ldap
    {
        if ($this->ldap === null) {
            $this->ldap = Ldap::create('ext_ldap', [
                'connection_string' => $this->providerConfig['ldap-host'],
            ]);
            $this->ldap->bind(
                $this->providerConfig['ldap-bind-dn'],
                $this->providerConfig['ldap-bind-password'],
            );
        }
        return $this->ldap;
    }
}
