<?php

declare(strict_types=1);

namespace Hengeb\Listig\Provider;

use Hengeb\Listig\Config\ConfigResolver;
use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Crypto\PasswordCrypto;
use Hengeb\Listig\Member\LdapMemberResolver;
use Symfony\Component\Ldap\Entry;
use Symfony\Component\Ldap\Ldap;

class LdapListProvider implements ListProvider
{
    private ?Ldap $ldap = null;
    private ?array $lists = null;
    private ?array $resolvedProviderConfig = null;

    public function __construct(
        private readonly string $name,
        private readonly ConfigResolver $configResolver,
        private readonly array $providerConfig,
    ) {
    }

    /**
     * $providerConfig (the constructor arg) is the raw list-providers.{name} entry —
     * if it sets ldap-host/ldap-base-dn/etc. via its own `use:` (e.g. `use: [ldap-config]`
     * referencing a root-level named block) rather than as direct keys, those keys are
     * simply absent from it; `use:` is only ever merged in by
     * ConfigResolver::resolveListConfig(). Every method below that needs ldap-* reads
     * this resolved config instead of $this->providerConfig directly — entryToListConfig()
     * is the one exception, since it already calls resolveListConfig() itself (with
     * per-list description[] overrides layered on top, which this cached, provider-level-only
     * resolution deliberately excludes).
     */
    private function resolvedProviderConfig(): array
    {
        return $this->resolvedProviderConfig ??= $this->configResolver->resolveListConfig($this->providerConfig);
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
            error_log("Listig: LDAP connection failed for list provider '{$this->name}' ({$this->resolvedProviderConfig()['ldap-host']}): " . $e->getMessage());
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
                $listName = ($entry->getAttribute('cn') ?? [])[0] ?? 'unknown';
                error_log("Listig: Failed to load LDAP list '$listName' from provider '{$this->name}', skipping: " . $e->getMessage());
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
        $config = $this->resolvedProviderConfig();
        $listDn = $config['ldap-list-dn'] ?? $config['ldap-base-dn'];
        $filter = $config['ldap-filter'] ?? '(objectClass=mailGroup)';

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

        // Unlike a config.yml value (always trusted plaintext, e.g. from .env via
        // $VAR), a password stored directly in LDAP's description[] should be
        // encrypted — see PasswordCrypto::warnIfPlaintext().
        foreach (['password', 'mail-password', 'imap-password', 'smtp-password'] as $key) {
            PasswordCrypto::warnIfPlaintext($key, $listOverrides[$key] ?? '', "LDAP description[] for list '$name'");
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
        $config = $this->resolvedProviderConfig();
        $listDn = $config['ldap-list-dn'] ?? $config['ldap-base-dn'];
        $filter = "(&(objectClass=mailGroup)(cn={$this->escape($listName)}))";

        $entry = null;
        foreach ($ldap->query($listDn, $filter)->execute() as $e) {
            $entry = $e;
            break;
        }

        if ($entry === null) {
            throw new \RuntimeException("List '$listName' not found in LDAP (provider '{$this->name}')");
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
        $config = $this->resolvedProviderConfig();
        return new LdapMemberResolver(
            $config['ldap-host'],
            $config['ldap-base-dn'],
            $config['ldap-bind-dn'],
            $config['ldap-bind-password'],
        );
    }

    private function connect(): Ldap
    {
        if ($this->ldap === null) {
            $config = $this->resolvedProviderConfig();
            $this->ldap = Ldap::create('ext_ldap', [
                'connection_string' => $config['ldap-host'],
            ]);
            $this->ldap->bind(
                $config['ldap-bind-dn'],
                $config['ldap-bind-password'],
            );
        }
        return $this->ldap;
    }
}
