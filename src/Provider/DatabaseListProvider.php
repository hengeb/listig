<?php

declare(strict_types=1);

namespace Hengeb\Listig\Provider;

use Hengeb\Listig\Config\ConfigResolver;
use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Config\RestrictionList;
use Hengeb\Listig\Crypto\PasswordCrypto;
use Hengeb\Listig\Database\DatabaseConnectionFactory;
use Hengeb\Listig\Member\MemberResolverFactory;
use PDO;

class DatabaseListProvider extends AbstractListProvider
{
    private readonly MemberResolverFactory $memberResolverFactory;

    public function __construct(
        string $name,
        ConfigResolver $configResolver,
        array $providerConfig,
        private readonly DatabaseConnectionFactory $dbFactory,
    ) {
        parent::__construct($name, $configResolver, $providerConfig);
        $this->memberResolverFactory = new MemberResolverFactory($this->dbFactory);
    }

    /** @see AbstractListProvider::loadLists() */
    protected function loadLists(): array
    {
        $lists = [];
        $table = $this->providerConfig['config-table'] ?? 'list_config';

        $stmt = $this->db()->query("SELECT DISTINCT name FROM {$table}");
        $names = $stmt->fetchAll(PDO::FETCH_COLUMN);

        foreach ($names as $name) {
            $list = $this->loadList($name, $table);
            if ($list !== null) {
                $lists[$name] = $list;
            }
        }

        return $lists;
    }

    /**
     * Overrides AbstractListProvider's default (which would always call
     * getLists() first, loading every list just to answer one lookup) — a
     * single targeted row fetch is cheaper when $lists isn't already cached
     * this cycle.
     */
    public function getList(string $name): ?ListConfig
    {
        if ($this->lists !== null) {
            return $this->lists[$name] ?? null;
        }

        $table = $this->providerConfig['config-table'] ?? 'list_config';
        return $this->loadList($name, $table);
    }

    private function loadList(string $name, string $table): ?ListConfig
    {
        $stmt = $this->db()->prepare("SELECT `key`, value FROM {$table} WHERE name = :name");
        $stmt->execute(['name' => $name]);
        $rows = $stmt->fetchAll(PDO::FETCH_KEY_PAIR);

        $mail = $rows['mail'] ?? null;
        if ($mail === null) {
            return null;
        }

        // Unlike a config.yml value (always trusted plaintext, e.g. from .env via
        // $VAR), a password stored directly in a config-table row should be
        // encrypted — see PasswordCrypto::warnIfPlaintext().
        foreach (['mail-password', 'imap-password', 'smtp-password'] as $key) {
            PasswordCrypto::warnIfPlaintext($key, $rows[$key] ?? '', "config-table row for list '$name'");
        }

        // Root-level `lists: <name>:` — see InlineListProvider for the identical
        // pattern and docs/architecture/config.md "Root-level lists:". config-table rows are plain
        // key/value TEXT pairs, so member-resolver:/owner-resolver: (structured,
        // possibly nested config) can never come from $rows — but a scalar
        // `senders:`/`restricted-members:` string can, so all six keys are
        // excluded from the plain raw-config merge below and gathered separately
        // via scopedLevels() instead — see docs/architecture/config.md "Global / provider / list
        // levels".
        $rootOverride = $this->configResolver->getListOverride($name);
        $excludedKeys = array_flip(['member-resolver', 'owner-resolver', 'members', 'owners', 'senders', 'restricted-members']);
        $listOverrides = array_merge(array_diff_key($rows, $excludedKeys), array_diff_key($rootOverride, $excludedKeys));

        $raw = $this->configResolver->resolveListConfig($this->providerConfig, $listOverrides);
        $raw['name'] = $name;
        $raw['mail'] = $mail;

        // $listConfig for scopedLevels() combines the config-table row (list-level,
        // may include a scalar `senders:`/`restricted-members:` string) with the
        // root-level lists: override.
        $listConfig = array_merge($rows, $rootOverride);

        $memberResolver = $this->memberResolverFactory->buildComposedResolver(
            $this->scopedLevels('member-resolver', $listConfig),
            $this->scopedLevels('members', $listConfig),
            $this->scopedLevels('owner-resolver', $listConfig),
            $this->scopedLevels('owners', $listConfig),
            $this->resolvedProviderConfig(),
        );

        $raw['senders'] = array_merge(...array_map(
            fn($v) => is_string($v) ? ListConfig::splitCommaList($v) : ($v ?? []),
            $this->scopedLevels('senders', $listConfig),
        ));

        $restrictions = new RestrictionList(array_merge(...array_map(
            fn($v) => is_string($v)
                ? array_map(fn(string $mail) => ['mail' => $mail], ListConfig::splitCommaList($v))
                : ($v ?? []),
            $this->scopedLevels('restricted-members', $listConfig),
        )));

        return new ListConfig($name, $mail, $raw, $memberResolver, restrictions: $restrictions);
    }

    public function setListConfigValue(string $listName, string $key, string $value): void
    {
        $table = $this->providerConfig['config-table'] ?? 'list_config';
        $stmt = $this->db()->prepare(
            "INSERT INTO {$table} (name, `key`, value) VALUES (:name, :key, :value)
             ON DUPLICATE KEY UPDATE value = VALUES(value)"
        );
        $stmt->execute(['name' => $listName, 'key' => $key, 'value' => $value]);

        // Invalidate cache so a subsequent getLists()/getList() in this request re-reads.
        $this->lists = null;
    }

    private function db(): PDO
    {
        return $this->dbFactory->getConnection($this->resolvedProviderConfig());
    }
}
