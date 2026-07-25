<?php

declare(strict_types=1);

namespace Hengeb\Listig\Provider;

use Hengeb\Listig\Config\ConfigResolver;
use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Database\DatabaseConnectionFactory;
use Hengeb\Listig\Member\MemberResolverFactory;
use PDO;

class DatabaseListProvider implements ListProvider
{
    private ?array $lists = null;
    private ?array $resolvedConfig = null;
    private readonly MemberResolverFactory $memberResolverFactory;

    public function __construct(
        private readonly string $name,
        private readonly ConfigResolver $configResolver,
        private readonly array $providerConfig,
        private readonly DatabaseConnectionFactory $dbFactory,
    ) {
        $this->memberResolverFactory = new MemberResolverFactory($this->dbFactory);
    }

    public function getLists(): array
    {
        if ($this->lists !== null) {
            return $this->lists;
        }

        $this->lists = [];
        $table = $this->providerConfig['config-table'] ?? 'list_config';

        $stmt = $this->db()->query("SELECT DISTINCT name FROM {$table}");
        $names = $stmt->fetchAll(PDO::FETCH_COLUMN);

        foreach ($names as $name) {
            $list = $this->loadList($name, $table);
            if ($list !== null) {
                $this->lists[$name] = $list;
            }
        }

        return array_values($this->lists);
    }

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

        $raw = $this->configResolver->resolveListConfig($this->providerConfig, $rows);
        $raw['name'] = $name;
        $raw['mail'] = $mail;

        $memberResolver = $this->memberResolverFactory->create(
            $this->providerConfig['member-resolver'] ?? null,
            $this->resolvedConfig(),
        );

        return new ListConfig($name, $mail, $raw, $memberResolver);
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
        return $this->dbFactory->getConnection($this->resolvedConfig());
    }

    /** Provider-level resolved config (no per-list overrides) — cached for reuse. */
    private function resolvedConfig(): array
    {
        return $this->resolvedConfig ??= $this->configResolver->resolveListConfig($this->providerConfig);
    }
}
