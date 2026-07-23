<?php

declare(strict_types=1);

namespace Hengeb\Listig\Database;

use PDO;

/**
 * Caches PDO connections by fingerprint of the db-* config keys.
 * If two callers supply identical db-host/port/name/user/password, they share one connection.
 */
class DatabaseConnectionFactory
{
    /** @var array<string, PDO> */
    private array $cache = [];

    public function getConnection(array $config): PDO
    {
        $fingerprint = $this->fingerprint($config);
        return $this->cache[$fingerprint] ??= $this->createConnection($config);
    }

    private function fingerprint(array $config): string
    {
        return hash('sha256', implode("\0", [
            $config['db-host'] ?? '',
            $config['db-port'] ?? '',
            $config['db-name'] ?? '',
            $config['db-user'] ?? '',
            $config['db-password'] ?? '',
        ]));
    }

    private function createConnection(array $config): PDO
    {
        $host = $config['db-host'] ?? 'db';
        $port = $config['db-port'] ?? '3306';
        $name = $config['db-name'] ?? 'listig';
        $user = $config['db-user'] ?? 'listig';
        $pass = $config['db-password'] ?? '';

        return new PDO(
            "mysql:host={$host};port={$port};dbname={$name};charset=utf8mb4",
            $user,
            $pass,
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            ]
        );
    }
}
