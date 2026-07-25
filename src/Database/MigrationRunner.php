<?php

declare(strict_types=1);

namespace Hengeb\Listig\Database;

use PDO;

/**
 * Applies pending *.sql files from migrations/ and records them in schema_migrations,
 * so a fresh or upgraded deployment never needs a migration file downloaded or applied
 * by hand — see CLAUDE.md "Database migrations".
 *
 * Migration files must be idempotent (e.g. CREATE TABLE IF NOT EXISTS): MariaDB commits
 * DDL implicitly, so a crash between running a file's SQL and recording it as applied
 * cannot be rolled back — the file is simply re-run on the next start, and idempotency
 * is what makes that safe rather than merely convenient.
 */
class MigrationRunner
{
    public function __construct(
        private readonly PDO $db,
        private readonly string $migrationsPath = __DIR__ . '/../../migrations',
    ) {
    }

    /** @return string[] filenames of migrations applied during this call (empty if already up to date) */
    public function run(): array
    {
        $this->db->exec(
            'CREATE TABLE IF NOT EXISTS schema_migrations (
                version    VARCHAR(255) NOT NULL PRIMARY KEY,
                applied_at DATETIME NOT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
        );

        $applied = $this->db->query('SELECT version FROM schema_migrations')->fetchAll(PDO::FETCH_COLUMN);
        $appliedSet = array_flip($applied);

        // Zero-padded numeric prefixes (001_, 002_, ...) sort correctly as plain strings —
        // see CLAUDE.md for the naming convention new migration files must follow.
        $files = glob($this->migrationsPath . '/*.sql') ?: [];
        sort($files, SORT_STRING);

        $newlyApplied = [];
        foreach ($files as $file) {
            $version = basename($file);
            if (isset($appliedSet[$version])) {
                continue;
            }

            $sql = file_get_contents($file);
            if ($sql === false) {
                throw new \RuntimeException("Could not read migration file: $file");
            }

            $this->db->exec($sql);

            $stmt = $this->db->prepare(
                'INSERT INTO schema_migrations (version, applied_at) VALUES (:version, NOW())'
            );
            $stmt->execute(['version' => $version]);

            $newlyApplied[] = $version;
        }

        return $newlyApplied;
    }
}
