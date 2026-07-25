#!/usr/bin/env php
<?php

declare(strict_types=1);

use Hengeb\Listig\Database\MigrationRunner;

require_once __DIR__ . '/../vendor/autoload.php';

// Load .env
$envFile = __DIR__ . '/../.env';
if (file_exists($envFile)) {
    foreach (file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        if (str_starts_with($line, '#') || !str_contains($line, '=')) {
            continue;
        }
        [$key, $value] = explode('=', $line, 2);
        $_ENV[trim($key)] = trim($value);
        putenv(trim($key) . '=' . trim($value));
    }
}

$container = require __DIR__ . '/../config/container.php';

try {
    $applied = $container->get(MigrationRunner::class)->run();
} catch (\Throwable $e) {
    fwrite(STDERR, 'Listig: Migration failed: ' . $e->getMessage() . PHP_EOL);
    exit(1);
}

if ($applied === []) {
    fwrite(STDOUT, "Listig: Database schema is up to date.\n");
} else {
    fwrite(STDOUT, 'Listig: Applied migration(s): ' . implode(', ', $applied) . "\n");
}
