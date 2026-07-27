<?php

declare(strict_types=1);

namespace Hengeb\Listig\Archive;

/**
 * Shared by ArchiveController (building the "%size%" param for the collapsed
 * attachments summary) and the `formatBytes` Latte filter (config/container.php,
 * per-attachment size in archive/show.latte) — one formatting rule, not two.
 */
final class ByteFormatter
{
    private const UNITS = ['B', 'KB', 'MB', 'GB', 'TB'];

    public static function format(?int $bytes): string
    {
        if ($bytes === null) {
            return '';
        }

        $value = (float) $bytes;
        $unitIndex = 0;
        while ($value >= 1024.0 && $unitIndex < count(self::UNITS) - 1) {
            $value /= 1024.0;
            $unitIndex++;
        }

        $formatted = $unitIndex === 0 ? (string) $bytes : number_format($value, 1);
        return "{$formatted} " . self::UNITS[$unitIndex];
    }
}
