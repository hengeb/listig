<?php

declare(strict_types=1);

namespace Hengeb\Listig\Archive;

/**
 * Annotates an already-SQL-sorted page of archived_mail rows (see
 * ArchiveController::index()'s query — threads sorted by their most recent
 * message, rows within a thread oldest-first) with per-row `depth`,
 * `thread_size`, and `is_thread_start`, ready for the table template to render
 * indentation/collapsing. Pure PHP, no DB access — depth is resolved by walking
 * `in_reply_to` against `message_id` of OTHER ROWS ON THIS PAGE ONLY; a row whose
 * parent isn't present on the page is simply depth 0 (still grouped under the
 * same thread_root, just not indented) — not an error.
 */
class ArchiveThreader
{
    /**
     * @param array<int, array<string, mixed>> $rows
     * @return array<int, array<string, mixed>>
     */
    public function annotate(array $rows): array
    {
        $indexByMessageId = [];
        foreach ($rows as $i => $row) {
            $indexByMessageId[$row['message_id']] = $i;
        }

        $threadSizes = [];
        foreach ($rows as $row) {
            $threadSizes[$row['thread_root']] = ($threadSizes[$row['thread_root']] ?? 0) + 1;
        }

        $lastThreadRoot = null;
        foreach ($rows as $i => &$row) {
            $row['depth']           = $this->depthOf($row, $rows, $indexByMessageId);
            $row['thread_size']     = $threadSizes[$row['thread_root']];
            $row['is_thread_start'] = $row['thread_root'] !== $lastThreadRoot;
            $lastThreadRoot         = $row['thread_root'];
        }
        unset($row);

        return $rows;
    }

    /** @param array<int, array<string, mixed>> $rows */
    private function depthOf(array $row, array $rows, array $indexByMessageId): int
    {
        $depth  = 0;
        $seen   = [];
        $parent = $row['in_reply_to'];

        // 50 is far beyond any realistic reply chain — a safety valve against a
        // malformed/cyclical In-Reply-To chain looping forever, not a real limit.
        while ($parent !== null && isset($indexByMessageId[$parent]) && !isset($seen[$parent]) && $depth < 50) {
            $seen[$parent] = true;
            $depth++;
            $parent = $rows[$indexByMessageId[$parent]]['in_reply_to'];
        }

        return $depth;
    }
}
