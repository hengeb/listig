<?php

declare(strict_types=1);

namespace Hengeb\Listig\Member;

/**
 * Resolves members/owners from a flat CSV file, shared across lists like
 * DatabaseMemberResolver's members-table (rows are scoped by a `name` column).
 * Only `name`, `mail`, `is_member`, `is_owner` are reserved/structural — every
 * other column the file happens to have (firstname, lastname, pronoun, title,
 * ...) is read as-is and exposed on Member::$attributes under its own column
 * name, with zero hardcoded field names in this class. The header row is
 * whatever the file currently has; addMember() extends it with any new
 * attribute key it's asked to write, backfilling '' for every other row.
 *
 * Rows are re-read from disk on every call rather than cached in memory — CSV
 * files are expected to be small, and this avoids serving stale data across
 * requests/worker cycles without needing explicit cache invalidation. Reads
 * are lock-free; writes (addMember/removeMember) take an exclusive flock for
 * the whole read-modify-write. This makes concurrent writers safe against each
 * other but not against a reader observing a write mid-flight — a lightweight
 * option, not a substitute for the database backend where that matters.
 */
class CsvMemberResolver implements MemberResolver
{
    private const RESERVED_COLUMNS = ['name', 'mail', 'is_member', 'is_owner'];

    public function __construct(
        private readonly string $file,
    ) {
    }

    public function getMembers(string $name): array
    {
        return $this->filter($this->readRows(), $name, fn(array $r) => $r['is_member']);
    }

    public function getOwners(string $name): array
    {
        return $this->filter($this->readRows(), $name, fn(array $r) => $r['is_owner']);
    }

    public function findByEmail(string $email): ?Member
    {
        $email = strtolower($email);
        foreach ($this->readRows() as $row) {
            if (strtolower($row['mail']) === $email) {
                return $this->rowToMember($row);
            }
        }
        return null;
    }

    public function supportsRemoval(): bool
    {
        return true;
    }

    public function removeMember(string $listName, string $email): void
    {
        $email = strtolower($email);

        $this->withLock(function (array $rows) use ($listName, $email): array {
            $result = [];
            foreach ($rows as $row) {
                if ($row['name'] === $listName && strtolower($row['mail']) === $email) {
                    if ($row['is_owner']) {
                        $row['is_member'] = false;
                        $result[] = $row;
                    }
                    // else: drop the row entirely (no longer member or owner)
                    continue;
                }
                $result[] = $row;
            }
            return $result;
        });
    }

    public function addMember(string $listName, Member $member): void
    {
        $email = strtolower($member->email);

        $this->withLock(function (array $rows) use ($listName, $email, $member): array {
            foreach ($rows as $i => $row) {
                if ($row['name'] === $listName && strtolower($row['mail']) === $email) {
                    $rows[$i]['is_member'] = true;
                    $rows[$i] = array_merge($rows[$i], $member->attributes);
                    return $rows;
                }
            }
            $rows[] = array_merge(
                ['name' => $listName, 'mail' => $member->email, 'is_member' => true, 'is_owner' => false],
                $member->attributes,
            );
            return $rows;
        });
    }

    /** @return Member[] */
    private function filter(array $rows, string $name, callable $predicate): array
    {
        $result = [];
        foreach ($rows as $row) {
            if ($row['name'] === $name && $predicate($row)) {
                $result[] = $this->rowToMember($row);
            }
        }
        return $result;
    }

    private function rowToMember(array $row): Member
    {
        $attributes = array_diff_key($row, array_flip(self::RESERVED_COLUMNS));
        return new Member($row['mail'], $attributes);
    }

    /** @return list<array<string, mixed>> */
    private function readRows(): array
    {
        if (!file_exists($this->file)) {
            return [];
        }

        $handle = fopen($this->file, 'r');
        if ($handle === false) {
            throw new \RuntimeException("Cannot open CSV member file: {$this->file}");
        }

        try {
            return $this->parseHandle($handle);
        } finally {
            fclose($handle);
        }
    }

    /**
     * @param resource $handle
     * @return list<array<string, mixed>>
     */
    private function parseHandle($handle): array
    {
        $header = fgetcsv($handle);
        if ($header === false) {
            return [];
        }

        $rows = [];
        while (($data = fgetcsv($handle)) !== false) {
            $raw = array_combine($header, $data);
            $row = [
                'name' => $raw['name'] ?? '',
                'mail' => $raw['mail'] ?? '',
                'is_member' => ($raw['is_member'] ?? '1') !== '0',
                'is_owner' => ($raw['is_owner'] ?? '0') === '1',
            ];
            foreach ($raw as $key => $value) {
                if (!in_array($key, self::RESERVED_COLUMNS, true)) {
                    $row[$key] = $value;
                }
            }
            $rows[] = $row;
        }
        return $rows;
    }

    /**
     * Opens the file once, holds an exclusive lock for the whole read-modify-write,
     * and writes through the same handle — never a second, unlocked one.
     */
    private function withLock(callable $mutator): void
    {
        $handle = fopen($this->file, 'c+');
        if ($handle === false) {
            throw new \RuntimeException("Cannot lock CSV member file: {$this->file}");
        }

        try {
            flock($handle, LOCK_EX);
            rewind($handle);
            $rows = $this->parseHandle($handle);
            $rows = $mutator($rows);

            // Header: reserved columns first, then every non-reserved key seen
            // across all rows (first-seen order) — so a newly written attribute
            // that never had a column gets one, backfilled with '' elsewhere.
            $extra = [];
            foreach ($rows as $row) {
                foreach (array_keys($row) as $key) {
                    if (!in_array($key, self::RESERVED_COLUMNS, true) && !in_array($key, $extra, true)) {
                        $extra[] = $key;
                    }
                }
            }
            $header = ['name', 'mail', ...$extra, 'is_member', 'is_owner'];

            ftruncate($handle, 0);
            rewind($handle);
            fputcsv($handle, $header);
            foreach ($rows as $row) {
                fputcsv($handle, array_map(
                    fn(string $col) => match ($col) {
                        'is_member' => $row['is_member'] ? '1' : '0',
                        'is_owner'  => $row['is_owner'] ? '1' : '0',
                        default     => $row[$col] ?? '',
                    },
                    $header,
                ));
            }
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }
}
