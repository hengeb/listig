<?php

declare(strict_types=1);

namespace Hengeb\Listig\Member;

use Hengeb\Listig\Database\DatabaseConnectionFactory;
use PDO;

/**
 * Reads/writes an arbitrary EAV-style members-table. Only `name` (list name),
 * `mail`, `is_member`, `is_owner` are reserved/structural — every other column
 * a deployment happens to add (firstname, lastname, pronoun, title, ...) is
 * read via SELECT * and exposed on Member::$attributes under its own column
 * name, with zero hardcoded field names in this class.
 */
class DatabaseMemberResolver implements MemberResolver
{
    private const RESERVED_COLUMNS = ['name', 'mail', 'is_member', 'is_owner'];

    public function __construct(
        private readonly DatabaseConnectionFactory $dbFactory,
        private readonly array $dbConfig,
        private readonly string $membersTable = 'list_members',
    ) {
    }

    public function getMembers(string $name): array
    {
        $stmt = $this->db()->prepare(
            "SELECT * FROM {$this->membersTable} WHERE name = :name AND is_member = 1"
        );
        $stmt->execute(['name' => $name]);
        return array_map(fn(array $row) => $this->rowToMember($row), $stmt->fetchAll(PDO::FETCH_ASSOC));
    }

    public function getOwners(string $name): array
    {
        $stmt = $this->db()->prepare(
            "SELECT * FROM {$this->membersTable} WHERE name = :name AND is_owner = 1"
        );
        $stmt->execute(['name' => $name]);
        return array_map(fn(array $row) => $this->rowToMember($row), $stmt->fetchAll(PDO::FETCH_ASSOC));
    }

    public function findByEmail(string $email): ?Member
    {
        $stmt = $this->db()->prepare(
            "SELECT * FROM {$this->membersTable} WHERE mail = :mail LIMIT 1"
        );
        $stmt->execute(['mail' => $email]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($row === false) {
            return null;
        }
        return $this->rowToMember($row);
    }

    public function removeMember(string $listName, string $email): void
    {
        $this->db()->prepare(
            "UPDATE {$this->membersTable} SET is_member = 0 WHERE name = :name AND mail = :mail"
        )->execute(['name' => $listName, 'mail' => $email]);

        $this->db()->prepare(
            "DELETE FROM {$this->membersTable} WHERE name = :name AND mail = :mail AND is_member = 0 AND is_owner = 0"
        )->execute(['name' => $listName, 'mail' => $email]);
    }

    /**
     * Builds the INSERT/UPDATE column list dynamically from $member->attributes
     * — the whole point of a schema-less members table. Attribute names are
     * validated as plain SQL identifiers (and backtick-quoted) before being
     * interpolated into the query; PDO placeholders cover values, not column
     * names, so this validation is what actually prevents SQL injection via a
     * maliciously named attribute. An attribute naming a column that doesn't
     * really exist in the table still fails, just at the database (unknown
     * column), not here.
     */
    public function addMember(string $listName, Member $member): void
    {
        $attributes = array_diff_key($member->attributes, array_flip(self::RESERVED_COLUMNS));
        foreach (array_keys($attributes) as $column) {
            if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $column)) {
                throw new \RuntimeException("Invalid attribute name '$column' — cannot be used as a database column");
            }
        }

        $columns = array_keys($attributes);
        $insertColumns = array_merge(['name', 'mail'], $columns);
        $quoted = array_map(fn($c) => "`$c`", $insertColumns);
        $placeholders = array_map(fn($c) => ":$c", $insertColumns);
        $updateClause = array_map(fn($c) => "`$c` = VALUES(`$c`)", $columns);

        $sql = "INSERT INTO {$this->membersTable} (" . implode(', ', $quoted) . ", is_member, is_owner)
                VALUES (" . implode(', ', $placeholders) . ", 1, 0)
                ON DUPLICATE KEY UPDATE is_member = 1"
            . ($updateClause !== [] ? ', ' . implode(', ', $updateClause) : '');

        $stmt = $this->db()->prepare($sql);
        $stmt->execute(array_merge(['name' => $listName, 'mail' => $member->email], $attributes));
    }

    private function db(): PDO
    {
        return $this->dbFactory->getConnection($this->dbConfig);
    }

    private function rowToMember(array $row): Member
    {
        $mail = $row['mail'];
        $attributes = array_diff_key($row, array_flip(self::RESERVED_COLUMNS));
        $attributes = array_map(fn($v) => $v === null ? '' : (string) $v, $attributes);
        return new Member($mail, $attributes);
    }
}
