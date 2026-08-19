<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

use PDO;

/**
 * Backs the `restrict` automatic bounce action (see CLAUDE.md "Automatic
 * bounce actions") — a small, dedicated, DB-gated collaborator (like
 * RateLimiter) rather than SQL inline in MailProcessor, which per "Coding
 * Conventions" may not run SQL itself. Deliberately independent of every
 * list's own ListProvider/MemberResolver backend (LDAP/database/csv/inline):
 * an address suppressed here is skipped at send time regardless of which
 * backend the list's own membership comes from, without needing write access
 * to that backend at all. Not an extension of the existing, purely
 * config-derived `restricted-members:`/RestrictionList mechanism — see the
 * class docblock discussion in CLAUDE.md for why a dedicated table was
 * chosen instead for this iteration.
 */
class BounceSuppressionList
{
    public function __construct(
        private readonly PDO $db,
    ) {
    }

    public function suppress(string $listCn, string $envelopeTo, string $reason): void
    {
        $stmt = $this->db->prepare(
            'INSERT INTO bounce_suppressed_members (list_cn, envelope_to, reason, created_at)
             VALUES (:list, :envelope_to, :reason, NOW())
             ON DUPLICATE KEY UPDATE reason = VALUES(reason), created_at = VALUES(created_at)'
        );
        $stmt->execute(['list' => $listCn, 'envelope_to' => $envelopeTo, 'reason' => $reason]);
    }

    public function isSuppressed(string $listCn, string $envelopeTo): bool
    {
        $stmt = $this->db->prepare(
            'SELECT 1 FROM bounce_suppressed_members WHERE list_cn = :list AND LOWER(envelope_to) = LOWER(:envelope_to) LIMIT 1'
        );
        $stmt->execute(['list' => $listCn, 'envelope_to' => $envelopeTo]);
        return $stmt->fetchColumn() !== false;
    }

    /**
     * For the manage page's own suppression table (see CLAUDE.md "Automatic
     * bounce actions") — rendered only when non-empty, so owners see *why* an
     * address stopped receiving mail instead of it silently vanishing.
     *
     * @return array<array{envelope_to: string, reason: string, created_at: string}>
     */
    public function listForOwner(string $listCn): array
    {
        $stmt = $this->db->prepare(
            'SELECT envelope_to, reason, created_at FROM bounce_suppressed_members WHERE list_cn = :list ORDER BY created_at DESC'
        );
        $stmt->execute(['list' => $listCn]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}
