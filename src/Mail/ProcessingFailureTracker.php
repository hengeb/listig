<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

use PDO;

/**
 * Bounds how many times bin/worker.php retries the same incoming mail after an
 * unexpected exception anywhere in its per-mail processing pipeline (filtering,
 * distribution, bounce/reject/moderation handling). Without this, a mail that
 * reliably crashes processing would be re-fetched and re-crash on every single
 * worker cycle forever — silently, since nothing marks it seen and nothing
 * tells the list owner (confirmed live: a non-conformant Content-ID, see
 * MailProcessor, retried every ~20s for at least several minutes with no signal
 * beyond docker logs). Persisted in the DB, not an in-memory counter, so the
 * attempt count survives a worker restart between cycles — same durability as
 * imap_seen/moderation_queue.
 */
class ProcessingFailureTracker
{
    /**
     * Matches queue_recipients' own give-up threshold (see QueueSender /
     * "queue.failure_notice") — same "3 tries, then stop and tell the owner"
     * philosophy, applied to incoming-mail processing instead of outgoing queue
     * sending.
     */
    public const int MAX_ATTEMPTS = 3;

    public function __construct(
        private readonly PDO $db,
    ) {
    }

    /** Records a failed attempt and returns the new total attempt count for this mail. */
    public function recordFailure(string $listCn, int $uid, int $uidValidity, string $error): int
    {
        $stmt = $this->db->prepare(
            'INSERT INTO processing_failures (list_cn, imap_uid, imap_uidvalidity, attempts, last_error, first_attempt_at, last_attempt_at)
             VALUES (:list, :uid, :validity, 1, :error, NOW(), NOW())
             ON DUPLICATE KEY UPDATE attempts = attempts + 1, last_error = :error, last_attempt_at = NOW()'
        );
        $stmt->execute(['list' => $listCn, 'uid' => $uid, 'validity' => $uidValidity, 'error' => $error]);

        $select = $this->db->prepare(
            'SELECT attempts FROM processing_failures WHERE list_cn = :list AND imap_uid = :uid AND imap_uidvalidity = :validity'
        );
        $select->execute(['list' => $listCn, 'uid' => $uid, 'validity' => $uidValidity]);
        return (int) $select->fetchColumn();
    }

    /** Clears any tracked failures for this mail — called once it's either processed successfully or given up on. */
    public function clear(string $listCn, int $uid, int $uidValidity): void
    {
        $stmt = $this->db->prepare(
            'DELETE FROM processing_failures WHERE list_cn = :list AND imap_uid = :uid AND imap_uidvalidity = :validity'
        );
        $stmt->execute(['list' => $listCn, 'uid' => $uid, 'validity' => $uidValidity]);
    }
}
