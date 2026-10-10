<?php

declare(strict_types=1);

namespace Hengeb\Listig\Queue;

use PDO;
use Symfony\Component\Mime\Email;

class QueueWriter
{
    public function __construct(
        private readonly PDO $db,
    ) {
    }

    /**
     * @param string $batchId Groups all recipients' copies of one original incoming mail
     *                        together — see mail_queue.batch_id in migrations/001_initial.sql.
     *                        Constant across one MailProcessor::process() call, unlike $id below,
     *                        which is derived from the (possibly personalized) outgoing MIME.
     */
    public function enqueue(string $listCn, Email $email, string $envelopeTo, string $batchId): void
    {
        // The body is stored once for all recipients that get the same content; the row keeps only
        // this recipient's headers (the List-Unsubscribe token makes them differ) — ADR-0023.
        [$headers, $body] = QueueMime::split($email);
        $bodyId = QueueMime::bodyKey($body);
        $id = hash('sha256', $listCn . ':' . $headers . ':' . $bodyId);

        $this->db->beginTransaction();
        try {
            // created_at is refreshed on reuse: purge only drops bodies nobody references AND that
            // are old, so a body being reused right now cannot be pulled from under this transaction.
            $stmt = $this->db->prepare(
                'INSERT INTO mail_bodies (id, body, created_at) VALUES (:id, :body, NOW())
                 ON DUPLICATE KEY UPDATE created_at = NOW()'
            );
            $stmt->execute(['id' => $bodyId, 'body' => $body]);

            $stmt = $this->db->prepare(
                'INSERT INTO mail_queue (id, list_cn, batch_id, headers, body_id, created_at) VALUES (:id, :list, :batch, :headers, :body, NOW())
                 ON DUPLICATE KEY UPDATE id=id'
            );
            $stmt->execute(['id' => $id, 'list' => $listCn, 'batch' => $batchId, 'headers' => $headers, 'body' => $bodyId]);

            $stmt = $this->db->prepare(
                'INSERT INTO queue_recipients (mail_queue_id, envelope_to) VALUES (:qid, :to)'
            );
            $stmt->execute(['qid' => $id, 'to' => $envelopeTo]);

            $this->db->commit();
        } catch (\Throwable $e) {
            $this->db->rollBack();
            throw $e;
        }
    }
}
