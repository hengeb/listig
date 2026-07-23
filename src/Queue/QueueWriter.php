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
        $mimeString = $email->toString();
        $id = hash('sha256', $listCn . ':' . $mimeString);

        $this->db->beginTransaction();
        try {
            $stmt = $this->db->prepare(
                'INSERT INTO mail_queue (id, list_cn, batch_id, mime, created_at) VALUES (:id, :list, :batch, :mime, NOW())
                 ON DUPLICATE KEY UPDATE id=id'
            );
            $stmt->execute(['id' => $id, 'list' => $listCn, 'batch' => $batchId, 'mime' => $mimeString]);

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
