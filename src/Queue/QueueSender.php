<?php

declare(strict_types=1);

namespace Hengeb\Listig\Queue;

use Hengeb\Listig\Mail\NotificationMailer;
use Hengeb\Listig\Provider\ListProvider;
use Hengeb\Listig\Smtp\SmtpConnectionFactory;
use PDO;
use Symfony\Component\Mailer\Envelope;
use Symfony\Component\Mailer\Mailer;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\RawMessage;
use Symfony\Contracts\Translation\TranslatorInterface;

class QueueSender
{
    public function __construct(
        private readonly PDO $db,
        private readonly SmtpConnectionFactory $smtpFactory,
        private readonly ListProvider $listProvider,
        private readonly NotificationMailer $notificationMailer,
        private readonly TranslatorInterface $translator,
        private readonly SpamRejectionDetector $spamRejectionDetector,
        private readonly string $appName,
    ) {
    }

    public function sendBatch(int $batchSize = 50): void
    {
        $stmt = $this->db->prepare(
            'SELECT qr.id, qr.mail_queue_id, qr.envelope_to, mq.list_cn, mq.batch_id, mq.mime
             FROM queue_recipients qr
             JOIN mail_queue mq ON mq.id = qr.mail_queue_id
             WHERE qr.status = \'pending\'
             ORDER BY qr.last_attempt_at ASC, qr.id ASC
             LIMIT :limit'
        );
        $stmt->bindValue('limit', $batchSize, PDO::PARAM_INT);
        $stmt->execute();
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($rows as $row) {
            $this->sendOne($row);
        }
    }

    private function sendOne(array $row): void
    {
        $recipientId = (int) $row['id'];
        $queueId = $row['mail_queue_id'];
        $listCn = $row['list_cn'];
        $batchId = $row['batch_id'];
        $envelopeTo = $row['envelope_to'];
        $mime = $row['mime'];

        // RFC 2606 reserved TLD — never a real, deliverable domain. Skip outright
        // rather than wasting an SMTP attempt (and a retry cycle) on it.
        if (self::isInvalidAddress($envelopeTo)) {
            $this->db->prepare(
                "UPDATE queue_recipients SET status = 'failed', error = :error WHERE id = :id"
            )->execute(['error' => 'Skipped: recipient uses the reserved .invalid domain', 'id' => $recipientId]);
            $this->cleanupQueueEntry($queueId);
            return;
        }

        // Update attempt
        $this->db->prepare(
            'UPDATE queue_recipients SET attempts = attempts + 1, last_attempt_at = NOW() WHERE id = :id'
        )->execute(['id' => $recipientId]);

        try {
            $list = $this->listProvider->getList($listCn);
            if ($list === null) {
                throw new \RuntimeException("List not found: $listCn");
            }

            $transport = $this->smtpFactory->getTransport($list);
            $mailer = new Mailer($transport);

            $bounceFrom = "{$listCn}+bounce@{$list->domain}";

            $mailer->send(
                new RawMessage($mime),
                new Envelope(
                    new Address($bounceFrom),
                    [new Address($envelopeTo)]
                )
            );

            // Mark sent
            $this->db->prepare(
                "UPDATE queue_recipients SET status = 'sent' WHERE id = :id"
            )->execute(['id' => $recipientId]);

            // Delete mail_queue row if all recipients are done
            $this->cleanupQueueEntry($queueId);
        } catch (\Throwable $e) {
            error_log("Listig: Failed to send to $envelopeTo for list $listCn: " . $e->getMessage());

            if ($this->spamRejectionDetector->isSpamRejection($e, $envelopeTo)) {
                $this->discardBatchAsSpam($recipientId, $batchId, $listCn, $envelopeTo, $e);
                return;
            }

            $stmtCheck = $this->db->prepare('SELECT attempts FROM queue_recipients WHERE id = :id');
            $stmtCheck->execute(['id' => $recipientId]);
            $attempts = (int) $stmtCheck->fetchColumn();

            if ($attempts >= 3) {
                $this->db->prepare(
                    "UPDATE queue_recipients SET status = 'failed', error = :error WHERE id = :id"
                )->execute(['error' => $e->getMessage(), 'id' => $recipientId]);

                $this->notifyOwnerOfFailure($listCn, $envelopeTo, $e->getMessage());
            }
        }
    }

    /**
     * A trusted large provider's mail server rejected this recipient's copy as spam
     * (see SpamRejectionDetector) — abort immediately (don't wait for 3 attempts) and
     * discard every other still-pending queued copy of the same original mail, found
     * via mail_queue.batch_id (identifies siblings across personalized copies, which
     * have different MIME/mail_queue.id — see MailProcessor::process()). Copies are
     * marked 'failed', not deleted outright, so the owner still sees and can inspect
     * them via the manage page's queue status, same as any other delivery failure.
     */
    private function discardBatchAsSpam(int $recipientId, ?string $batchId, string $listCn, string $envelopeTo, \Throwable $e): void
    {
        $errorMessage = 'Rejected as spam by receiving mail server: ' . $e->getMessage();

        $recipientIds = [$recipientId];
        if ($batchId !== null && $batchId !== '') {
            $stmt = $this->db->prepare(
                "SELECT qr.id
                 FROM queue_recipients qr
                 JOIN mail_queue mq ON mq.id = qr.mail_queue_id
                 WHERE mq.batch_id = :batch AND qr.status = 'pending' AND qr.id != :id"
            );
            $stmt->execute(['batch' => $batchId, 'id' => $recipientId]);
            foreach ($stmt->fetchAll(PDO::FETCH_COLUMN) as $siblingId) {
                $recipientIds[] = (int) $siblingId;
            }
        }

        $placeholders = implode(',', array_fill(0, count($recipientIds), '?'));
        $stmt = $this->db->prepare(
            "UPDATE queue_recipients SET status = 'failed', error = ? WHERE id IN ($placeholders)"
        );
        $stmt->execute([$errorMessage, ...$recipientIds]);

        $domain = $this->spamRejectionDetector->domainOf($envelopeTo);
        error_log(
            "Listig: Discarded " . count($recipientIds) . " queued copy/copies for list $listCn "
            . "after $domain rejected mail to $envelopeTo as spam: " . $e->getMessage()
        );

        $this->notifySpamRejection($listCn, $domain, $errorMessage, count($recipientIds));
    }

    private static function isInvalidAddress(string $address): bool
    {
        $domain = substr(strrchr($address, '@') ?: '', 1);
        return $domain !== '' && str_ends_with(strtolower($domain), '.invalid');
    }

    private function cleanupQueueEntry(string $queueId): void
    {
        // A 'failed' recipient deliberately still counts as blocking deletion here:
        // the mail_queue row holds the MIME body that QueueController::retry needs
        // to resend it, and the owner is expected to retry or delete it via the UI.
        // purgeStaleFailedEntries() bounds how long such rows are kept if nobody does.
        $stmt = $this->db->prepare(
            "SELECT COUNT(*) FROM queue_recipients WHERE mail_queue_id = :qid AND status != 'sent'"
        );
        $stmt->execute(['qid' => $queueId]);
        if ((int) $stmt->fetchColumn() === 0) {
            $this->db->prepare('DELETE FROM mail_queue WHERE id = :id')->execute(['id' => $queueId]);
        }
    }

    /**
     * Without this, a mail_queue row with at least one permanently 'failed' recipient
     * would never be deleted by cleanupQueueEntry() — the MIME body (and attachments)
     * would accumulate forever for lists with persistent delivery problems. Owners are
     * notified immediately on failure and can retry/delete via the UI; after 30 days
     * of inaction (matching the retention window used elsewhere, e.g. bounce_log) the
     * failed recipient and any now-orphaned mail_queue row are purged.
     */
    public function purgeStaleFailedEntries(): void
    {
        $this->db->exec(
            "DELETE FROM queue_recipients WHERE status = 'failed' AND last_attempt_at < NOW() - INTERVAL 30 DAY"
        );
        $this->db->exec(
            'DELETE FROM mail_queue WHERE NOT EXISTS (
                SELECT 1 FROM queue_recipients WHERE queue_recipients.mail_queue_id = mail_queue.id
            )'
        );
    }

    private function notifyOwnerOfFailure(string $listCn, string $failedRecipient, string $error): void
    {
        $list = $this->listProvider->getList($listCn);
        if ($list === null) {
            return;
        }

        $locale = $list->language;
        $this->notificationMailer->sendToOwners(
            $list,
            $this->translator->trans('queue.failure_notice.subject', [
                '%list%' => $list->displayName,
                '%recipient%' => $failedRecipient,
            ], null, $locale),
            $this->translator->trans('queue.failure_notice.body', [
                '%recipient%' => $failedRecipient,
                '%error%' => $error,
                '%app_name%' => $this->appName,
            ], null, $locale),
        );
    }

    private function notifySpamRejection(string $listCn, string $domain, string $error, int $discardedCount): void
    {
        $list = $this->listProvider->getList($listCn);
        if ($list === null) {
            return;
        }

        $locale = $list->language;
        $this->notificationMailer->sendToOwners(
            $list,
            $this->translator->trans('queue.spam_rejected.subject', [
                '%list%' => $list->displayName,
                '%domain%' => $domain,
            ], null, $locale),
            $this->translator->trans('queue.spam_rejected.body', [
                '%list%' => $list->displayName,
                '%domain%' => $domain,
                '%count%' => $discardedCount,
                '%error%' => $error,
            ], null, $locale),
        );
    }
}
