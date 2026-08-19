<?php

declare(strict_types=1);

namespace Hengeb\Listig\Queue;

use Hengeb\Listig\Mail\NotificationMailer;
use Hengeb\Listig\Provider\ListProvider;
use Hengeb\Listig\Smtp\SmtpConnectionFactory;
use Hengeb\Listig\Token\TokenService;
use PDO;
use Symfony\Component\Mailer\Envelope;
use Symfony\Component\Mailer\Mailer;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\RawMessage;
use Symfony\Contracts\Translation\TranslatorInterface;

class QueueSender
{
    /**
     * Max age for a signed per-recipient bounce token (see sendOne()) —
     * matches unsubscribe/accept/reject's own 7-day window (CLAUDE.md "Token
     * Format"). A bounce can legitimately arrive well after the original
     * send, so this needs to be generous, not just long enough for the
     * fastest hard-bounce case.
     */
    public const int BOUNCE_TOKEN_MAX_AGE = 7 * 24 * 3600;

    public function __construct(
        private readonly PDO $db,
        private readonly SmtpConnectionFactory $smtpFactory,
        private readonly ListProvider $listProvider,
        private readonly NotificationMailer $notificationMailer,
        private readonly TranslatorInterface $translator,
        private readonly SpamRejectionDetector $spamRejectionDetector,
        private readonly TokenService $tokenService,
        private readonly string $appName,
    ) {
    }

    public function sendBatch(int $batchSize = 50): void
    {
        // last_attempt_at ASC stays the primary order — a never-attempted or
        // longest-waiting recipient is still served first, so a persistent backlog
        // can't starve a retry indefinitely. RAND() only breaks ties *within* the
        // same priority (e.g. a whole batch just enqueued with last_attempt_at
        // NULL, or several retries from the same prior cycle) — without it, the
        // same recipient/provider tended to always be first in line for a given
        // send, which meant one specific mailbox got hit first on every mass send.
        // The NOT EXISTS clause skips a recipient currently deferred after a
        // mailbox-full bounce (BounceHandler::handleMailboxFull() sets
        // retry_not_before on the *bounced* row itself, via markBounced() —
        // see CLAUDE.md "Automatic bounce actions"). Self-joins against this
        // same table/list/recipient rather than a separate tracking table,
        // since queue_recipients now retains completed rows for 30 days
        // (purgeCompletedEntries()) specifically so this history is still
        // there to query.
        $stmt = $this->db->prepare(
            'SELECT qr.id, qr.mail_queue_id, qr.envelope_to, mq.list_cn, mq.batch_id, mq.mime
             FROM queue_recipients qr
             JOIN mail_queue mq ON mq.id = qr.mail_queue_id
             WHERE qr.status = \'pending\'
               AND NOT EXISTS (
                   SELECT 1 FROM queue_recipients qr2
                   JOIN mail_queue mq2 ON mq2.id = qr2.mail_queue_id
                   WHERE mq2.list_cn = mq.list_cn
                     AND LOWER(qr2.envelope_to) = LOWER(qr.envelope_to)
                     AND qr2.retry_not_before > NOW()
               )
             ORDER BY qr.last_attempt_at ASC, RAND()
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
        $listCn = $row['list_cn'];
        $batchId = $row['batch_id'];
        $envelopeTo = $row['envelope_to'];
        $mime = $row['mime'];

        // Empty recipient — e.g. a member row/resolver template that produced no
        // address at all. Never a deliverable target; skip outright rather than
        // wasting an SMTP attempt (and a retry cycle) on it.
        if ($envelopeTo === '') {
            $this->db->prepare(
                "UPDATE queue_recipients SET status = 'failed', error = :error WHERE id = :id"
            )->execute(['error' => 'Skipped: recipient has no email address', 'id' => $recipientId]);
            return;
        }

        // RFC 2606 reserved TLD — never a real, deliverable domain. Skip outright
        // rather than wasting an SMTP attempt (and a retry cycle) on it.
        if (self::isInvalidAddress($envelopeTo)) {
            $this->db->prepare(
                "UPDATE queue_recipients SET status = 'failed', error = :error WHERE id = :id"
            )->execute(['error' => 'Skipped: recipient uses the reserved .invalid domain', 'id' => $recipientId]);
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

            // Per-recipient bounce address (VERP-style, signed rather than
            // sequential) — see BounceHandler::resolveVerifiedRecipient(),
            // which decodes this same token from wherever the resulting DSN
            // gets delivered back to. This is what lets an async bounce be
            // bound to *exactly* this queue_recipients row, rather than
            // trusting whatever the DSN's own content claims (Final-Recipient,
            // an attached original message's Message-ID — both plain text an
            // attacker fully controls). Same "URL-safe base64, safe in mail +
            // addresses" token shape already used for accept/reject — see
            // CLAUDE.md "Token Format".
            $bounceToken = $this->tokenService->sign('bounce', $listCn, $recipientId);
            $bounceFrom = "{$list->localPart}+bounce+{$bounceToken}@{$list->domain}";

            $mailer->send(
                new RawMessage($mime),
                new Envelope(
                    new Address($bounceFrom),
                    [new Address($envelopeTo)]
                )
            );

            // Mark sent — the row (and its mail_queue parent) is deliberately
            // NOT deleted now; it stays around for purgeCompletedEntries()'s
            // own 30-day retention so a delayed async bounce can still find
            // and retroactively correct it (see markBounced()).
            $this->db->prepare(
                "UPDATE queue_recipients SET status = 'sent' WHERE id = :id"
            )->execute(['id' => $recipientId]);
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

        $this->markRecipientsFailed($recipientIds, $errorMessage);

        $domain = $this->spamRejectionDetector->domainOf($envelopeTo);
        error_log(
            "Listig: Discarded " . count($recipientIds) . " queued copy/copies for list $listCn "
            . "after $domain rejected mail to $envelopeTo as spam: " . $e->getMessage()
        );

        $this->notifySpamRejection($listCn, $domain, $errorMessage, count($recipientIds));
    }

    /**
     * Looks up the exact queue_recipients row a signed bounce token (see
     * sendOne()) decodes to, together with its batch_id and list_cn — the
     * *only* trustworthy source BounceHandler uses for "which recipient/batch
     * does this async bounce concern", since it comes from Listig's own
     * HMAC-verified assignment rather than any self-reported DSN content.
     * Returns null if the row no longer exists — either genuinely never
     * existed, or aged out of purgeCompletedEntries()'s 30-day retention —
     * in which case there is nothing left to act on anyway, the same
     * graceful "nothing pending" outcome as everywhere else in this class.
     *
     * @return array{envelopeTo: string, batchId: ?string, listCn: string}|null
     */
    public function findRecipientById(int $recipientId): ?array
    {
        $stmt = $this->db->prepare(
            'SELECT qr.envelope_to AS envelopeTo, mq.batch_id AS batchId, mq.list_cn AS listCn
             FROM queue_recipients qr
             JOIN mail_queue mq ON mq.id = qr.mail_queue_id
             WHERE qr.id = :id'
        );
        $stmt->execute(['id' => $recipientId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row === false ? null : $row;
    }

    /**
     * Marks every still-pending queue_recipients row for a given batch as
     * failed, without an accompanying live SMTP-rejection Throwable — the
     * async equivalent of discardBatchAsSpam() above, used when a bounce (not
     * a live send() failure) already indicates this batch's content is
     * unwanted for at least one recipient (see BounceHandler /
     * BounceCauseClassifier). Unlike discardBatchAsSpam(), this sends no
     * notification of its own — the caller (BounceHandler) already forwards
     * the triggering bounce to the owners and folds a description of this
     * action into that same notice, rather than sending a second, separate
     * one.
     *
     * Returns the number of rows actually discarded (0 if the batch was
     * already fully sent/failed/gone by the time this runs — nothing left to
     * report).
     */
    public function discardPendingBatch(string $batchId, string $reason): int
    {
        $stmt = $this->db->prepare(
            "SELECT qr.id
             FROM queue_recipients qr
             JOIN mail_queue mq ON mq.id = qr.mail_queue_id
             WHERE mq.batch_id = :batch AND qr.status = 'pending'"
        );
        $stmt->execute(['batch' => $batchId]);
        $recipientIds = array_map('intval', $stmt->fetchAll(PDO::FETCH_COLUMN));

        if (empty($recipientIds)) {
            return 0;
        }

        $this->markRecipientsFailed($recipientIds, $reason);
        return count($recipientIds);
    }

    /** @param int[] $recipientIds */
    private function markRecipientsFailed(array $recipientIds, string $errorMessage): void
    {
        $placeholders = implode(',', array_fill(0, count($recipientIds), '?'));
        $stmt = $this->db->prepare(
            "UPDATE queue_recipients SET status = 'failed', error = ? WHERE id IN ($placeholders)"
        );
        $stmt->execute([$errorMessage, ...$recipientIds]);
    }

    private static function isInvalidAddress(string $address): bool
    {
        $domain = substr(strrchr($address, '@') ?: '', 1);
        return $domain !== '' && str_ends_with(strtolower($domain), '.invalid');
    }

    /**
     * Retroactively corrects a queue_recipients row's own outcome once an
     * authenticated async bounce (BounceHandler) proves it — a 'sent' row
     * genuinely bounced later, or (less commonly) a still-'pending' one
     * bounced before ever being attempted again. Called for *every*
     * recognized BounceCause, not just the ones with a further automatic
     * action, so the manage page's queue status always reflects reality
     * rather than a stale "sent" that turned out to be wrong.
     *
     * $errorTag is one of the fixed `BOUNCE:*` constants (see BounceHandler)
     * — a recognizable prefix, distinct from an ordinary SMTP failure's own
     * error text, so countRecentBounces() can query specifically for
     * bounce-caused failures. $retryNotBefore (only ever set for
     * BounceCause::MailboxFull) is what sendBatch()'s own NOT EXISTS clause
     * checks to defer this recipient's *future* sends — computed here, in
     * PHP, from the specific list's own bounce-defer-days, since
     * sendBatch()'s query spans every list at once and has no way to look up
     * a per-list interval itself.
     */
    public function markBounced(int $recipientId, string $errorTag, ?\DateTimeImmutable $retryNotBefore = null): void
    {
        $stmt = $this->db->prepare(
            "UPDATE queue_recipients SET status = 'failed', error = :error, retry_not_before = :notBefore WHERE id = :id"
        );
        $stmt->execute([
            'error' => $errorTag,
            'notBefore' => $retryNotBefore?->format('Y-m-d H:i:s'),
            'id' => $recipientId,
        ]);
    }

    /**
     * Counts this (list, recipient) pair's own bounce history tagged with
     * $errorTag — the basis for BounceHandler::handleMailboxFull()'s
     * escalation decision ("has this address bounced with mailbox-full at
     * least bounce-escalate-after times"). Naturally bounded to
     * purgeCompletedEntries()'s own 30-day retention window, since older
     * rows are purged — no separate time interval needed here.
     */
    public function countRecentBounces(string $listCn, string $envelopeTo, string $errorTag): int
    {
        $stmt = $this->db->prepare(
            'SELECT COUNT(*) FROM queue_recipients qr
             JOIN mail_queue mq ON mq.id = qr.mail_queue_id
             WHERE mq.list_cn = :list AND LOWER(qr.envelope_to) = LOWER(:envelope_to) AND qr.error = :error'
        );
        $stmt->execute(['list' => $listCn, 'envelope_to' => $envelopeTo, 'error' => $errorTag]);
        return (int) $stmt->fetchColumn();
    }

    /**
     * Deletes any queue_recipients row that's no longer 'pending' (sent or
     * failed) once it's at least 30 days old, then sweeps now-orphaned
     * mail_queue rows — the *only* place completed rows are ever deleted now
     * (sendOne() itself no longer deletes on completion, see its own
     * comments). Extending this to 'sent' rows too (not just 'failed', as
     * before) is deliberate: a delayed async bounce (mailbox-full retries in
     * particular) can arrive well after the original send was marked 'sent',
     * and markBounced() needs that row to still exist — via
     * BounceHandler::resolveVerifiedRecipient()'s token-decoded
     * queue_recipients.id — to correct it. 30 days comfortably covers even a
     * slow mailbox-full give-up sequence, matching the retention window
     * already used elsewhere (bounce_log, imap_seen, processing_failures).
     *
     * Accepted trade-off (confirmed): successfully sent mail's MIME body
     * (and attachments) now persists for up to 30 days per recipient instead
     * of being deleted within the same cycle — real, deliberate storage
     * growth in exchange for being able to retroactively correct/react to a
     * delayed bounce at all.
     */
    public function purgeCompletedEntries(): void
    {
        $this->db->exec(
            "DELETE FROM queue_recipients WHERE status != 'pending' AND last_attempt_at < NOW() - INTERVAL 30 DAY"
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
