<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Queue\QueueSender;
use PDO;
use PhpImap\IncomingMail;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * Records a bounce in bounce_log and forwards the original bounce mail to the
 * list owners. Extracted from bin/worker.php to keep that file a thin loop and
 * match the rest of the codebase's constructor-injected, class-based design.
 *
 * Also applies an automatic action for certain, well-recognized bounce causes
 * — today, only a spam-rejection reported by a reliable domain, which aborts
 * every other still-pending queued copy of the same original mail (see
 * applyAutomaticAction()/BounceCauseClassifier). This exists because a bounce
 * can arrive asynchronously, via IMAP, *while* QueueSender is still working
 * through the rest of the same batch across later worker cycles — without
 * this, a mail one reliable provider has already rejected as spam kept being
 * sent to every remaining recipient regardless. See CLAUDE.md "Automatic
 * bounce actions".
 *
 * A bounce-forward is itself an outgoing mail (via NotificationMailer), which
 * means it can itself bounce — and that new bounce would, without the two
 * guards in handle() below, be forwarded again, producing another
 * notification for the owner's server to possibly reject again, and so on.
 * Confirmed live: a single spam-rejected distributed mail produced roughly
 * 100 consecutive bounces this way before these guards existed. See
 * isBounceOnOwnNotification() (the primary fix) and the bounce-log circuit
 * breaker in handle() (the last-resort safety net) — plus
 * NotificationMailer's own null-sender envelope and X-Listig-Auto/
 * Auto-Submitted headers, which this class's detection depends on.
 */
class BounceHandler
{
    /** Trips the circuit breaker once more than this many bounces have been logged for a list within CIRCUIT_BREAKER_WINDOW_MINUTES — see handle(). */
    private const int CIRCUIT_BREAKER_THRESHOLD = 5;

    /** Rolling window (minutes) the circuit breaker counts bounces over — see handle(). */
    private const int CIRCUIT_BREAKER_WINDOW_MINUTES = 15;

    public function __construct(
        private readonly PDO $db,
        private readonly NotificationMailer $notificationMailer,
        private readonly TranslatorInterface $translator,
        private readonly HeaderFilter $headerFilter,
        private readonly QueueSender $queueSender,
        private readonly BounceCauseClassifier $bounceCauseClassifier,
    ) {
    }

    public function handle(ListConfig $list, IncomingMail $mail, string $rawMime): void
    {
        $this->logBounce($list->name, $mail);

        if ($this->isBounceOnOwnNotification($rawMime)) {
            return;
        }

        // The automatic action (e.g. aborting the rest of a spam-rejected
        // batch) is a protective measure against the underlying distributed
        // mail itself, independent of whether the owner actually gets
        // notified about this particular bounce below — it still runs even
        // while the circuit breaker is suppressing forwards, since a burst of
        // bounces is exactly the situation where it matters most.
        $autoAction = $this->applyAutomaticAction($list, $rawMime);

        if ($this->circuitBreakerTripped($list->name)) {
            return;
        }

        $this->forwardToOwners($list, $mail, $rawMime, $autoAction);
    }

    /**
     * Classifies this bounce (via BounceCauseClassifier) and, if it maps to a
     * known cause, executes the matching automatic action — always returns a
     * translated description for the owner notice's own "Automatic response:"
     * line, never null: the overwhelmingly common case (no cause recognized,
     * or a cause recognized but nothing was actually left to act on) still
     * gets an explicit "none" (bounce.auto_action.none) rather than the line
     * silently disappearing, so an owner reading the notice always knows
     * whether Listig reacted or not, not just when it did.
     *
     * Extension point for future causes (see BounceCause's own docblock) —
     * e.g. a permanent "user unknown" bounce could eventually drive a
     * block-or-remove-member action instead of Spam's abort-batch one: add a
     * new BounceCause case, a new check in BounceCauseClassifier, and a new
     * match arm below.
     */
    private function applyAutomaticAction(ListConfig $list, string $rawMime): string
    {
        $reason          = $this->extractDiagnostic($rawMime);
        $failedRecipient = $this->extractFailedRecipient($rawMime);

        $cause = $this->bounceCauseClassifier->classify($reason, $failedRecipient);
        if ($cause === null) {
            return $this->noAutomaticAction($list);
        }

        return match ($cause) {
            BounceCause::Spam => $this->abortBatchForBounce($list, $rawMime),
        };
    }

    /**
     * A reliable domain (see SpamRejectionDetector) reported this recipient's
     * copy as spam via an async DSN, not a live SMTP rejection — QueueSender's
     * own synchronous path (SpamRejectionDetector, checked inside
     * sendOne()) only ever sees a live send() failure, so this is the async
     * equivalent: find every other still-pending queued copy of the same
     * original mail — via mail_queue.message_id, preserved verbatim from the
     * incoming mail on every personalized outgoing copy, see
     * MailProcessor::process() — and discard it the same way, rather than
     * keep sending a message at least one reliable provider has already
     * rejected as spam to everyone else too.
     *
     * Falls back to noAutomaticAction() if the original Message-ID couldn't
     * be recovered from the attached original message, or if nothing was
     * actually still pending by the time this ran — nothing happened, so the
     * owner notice should say so rather than claim an abort that didn't do
     * anything.
     */
    private function abortBatchForBounce(ListConfig $list, string $rawMime): string
    {
        $messageId = $this->extractOriginalMessageId($rawMime);

        $discarded = 0;
        if ($messageId !== null) {
            foreach ($this->queueSender->findBatchIdsByMessageId($list->name, $messageId) as $batchId) {
                $discarded += $this->queueSender->discardPendingBatch(
                    $batchId,
                    "Aborted: a reliable domain's async bounce reported this mail as spam (Message-ID $messageId)",
                );
            }
        }

        if ($discarded === 0) {
            return $this->noAutomaticAction($list);
        }

        return $this->translator->trans(
            'bounce.auto_action.abort_batch',
            ['%count%' => $discarded],
            null,
            $list->language,
        );
    }

    private function noAutomaticAction(ListConfig $list): string
    {
        return $this->translator->trans('bounce.auto_action.none', [], null, $list->language);
    }

    /**
     * True if the message/rfc822 attachment of this bounce is itself one of
     * Listig's own auto-generated notifications (NotificationMailer's
     * X-Listig-Auto header) — i.e. this is a bounce *on a bounce forward*,
     * not a bounce on an original member/owner-authored mail. This is what
     * actually breaks the loop: forwardToOwners() sends every bounce
     * notification through NotificationMailer, which stamps that same header
     * on its own output, so a bounce on *that* forward is recognized here and
     * dropped rather than being treated as a brand-new bounce and forwarded
     * again.
     *
     * Mirrors extractOriginalSender()'s own approach of searching only from
     * the first message/rfc822 marker onward — a standard bounce carries the
     * original message as a message/rfc822 part after the human-readable
     * explanation and delivery-status parts, so this can't accidentally match
     * something in the outer bounce's own headers instead.
     */
    private function isBounceOnOwnNotification(string $rawMime): bool
    {
        $pos = stripos($rawMime, 'message/rfc822');
        if ($pos === false) {
            return false;
        }
        return $this->headerFilter->readHeader(substr($rawMime, $pos), NotificationMailer::AUTO_HEADER) !== null;
    }

    /**
     * Last-resort safety net beyond isBounceOnOwnNotification(): that check
     * only catches a bounce whose own X-Listig-Auto header survived intact in
     * the attached original message — a bounce generator that reformats,
     * truncates, or otherwise mangles the attached original (some do) could
     * still slip through undetected. If a list has already logged more than
     * $threshold bounces within the last $windowMinutes minutes (the just-
     * logged one from handle() included), stop forwarding entirely until it
     * cools down, rather than let a fast loop through whatever gap remains.
     * Uses bounce_log's own idx_list_time index (list_cn, bounced_at) — a
     * single indexed COUNT(*), not a new query shape.
     */
    private function circuitBreakerTripped(
        string $listCn,
        int $threshold = self::CIRCUIT_BREAKER_THRESHOLD,
        int $windowMinutes = self::CIRCUIT_BREAKER_WINDOW_MINUTES,
    ): bool {
        $cutoff = (new \DateTimeImmutable())->modify("-{$windowMinutes} minutes")->format('Y-m-d H:i:s');

        $stmt = $this->db->prepare(
            'SELECT COUNT(*) FROM bounce_log WHERE list_cn = :list AND bounced_at > :cutoff'
        );
        $stmt->execute(['list' => $listCn, 'cutoff' => $cutoff]);

        $count = (int) $stmt->fetchColumn();
        if ($count > $threshold) {
            error_log(
                "Listig: Bounce circuit breaker tripped for list $listCn ($count bounces in the last "
                . "$windowMinutes minutes) — not forwarding to owners until it cools down."
            );
            return true;
        }

        return false;
    }

    private function logBounce(string $listCn, IncomingMail $mail): void
    {
        // Lets the manage page's bounce table offer a click-through preview, the
        // same way ArchiveIndexer keys an archived_mail row — null when archive
        // is off (the bounce mail gets deleted, not archived, by
        // ImapArchiver::archiveOrDelete() right after this) or the bounce mail
        // simply had no Message-ID; either way BounceController degrades to a
        // "mail unavailable" preview rather than erroring, same as the archive
        // viewer already does for a missing mail.
        $messageId = $this->headerFilter->readMessageId($mail->headersRaw ?? '');

        $stmt = $this->db->prepare(
            'INSERT INTO bounce_log (list_cn, sender, subject, message_id, bounced_at) VALUES (:list, :sender, :subject, :message_id, NOW())'
        );
        $stmt->execute([
            'list'       => $listCn,
            'sender'     => $mail->fromAddress ?? '',
            'subject'    => $mail->subject,
            'message_id' => $messageId,
        ]);
    }

    private function forwardToOwners(ListConfig $list, IncomingMail $mail, string $rawMime, string $autoAction): void
    {
        $sender  = $mail->fromAddress ?? 'unknown';
        $subject = $mail->subject ?? '';
        $locale  = $list->language;

        $unknown = $this->translator->trans('bounce.unknown', [], null, $locale);
        $reason          = $this->extractDiagnostic($rawMime) ?? $unknown;
        $failedRecipient = $this->extractFailedRecipient($rawMime) ?? $unknown;
        $originalSender  = $this->extractOriginalSender($rawMime) ?? $unknown;

        $this->notificationMailer->sendToOwners(
            $list,
            $this->translator->trans('bounce.owner_notice.subject', [
                '%list%' => $list->displayName,
                '%sender%' => $sender,
            ], null, $locale),
            // %auto_action% is always present — applyAutomaticAction() never
            // returns null, so the owner can always see whether Listig
            // reacted automatically, not just when it did (see its docblock).
            $this->translator->trans('bounce.owner_notice.body', [
                '%list%' => $list->displayName,
                '%sender%' => $sender,
                '%subject%' => $subject,
                '%reason%' => $reason,
                '%failed_recipient%' => $failedRecipient,
                '%original_sender%' => $originalSender,
                '%auto_action%' => $autoAction,
            ], null, $locale),
            $rawMime,
            'bounce.eml',
            'message/rfc822',
        );
    }

    /**
     * RFC 3464 delivery-status field carrying the actual failure reason, e.g.
     * "smtp; 550 5.1.1 <user@example.com>: Recipient address rejected: User
     * unknown". Diagnostic-Code is preferred over the terser numeric Status
     * (e.g. "5.1.1") when both are present. HeaderFilter::readHeader() finds the
     * first occurrence anywhere in the raw bounce — safe here because a standard
     * DSN always has its own delivery-status part (where this lives) before the
     * attached original message, so it can't accidentally match something inside
     * the original mail's own body/headers instead.
     */
    private function extractDiagnostic(string $rawMime): ?string
    {
        return $this->headerFilter->readHeader($rawMime, 'Diagnostic-Code')
            ?? $this->headerFilter->readHeader($rawMime, 'Status');
    }

    /**
     * RFC 3464's Final-Recipient/Original-Recipient fields — the address delivery
     * actually failed for. Values look like "rfc822;user@example.com", so the
     * "rfc822;" address-type prefix is stripped.
     */
    private function extractFailedRecipient(string $rawMime): ?string
    {
        $value = $this->headerFilter->readHeader($rawMime, 'Final-Recipient')
            ?? $this->headerFilter->readHeader($rawMime, 'Original-Recipient');
        return $value !== null ? preg_replace('/^rfc822;\s*/i', '', $value) : null;
    }

    /**
     * Who originally posted the mail that bounced — read from the From: header
     * of the *attached original message*, not the outer bounce's own From:
     * (typically MAILER-DAEMON@..., not useful here). A standard bounce carries
     * the original message as a message/rfc822 part after the human-readable
     * explanation and delivery-status parts, so searching for the first From:
     * header only from that point onward skips the outer one.
     */
    private function extractOriginalSender(string $rawMime): ?string
    {
        $pos = stripos($rawMime, 'message/rfc822');
        if ($pos === false) {
            return null;
        }
        return $this->headerFilter->readHeader(substr($rawMime, $pos), 'From');
    }

    /**
     * Message-ID of the *attached original message* (not the outer bounce's
     * own) — used to correlate this bounce back to mail_queue.message_id, see
     * abortBatchForBounce(). Same message/rfc822-marker-onward search as
     * extractOriginalSender(), and the same bare-id normalization
     * QueueWriter::enqueue() stores under that column (HeaderFilter::readMessageId()).
     */
    private function extractOriginalMessageId(string $rawMime): ?string
    {
        $pos = stripos($rawMime, 'message/rfc822');
        if ($pos === false) {
            return null;
        }
        return $this->headerFilter->readMessageId(substr($rawMime, $pos));
    }
}
