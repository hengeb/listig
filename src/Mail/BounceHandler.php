<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

use Hengeb\Listig\Config\ListConfig;
use PDO;
use PhpImap\IncomingMail;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * Records a bounce in bounce_log and forwards the original bounce mail to the
 * list owners. Extracted from bin/worker.php to keep that file a thin loop and
 * match the rest of the codebase's constructor-injected, class-based design.
 */
class BounceHandler
{
    public function __construct(
        private readonly PDO $db,
        private readonly NotificationMailer $notificationMailer,
        private readonly TranslatorInterface $translator,
        private readonly HeaderFilter $headerFilter,
    ) {
    }

    public function handle(ListConfig $list, IncomingMail $mail, string $rawMime): void
    {
        $this->logBounce($list->name, $mail);
        $this->forwardToOwners($list, $mail, $rawMime);
    }

    private function logBounce(string $listCn, IncomingMail $mail): void
    {
        $stmt = $this->db->prepare(
            'INSERT INTO bounce_log (list_cn, sender, subject, bounced_at) VALUES (:list, :sender, :subject, NOW())'
        );
        $stmt->execute([
            'list'    => $listCn,
            'sender'  => $mail->fromAddress ?? '',
            'subject' => $mail->subject,
        ]);
    }

    private function forwardToOwners(ListConfig $list, IncomingMail $mail, string $rawMime): void
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
            $this->translator->trans('bounce.owner_notice.body', [
                '%list%' => $list->displayName,
                '%sender%' => $sender,
                '%subject%' => $subject,
                '%reason%' => $reason,
                '%failed_recipient%' => $failedRecipient,
                '%original_sender%' => $originalSender,
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
}
